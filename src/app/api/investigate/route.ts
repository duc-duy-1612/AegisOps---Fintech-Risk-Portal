import { NextRequest, NextResponse } from 'next/server';
import { executeAlertInvestigation } from '@/application/workspace-orchestrator';
import { InvestigateRequestSchema, parseRequestJsonWithSchema } from '@/domain/api-schemas';
import type { SessionDeltaSnapshot } from '@/domain/types';
import {
  enforceDistributedRouteRateLimit,
  resolvePublicAiRouteLimits,
} from '@/infrastructure/distributed-rate-limiter';
import { logStructuredEvent } from '@/infrastructure/observability';
import {
  buildRateLimitErrorResponse,
  mapPersistenceOrSessionErrorResponse,
} from '@/infrastructure/route-guards';
import { sanitizePlainText } from '@/infrastructure/security-guard';
import {
  authenticateSessionFromRequest,
  verifySameOriginCsrf,
} from '@/infrastructure/session-auth';
import {
  InvalidStateIntegrityError,
  commitSessionToPersistence,
  hydrateSessionFromPersistence,
} from '@/infrastructure/workspace-store';

export async function POST(req: NextRequest) {
  const start = performance.now();
  const csrf = verifySameOriginCsrf(req);
  if (!csrf.ok) {
    return NextResponse.json(
      { code: 'CSRF_ORIGIN_MISMATCH', errorVi: csrf.errorVi },
      { status: csrf.status }
    );
  }

  const limits = resolvePublicAiRouteLimits('INVESTIGATE');
  const auth = authenticateSessionFromRequest(req);
  if (!auth.authenticated) {
    const anonRate = await enforceDistributedRouteRateLimit(
      req,
      'investigate',
      limits.ipBurstMaxPerMinute
    );
    const anonRateErr = buildRateLimitErrorResponse(
      anonRate,
      'Vượt quá giới hạn tần suất gọi AI trong 1 phút. Vui lòng thử lại sau giây lát.',
      '/api/investigate'
    );
    if (anonRateErr) return anonRateErr;
    return NextResponse.json(
      { code: auth.status === 503 ? 'MISCONFIGURED_FAIL_CLOSED' : 'UNAUTHORIZED', errorVi: auth.errorVi },
      { status: auth.status }
    );
  }

  const rate = await enforceDistributedRouteRateLimit(
    req,
    'investigate',
    limits.ipBurstMaxPerMinute,
    {
      sessionId: auth.identity.sessionId,
      sessionMaxPerMinute: limits.sessionMaxPerMinute,
    }
  );
  const rateErr = buildRateLimitErrorResponse(
    rate,
    'Vượt quá giới hạn tần suất gọi AI trong 1 phút. Vui lòng thử lại sau giây lát.',
    '/api/investigate'
  );
  if (rateErr) return rateErr;

  if (auth.identity.role === 'END_USER') {
    return NextResponse.json(
      {
        code: 'FORBIDDEN_RBAC',
        errorVi: 'Vai trò END_USER không có quyền chạy điều tra hệ thống nội bộ Fintech.',
      },
      { status: 403 }
    );
  }

  const parsed = await parseRequestJsonWithSchema(req, InvestigateRequestSchema);
  if (!parsed.ok) return parsed.response;

  const sessionId = auth.identity.sessionId;
  const alertId = sanitizePlainText(parsed.data.alertId, 64) || 'ALT-APP-003';

  try {
    const { preMutationRevision } = await hydrateSessionFromPersistence(sessionId);
    const result = await executeAlertInvestigation({
      sessionId,
      alertId,
      clientDelta: (parsed.data.clientDelta ?? null) as Partial<SessionDeltaSnapshot> | null,
    });
    const committed =
      (result.delta.stateRevision ?? 0) > preMutationRevision
        ? await commitSessionToPersistence({
            sessionId,
            principalId: auth.identity.principalId,
            expectedRevision: preMutationRevision,
            committedDelta: result.delta,
          })
        : result.delta;

    logStructuredEvent({
      route: '/api/investigate',
      action: 'INVESTIGATE_ALERT',
      status: '200',
      durationMs: performance.now() - start,
      metadata: { modelUsed: result.report.modelUsed },
    });

    return NextResponse.json({ ...result, delta: committed });
  } catch (err) {
    const mapped = mapPersistenceOrSessionErrorResponse({
      err,
      route: '/api/investigate',
      action: 'INVESTIGATE_ALERT',
    });
    if (mapped) return mapped;
    if (err instanceof InvalidStateIntegrityError) {
      return NextResponse.json(
        { code: 'FORGED_STATE_REVISION', errorVi: err.message },
        { status: 400 }
      );
    }
    logStructuredEvent({
      level: 'ERROR',
      route: '/api/investigate',
      action: 'INVESTIGATE_ALERT',
      status: '400',
      errorCode: 'INVESTIGATION_ERROR',
    });
    return NextResponse.json(
      {
        code: 'INVESTIGATION_ERROR',
        errorVi: 'Không thể hoàn tất quá trình điều tra sự cố. Vui lòng thử lại sau.',
      },
      { status: 400 }
    );
  }
}
