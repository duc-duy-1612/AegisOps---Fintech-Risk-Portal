import { NextRequest, NextResponse } from 'next/server';
import { handleCopilotQuestion } from '@/application/workspace-orchestrator';
import { CopilotRequestSchema, parseRequestJsonWithSchema } from '@/domain/api-schemas';
import type { SessionDeltaSnapshot } from '@/domain/types';
import { enforceDistributedRouteRateLimit } from '@/infrastructure/distributed-rate-limiter';
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
  hydrateSessionFromPersistence,
} from '@/infrastructure/workspace-store';

export async function POST(req: NextRequest) {
  const start = performance.now();
  const rate = await enforceDistributedRouteRateLimit(
    req,
    'copilot',
    Number(process.env.AI_RATE_LIMIT_PER_MIN ?? 30)
  );
  const rateErr = buildRateLimitErrorResponse(
    rate,
    'Vượt quá giới hạn truy vấn Copilot mỗi phút. Vui lòng chờ giây lát.',
    '/api/copilot'
  );
  if (rateErr) return rateErr;

  const csrf = verifySameOriginCsrf(req);
  if (!csrf.ok) {
    return NextResponse.json(
      { code: 'CSRF_ORIGIN_MISMATCH', errorVi: csrf.errorVi },
      { status: csrf.status }
    );
  }

  const auth = authenticateSessionFromRequest(req);
  if (!auth.authenticated) {
    return NextResponse.json(
      { code: auth.status === 503 ? 'MISCONFIGURED_FAIL_CLOSED' : 'UNAUTHORIZED', errorVi: auth.errorVi },
      { status: auth.status }
    );
  }

  if (auth.identity.role === 'END_USER') {
    return NextResponse.json(
      {
        code: 'FORBIDDEN_RBAC',
        errorVi: 'Vai trò END_USER không được phép truy vấn AI Copilot nội bộ.',
      },
      { status: 403 }
    );
  }

  const parsed = await parseRequestJsonWithSchema(req, CopilotRequestSchema);
  if (!parsed.ok) return parsed.response;

  const question = sanitizePlainText(parsed.data.question, 600);
  if (!question) {
    return NextResponse.json(
      { code: 'VALIDATION_ERROR', errorVi: 'Câu hỏi không được để trống.' },
      { status: 400 }
    );
  }

  const alertId = sanitizePlainText(parsed.data.alertId, 64) || 'ALT-APP-003';
  try {
    await hydrateSessionFromPersistence(auth.identity.sessionId);
    const reply = await handleCopilotQuestion({
      sessionId: auth.identity.sessionId,
      alertId,
      question,
      clientDelta: (parsed.data.clientDelta ?? null) as Partial<SessionDeltaSnapshot> | null,
    });
    logStructuredEvent({
      route: '/api/copilot',
      action: 'COPILOT_ASK',
      status: '200',
      durationMs: performance.now() - start,
      metadata: { modelUsed: reply.modelUsed },
    });
    return NextResponse.json(reply);
  } catch (err) {
    const mapped = mapPersistenceOrSessionErrorResponse({
      err,
      route: '/api/copilot',
      action: 'COPILOT_ASK',
    });
    if (mapped) return mapped;
    if (err instanceof InvalidStateIntegrityError) {
      return NextResponse.json(
        { code: 'FORGED_STATE_REVISION', errorVi: err.message },
        { status: 400 }
      );
    }
    return NextResponse.json(
      {
        code: 'COPILOT_ERROR',
        errorVi: err instanceof Error ? err.message : 'Không thể xử lý câu hỏi Copilot.',
      },
      { status: 400 }
    );
  }
}
