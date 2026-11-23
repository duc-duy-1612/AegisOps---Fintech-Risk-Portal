import { NextRequest, NextResponse } from 'next/server';
import { ingestBatchSandboxCases } from '@/application/workspace-orchestrator';
import { BatchImportRequestSchema, parseRequestJsonWithSchema } from '@/domain/api-schemas';
import { parseBatchCasesPayload } from '@/domain/batch-io';
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
  commitSessionToPersistence,
  hydrateSessionFromPersistence,
} from '@/infrastructure/workspace-store';

export async function POST(req: NextRequest) {
  const start = performance.now();
  const rate = await enforceDistributedRouteRateLimit(req, 'batch-import', 15, {
    criticalMutation: true,
  });
  const rateErr = buildRateLimitErrorResponse(
    rate,
    'Tần suất nhập file hàng loạt quá nhanh. Vui lòng thử lại sau ít giây.',
    '/api/batch-import'
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
        errorVi: 'Vai trò END_USER không có quyền nhập lô dữ liệu nghiệp vụ hàng loạt.',
      },
      { status: 403 }
    );
  }

  const parsed = await parseRequestJsonWithSchema(req, BatchImportRequestSchema);
  if (!parsed.ok) return parsed.response;

  const rawContent = parsed.data.rawContent;
  const fileName = sanitizePlainText(parsed.data.fileName, 120) || 'batch.csv';

  try {
    const { preMutationRevision } = await hydrateSessionFromPersistence(auth.identity.sessionId);

    const { specs, warnings } = parseBatchCasesPayload(rawContent, fileName);
    if (specs.length === 0) {
      return NextResponse.json(
        {
          code: 'VALIDATION_ERROR',
          errorVi: warnings[0] ?? 'Không đọc được hồ sơ hợp lệ nào từ file CSV/JSON.',
        },
        { status: 400 }
      );
    }

    const result = ingestBatchSandboxCases({
      sessionId: auth.identity.sessionId,
      specs,
      fileName,
      clientDelta: (parsed.data.clientDelta ?? null) as Partial<SessionDeltaSnapshot> | null,
    });

    const committed =
      (result.delta.stateRevision ?? 0) > preMutationRevision
        ? await commitSessionToPersistence({
            sessionId: auth.identity.sessionId,
            principalId: auth.identity.principalId,
            expectedRevision: preMutationRevision,
            committedDelta: result.delta,
          })
        : result.delta;

    logStructuredEvent({
      route: '/api/batch-import',
      action: 'BATCH_IMPORT',
      status: '200',
      durationMs: performance.now() - start,
      metadata: { importedCount: result.importedCount },
    });

    return NextResponse.json({
      ...result,
      delta: committed,
      warnings,
    });
  } catch (err) {
    const mapped = mapPersistenceOrSessionErrorResponse({
      err,
      route: '/api/batch-import',
      action: 'BATCH_IMPORT',
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
        code: 'BATCH_PARSE_ERROR',
        errorVi: err instanceof Error ? err.message : 'Định dạng file CSV/JSON không hợp lệ.',
      },
      { status: 400 }
    );
  }
}
