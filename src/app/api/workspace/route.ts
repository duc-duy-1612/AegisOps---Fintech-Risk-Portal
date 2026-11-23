import { NextRequest, NextResponse } from 'next/server';
import { getWorkspaceBootstrap } from '@/application/workspace-orchestrator';
import {
  WORKSPACE_SYNC_MAX_JSON_BODY_BYTES,
  WorkspaceSyncRequestSchema,
  parseRequestJsonWithSchema,
} from '@/domain/api-schemas';
import type { SessionDeltaSnapshot } from '@/domain/types';
import { enforceDistributedRouteRateLimit } from '@/infrastructure/distributed-rate-limiter';
import { logStructuredEvent } from '@/infrastructure/observability';
import {
  buildRateLimitErrorResponse,
  mapPersistenceOrSessionErrorResponse,
} from '@/infrastructure/route-guards';
import {
  authenticateSessionFromRequest,
  isStrictSecretsModeEnabled,
  verifySameOriginCsrf,
} from '@/infrastructure/session-auth';
import {
  InvalidStateIntegrityError,
  commitSessionToPersistence,
  hydrateSessionFromPersistence,
  resetAuthoritativeSession,
} from '@/infrastructure/workspace-store';

const rejectPredictableStrictDefaultSession = (sessionId: string): NextResponse | null => {
  if (isStrictSecretsModeEnabled() && sessionId === 'judge-default-session') {
    return NextResponse.json(
      {
        code: 'PREDICTABLE_DEFAULT_SESSION_FORBIDDEN',
        errorVi:
          'Từ chối truy cập (HTTP 401): Phiên mặc định dễ đoán judge-default-session không được phép sử dụng ở chế độ bảo mật nghiêm ngặt.',
      },
      { status: 401 }
    );
  }
  return null;
};

export async function GET(req: NextRequest) {
  const rate = await enforceDistributedRouteRateLimit(req, 'workspace-get', 60);
  const rateErr = buildRateLimitErrorResponse(
    rate,
    'Quá nhiều yêu cầu đọc workspace.',
    '/api/workspace'
  );
  if (rateErr) return rateErr;

  const auth = authenticateSessionFromRequest(req);
  if (!auth.authenticated) {
    return NextResponse.json(
      {
        code: auth.status === 503 ? 'MISCONFIGURED_FAIL_CLOSED' : 'UNAUTHORIZED',
        errorVi: auth.errorVi,
      },
      { status: auth.status }
    );
  }

  const strictDefaultErr = rejectPredictableStrictDefaultSession(auth.identity.sessionId);
  if (strictDefaultErr) return strictDefaultErr;

  try {
    await hydrateSessionFromPersistence(auth.identity.sessionId);
    const data = getWorkspaceBootstrap(auth.identity.sessionId, null);
    return NextResponse.json(data);
  } catch (err) {
    const mapped = mapPersistenceOrSessionErrorResponse({
      err,
      route: '/api/workspace',
      action: 'GET_WORKSPACE',
    });
    if (mapped) return mapped;
    return NextResponse.json(
      { code: 'WORKSPACE_ERROR', errorVi: 'Không thể tải dữ liệu workspace.' },
      { status: 400 }
    );
  }
}

export async function POST(req: NextRequest) {
  const rate = await enforceDistributedRouteRateLimit(req, 'workspace', 60);
  const rateErr = buildRateLimitErrorResponse(
    rate,
    'Quá nhiều yêu cầu đồng bộ workspace.',
    '/api/workspace'
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
      {
        code: auth.status === 503 ? 'MISCONFIGURED_FAIL_CLOSED' : 'UNAUTHORIZED',
        errorVi: auth.errorVi,
      },
      { status: auth.status }
    );
  }

  const strictDefaultErr = rejectPredictableStrictDefaultSession(auth.identity.sessionId);
  if (strictDefaultErr) return strictDefaultErr;

  const parsed = await parseRequestJsonWithSchema(req, WorkspaceSyncRequestSchema, {
    maxBytes: WORKSPACE_SYNC_MAX_JSON_BODY_BYTES,
  });
  if (!parsed.ok) return parsed.response;

  const clientDelta = (parsed.data.clientDelta ?? null) as Partial<SessionDeltaSnapshot> | null;
  if (clientDelta?.sessionId && clientDelta.sessionId !== auth.identity.sessionId) {
    return NextResponse.json(
      {
        code: 'CROSS_SESSION_ACCESS_DENIED',
        errorVi:
          'Từ chối truy cập chéo phiên (HTTP 403): Không được phép ghi đè hoặc đồng bộ dữ liệu thuộc phiên làm việc khác.',
      },
      { status: 403 }
    );
  }

  try {
    const { preMutationRevision } = await hydrateSessionFromPersistence(auth.identity.sessionId);
    const data = getWorkspaceBootstrap(auth.identity.sessionId, clientDelta);
    if ((data.state.delta.stateRevision ?? 0) > preMutationRevision) {
      await commitSessionToPersistence({
        sessionId: auth.identity.sessionId,
        principalId: auth.identity.principalId,
        expectedRevision: preMutationRevision,
        committedDelta: data.state.delta,
      });
    }
    return NextResponse.json(data);
  } catch (err) {
    const mapped = mapPersistenceOrSessionErrorResponse({
      err,
      route: '/api/workspace',
      action: 'SYNC_WORKSPACE',
    });
    if (mapped) return mapped;
    if (err instanceof InvalidStateIntegrityError) {
      return NextResponse.json(
        { code: 'FORGED_STATE_REVISION', errorVi: err.message },
        { status: 400 }
      );
    }
    return NextResponse.json(
      { code: 'WORKSPACE_ERROR', errorVi: 'Không thể đồng bộ workspace.' },
      { status: 400 }
    );
  }
}

export async function DELETE(req: NextRequest) {
  const rate = await enforceDistributedRouteRateLimit(req, 'workspace-delete', 20, {
    criticalMutation: true,
  });
  const rateErr = buildRateLimitErrorResponse(
    rate,
    'Quá nhiều yêu cầu đặt lại dữ liệu.',
    '/api/workspace'
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
      {
        code: auth.status === 503 ? 'MISCONFIGURED_FAIL_CLOSED' : 'UNAUTHORIZED',
        errorVi: auth.errorVi,
      },
      { status: auth.status }
    );
  }

  const strictDefaultErr = rejectPredictableStrictDefaultSession(auth.identity.sessionId);
  if (strictDefaultErr) return strictDefaultErr;

  try {
    await resetAuthoritativeSession(auth.identity.sessionId, auth.identity.principalId);
    const data = getWorkspaceBootstrap(auth.identity.sessionId, null);
    logStructuredEvent({
      route: '/api/workspace',
      action: 'RESET_WORKSPACE',
      status: '200',
    });
    return NextResponse.json(data);
  } catch (err) {
    const mapped = mapPersistenceOrSessionErrorResponse({
      err,
      route: '/api/workspace',
      action: 'RESET_WORKSPACE',
    });
    if (mapped) return mapped;
    return NextResponse.json(
      { code: 'WORKSPACE_ERROR', errorVi: 'Không thể đặt lại workspace.' },
      { status: 400 }
    );
  }
}
