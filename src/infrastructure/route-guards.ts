import { NextResponse } from 'next/server';
import type { DistributedRateLimitResult } from './distributed-rate-limiter';
import { generateRequestTraceId, logStructuredEvent } from './observability';
import {
  ConcurrentStateConflictError,
  PersistenceUnavailableError,
  SessionRevokedError,
} from './persistence-adapter';

export const buildRateLimitErrorResponse = (
  rate: DistributedRateLimitResult,
  rateLimitMessageVi: string,
  routeTag: string
): NextResponse | null => {
  if (rate.allowed) return null;

  const isInfraUnavailable =
    rate.modeUsed === 'MISCONFIGURED_FAIL_CLOSED' ||
    (rate.degraded && rate.modeUsed === 'UPSTASH_REDIS');

  if (isInfraUnavailable) {
    logStructuredEvent({
      level: 'ERROR',
      route: routeTag,
      action: 'RATE_LIMIT_FAIL_CLOSED',
      status: '503',
      errorCode: 'DISTRIBUTED_RATE_LIMIT_UNAVAILABLE',
    });
    return NextResponse.json(
      {
        code: 'DISTRIBUTED_RATE_LIMIT_UNAVAILABLE',
        errorVi:
          'Hệ thống giới hạn tần suất phân tán (Redis) chưa sẵn sàng ở chế độ Fail-Closed.',
      },
      { status: 503 }
    );
  }

  return NextResponse.json(
    { code: 'RATE_LIMITED', errorVi: rateLimitMessageVi },
    { status: 429 }
  );
};

export const mapPersistenceOrSessionErrorResponse = (params: {
  err: unknown;
  route: string;
  action: string;
  requestId?: string;
}): NextResponse | null => {
  const { err, route, action, requestId = generateRequestTraceId() } = params;

  if (err instanceof SessionRevokedError) {
    logStructuredEvent({
      level: 'WARN',
      requestId,
      route,
      action,
      status: '401',
      errorCode: 'SESSION_REVOKED',
    });
    return NextResponse.json(
      { code: 'SESSION_REVOKED', errorVi: err.message },
      { status: 401 }
    );
  }

  if (err instanceof ConcurrentStateConflictError) {
    logStructuredEvent({
      level: 'WARN',
      requestId,
      route,
      action,
      status: '409',
      errorCode: 'CONCURRENT_STATE_CONFLICT',
    });
    return NextResponse.json(
      { code: 'CONCURRENT_STATE_CONFLICT', errorVi: err.message },
      { status: 409 }
    );
  }

  if (err instanceof PersistenceUnavailableError) {
    logStructuredEvent({
      level: 'ERROR',
      requestId,
      route,
      action,
      status: '503',
      errorCode: 'PERSISTENCE_UNAVAILABLE',
    });
    return NextResponse.json(
      { code: 'PERSISTENCE_UNAVAILABLE', errorVi: err.message },
      { status: 503 }
    );
  }

  return null;
};
