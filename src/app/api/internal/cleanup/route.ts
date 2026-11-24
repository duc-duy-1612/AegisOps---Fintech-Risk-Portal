import { timingSafeEqual } from 'node:crypto';
import { NextRequest, NextResponse } from 'next/server';
import { logStructuredEvent } from '@/infrastructure/observability';
import {
  FIXED_CLEANUP_BATCH_LIMIT,
  FIXED_CLEANUP_MAX_BATCHES,
  FIXED_CLEANUP_TIME_BUDGET_MS,
  PartialCleanupDrainError,
  PersistenceUnavailableError,
  getWorkspacePersistenceAdapter,
  runBoundedExpiredSessionDrain,
} from '@/infrastructure/persistence-adapter';

export const dynamic = 'force-dynamic';

/**
 * Verifies dedicated high-entropy `CRON_SECRET` (>= 32 chars) via `Authorization: Bearer <token>`.
 * - Enforces cryptographic domain separation (never reuses session, PII, diagnostics, or admin secrets).
 * - Uses constant-time `timingSafeEqual` comparison.
 * - Never reveals whether the secret is unconfigured vs. mismatched.
 */
const isAuthorizedCleanupCaller = (req: NextRequest): boolean => {
  const configuredSecret = (process.env.CRON_SECRET ?? '').trim();
  if (configuredSecret.length < 32) {
    return false;
  }

  const forbiddenReuseSecrets = [
    process.env.AEGIS_SESSION_SECRET,
    process.env.AEGIS_PII_HMAC_KEY,
    process.env.AEGIS_DIAGNOSTICS_SECRET,
    process.env.AEGIS_ADMIN_RESET_SECRET,
  ]
    .map((s) => (s ?? '').trim())
    .filter(Boolean);

  if (forbiddenReuseSecrets.includes(configuredSecret)) {
    return false;
  }

  const authHeader = req.headers.get('authorization')?.trim() ?? '';
  if (!authHeader.startsWith('Bearer ')) {
    return false;
  }
  const providedToken = authHeader.slice('Bearer '.length).trim();
  if (!providedToken) {
    return false;
  }

  const aBuf = Buffer.from(providedToken, 'utf8');
  const bBuf = Buffer.from(configuredSecret, 'utf8');
  return aBuf.length === bBuf.length && timingSafeEqual(aBuf, bBuf);
};

async function executeScheduledCleanup(req: NextRequest): Promise<NextResponse> {
  const start = performance.now();

  if (!isAuthorizedCleanupCaller(req)) {
    logStructuredEvent({
      level: 'WARN',
      route: '/api/internal/cleanup',
      action: 'EXPIRED_SESSION_CLEANUP',
      status: '401',
      errorCode: 'UNAUTHORIZED_CLEANUP',
    });
    return NextResponse.json(
      {
        code: 'UNAUTHORIZED',
        errorVi: 'Từ chối truy cập: Endpoint dọn dẹp nội bộ yêu cầu xác thực CRON_SECRET hợp lệ.',
      },
      { status: 401 }
    );
  }

  try {
    const adapter = getWorkspacePersistenceAdapter();
    const result = await runBoundedExpiredSessionDrain(adapter, {
      batchSize: FIXED_CLEANUP_BATCH_LIMIT,
      maxBatches: FIXED_CLEANUP_MAX_BATCHES,
      timeBudgetMs: FIXED_CLEANUP_TIME_BUDGET_MS,
    });

    logStructuredEvent({
      level: 'INFO',
      route: '/api/internal/cleanup',
      action: 'EXPIRED_SESSION_CLEANUP',
      status: '200',
      durationMs: result.durationMs,
      metadata: {
        purgedCount: result.purgedCount,
        batchSize: result.batchSize,
        batchesExecuted: result.batchesExecuted,
        maxBatches: result.maxBatches,
        budgetExhausted: result.budgetExhausted,
        batchLimitReached: result.batchLimitReached,
        hasMoreExpiredPossible: result.hasMoreExpiredPossible,
        mode: result.mode,
      },
    });

    return NextResponse.json({
      ...result,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    const partialErr = err instanceof PartialCleanupDrainError ? err : null;
    const rootErr = partialErr ? partialErr.causeError : err;
    const isUnavailable = rootErr instanceof PersistenceUnavailableError;
    const durationMs = partialErr ? partialErr.durationMs : Math.round(performance.now() - start);
    const purgedCount = partialErr ? partialErr.purgedCountBeforeError : 0;
    const batchesExecuted = partialErr ? partialErr.batchesExecutedBeforeError : 0;

    logStructuredEvent({
      level: 'ERROR',
      route: '/api/internal/cleanup',
      action: 'EXPIRED_SESSION_CLEANUP',
      status: isUnavailable ? '503' : '500',
      durationMs,
      errorCode: isUnavailable ? 'PERSISTENCE_UNAVAILABLE' : 'CLEANUP_EXECUTION_ERROR',
      metadata: {
        purgedCount,
        batchesExecuted,
        incomplete: true,
      },
    });
    return NextResponse.json(
      {
        ok: false,
        code: isUnavailable ? 'PERSISTENCE_UNAVAILABLE' : 'CLEANUP_ERROR',
        errorVi: isUnavailable
          ? 'Hệ thống lưu trữ dùng chung chưa sẵn sàng để dọn dẹp phiên hết hạn.'
          : 'Không thể hoàn tất tác vụ dọn dẹp phiên hết hạn.',
        purgedCount,
        batchSize: FIXED_CLEANUP_BATCH_LIMIT,
        batchesExecuted,
        maxBatches: FIXED_CLEANUP_MAX_BATCHES,
        hasMoreExpiredPossible: true,
        durationMs,
        timestamp: new Date().toISOString(),
      },
      { status: isUnavailable ? 503 : 500 }
    );
  }
}

export async function GET(req: NextRequest) {
  return executeScheduledCleanup(req);
}

export async function POST(req: NextRequest) {
  return executeScheduledCleanup(req);
}
