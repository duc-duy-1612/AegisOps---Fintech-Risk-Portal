import { NextRequest, NextResponse } from 'next/server';
import { verifyMerchantReceiptInSession } from '@/application/workspace-orchestrator';
import { MerchantVerifyRequestSchema, parseRequestJsonWithSchema } from '@/domain/api-schemas';
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
  const rate = await enforceDistributedRouteRateLimit(req, 'merchant_verify', 90);
  const rateErr = buildRateLimitErrorResponse(
    rate,
    'Quá nhiều yêu cầu đối soát Tiểu thương trong 1 phút.',
    '/api/merchant/verify'
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

  const parsed = await parseRequestJsonWithSchema(req, MerchantVerifyRequestSchema);
  if (!parsed.ok) return parsed.response;

  const body = parsed.data;
  const cleanTxId = sanitizePlainText(body.claimedTxId, 80);
  if (!cleanTxId) {
    return NextResponse.json(
      { code: 'VALIDATION_ERROR', errorVi: 'Vui lòng cung cấp mã giao dịch cần đối soát.' },
      { status: 400 }
    );
  }

  const merchantTarget = body.merchantAccountIdOrNumber
    ? sanitizePlainText(body.merchantAccountIdOrNumber, 80)
    : undefined;

  try {
    const { preMutationRevision } = await hydrateSessionFromPersistence(auth.identity.sessionId);
    const { verification, delta } = verifyMerchantReceiptInSession({
      sessionId: auth.identity.sessionId,
      claimedTxId: cleanTxId,
      claimedAmountVnd: body.claimedAmountVnd,
      merchantAccountIdOrNumber: merchantTarget,
      clientDelta: (body.clientDelta ?? null) as Partial<SessionDeltaSnapshot> | null,
    });

    const committed =
      (delta.stateRevision ?? 0) > preMutationRevision
        ? await commitSessionToPersistence({
            sessionId: auth.identity.sessionId,
            principalId: auth.identity.principalId,
            expectedRevision: preMutationRevision,
            committedDelta: delta,
          })
        : delta;

    logStructuredEvent({
      route: '/api/merchant/verify',
      action: 'MERCHANT_VERIFY_MANUAL',
      status: '200',
      durationMs: performance.now() - start,
      metadata: { verdict: verification.verdict, stateRevision: committed.stateRevision },
    });

    return NextResponse.json({
      verification,
      sessionId: auth.identity.sessionId,
      stateRevision: committed.stateRevision ?? 0,
      delta: committed,
    });
  } catch (err) {
    const mapped = mapPersistenceOrSessionErrorResponse({
      err,
      route: '/api/merchant/verify',
      action: 'MERCHANT_VERIFY',
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
        code: 'MERCHANT_VERIFY_ERROR',
        errorVi: err instanceof Error ? err.message : 'Lỗi đối soát giao dịch Tiểu thương.',
      },
      { status: 400 }
    );
  }
}
