import { NextRequest, NextResponse } from 'next/server';
import {
  IdempotencyKeyConflictError,
  recordVictimSelfRescueInSession,
  simulateWalletTransferInSession,
} from '@/application/workspace-orchestrator';
import { WalletRequestSchema, parseRequestJsonWithSchema } from '@/domain/api-schemas';
import {
  InsufficientBalanceError,
  LedgerValidationError,
} from '@/domain/ledger-engine';
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
  const rate = await enforceDistributedRouteRateLimit(req, 'wallet', 60, {
    criticalMutation: true,
  });
  const rateErr = buildRateLimitErrorResponse(
    rate,
    'Quá nhiều yêu cầu giao dịch Ví trong 1 phút.',
    '/api/wallet'
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

  const parsed = await parseRequestJsonWithSchema(req, WalletRequestSchema);
  if (!parsed.ok) return parsed.response;

  const body = parsed.data;
  const sessionId = auth.identity.sessionId;
  const recipient = sanitizePlainText(body.recipientAccountIdOrNumber, 80);
  if (!recipient) {
    return NextResponse.json(
      { code: 'VALIDATION_ERROR', errorVi: 'Vui lòng nhập số tài khoản hoặc mã người nhận.' },
      { status: 400 }
    );
  }

  const clientDelta = (body.clientDelta ?? null) as Partial<SessionDeltaSnapshot> | null;

  try {
    const { preMutationRevision } = await hydrateSessionFromPersistence(sessionId);

    if (body.action === 'SELF_RESCUE_CANCEL') {
      const rescue = recordVictimSelfRescueInSession({
        sessionId,
        recipientAccount: recipient,
        amountVnd: body.amountVnd,
        clientDelta,
      });
      if ((rescue.delta.stateRevision ?? 0) > preMutationRevision) {
        const committed = await commitSessionToPersistence({
          sessionId,
          principalId: auth.identity.principalId,
          expectedRevision: preMutationRevision,
          committedDelta: rescue.delta,
        });
        return NextResponse.json({ ...rescue, delta: committed });
      }
      return NextResponse.json(rescue);
    }

    const result = simulateWalletTransferInSession({
      sessionId,
      transfer: {
        senderAccountId: body.senderAccountId ? sanitizePlainText(body.senderAccountId, 64) : undefined,
        senderName: sanitizePlainText(body.senderName, 80) || 'Nguyễn Thị Thu Hà (Nạn nhân APP Fraud #1)',
        recipientAccountIdOrNumber: recipient,
        amountVnd: body.amountVnd,
        message: sanitizePlainText(body.message, 300) || 'Chuyen khoan thanh toan',
        idempotencyKey: body.idempotencyKey ? sanitizePlainText(body.idempotencyKey, 100) : undefined,
      },
      clientDelta,
    });

    if (!result.decision.idempotentReplay && (result.delta.stateRevision ?? 0) > preMutationRevision) {
      const committed = await commitSessionToPersistence({
        sessionId,
        principalId: auth.identity.principalId,
        expectedRevision: preMutationRevision,
        committedDelta: result.delta,
      });
      logStructuredEvent({
        route: '/api/wallet',
        action: 'WALLET_TRANSFER',
        status: '200',
        durationMs: performance.now() - start,
        metadata: { decision: result.decision.decision, stateRevision: committed.stateRevision },
      });
      return NextResponse.json({ ...result, delta: committed });
    }

    return NextResponse.json(result);
  } catch (err) {
    const mapped = mapPersistenceOrSessionErrorResponse({
      err,
      route: '/api/wallet',
      action: body.action ?? 'TRANSFER',
    });
    if (mapped) return mapped;
    if (err instanceof IdempotencyKeyConflictError) {
      return NextResponse.json(
        {
          code: 'IDEMPOTENCY_KEY_CONFLICT',
          errorVi: err.message,
          idempotencyKey: err.idempotencyKey,
        },
        { status: 409 }
      );
    }
    if (err instanceof InvalidStateIntegrityError) {
      return NextResponse.json(
        { code: 'FORGED_STATE_REVISION', errorVi: err.message },
        { status: 400 }
      );
    }
    if (err instanceof InsufficientBalanceError) {
      return NextResponse.json(
        {
          code: 'INSUFFICIENT_BALANCE',
          errorVi: err.message,
          availableVnd: err.availableVnd,
          requiredVnd: err.requiredVnd,
        },
        { status: 400 }
      );
    }
    if (err instanceof LedgerValidationError) {
      return NextResponse.json(
        { code: 'LEDGER_VALIDATION_ERROR', errorVi: err.message },
        { status: 400 }
      );
    }
    return NextResponse.json(
      {
        code: 'WALLET_ERROR',
        errorVi: err instanceof Error ? err.message : 'Lỗi mô phỏng giao dịch Ví.',
      },
      { status: 400 }
    );
  }
}
