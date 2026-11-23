import { NextRequest, NextResponse } from 'next/server';
import {
  IdempotencyKeyConflictError,
  SelfApprovalForbiddenError,
  addCustomShieldRuleInSession,
  executeAnalystOverrideInSession,
  executeBatchTriageInSession,
  executeClawbackAndRefundInSession,
  executePlaybookApproval,
  pushDossierToSimoInSession,
  toggleShieldRuleInSession,
} from '@/application/workspace-orchestrator';
import { PlaybookRequestSchema, parseRequestJsonWithSchema } from '@/domain/api-schemas';
import { LedgerValidationError } from '@/domain/ledger-engine';
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
  authorizePlaybookMutation,
  verifySameOriginCsrf,
  type PlaybookMutationAction,
} from '@/infrastructure/session-auth';
import {
  InvalidStateIntegrityError,
  commitSessionToPersistence,
  hydrateSessionFromPersistence,
} from '@/infrastructure/workspace-store';

export async function POST(req: NextRequest) {
  const start = performance.now();
  const prelimRate = await enforceDistributedRouteRateLimit(req, 'playbook', 35, {
    criticalMutation: true,
  });
  const rateErr = buildRateLimitErrorResponse(
    prelimRate,
    'Vượt quá giới hạn thao tác Playbook trong 1 phút.',
    '/api/playbook'
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

  const parsed = await parseRequestJsonWithSchema(req, PlaybookRequestSchema);
  if (!parsed.ok) return parsed.response;

  const body = parsed.data;
  const sessionId = auth.identity.sessionId;
  const action: PlaybookMutationAction = body.mode ?? 'APPROVE_L2';

  const authz = authorizePlaybookMutation(auth.identity.role, action);
  if (!authz.allowed) {
    return NextResponse.json(
      { code: 'FORBIDDEN_RBAC', errorVi: authz.errorVi },
      { status: authz.status }
    );
  }

  const clientDelta = (body.clientDelta ?? null) as Partial<SessionDeltaSnapshot> | null;

  try {
    const { preMutationRevision } = await hydrateSessionFromPersistence(sessionId);

    const commitAndRespond = async <T extends { delta: SessionDeltaSnapshot; idempotentReplay?: boolean }>(
      payload: T
    ) => {
      if (!payload.idempotentReplay && (payload.delta.stateRevision ?? 0) > preMutationRevision) {
        const committed = await commitSessionToPersistence({
          sessionId,
          principalId: auth.identity.principalId,
          expectedRevision: preMutationRevision,
          committedDelta: payload.delta,
        });
        logStructuredEvent({
          route: '/api/playbook',
          action,
          status: '200',
          durationMs: performance.now() - start,
          metadata: { stateRevision: committed.stateRevision },
        });
        return NextResponse.json({ ...payload, delta: committed });
      }
      return NextResponse.json(payload);
    };

    if (action === 'TOGGLE_SHIELD') {
      const ruleId = sanitizePlainText(body.ruleId, 64);
      if (!ruleId) {
        return NextResponse.json(
          { code: 'VALIDATION_ERROR', errorVi: 'Thiếu mã quy tắc ruleId.' },
          { status: 400 }
        );
      }
      return commitAndRespond(toggleShieldRuleInSession({ sessionId, ruleId, clientDelta }));
    }

    if (action === 'ADD_CUSTOM_SHIELD') {
      const targetAccountNumber = sanitizePlainText(body.targetAccountNumber, 40);
      if (!targetAccountNumber) {
        return NextResponse.json(
          { code: 'VALIDATION_ERROR', errorVi: 'Vui lòng nhập số tài khoản cần chặn.' },
          { status: 400 }
        );
      }
      return commitAndRespond(
        addCustomShieldRuleInSession({
          sessionId,
          targetAccountNumber,
          targetOwnerName: sanitizePlainText(body.targetOwnerName, 80),
          reasonVi: sanitizePlainText(body.reasonVi, 240),
          clientDelta,
        })
      );
    }

    if (action === 'BATCH_TRIAGE') {
      return commitAndRespond(executeBatchTriageInSession({ sessionId, clientDelta }));
    }

    const alertId = sanitizePlainText(body.alertId, 64);
    if (!alertId) {
      return NextResponse.json(
        { code: 'VALIDATION_ERROR', errorVi: 'Thiếu mã cảnh báo alertId.' },
        { status: 400 }
      );
    }

    if (action === 'ANALYST_OVERRIDE') {
      if (!body.targetVerdict) {
        return NextResponse.json(
          { code: 'VALIDATION_ERROR', errorVi: 'Thiếu quyết định ghi đè targetVerdict.' },
          { status: 400 }
        );
      }
      return commitAndRespond(
        executeAnalystOverrideInSession({
          sessionId,
          alertId,
          targetVerdict: body.targetVerdict,
          reasonVi: sanitizePlainText(body.reasonVi, 240),
          clientDelta,
        })
      );
    }

    if (action === 'PUSH_SIMO') {
      return commitAndRespond(pushDossierToSimoInSession({ sessionId, alertId, clientDelta }));
    }

    if (action === 'CLAWBACK_REFUND') {
      return commitAndRespond(
        executeClawbackAndRefundInSession({
          sessionId,
          alertId,
          originalTxId: body.originalTxId ? sanitizePlainText(body.originalTxId, 80) : undefined,
          requestedAmountVnd: body.requestedAmountVnd,
          idempotencyKey: body.idempotencyKey ? sanitizePlainText(body.idempotencyKey, 100) : undefined,
          clientDelta,
        })
      );
    }

    const mode = action === 'PROPOSE_L1' ? 'PROPOSE_L1' : 'APPROVE_L2';
    const result = executePlaybookApproval({
      sessionId,
      alertId,
      selectedActionIds: body.selectedActionIds,
      mode,
      actorPrincipalId: auth.identity.principalId,
      clientDelta,
    });
    return commitAndRespond(result);
  } catch (err) {
    const mapped = mapPersistenceOrSessionErrorResponse({
      err,
      route: '/api/playbook',
      action,
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
    if (err instanceof SelfApprovalForbiddenError) {
      return NextResponse.json(
        { code: 'SELF_APPROVAL_FORBIDDEN', errorVi: err.message },
        { status: 403 }
      );
    }
    if (err instanceof LedgerValidationError) {
      return NextResponse.json(
        { code: 'LEDGER_VALIDATION_ERROR', errorVi: err.message },
        { status: 400 }
      );
    }
    if (err instanceof InvalidStateIntegrityError) {
      return NextResponse.json(
        { code: 'FORGED_STATE_REVISION', errorVi: err.message },
        { status: 400 }
      );
    }
    return NextResponse.json(
      {
        code: 'PLAYBOOK_ERROR',
        errorVi: err instanceof Error ? err.message : 'Lỗi khi thực thi Playbook.',
      },
      { status: 400 }
    );
  }
}
