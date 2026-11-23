import { NextRequest, NextResponse } from 'next/server';
import {
  ForbiddenFeedbackActionError,
  SelfApprovalForbiddenError,
  createHitlFeedbackInSession,
  moderateHitlFeedbackInSession,
} from '@/application/workspace-orchestrator';
import { HitlFeedbackRequestSchema, parseRequestJsonWithSchema } from '@/domain/api-schemas';
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
  const rate = await enforceDistributedRouteRateLimit(req, 'hitl_feedback', 40, {
    criticalMutation: true,
  });
  const rateErr = buildRateLimitErrorResponse(
    rate,
    'Quá nhiều thao tác phản hồi HITL trong 1 phút.',
    '/api/feedback'
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
        errorVi: 'Từ chối truy cập (HTTP 403): Khách hàng Ví (END_USER) không được tạo hoặc điều chỉnh bộ nhớ HITL.',
      },
      { status: 403 }
    );
  }

  const parsed = await parseRequestJsonWithSchema(req, HitlFeedbackRequestSchema);
  if (!parsed.ok) return parsed.response;

  const body = parsed.data;
  const sessionId = auth.identity.sessionId;
  const clientDelta = (body.clientDelta ?? null) as Partial<SessionDeltaSnapshot> | null;

  try {
    const { preMutationRevision } = await hydrateSessionFromPersistence(sessionId);

    if (body.action === 'CREATE') {
      const alertId = sanitizePlainText(body.alertId, 64);
      if (!alertId || !body.feedbackDecision) {
        return NextResponse.json(
          {
            code: 'VALIDATION_ERROR',
            errorVi: 'Vui lòng cung cấp alertId và feedbackDecision (OVERRIDE_SAFE hoặc FORCE_BLOCK).',
          },
          { status: 400 }
        );
      }
      const res = createHitlFeedbackInSession({
        sessionId,
        alertId,
        feedbackDecision: body.feedbackDecision,
        targetScope: body.targetScope ?? 'RECIPIENT_PATTERN',
        reasonCode:
          body.reasonCode ??
          (body.feedbackDecision === 'OVERRIDE_SAFE'
            ? 'FALSE_POSITIVE_CONTEXT'
            : 'CONFIRMED_MULE_PATTERN'),
        analystRationale: sanitizePlainText(body.analystRationale, 400),
        evidenceReferences: (body.evidenceReferences ?? []).map((e) => sanitizePlainText(e, 64)),
        ttlHours: body.ttlHours ?? 24,
        actorPrincipalId: auth.identity.principalId,
        actorRole: auth.identity.role,
        clientDelta,
      });

      const committed =
        (res.delta.stateRevision ?? 0) > preMutationRevision
          ? await commitSessionToPersistence({
              sessionId,
              principalId: auth.identity.principalId,
              expectedRevision: preMutationRevision,
              committedDelta: res.delta,
            })
          : res.delta;

      logStructuredEvent({
        route: '/api/feedback',
        action: 'CREATE_HITL_FEEDBACK',
        status: '200',
        durationMs: performance.now() - start,
        metadata: { decision: body.feedbackDecision, stateRevision: committed.stateRevision },
      });

      return NextResponse.json({ ...res, delta: committed });
    }

    // APPROVE / REJECT / REVOKE -> L2_CHECKER only
    const feedbackId = sanitizePlainText(body.feedbackId, 80);
    if (!feedbackId) {
      return NextResponse.json(
        { code: 'VALIDATION_ERROR', errorVi: 'Thiếu mã phản hồi feedbackId.' },
        { status: 400 }
      );
    }

    const res = moderateHitlFeedbackInSession({
      sessionId,
      feedbackId,
      moderationAction: body.action,
      rejectReasonVi: sanitizePlainText(body.rejectReasonVi, 300),
      actorPrincipalId: auth.identity.principalId,
      actorRole: auth.identity.role,
      clientDelta,
    });

    const committed =
      (res.delta.stateRevision ?? 0) > preMutationRevision
        ? await commitSessionToPersistence({
            sessionId,
            principalId: auth.identity.principalId,
            expectedRevision: preMutationRevision,
            committedDelta: res.delta,
          })
        : res.delta;

    logStructuredEvent({
      route: '/api/feedback',
      action: `HITL_${body.action}`,
      status: '200',
      durationMs: performance.now() - start,
      metadata: { stateRevision: committed.stateRevision },
    });

    return NextResponse.json({ ...res, delta: committed });
  } catch (err) {
    const mapped = mapPersistenceOrSessionErrorResponse({
      err,
      route: '/api/feedback',
      action: body.action,
    });
    if (mapped) return mapped;
    if (err instanceof SelfApprovalForbiddenError) {
      return NextResponse.json(
        { code: 'SELF_APPROVAL_FORBIDDEN', errorVi: err.message },
        { status: 403 }
      );
    }
    if (err instanceof ForbiddenFeedbackActionError) {
      return NextResponse.json(
        { code: 'FORBIDDEN_RBAC', errorVi: err.message },
        { status: 403 }
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
        code: 'FEEDBACK_ERROR',
        errorVi: err instanceof Error ? err.message : 'Lỗi xử lý bộ nhớ phản hồi HITL.',
      },
      { status: 400 }
    );
  }
}
