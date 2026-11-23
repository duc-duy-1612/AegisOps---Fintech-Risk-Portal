import { NextRequest, NextResponse } from 'next/server';
import { ingestCustomSandboxAlert } from '@/application/workspace-orchestrator';
import {
  MEDIA_MAX_JSON_BODY_BYTES,
  SandboxRequestSchema,
  parseRequestJsonWithSchema,
} from '@/domain/api-schemas';
import type { SessionDeltaSnapshot, StandardCaseInputSpec } from '@/domain/types';
import { enforceDistributedRouteRateLimit } from '@/infrastructure/distributed-rate-limiter';
import { logStructuredEvent } from '@/infrastructure/observability';
import {
  buildRateLimitErrorResponse,
  mapPersistenceOrSessionErrorResponse,
} from '@/infrastructure/route-guards';
import {
  sanitizePlainText,
  validateImageDataUrl,
} from '@/infrastructure/security-guard';
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
  const rate = await enforceDistributedRouteRateLimit(req, 'sandbox', 25);
  const rateErr = buildRateLimitErrorResponse(
    rate,
    'Tần suất tạo kịch bản Sandbox quá nhanh. Vui lòng thử lại sau ít giây.',
    '/api/sandbox'
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

  const parsed = await parseRequestJsonWithSchema(req, SandboxRequestSchema, {
    maxBytes: MEDIA_MAX_JSON_BODY_BYTES,
  });
  if (!parsed.ok) return parsed.response;

  const body = parsed.data;
  const sessionId = auth.identity.sessionId;

  try {
    const { preMutationRevision } = await hydrateSessionFromPersistence(sessionId);

    const imgCheck = validateImageDataUrl(body.caseInputSpec?.imageDataUrl ?? body.imageDataUrl);
    if (!imgCheck.valid) {
      const isOversized = imgCheck.errorCode === 'PAYLOAD_TOO_LARGE';
      return NextResponse.json(
        {
          code: isOversized ? 'PAYLOAD_TOO_LARGE' : 'INVALID_IMAGE',
          errorVi: imgCheck.errorVi,
        },
        { status: isOversized ? 413 : 400 }
      );
    }

    const rawTranscript = sanitizePlainText(
      body.caseInputSpec?.rawTranscript ?? body.rawTranscript,
      2500
    );
    const hasStructuredSpec = Boolean(
      body.caseInputSpec &&
        (body.caseInputSpec.recipientAccountNumber || body.caseInputSpec.amountVnd)
    );

    if (!rawTranscript && !imgCheck.cleaned && !hasStructuredSpec) {
      return NextResponse.json(
        {
          code: 'VALIDATION_ERROR',
          errorVi: 'Vui lòng nhập thông tin giao dịch, hội thoại hoặc tải lên ảnh bằng chứng.',
        },
        { status: 400 }
      );
    }

    const sanitizedSpec: Partial<StandardCaseInputSpec> | undefined = body.caseInputSpec
      ? {
          ...body.caseInputSpec,
          customTitle: sanitizePlainText(body.caseInputSpec.customTitle ?? body.customTitle, 140),
          senderName: sanitizePlainText(body.caseInputSpec.senderName, 80),
          senderAccountNumber: sanitizePlainText(body.caseInputSpec.senderAccountNumber, 40),
          recipientAccountNumber: sanitizePlainText(
            body.caseInputSpec.recipientAccountNumber ?? body.recipientAccountNumber,
            40
          ),
          recipientOwnerName: sanitizePlainText(
            body.caseInputSpec.recipientOwnerName ?? body.recipientOwnerName,
            80
          ),
          bankOrWalletName: sanitizePlainText(body.caseInputSpec.bankOrWalletName, 80),
          rawTranscript,
          imageDataUrl: imgCheck.cleaned,
        }
      : undefined;

    const result = await ingestCustomSandboxAlert({
      sessionId,
      customTitle: sanitizePlainText(body.customTitle ?? sanitizedSpec?.customTitle, 140),
      rawTranscript,
      imageDataUrl: imgCheck.cleaned,
      recipientAccountNumber: sanitizePlainText(
        body.recipientAccountNumber ?? sanitizedSpec?.recipientAccountNumber,
        40
      ),
      recipientOwnerName: sanitizePlainText(
        body.recipientOwnerName ?? sanitizedSpec?.recipientOwnerName,
        80
      ),
      amountVnd:
        typeof body.amountVnd === 'number' && body.amountVnd > 0
          ? body.amountVnd
          : sanitizedSpec?.amountVnd,
      caseInputSpec: sanitizedSpec,
      clientDelta: (body.clientDelta ?? null) as Partial<SessionDeltaSnapshot> | null,
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
      route: '/api/sandbox',
      action: 'CREATE_SANDBOX_ALERT',
      status: '200',
      durationMs: performance.now() - start,
    });

    return NextResponse.json({ ...result, delta: committed });
  } catch (err) {
    const mapped = mapPersistenceOrSessionErrorResponse({
      err,
      route: '/api/sandbox',
      action: 'CREATE_SANDBOX_ALERT',
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
        code: 'SANDBOX_ERROR',
        errorVi: err instanceof Error ? err.message : 'Không thể khởi tạo hồ sơ kiểm thử.',
      },
      { status: 400 }
    );
  }
}
