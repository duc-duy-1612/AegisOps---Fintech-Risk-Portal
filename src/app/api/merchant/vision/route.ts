import { NextRequest, NextResponse } from 'next/server';
import { getWorkspaceBootstrap } from '@/application/workspace-orchestrator';
import {
  MEDIA_MAX_JSON_BODY_BYTES,
  MerchantVisionVerifyRequestSchema,
  parseRequestJsonWithSchema,
} from '@/domain/api-schemas';
import { crossVerifyMerchantVisionAgainstLedger } from '@/domain/merchant-vision';
import type { SessionDeltaSnapshot } from '@/domain/types';
import { enforceDistributedRouteRateLimit } from '@/infrastructure/distributed-rate-limiter';
import { extractMerchantBillWithGeminiVision } from '@/infrastructure/gemini-agent';
import { logStructuredEvent } from '@/infrastructure/observability';
import {
  buildRateLimitErrorResponse,
  mapPersistenceOrSessionErrorResponse,
} from '@/infrastructure/route-guards';
import {
  sanitizePlainText,
  validateStrictMerchantReceiptImage,
} from '@/infrastructure/security-guard';
import {
  authenticateSessionFromRequest,
  verifySameOriginCsrf,
} from '@/infrastructure/session-auth';
import {
  InvalidStateIntegrityError,
  commitSessionToPersistence,
  hydrateSessionFromPersistence,
  saveSessionDelta,
} from '@/infrastructure/workspace-store';

export async function POST(req: NextRequest) {
  const start = performance.now();
  const rate = await enforceDistributedRouteRateLimit(req, 'merchant_vision', 25);
  const rateErr = buildRateLimitErrorResponse(
    rate,
    'Tần suất quét ảnh Bill quá nhanh. Vui lòng thử lại sau ít giây.',
    '/api/merchant/vision'
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

  const parsed = await parseRequestJsonWithSchema(req, MerchantVisionVerifyRequestSchema, {
    maxBytes: MEDIA_MAX_JSON_BODY_BYTES,
  });
  if (!parsed.ok) return parsed.response;

  const body = parsed.data;
  const sessionId = auth.identity.sessionId;
  const merchantTarget = body.merchantAccountIdOrNumber
    ? sanitizePlainText(body.merchantAccountIdOrNumber, 80)
    : undefined;

  const clientDelta: Partial<SessionDeltaSnapshot> | null =
    (body.clientDelta ?? null) as Partial<SessionDeltaSnapshot> | null;

  try {
    const { preMutationRevision } = await hydrateSessionFromPersistence(sessionId);
    const { state } = getWorkspaceBootstrap(sessionId, clientDelta);

    // 1. Strict binary-level image security validation (reject SVG, malformed binary, oversized > 3,000,000 B, decompression bombs)
    const imgCheck = validateStrictMerchantReceiptImage(body.imageDataUrl);
    if (!imgCheck.valid) {
      const isOversized = imgCheck.errorCode === 'PAYLOAD_TOO_LARGE';
      const invalidBundle = crossVerifyMerchantVisionAgainstLedger({
        extracted: null,
        ocrOutcome: 'INVALID_IMAGE',
        merchantAccountIdOrNumber: merchantTarget,
        ledgerTransactions: state.transactions,
        accounts: state.accounts,
        modelUsed: 'security-gate-v1',
        latencyMs: 1,
        securityErrorVi: imgCheck.errorVi,
      });
      return NextResponse.json(
        {
          code: isOversized ? 'PAYLOAD_TOO_LARGE' : 'INVALID_IMAGE',
          errorVi: imgCheck.errorVi,
          verification: invalidBundle,
        },
        { status: isOversized ? 413 : 400 }
      );
    }

    // 2. Server-side Gemini Vision structured extraction (transient processing; never stored in delta/localStorage)
    const ocrResult = await extractMerchantBillWithGeminiVision({
      mimeType: imgCheck.mimeType,
      base64Data: imgCheck.base64Data,
    });

    // 3. Authoritative deterministic cross-verification against Unified Ledger
    const verification = crossVerifyMerchantVisionAgainstLedger({
      extracted: ocrResult.extracted,
      ocrOutcome: ocrResult.outcome,
      merchantAccountIdOrNumber: merchantTarget,
      ledgerTransactions: state.transactions,
      accounts: state.accounts,
      modelUsed: ocrResult.modelUsed,
      latencyMs: ocrResult.latencyMs,
    });

    // Record concise masked verification audit log (NO raw image stored)
    const savedLocal = saveSessionDelta(sessionId, {
      ...state.delta,
      auditLogs: [
        ...state.delta.auditLogs,
        {
          id: `AUD-MV-${Date.now().toString().slice(-5)}`,
          alertId: verification.ledgerComparison.txId ?? 'MERCHANT_VISION',
          actor: 'CONSUMER_SHIELD',
          action: `MERCHANT_VISION_${verification.status}`,
          detailsVi: `Merchant Vision OCR (${verification.modelUsed}) → Kết luận Sổ cái: ${verification.status} (Mã GD: ${verification.ledgerComparison.txId ?? 'N/A'}, Ảnh ${imgCheck.width}x${imgCheck.height}px, không lưu ảnh gốc).`,
          timestamp: new Date().toISOString(),
        },
      ],
    });

    const committed = await commitSessionToPersistence({
      sessionId,
      principalId: auth.identity.principalId,
      expectedRevision: preMutationRevision,
      committedDelta: savedLocal,
    });

    logStructuredEvent({
      route: '/api/merchant/vision',
      action: 'MERCHANT_VISION_SCAN',
      status: '200',
      durationMs: performance.now() - start,
      metadata: { outcome: ocrResult.outcome, verdict: verification.status },
    });

    return NextResponse.json({
      verification,
      imageMeta: {
        mimeType: imgCheck.mimeType,
        width: imgCheck.width,
        height: imgCheck.height,
        byteLength: imgCheck.byteLength,
      },
      delta: committed,
    });
  } catch (err) {
    const mapped = mapPersistenceOrSessionErrorResponse({
      err,
      route: '/api/merchant/vision',
      action: 'MERCHANT_VISION_SCAN',
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
        code: 'MERCHANT_VISION_ERROR',
        errorVi: err instanceof Error ? err.message : 'Lỗi xử lý Merchant Vision OCR.',
      },
      { status: 400 }
    );
  }
}
