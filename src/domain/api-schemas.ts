import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';

/**
 * Strict Runtime Zod Request Schemas for All POST API Endpoints (IMP-03 / CR-1.1).
 * Prevents unvalidated clientDelta injection, type confusion, and oversized payloads.
 */

export const DEFAULT_MAX_JSON_BODY_BYTES = 512 * 1024; // 512 KB
export const WORKSPACE_SYNC_MAX_JSON_BODY_BYTES = 1_500_000; // 1.5 MB
/** Maximum raw decoded image binary size (decimal 3,000,000 bytes). */
export const MAX_IMAGE_BINARY_BYTES = 3_000_000;
/**
 * Maximum base64 data URL length for a 3,000,000-byte binary image:
 * ceil(3,000,000 / 3) * 4 = 4,000,000 base64 chars + <= 64-byte data URL prefix.
 */
export const MAX_IMAGE_DATA_URL_LENGTH = 4_000_064;
/**
 * Maximum complete UTF-8 JSON request body size for image-bearing routes (`/api/merchant/vision`, `/api/sandbox`).
 * Kept strictly below Vercel's default 4.5 MB Serverless Function request-body limit (4 * 1024 * 1024 = 4,194,304 bytes).
 */
export const MEDIA_MAX_JSON_BODY_BYTES = 4 * 1024 * 1024;

const boundedRecord = <K extends z.ZodString, V extends z.ZodTypeAny>(
  keySchema: K,
  valueSchema: V,
  maxKeys: number
) =>
  z.record(keySchema, valueSchema).refine((obj) => Object.keys(obj).length <= maxKeys, {
    message: `Số lượng khóa vượt quá giới hạn cho phép (${maxKeys}).`,
  });

const AccountTypeEnum = z.enum(['CONSUMER', 'MERCHANT', 'MULE_SUSPECT', 'TRUSTED_INSTITUTION']);
const ChannelEnum = z.enum(['P2P_WALLET', 'VIETQR', 'PAYMENT_GATEWAY', 'VOUCHER_REDEEM']);
const AlertStatusEnum = z.enum(['OPEN', 'INVESTIGATING', 'MITIGATED', 'DISMISSED_SAFE']);

export const StandardCaseInputSpecSchema = z
  .object({
    customTitle: z.string().max(160).optional(),
    senderName: z.string().max(100).optional(),
    senderAccountNumber: z.string().max(40).optional(),
    senderAvgTxVnd: z.number().finite().positive().max(1_000_000_000).optional(),
    senderKycLevel: z.enum(['LEVEL_1', 'LEVEL_2_BIOMETRIC']).optional(),
    amountVnd: z.number().finite().positive().max(5_000_000_000).optional(),
    splitTxCount: z.number().int().min(1).max(10).optional(),
    channel: ChannelEnum.optional(),
    recipientAccountNumber: z.string().max(40).optional(),
    recipientOwnerName: z.string().max(100).optional(),
    bankOrWalletName: z.string().max(100).optional(),
    recipientAccountType: AccountTypeEnum.optional(),
    recipientAccountAgeDays: z.number().int().min(0).max(20_000).optional(),
    recipientKycLevel: z.enum(['LEVEL_1', 'LEVEL_2_BIOMETRIC']).optional(),
    crossVictimFanInCount: z.number().int().min(0).max(20).optional(),
    deviceIntegrity: z
      .enum(['TRUSTED_PERSONAL_DEVICE', 'SHARED_EMULATOR_ROOTED', 'UNRECOGNIZED_FOREIGN_IP'])
      .optional(),
    sessionSecurity: z
      .enum(['BIOMETRIC_FACEID_PASSED', 'SESSION_SURVIVED_PASSWORD_RESET', 'NORMAL_LOGIN'])
      .optional(),
    inCallCoercionDetected: z.boolean().optional(),
    deepfakeOrVirtualCamDetected: z.boolean().optional(),
    apiConcurrentRequests100ms: z.number().int().min(1).max(100).optional(),
    webhookHmacValid: z.boolean().optional(),
    rawTranscript: z.string().max(3000).optional(),
    imageDataUrl: z.string().max(MAX_IMAGE_DATA_URL_LENGTH).optional(),
  })
  .strict();

const ShieldRuleSchema = z.object({
  id: z.string().min(1).max(64),
  alertId: z.string().min(1).max(64),
  targetAccountId: z.string().min(1).max(64),
  targetAccountNumber: z.string().min(1).max(64),
  targetOwnerName: z.string().min(1).max(120),
  targetDeviceId: z.string().max(64).optional(),
  ruleType: z.enum(['BLOCK_RECIPIENT_MULE', 'FREEZE_SESSION_FAMILY', 'RATE_LIMIT_ENDPOINT']),
  userWarningVi: z.string().max(500),
  active: z.boolean(),
  createdAt: z.string().max(64),
});

const AuditLogEntrySchema = z.object({
  id: z.string().min(1).max(64),
  alertId: z.string().min(1).max(64),
  actor: z.enum(['AI_AGENT', 'OPS_ANALYST', 'CONSUMER_SHIELD']),
  action: z.string().min(1).max(80),
  detailsVi: z.string().max(600),
  timestamp: z.string().max(64),
});

export const SessionDeltaClientSchema = z
  .object({
    sessionId: z.string().max(80).optional(),
    stateRevision: z.number().int().min(0).max(1_000_000).optional(),
    deltaIntegrityTag: z.string().max(128).optional(),
    makerPrincipalByAlertId: boundedRecord(z.string().max(64), z.string().max(120), 100).optional(),
    alertStatuses: boundedRecord(z.string().max(64), AlertStatusEnum, 100).optional(),
    pendingL2ApprovalAlertIds: z.array(z.string().max(64)).max(100).optional(),
    frozenAccountIds: z.array(z.string().max(64)).max(100).optional(),
    activeShieldRules: z.array(ShieldRuleSchema).max(100).optional(),
    selfRescuedAmountVnd: z.number().finite().min(0).max(50_000_000_000).optional(),
    analystFeedbackCount: z.number().int().min(0).max(10_000).optional(),
    analystOverridesByAlertId: boundedRecord(z.string().max(64), z.any(), 100).optional(),
    hitlFeedbackMemory: z.array(z.any()).max(200).optional(),
    simoAckReceipts: z.array(z.any()).max(100).optional(),
    clawbackReceipts: z.array(z.any()).max(100).optional(),
    ledgerEntries: z.array(z.any()).max(500).optional(),
    processedIdempotencyKeys: boundedRecord(z.string().max(100), z.string().max(80), 200).optional(),
    idempotencyRecordsByKey: boundedRecord(z.string().max(100), z.any(), 200).optional(),
    reportsByAlertId: boundedRecord(z.string().max(64), z.any(), 100).optional(),
    customAlerts: z.array(z.any()).max(50).optional(),
    customAccounts: z.array(z.any()).max(150).optional(),
    customTransactions: z.array(z.any()).max(250).optional(),
    customEvidences: z.array(z.any()).max(50).optional(),
    customDevices: z.array(z.any()).max(50).optional(),
    customAuthLogs: z.array(z.any()).max(150).optional(),
    customApiEvents: z.array(z.any()).max(100).optional(),
    customInputSpecsByAlertId: boundedRecord(z.string().max(64), z.any(), 50).optional(),
    auditLogs: z.array(AuditLogEntrySchema).max(200).optional(),
    updatedAt: z.string().max(64).optional(),
  })
  .nullable()
  .optional();

export const InvestigateRequestSchema = z
  .object({
    alertId: z.string().trim().min(1).max(64).optional(),
    clientDelta: SessionDeltaClientSchema,
  })
  .strict();

export const PlaybookModeEnum = z.enum([
  'PROPOSE_L1',
  'APPROVE_L2',
  'TOGGLE_SHIELD',
  'ADD_CUSTOM_SHIELD',
  'BATCH_TRIAGE',
  'ANALYST_OVERRIDE',
  'PUSH_SIMO',
  'CLAWBACK_REFUND',
]);

export const PlaybookRequestSchema = z
  .object({
    alertId: z.string().trim().min(1).max(64).optional(),
    ruleId: z.string().trim().min(1).max(64).optional(),
    targetAccountNumber: z.string().trim().min(1).max(40).optional(),
    targetOwnerName: z.string().trim().max(100).optional(),
    reasonVi: z.string().trim().max(300).optional(),
    targetVerdict: z.enum(['OVERRIDE_SAFE', 'FORCE_BLOCK']).optional(),
    selectedActionIds: z.array(z.string().max(64)).max(20).optional(),
    originalTxId: z.string().trim().min(1).max(80).optional(),
    requestedAmountVnd: z
      .number()
      .int('Số tiền thu hồi phải là số nguyên dương.')
      .positive('Số tiền thu hồi phải lớn hơn 0.')
      .max(5_000_000_000)
      .optional(),
    idempotencyKey: z.string().trim().min(4).max(100).optional(),
    mode: PlaybookModeEnum.optional(),
    clientDelta: SessionDeltaClientSchema,
  })
  .strict();

export const WalletRequestSchema = z
  .object({
    action: z.enum(['TRANSFER', 'SELF_RESCUE_CANCEL']).optional(),
    senderAccountId: z.string().trim().max(64).optional(),
    senderName: z.string().trim().max(100).optional(),
    recipientAccountIdOrNumber: z.string().trim().min(1, 'Vui lòng nhập số tài khoản nhận.').max(80),
    amountVnd: z.number().int('Số tiền VND phải là số nguyên dương.').positive('Số tiền phải lớn hơn 0.').max(5_000_000_000),
    message: z.string().trim().max(300).optional(),
    idempotencyKey: z.string().trim().min(4).max(100).optional(),
    clientDelta: SessionDeltaClientSchema,
  })
  .strict();

export const MerchantVerifyRequestSchema = z
  .object({
    claimedTxId: z.string().trim().min(1, 'Vui lòng nhập mã giao dịch cần đối soát.').max(80),
    claimedAmountVnd: z.number().int('Số tiền đối soát phải là số nguyên không âm.').min(0).max(50_000_000_000),
    merchantAccountIdOrNumber: z.string().trim().max(80).optional(),
    clientDelta: SessionDeltaClientSchema,
  })
  .strict();

export const MerchantVisionVerifyRequestSchema = z
  .object({
    imageDataUrl: z.string().min(10, 'Ảnh Bill tải lên không hợp lệ.').max(MAX_IMAGE_DATA_URL_LENGTH),
    merchantAccountIdOrNumber: z.string().trim().max(80).optional(),
    clientDelta: SessionDeltaClientSchema,
  })
  .strict();

export const HitlFeedbackRequestSchema = z
  .object({
    action: z.enum(['CREATE', 'APPROVE', 'REJECT', 'REVOKE']),
    alertId: z.string().trim().min(1).max(64).optional(),
    feedbackId: z.string().trim().min(1).max(80).optional(),
    feedbackDecision: z.enum(['OVERRIDE_SAFE', 'FORCE_BLOCK']).optional(),
    targetScope: z.enum(['ALERT_CASE', 'RECIPIENT_PATTERN', 'TX_PATTERN']).optional(),
    reasonCode: z
      .enum([
        'VERIFIED_LEGITIMATE_PARTNER',
        'FALSE_POSITIVE_CONTEXT',
        'CONFIRMED_MULE_PATTERN',
        'MERCHANT_BILL_FRAUD',
        'ANALYST_ESCALATION',
      ])
      .optional(),
    analystRationale: z.string().trim().max(400).optional(),
    evidenceReferences: z.array(z.string().trim().max(64)).max(15).optional(),
    ttlHours: z.number().int().min(1).max(168).optional(),
    rejectReasonVi: z.string().trim().max(300).optional(),
    clientDelta: SessionDeltaClientSchema,
  })
  .strict();

export const SandboxRequestSchema = z
  .object({
    customTitle: z.string().max(160).optional(),
    rawTranscript: z.string().max(3000).optional(),
    imageDataUrl: z.string().max(MAX_IMAGE_DATA_URL_LENGTH).optional(),
    recipientAccountNumber: z.string().max(40).optional(),
    recipientOwnerName: z.string().max(100).optional(),
    amountVnd: z.number().finite().positive().max(5_000_000_000).optional(),
    caseInputSpec: StandardCaseInputSpecSchema.optional(),
    clientDelta: SessionDeltaClientSchema,
  })
  .strict();

export const CopilotRequestSchema = z
  .object({
    alertId: z.string().trim().min(1).max(64).optional(),
    question: z.string().trim().min(1, 'Câu hỏi không được để trống.').max(600),
    clientDelta: SessionDeltaClientSchema,
  })
  .strict();

export const BatchImportRequestSchema = z
  .object({
    rawContent: z.string().trim().min(1, 'Tệp dữ liệu tải lên bị trống.').max(150_000),
    fileName: z.string().trim().max(120).optional(),
    clientDelta: SessionDeltaClientSchema,
  })
  .strict();

export const WorkspaceSyncRequestSchema = z
  .object({
    clientDelta: SessionDeltaClientSchema,
  })
  .strict();

export const SessionRoleSwitchSchema = z
  .object({
    sessionId: z.string().trim().min(3).max(80).optional(),
    role: z.enum(['L2_CHECKER', 'L1_MAKER', 'END_USER']),
    principalId: z.string().trim().min(2).max(80).optional(),
  })
  .strict();

const buildPayloadTooLargeResponse = (maxBytes: number): NextResponse =>
  NextResponse.json(
    {
      code: 'PAYLOAD_TOO_LARGE',
      errorVi: `Dung lượng dữ liệu JSON vượt quá giới hạn cho phép (${maxBytes.toLocaleString('en-US')} bytes). Vui lòng giảm dung lượng ảnh (tối đa 3.000.000 bytes) và thử lại.`,
      maxBytes,
    },
    { status: 413 }
  );

/**
 * Reads a NextRequest body as UTF-8 text while enforcing a strict actual-byte ceiling.
 * - Uses streamed `req.body.getReader()` when available so oversized payloads terminate early
 *   and cancel the stream without unbounded buffering.
 * - Counts actual UTF-8 wire bytes (not JS UTF-16 string length) and cannot be bypassed by
 *   missing or falsified `Content-Length` headers.
 */
export const readRequestBodyTextWithByteLimit = async (
  req: NextRequest,
  maxBytes: number
): Promise<
  | { ok: true; text: string; byteLength: number }
  | { ok: false; response: NextResponse }
> => {
  const contentLengthHeader = req.headers?.get?.('content-length');
  if (contentLengthHeader !== null && contentLengthHeader !== undefined) {
    const trimmedLen = contentLengthHeader.trim();
    if (!/^\d+$/.test(trimmedLen)) {
      return {
        ok: false,
        response: NextResponse.json(
          {
            code: 'INVALID_CONTENT_LENGTH',
            errorVi: 'Header Content-Length không hợp lệ.',
          },
          { status: 400 }
        ),
      };
    }
    const declaredLength = Number(trimmedLen);
    if (!Number.isSafeInteger(declaredLength) || declaredLength < 0) {
      return {
        ok: false,
        response: NextResponse.json(
          {
            code: 'INVALID_CONTENT_LENGTH',
            errorVi: 'Header Content-Length không hợp lệ.',
          },
          { status: 400 }
        ),
      };
    }
    if (declaredLength > maxBytes) {
      return { ok: false, response: buildPayloadTooLargeResponse(maxBytes) };
    }
  }

  const streamBody = req.body;
  if (streamBody && typeof streamBody.getReader === 'function') {
    const reader = streamBody.getReader();
    const chunks: Uint8Array[] = [];
    let totalBytes = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!value || value.byteLength === 0) continue;
        totalBytes += value.byteLength;
        if (totalBytes > maxBytes) {
          try {
            await reader.cancel();
          } catch {
            // Best-effort cancellation on oversized stream
          }
          return { ok: false, response: buildPayloadTooLargeResponse(maxBytes) };
        }
        chunks.push(value);
      }
    } catch {
      return {
        ok: false,
        response: NextResponse.json(
          {
            code: 'INVALID_JSON',
            errorVi: 'Không thể đọc luồng dữ liệu JSON gửi lên.',
          },
          { status: 400 }
        ),
      };
    } finally {
      try {
        reader.releaseLock();
      } catch {
        // Ignore if lock already released
      }
    }

    const merged = Buffer.concat(chunks);
    return { ok: true, text: merged.toString('utf8'), byteLength: totalBytes };
  }

  if (typeof req.text === 'function') {
    const rawText = await req.text();
    const actualBytes = Buffer.byteLength(rawText, 'utf8');
    if (actualBytes > maxBytes) {
      return { ok: false, response: buildPayloadTooLargeResponse(maxBytes) };
    }
    return { ok: true, text: rawText, byteLength: actualBytes };
  }

  return {
    ok: false,
    response: NextResponse.json(
      {
        code: 'INVALID_JSON',
        errorVi: 'Dữ liệu JSON gửi lên không hợp lệ.',
      },
      { status: 400 }
    ),
  };
};

export const parseRequestJsonWithSchema = async <T>(
  req: NextRequest,
  schema: z.ZodType<T>,
  options?: { maxBytes?: number }
): Promise<
  | { ok: true; data: T }
  | { ok: false; response: NextResponse }
> => {
  const maxBytes = options?.maxBytes ?? DEFAULT_MAX_JSON_BODY_BYTES;
  let raw: unknown;

  if (req.body || typeof req.text === 'function') {
    const bodyRead = await readRequestBodyTextWithByteLimit(req, maxBytes);
    if (!bodyRead.ok) return bodyRead;
    try {
      raw = JSON.parse(bodyRead.text);
    } catch {
      return {
        ok: false,
        response: NextResponse.json(
          {
            code: 'INVALID_JSON',
            errorVi: 'Dữ liệu JSON gửi lên không hợp lệ.',
          },
          { status: 400 }
        ),
      };
    }
  } else {
    try {
      raw = await req.json();
    } catch {
      return {
        ok: false,
        response: NextResponse.json(
          {
            code: 'INVALID_JSON',
            errorVi: 'Dữ liệu JSON gửi lên không hợp lệ.',
          },
          { status: 400 }
        ),
      };
    }
  }

  const parsed = schema.safeParse(raw);
  if (!parsed.success) {
    const details = parsed.error.issues.map((iss) => `${iss.path.join('.') || 'body'}: ${iss.message}`);
    return {
      ok: false,
      response: NextResponse.json(
        {
          code: 'VALIDATION_ERROR',
          errorVi: details[0] ?? 'Dữ liệu đầu vào không hợp lệ theo chuẩn schema API.',
          details,
        },
        { status: 400 }
      ),
    };
  }

  return { ok: true, data: parsed.data };
};
