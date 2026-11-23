/**
 * Pure Domain Merchant Vision OCR Normalization & Deterministic Ledger Cross-Verifier (Wave 3):
 * - Validates and normalizes AI-extracted receipt fields (strictly treated as untrusted user-claimed input).
 * - NEVER creates, modifies, or settles ledger transactions from an image.
 * - Cross-verifies solely against Unified Ledger via verifyMerchantBillReceipt() across MV-01..MV-09.
 */
import { z } from 'zod';
import { verifyMerchantBillReceipt } from './merchant-verifier';
import type {
  Account,
  MerchantVisionExtractedFields,
  MerchantVisionStatus,
  MerchantVisionVerificationBundle,
  Transaction,
} from './types';

export const MerchantOcrRawExtractionSchema = z.object({
  claimedTransactionId: z.string().trim().max(100).nullable().optional(),
  claimedAmountVnd: z.union([z.number(), z.string()]).nullable().optional(),
  currency: z.string().trim().max(16).optional(),
  claimedRecipientAccount: z.string().trim().max(80).nullable().optional(),
  claimedRecipientName: z.string().trim().max(120).nullable().optional(),
  claimedSenderInfo: z.string().trim().max(160).nullable().optional(),
  claimedTransactionTime: z.string().trim().max(80).nullable().optional(),
  paymentProvider: z.string().trim().max(80).nullable().optional(),
  otherReferences: z.array(z.string().trim().max(120)).max(10).optional(),
  detectedAmountsCount: z.number().int().min(0).max(20).optional(),
  candidateTransactionIds: z.array(z.string().trim().max(100)).max(10).optional(),
  imageQualityStatus: z
    .enum(['CLEAR', 'BLURRY', 'CROPPED', 'ROTATED', 'UNREADABLE'])
    .optional(),
  fieldConfidence: z
    .object({
      transactionId: z.number().min(0).max(1).optional(),
      amountVnd: z.number().min(0).max(1).optional(),
      recipientAccount: z.number().min(0).max(1).optional(),
      overall: z.number().min(0).max(1).optional(),
    })
    .optional(),
  extractionWarnings: z.array(z.string().trim().max(240)).max(10).optional(),
  missingFields: z.array(z.string().trim().max(64)).max(10).optional(),
  suspiciousVisualIndicators: z.array(z.string().trim().max(200)).max(10).optional(),
});

/**
 * Parses Vietnamese bank/e-wallet receipt currency amounts cleanly (e.g. "15.000.000 đ", "4,850,000 VND").
 * Rejects ambiguous non-integer decimals or invalid strings instead of guessing.
 */
export const normalizeVndAmountValue = (raw: unknown): number | null => {
  if (typeof raw === 'number') {
    if (!Number.isFinite(raw) || raw <= 0 || !Number.isInteger(raw)) return null;
    return raw;
  }
  if (typeof raw !== 'string') return null;

  let text = raw.trim().toUpperCase();
  if (!text) return null;

  // Strip Vietnamese currency suffixes/symbols
  text = text.replace(/(VNĐ|VND|ĐỒNG|DONG|₫|Đ)\s*$/g, '').trim();
  if (!text || /^-/.test(text)) return null;

  // Reject mixed letters/currency like USD 150
  if (/[A-Z]/.test(text)) return null;

  // Grouped thousands like "15.000.000" or "4,850,000" -> remove separators ONLY when valid 3-digit groups
  const dotGrouped = /^\d{1,3}(\.\d{3})+$/.test(text);
  const commaGrouped = /^\d{1,3}(,\d{3})+$/.test(text);
  const plainDigits = /^\d+$/.test(text);
  const spaceGrouped = /^\d{1,3}(\s\d{3})+$/.test(text);

  let cleanDigits = '';
  if (plainDigits) {
    cleanDigits = text;
  } else if (dotGrouped || commaGrouped || spaceGrouped) {
    cleanDigits = text.replace(/[.,\s]/g, '');
  } else {
    return null;
  }

  const parsed = Number(cleanDigits);
  if (!Number.isSafeInteger(parsed) || parsed <= 0 || parsed > 50_000_000_000) {
    return null;
  }
  return parsed;
};

export const normalizeTransactionIdText = (raw: unknown): string | null => {
  if (typeof raw !== 'string') return null;
  const cleaned = raw
    .trim()
    .toUpperCase()
    .replace(/\s+/g, '')
    .replace(/[^A-Z0-9_-]/g, '');
  if (cleaned.length < 4 || cleaned.length > 64) return null;
  return cleaned;
};

export const normalizeExtractedFields = (
  raw: z.infer<typeof MerchantOcrRawExtractionSchema>
): MerchantVisionExtractedFields => {
  const claimedTransactionId = normalizeTransactionIdText(raw.claimedTransactionId);
  const claimedAmountVnd = normalizeVndAmountValue(raw.claimedAmountVnd);
  const currency = (raw.currency || 'VND').trim().toUpperCase();
  const claimedRecipientAccount = raw.claimedRecipientAccount?.trim() || null;

  const candidateIds = Array.from(
    new Set(
      (raw.candidateTransactionIds ?? [])
        .map((c) => normalizeTransactionIdText(c))
        .filter((c): c is string => Boolean(c))
    )
  );
  if (claimedTransactionId && !candidateIds.includes(claimedTransactionId)) {
    candidateIds.unshift(claimedTransactionId);
  }

  const missingFields = new Set<string>(raw.missingFields ?? []);
  if (!claimedTransactionId) missingFields.add('transactionId');
  if (!claimedAmountVnd) missingFields.add('amountVnd');
  if (!claimedRecipientAccount) missingFields.add('recipientAccount');

  return {
    claimedTransactionId,
    claimedAmountVnd,
    currency,
    claimedRecipientAccount,
    claimedRecipientName: raw.claimedRecipientName?.trim() || null,
    claimedSenderInfo: raw.claimedSenderInfo?.trim() || null,
    claimedTransactionTime: raw.claimedTransactionTime?.trim() || null,
    paymentProvider: raw.paymentProvider?.trim() || null,
    otherReferences: raw.otherReferences ?? [],
    detectedAmountsCount: raw.detectedAmountsCount ?? (claimedAmountVnd ? 1 : 0),
    candidateTransactionIds: candidateIds,
    imageQualityStatus: raw.imageQualityStatus ?? 'CLEAR',
    fieldConfidence: {
      transactionId: Number((raw.fieldConfidence?.transactionId ?? (claimedTransactionId ? 0.8 : 0)).toFixed(2)),
      amountVnd: Number((raw.fieldConfidence?.amountVnd ?? (claimedAmountVnd ? 0.8 : 0)).toFixed(2)),
      recipientAccount: Number(
        (raw.fieldConfidence?.recipientAccount ?? (claimedRecipientAccount ? 0.75 : 0)).toFixed(2)
      ),
      overall: Number((raw.fieldConfidence?.overall ?? 0.75).toFixed(2)),
    },
    extractionWarnings: raw.extractionWarnings ?? [],
    missingFields: Array.from(missingFields),
    suspiciousVisualIndicators: raw.suspiciousVisualIndicators ?? [],
  };
};

export const crossVerifyMerchantVisionAgainstLedger = (params: {
  extracted: MerchantVisionExtractedFields | null;
  ocrOutcome: 'OK' | 'AI_UNAVAILABLE' | 'MALFORMED_OCR' | 'INVALID_IMAGE';
  merchantAccountIdOrNumber?: string;
  ledgerTransactions: Transaction[];
  accounts: Account[];
  modelUsed: string;
  latencyMs: number;
  securityErrorVi?: string;
}): MerchantVisionVerificationBundle => {
  const confidenceDisclaimerVi =
    'Lưu ý: Độ tin cậy OCR chỉ là ước lượng từ mô hình thị giác, KHÔNG phải xác suất hiệu chuẩn hay bằng chứng thanh toán. Chỉ Sổ cái Hợp nhất (Unified Ledger) có thẩm quyền xác nhận tiền đã vào tài khoản.';

  if (params.ocrOutcome === 'INVALID_IMAGE') {
    return {
      status: 'INVALID_IMAGE',
      verificationSource: 'SECURITY_GATE',
      extractedFields: null,
      ledgerComparison: {
        foundInLedger: false,
        txId: null,
        ledgerStatus: 'NOT_CHECKED',
        actualAmountVnd: 0,
        claimedAmountVnd: null,
      },
      matchedFields: [],
      mismatchedFields: [],
      reasonsVi: [params.securityErrorVi ?? 'Tệp ảnh không hợp lệ hoặc vi phạm kiểm soát an toàn.'],
      warningsVi: [],
      recommendedNextActionVi: 'Vui lòng tải lại ảnh chụp màn hình Bill định dạng PNG, JPEG hoặc WebP dưới 4MB.',
      confidenceNoteVi: confidenceDisclaimerVi,
      modelUsed: params.modelUsed,
      latencyMs: params.latencyMs,
    };
  }

  if (params.ocrOutcome === 'AI_UNAVAILABLE') {
    return {
      status: 'AI_UNAVAILABLE',
      verificationSource: 'SECURITY_GATE',
      extractedFields: null,
      ledgerComparison: {
        foundInLedger: false,
        txId: null,
        ledgerStatus: 'NOT_CHECKED',
        actualAmountVnd: 0,
        claimedAmountVnd: null,
      },
      matchedFields: [],
      mismatchedFields: [],
      reasonsVi: [
        'Dịch vụ Gemini Vision hiện tạm thời không khả dụng hoặc vượt thời gian chờ (timeout). Hệ thống tuyệt đối không tự đoán hay xác nhận giao dịch.',
      ],
      warningsVi: ['Tiểu thương có thể nhập tay Mã giao dịch + Số tiền ở biểu mẫu bên dưới để đối soát trực tiếp với Sổ cái.'],
      recommendedNextActionVi:
        'Chuyển sang nhập liệu thủ công Mã GD & Số tiền để đối soát Unified Ledger, hoặc bấm Thử lại OCR.',
      confidenceNoteVi: confidenceDisclaimerVi,
      modelUsed: params.modelUsed,
      latencyMs: params.latencyMs,
    };
  }

  if (params.ocrOutcome === 'MALFORMED_OCR' || !params.extracted) {
    return {
      status: 'NEEDS_MANUAL_REVIEW',
      verificationSource: 'AI_OCR_AND_LEDGER',
      extractedFields: null,
      ledgerComparison: {
        foundInLedger: false,
        txId: null,
        ledgerStatus: 'NOT_CHECKED',
        actualAmountVnd: 0,
        claimedAmountVnd: null,
      },
      matchedFields: [],
      mismatchedFields: [],
      reasonsVi: [
        'Kết quả OCR trả về không đúng cấu trúc chuẩn hoặc ảnh không thể đọc rõ trường dữ liệu bắt buộc.',
      ],
      warningsVi: ['Không tự động xác nhận Bill khi kết quả trích xuất chưa đạt chuẩn schema.'],
      recommendedNextActionVi: 'Kiểm tra trực tiếp số dư trên App MoMo Merchant hoặc nhập tay Mã GD để đối soát.',
      confidenceNoteVi: confidenceDisclaimerVi,
      modelUsed: params.modelUsed,
      latencyMs: params.latencyMs,
    };
  }

  const ext = params.extracted;

  // MV-09: Ambiguous extraction (multiple distinct transaction IDs or multiple unclear amounts)
  if (ext.candidateTransactionIds.length > 1 || ext.detectedAmountsCount > 1) {
    return {
      status: 'AMBIGUOUS_EXTRACTION',
      verificationSource: 'AI_OCR_AND_LEDGER',
      extractedFields: ext,
      ledgerComparison: {
        foundInLedger: false,
        txId: ext.claimedTransactionId,
        ledgerStatus: 'PENDING_DISAMBIGUATION',
        actualAmountVnd: 0,
        claimedAmountVnd: ext.claimedAmountVnd,
      },
      matchedFields: [],
      mismatchedFields: [],
      reasonsVi: [
        ext.candidateTransactionIds.length > 1
          ? `Ảnh chứa nhiều mã tham chiếu giao dịch (${ext.candidateTransactionIds.join(', ')}), không đủ cơ sở phân biệt mã chính xác.`
          : `Ảnh chứa ${ext.detectedAmountsCount} giá trị tiền tệ khác nhau (có thể lẫn số dư/phí giao dịch).`,
      ],
      warningsVi: [...ext.extractionWarnings, ...ext.suspiciousVisualIndicators],
      recommendedNextActionVi:
        'Đối chiếu thủ công Mã giao dịch duy nhất & số tiền chuyển khoản thực tế trên Biểu mẫu Sổ cái.',
      confidenceNoteVi: confidenceDisclaimerVi,
      modelUsed: params.modelUsed,
      latencyMs: params.latencyMs,
    };
  }

  // MV-06: Blurry/unreadable/cropped low-trust image, missing TX ID or Amount, currency != VND, or low field confidence
  const hasLowFieldConfidence =
    ext.fieldConfidence.overall < 0.55 ||
    ext.fieldConfidence.transactionId < 0.55 ||
    ext.fieldConfidence.amountVnd < 0.55;
  const hasUncertainCroppedImage =
    ext.imageQualityStatus === 'CROPPED' &&
    (ext.fieldConfidence.overall < 0.7 || !ext.claimedRecipientAccount);

  if (
    ext.imageQualityStatus === 'BLURRY' ||
    ext.imageQualityStatus === 'UNREADABLE' ||
    hasUncertainCroppedImage ||
    !ext.claimedTransactionId ||
    !ext.claimedAmountVnd ||
    ext.currency !== 'VND' ||
    hasLowFieldConfidence
  ) {
    return {
      status: 'NEEDS_MANUAL_REVIEW',
      verificationSource: 'AI_OCR_AND_LEDGER',
      extractedFields: ext,
      ledgerComparison: {
        foundInLedger: false,
        txId: ext.claimedTransactionId,
        ledgerStatus: 'NOT_CHECKED',
        actualAmountVnd: 0,
        claimedAmountVnd: ext.claimedAmountVnd,
      },
      matchedFields: [],
      mismatchedFields: [],
      reasonsVi: [
        ext.currency !== 'VND'
          ? `Đơn vị tiền tệ trích xuất (${ext.currency}) không khớp VNĐ trên Sổ cái.`
          : ext.imageQualityStatus === 'BLURRY' || ext.imageQualityStatus === 'UNREADABLE' || hasUncertainCroppedImage
          ? `Chất lượng ảnh (${ext.imageQualityStatus}) không đạt độ nét/đầy đủ để xác minh tự động.`
          : !ext.claimedTransactionId || !ext.claimedAmountVnd
          ? `Thiếu trường dữ liệu bắt buộc (${ext.missingFields.join(', ')}).`
          : `Độ tự tin trích xuất trường trọng yếu (Tổng: ${Math.round(ext.fieldConfidence.overall * 100)}%, Mã GD: ${Math.round(ext.fieldConfidence.transactionId * 100)}%, Số tiền: ${Math.round(ext.fieldConfidence.amountVnd * 100)}%) dưới ngưỡng an toàn 55%.`,
      ],
      warningsVi: [...ext.extractionWarnings, ...ext.suspiciousVisualIndicators],
      recommendedNextActionVi:
        'Chỉnh sửa / bổ sung thông tin còn thiếu ở ô nhập thủ công bên dưới rồi bấm Đối soát Sổ cái.',
      confidenceNoteVi: confidenceDisclaimerVi,
      modelUsed: params.modelUsed,
      latencyMs: params.latencyMs,
    };
  }

  // Authoritative Deterministic Cross-Verification against Unified Ledger (MV-01..MV-05)
  const expectedMerchant =
    params.merchantAccountIdOrNumber?.trim() || ext.claimedRecipientAccount || undefined;

  const ledgerVerdict = verifyMerchantBillReceipt({
    claimedTxId: ext.claimedTransactionId,
    claimedAmountVnd: ext.claimedAmountVnd,
    merchantAccountIdOrNumber: expectedMerchant,
    ledgerTransactions: params.ledgerTransactions,
    accounts: params.accounts,
  });

  const statusMap: Record<typeof ledgerVerdict.verdict, MerchantVisionStatus> = {
    VERIFIED_LEDGER_MATCH: 'VERIFIED_LEDGER_MATCH',
    FORGED_PHOTOSHOP_AMOUNT_MISMATCH: 'AMOUNT_MISMATCH',
    FAKE_RECEIPT_NOT_IN_LEDGER: 'TRANSACTION_NOT_FOUND',
    BLOCKED_TRANSACTION_NO_SETTLEMENT: 'NOT_SETTLED',
    WRONG_MERCHANT_RECIPIENT: 'RECIPIENT_MISMATCH',
  };

  const status = statusMap[ledgerVerdict.verdict];
  const matchedFields: string[] = [];
  const mismatchedFields: string[] = [];

  if (ledgerVerdict.ledgerStatus !== 'NOT_FOUND') {
    matchedFields.push('transactionId');
  } else {
    mismatchedFields.push('transactionId');
  }
  if (status === 'VERIFIED_LEDGER_MATCH') {
    matchedFields.push('amountVnd', 'recipientAccount', 'ledgerSettled');
  } else if (status === 'AMOUNT_MISMATCH') {
    matchedFields.push('recipientAccount', 'ledgerSettled');
    mismatchedFields.push('amountVnd');
  } else if (status === 'RECIPIENT_MISMATCH') {
    mismatchedFields.push('recipientAccount');
  } else if (status === 'NOT_SETTLED') {
    mismatchedFields.push('ledgerSettled');
  }

  return {
    status,
    verificationSource: 'AI_OCR_AND_LEDGER',
    extractedFields: ext,
    ledgerComparison: {
      foundInLedger: ledgerVerdict.ledgerStatus !== 'NOT_FOUND',
      txId: ledgerVerdict.claimedTxId,
      ledgerStatus: ledgerVerdict.ledgerStatus,
      actualAmountVnd: ledgerVerdict.actualLedgerAmountVnd,
      claimedAmountVnd: ext.claimedAmountVnd,
      expectedMerchantAccountId: ledgerVerdict.expectedMerchantAccountId,
      actualReceiverAccountId: ledgerVerdict.actualReceiverAccountId,
      matchedSenderName: ledgerVerdict.matchedSenderName,
      soundboxAnnouncementVi: ledgerVerdict.soundboxAnnouncementVi,
    },
    matchedFields,
    mismatchedFields,
    reasonsVi: [ledgerVerdict.headlineVi, ledgerVerdict.explanationVi],
    warningsVi: [
      ...ext.extractionWarnings,
      ...ext.suspiciousVisualIndicators.map(
        (s) => `[Chỉ dấu hình ảnh tham khảo - Chưa coi là kết luận] ${s}`
      ),
    ],
    recommendedNextActionVi: ledgerVerdict.merchantActionVi,
    confidenceNoteVi: confidenceDisclaimerVi,
    modelUsed: params.modelUsed,
    latencyMs: params.latencyMs,
  };
};
