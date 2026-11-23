/**
 * Pure Domain MoMo Merchant Protection Engine (Wave 2 IMP-05):
 * Verifies customer-shown transfer screenshots/receipts against Unified Core Ledger
 * and generates MoMo Soundbox voice alerts across all 5 adversarial fraud & ledger cases (A-E).
 */
import type { Account, Transaction } from './types';

export type MerchantReceiptVerdict =
  | 'VERIFIED_LEDGER_MATCH'
  | 'FORGED_PHOTOSHOP_AMOUNT_MISMATCH'
  | 'FAKE_RECEIPT_NOT_IN_LEDGER'
  | 'BLOCKED_TRANSACTION_NO_SETTLEMENT'
  | 'WRONG_MERCHANT_RECIPIENT';

export interface MerchantBillVerificationResult {
  verdict: MerchantReceiptVerdict;
  claimedTxId: string;
  claimedAmountVnd: number;
  actualLedgerAmountVnd: number;
  ledgerStatus: string;
  expectedMerchantAccountId?: string;
  actualReceiverAccountId?: string;
  matchedSenderName: string;
  headlineVi: string;
  explanationVi: string;
  soundboxAnnouncementVi: string;
  merchantActionVi: string;
  responseTimeMs: number;
}

const MERCHANT_REFERENCE_LEDGER: Array<{
  txId: string;
  amountVnd: number;
  senderName: string;
  receiverAccountId: string;
  receiverAccountNumber: string;
  status: string;
}> = [
  {
    txId: 'TXN-MERCH-1K',
    amountVnd: 1_000,
    senderName: 'NGUYEN VAN GIAN (Khách đưa bill sửa ảnh)',
    receiverAccountId: 'ACC-HOSP-800',
    receiverAccountNumber: '1188999000888',
    status: 'SETTLED',
  },
  {
    txId: 'TXN-MERCH-OK',
    amountVnd: 4_850_000,
    senderName: 'LE THI MINH ANH (Khách hàng Verified)',
    receiverAccountId: 'ACC-HOSP-800',
    receiverAccountNumber: '1188999000888',
    status: 'SETTLED',
  },
];

export interface MerchantPresetSample {
  id: string;
  labelVi: string;
  claimedTxId: string;
  claimedAmountVnd: number;
  merchantAccountIdOrNumber?: string;
  tone: 'RED' | 'GREEN';
}

export const MERCHANT_RECEIPT_PRESETS: MerchantPresetSample[] = [
  {
    id: 'PRESET-REAL-OK',
    labelVi: 'Case A: Bill Thật khớp Sổ cái & Loa MoMo (4,85M)',
    claimedTxId: 'TXN-MERCH-OK',
    claimedAmountVnd: 4_850_000,
    merchantAccountIdOrNumber: 'ACC-HOSP-800',
    tone: 'GREEN',
  },
  {
    id: 'PRESET-PHOTOSHOP-1K',
    labelVi: 'Case B: Bill Sửa Số Tiền 1.000₫ → 15.000.000₫',
    claimedTxId: 'TXN-MERCH-1K',
    claimedAmountVnd: 15_000_000,
    merchantAccountIdOrNumber: 'ACC-HOSP-800',
    tone: 'RED',
  },
  {
    id: 'PRESET-GHOST-TXN',
    labelVi: 'Case C: Bill Không Tồn Tại Sổ Cái (TXN-GHOST-999)',
    claimedTxId: 'TXN-GHOST-999',
    claimedAmountVnd: 12_500_000,
    merchantAccountIdOrNumber: 'ACC-HOSP-800',
    tone: 'RED',
  },
  {
    id: 'PRESET-BLOCKED-SHIELD',
    labelVi: 'Case D: Giao dịch Đã Bị Chặn (TXN-8843 - Tiền không vào Sổ cái)',
    claimedTxId: 'TXN-8843',
    claimedAmountVnd: 35_000_000,
    merchantAccountIdOrNumber: 'ACC-MULE-903',
    tone: 'RED',
  },
  {
    id: 'PRESET-WRONG-MERCHANT',
    labelVi: 'Case E: Sai Tài Khoản Tiểu Thương Nhận (Chuyển nhầm nơi khác)',
    claimedTxId: 'TXN-MERCH-OK',
    claimedAmountVnd: 4_850_000,
    merchantAccountIdOrNumber: 'ACC-USR-104',
    tone: 'RED',
  },
];

const isSettledLedgerStatus = (status: string): boolean => {
  const upper = status.toUpperCase();
  return upper === 'SETTLED' || upper === 'COMPLETED' || upper === 'SETTLED_LEDGER';
};

const matchesMerchantTarget = (params: {
  expectedMerchant?: string;
  actualReceiverAccountId?: string;
  actualReceiverAccountNumber?: string;
  accounts?: Account[];
}): boolean => {
  if (!params.expectedMerchant || !params.expectedMerchant.trim()) {
    return true;
  }
  const cleanExpected = params.expectedMerchant.trim().toUpperCase();
  const resolvedMerchantAcc = params.accounts?.find(
    (a) => a.id.toUpperCase() === cleanExpected || a.accountNumber.toUpperCase() === cleanExpected
  );

  const actualIdUpper = (params.actualReceiverAccountId ?? '').trim().toUpperCase();
  const actualNumUpper = (params.actualReceiverAccountNumber ?? '').trim().toUpperCase();
  const actualAcc = params.accounts?.find((a) => a.id.toUpperCase() === actualIdUpper);
  const resolvedActualNum = (actualAcc?.accountNumber ?? actualNumUpper).toUpperCase();

  const candidateExpecteds = new Set<string>([
    cleanExpected,
    `EXT-${cleanExpected}`,
    ...(resolvedMerchantAcc
      ? [
          resolvedMerchantAcc.id.toUpperCase(),
          resolvedMerchantAcc.accountNumber.toUpperCase(),
        ]
      : []),
  ]);

  return (
    (actualIdUpper.length > 0 && candidateExpecteds.has(actualIdUpper)) ||
    (resolvedActualNum.length > 0 && candidateExpecteds.has(resolvedActualNum))
  );
};

export const verifyMerchantBillReceipt = (params: {
  claimedTxId: string;
  claimedAmountVnd: number;
  merchantAccountIdOrNumber?: string;
  ledgerTransactions?: Transaction[];
  accounts?: Account[];
}): MerchantBillVerificationResult => {
  const cleanTxId = params.claimedTxId.trim().toUpperCase();
  const claimedAmount = Math.max(0, Math.round(params.claimedAmountVnd || 0));

  const realTx = (params.ledgerTransactions ?? []).find(
    (t) => t.id.toUpperCase() === cleanTxId
  );
  const presetMatch = !realTx
    ? MERCHANT_REFERENCE_LEDGER.find((r) => r.txId === cleanTxId)
    : undefined;

  if (!realTx && !presetMatch) {
    return {
      verdict: 'FAKE_RECEIPT_NOT_IN_LEDGER',
      claimedTxId: cleanTxId,
      claimedAmountVnd: claimedAmount,
      actualLedgerAmountVnd: 0,
      ledgerStatus: 'NOT_FOUND',
      expectedMerchantAccountId: params.merchantAccountIdOrNumber?.trim() || undefined,
      matchedSenderName: '0 giao dịch khớp mã',
      headlineVi: 'KHÔNG TÌM THẤY GIAO DỊCH — BILL KHÔNG CÓ TRÊN SỔ CÁI',
      explanationVi: `Mã giao dịch "${cleanTxId}" trị giá ${claimedAmount.toLocaleString('vi-VN')} ₫ trên màn hình khách đưa KHÔNG TỒN TẠI trên Sổ cái Hợp nhất MoMo. Kẻ gian thường dùng app tạo bill giả hoặc lấy cớ "mạng nghẽn".`,
      soundboxAnnouncementVi:
        'Cảnh báo tiểu thương: Không tìm thấy giao dịch trên sổ cái, tuyệt đối không giao hàng!',
      merchantActionVi: 'KHÔNG GIAO HÀNG • Yêu cầu kiểm tra biến động số dư trực tiếp trên App MoMo Merchant.',
      responseTimeMs: 2,
    };
  }

  const ledgerAmount = realTx?.amountVnd ?? presetMatch?.amountVnd ?? 0;
  const ledgerStatus = realTx?.status ?? presetMatch?.status ?? 'NOT_FOUND';
  const actualReceiverAccountId = realTx?.receiverAccountId ?? presetMatch?.receiverAccountId;
  const matchedSenderName = realTx
    ? params.accounts?.find((a) => a.id === realTx.senderAccountId)?.ownerName ??
      realTx.senderAccountId
    : presetMatch?.senderName ?? 'Không xác định trong sổ cái';

  // Case D: Transaction was BLOCKED / FAILED / HELD / REVERSED -> No money settled in ledger!
  if (!isSettledLedgerStatus(ledgerStatus)) {
    return {
      verdict: 'BLOCKED_TRANSACTION_NO_SETTLEMENT',
      claimedTxId: cleanTxId,
      claimedAmountVnd: claimedAmount,
      actualLedgerAmountVnd: 0,
      ledgerStatus,
      expectedMerchantAccountId: params.merchantAccountIdOrNumber?.trim() || undefined,
      actualReceiverAccountId,
      matchedSenderName,
      headlineVi: 'GIAO DỊCH ĐÃ BỊ CHẶN – TIỀN KHÔNG VÀO SỔ CÁI',
      explanationVi: `Mã giao dịch "${cleanTxId}" có trạng thái [${ledgerStatus}] trên Sổ cái (tiền KHÔNG được hạch toán ghi có cho người nhận). Tuyệt đối không giao hàng dựa trên ảnh chụp màn hình.`,
      soundboxAnnouncementVi:
        'Cảnh báo khẩn: Giao dịch đã bị chặn hoặc chưa hoàn tất, tiền không vào sổ cái!',
      merchantActionVi: 'TỪ CHỐI GIAO HÀNG • Giao dịch chưa thanh toán vào tài khoản Tiểu thương.',
      responseTimeMs: 2,
    };
  }

  // Case E: Valid settled TXN, but receiver account is NOT the checked merchant!
  const receiverMatches = matchesMerchantTarget({
    expectedMerchant: params.merchantAccountIdOrNumber,
    actualReceiverAccountId,
    actualReceiverAccountNumber: presetMatch?.receiverAccountNumber,
    accounts: params.accounts,
  });

  if (!receiverMatches) {
    return {
      verdict: 'WRONG_MERCHANT_RECIPIENT',
      claimedTxId: cleanTxId,
      claimedAmountVnd: claimedAmount,
      actualLedgerAmountVnd: ledgerAmount,
      ledgerStatus,
      expectedMerchantAccountId: params.merchantAccountIdOrNumber?.trim(),
      actualReceiverAccountId,
      matchedSenderName,
      headlineVi: 'KHÔNG KHỚP NGƯỜI NHẬN — BILL CHUYỂN SANG TÀI KHOẢN KHÁC',
      explanationVi: `Giao dịch "${cleanTxId}" (${ledgerAmount.toLocaleString('vi-VN')} ₫) đã hạch toán NHƯNG chuyển tới "${actualReceiverAccountId}", KHÔNG PHẢI tài khoản Tiểu thương đang kiểm tra (${params.merchantAccountIdOrNumber}).`,
      soundboxAnnouncementVi:
        'Cảnh báo tiểu thương: Giao dịch không khớp người nhận, tiền không về tài khoản của bạn!',
      merchantActionVi: 'KHÔNG GIAO HÀNG • Đối chiếu lại số tài khoản thụ hưởng trên màn hình khách.',
      responseTimeMs: 2,
    };
  }

  // Case B: Claimed bill amount != Settled ledger amount
  if (ledgerAmount !== claimedAmount) {
    const diff = Math.abs(claimedAmount - ledgerAmount);
    return {
      verdict: 'FORGED_PHOTOSHOP_AMOUNT_MISMATCH',
      claimedTxId: cleanTxId,
      claimedAmountVnd: claimedAmount,
      actualLedgerAmountVnd: ledgerAmount,
      ledgerStatus,
      expectedMerchantAccountId: params.merchantAccountIdOrNumber?.trim() || undefined,
      actualReceiverAccountId,
      matchedSenderName,
      headlineVi: 'CẢNH BÁO BILL SỬA SỐ TIỀN (LỆCH SỐ TIỀN THỰC NHẬN)',
      explanationVi: `Ảnh Bill khách đưa ghi ${claimedAmount.toLocaleString('vi-VN')} ₫, NHƯNG Sổ cái chỉ ghi nhận thực nhận ${ledgerAmount.toLocaleString('vi-VN')} ₫ từ "${matchedSenderName}" (Chênh lệch giả mạo ${diff.toLocaleString('vi-VN')} ₫).`,
      soundboxAnnouncementVi: `Loa MoMo cảnh báo: Thực nhận chỉ ${ledgerAmount.toLocaleString('vi-VN')} đồng, sai lệch với ảnh bill khách đưa!`,
      merchantActionVi: 'GIỮ LẠI HÀNG HÓA • Chụp hình đối chiếu và báo cáo gian lận ngay.',
      responseTimeMs: 2,
    };
  }

  // Case A: Verified match across TXN ID + SETTLED status + Receiver + Amount
  return {
    verdict: 'VERIFIED_LEDGER_MATCH',
    claimedTxId: cleanTxId,
    claimedAmountVnd: claimedAmount,
    actualLedgerAmountVnd: ledgerAmount,
    ledgerStatus,
    expectedMerchantAccountId: params.merchantAccountIdOrNumber?.trim() || undefined,
    actualReceiverAccountId,
    matchedSenderName,
    headlineVi: 'GIAO DỊCH THẬT — ĐÃ NHẬN TIỀN ĐỦ VÀO SỔ CÁI',
    explanationVi: `Mã "${cleanTxId}" trạng thái [${ledgerStatus}] khớp 100% số tiền ${ledgerAmount.toLocaleString('vi-VN')} ₫ từ "${matchedSenderName}" tới "${actualReceiverAccountId}" trên Sổ cái Hợp nhất.`,
    soundboxAnnouncementVi: `Loa MoMo xin thông báo: Đã nhận thành công ${ledgerAmount.toLocaleString('vi-VN')} đồng!`,
    merchantActionVi: 'AN TOÀN • Tiểu thương có thể bàn giao hàng hóa cho khách.',
    responseTimeMs: 2,
  };
};
