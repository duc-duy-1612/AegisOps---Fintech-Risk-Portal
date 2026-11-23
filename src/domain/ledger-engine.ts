/**
 * Pure Domain Double-Entry Ledger Engine (Wave 2 IMP-05):
 * - Single source of truth for P2P transfers, Shield interceptions, and Clawback reversals.
 * - Strict integer VND accounting: every settled transfer or reversal emits balanced DEBIT + CREDIT entries.
 * - Ensures balances never go negative and idempotency keys never double-post.
 */
import type {
  Account,
  ClawbackRecoveryStatus,
  LedgerEntryRecord,
  Transaction,
} from './types';

export class InsufficientBalanceError extends Error {
  public readonly availableVnd: number;
  public readonly requiredVnd: number;

  constructor(message: string, availableVnd: number, requiredVnd: number) {
    super(message);
    this.name = 'InsufficientBalanceError';
    this.availableVnd = availableVnd;
    this.requiredVnd = requiredVnd;
  }
}

export class LedgerValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LedgerValidationError';
  }
}

export class LedgerInvariantError extends LedgerValidationError {
  public readonly violationCode:
    | 'NEGATIVE_OPENING_BALANCE'
    | 'NEGATIVE_INTERMEDIATE_BALANCE'
    | 'INVALID_ENTRY_AMOUNT'
    | 'INVALID_ENTRY_TYPE'
    | 'UNBALANCED_TRANSACTION_ENTRIES';
  public readonly accountId?: string;
  public readonly txId?: string;
  public readonly observedBalanceVnd?: number;

  constructor(params: {
    message: string;
    violationCode: LedgerInvariantError['violationCode'];
    accountId?: string;
    txId?: string;
    observedBalanceVnd?: number;
  }) {
    super(params.message);
    this.name = 'LedgerInvariantError';
    this.violationCode = params.violationCode;
    this.accountId = params.accountId;
    this.txId = params.txId;
    this.observedBalanceVnd = params.observedBalanceVnd;
  }
}

export interface LedgerBalanceInvariantCheckResult {
  valid: boolean;
  balances: Map<string, number>;
  violations: Array<{
    violationCode: LedgerInvariantError['violationCode'];
    message: string;
    accountId?: string;
    txId?: string;
    observedBalanceVnd?: number;
  }>;
}

export const DEFAULT_VICTIM_WALLET_ACCOUNT_ID = 'ACC-USR-103';

export const toIntegerVnd = (value: number): number => {
  if (!Number.isFinite(value)) {
    throw new LedgerValidationError('Số tiền VND phải là một số hợp lệ.');
  }
  const rounded = Math.round(value);
  if (rounded <= 0) {
    throw new LedgerValidationError('Số tiền giao dịch phải lớn hơn 0 VNĐ.');
  }
  return rounded;
};

/**
 * Evaluates authoritative per-account balances and double-entry invariants WITHOUT silently clamping
 * negative intermediate balances to 0.
 */
export const evaluateLedgerBalanceInvariants = (
  baseAccounts: Account[],
  ledgerEntries: LedgerEntryRecord[]
): LedgerBalanceInvariantCheckResult => {
  const balances = new Map<string, number>();
  const violations: LedgerBalanceInvariantCheckResult['violations'] = [];

  for (const acc of baseAccounts) {
    if (!Number.isFinite(acc.balanceVnd)) {
      violations.push({
        violationCode: 'NEGATIVE_OPENING_BALANCE',
        accountId: acc.id,
        message: `Số dư khởi tạo của tài khoản "${acc.id}" không hợp lệ (NaN/Infinity).`,
      });
      continue;
    }
    const opening = Math.round(acc.balanceVnd);
    if (opening < 0) {
      violations.push({
        violationCode: 'NEGATIVE_OPENING_BALANCE',
        accountId: acc.id,
        observedBalanceVnd: opening,
        message: `Số dư khởi tạo của tài khoản "${acc.id}" không được âm (${opening.toLocaleString('vi-VN')} ₫).`,
      });
    }
    balances.set(acc.id, opening);
  }

  const txTotals = new Map<string, { debit: number; credit: number }>();

  for (const entry of ledgerEntries) {
    if (entry.status !== 'SETTLED' && entry.status !== 'REVERSED') continue;

    if (entry.entryType !== 'DEBIT' && entry.entryType !== 'CREDIT') {
      violations.push({
        violationCode: 'INVALID_ENTRY_TYPE',
        accountId: entry.accountId,
        txId: entry.txId,
        message: `Loại bút toán không hợp lệ tại "${entry.id}" (txId="${entry.txId}").`,
      });
      continue;
    }

    if (!Number.isFinite(entry.amountVnd) || !Number.isInteger(entry.amountVnd) || entry.amountVnd <= 0) {
      violations.push({
        violationCode: 'INVALID_ENTRY_AMOUNT',
        accountId: entry.accountId,
        txId: entry.txId,
        message: `Số tiền bút toán "${entry.id}" phải là số nguyên dương (nhận: ${String(entry.amountVnd)}).`,
      });
      continue;
    }

    const txAcc = txTotals.get(entry.txId) ?? { debit: 0, credit: 0 };
    if (entry.entryType === 'DEBIT') txAcc.debit += entry.amountVnd;
    else txAcc.credit += entry.amountVnd;
    txTotals.set(entry.txId, txAcc);

    const prev = balances.get(entry.accountId) ?? 0;
    const delta = entry.entryType === 'CREDIT' ? entry.amountVnd : -entry.amountVnd;
    const nextBalance = prev + delta;
    balances.set(entry.accountId, nextBalance);

    if (nextBalance < 0) {
      violations.push({
        violationCode: 'NEGATIVE_INTERMEDIATE_BALANCE',
        accountId: entry.accountId,
        txId: entry.txId,
        observedBalanceVnd: nextBalance,
        message: `Vi phạm bất biến Sổ cái (Overdraft): Tài khoản "${entry.accountId}" có số dư âm trung gian (${nextBalance.toLocaleString('vi-VN')} ₫) tại bút toán "${entry.id}" (GD "${entry.txId}").`,
      });
    }
  }

  for (const [txId, totals] of txTotals.entries()) {
    if (totals.debit !== totals.credit) {
      violations.push({
        violationCode: 'UNBALANCED_TRANSACTION_ENTRIES',
        txId,
        message: `Giao dịch "${txId}" mất cân bằng hạch toán kép: DEBIT=${totals.debit.toLocaleString('vi-VN')} ₫ != CREDIT=${totals.credit.toLocaleString('vi-VN')} ₫.`,
      });
    }
  }

  return {
    valid: violations.length === 0,
    balances,
    violations,
  };
};

/**
 * Recompute authoritative per-account balances from opening balances + settled double-entry postings.
 * Throws LedgerInvariantError if any opening balance, intermediate balance, or transaction double-entry
 * invariant is violated (never hides overdrafts behind Math.max(0, ...)).
 */
export const computeAccountBalancesFromLedger = (
  baseAccounts: Account[],
  ledgerEntries: LedgerEntryRecord[]
): Map<string, number> => {
  const check = evaluateLedgerBalanceInvariants(baseAccounts, ledgerEntries);
  if (!check.valid) {
    const first = check.violations[0]!;
    throw new LedgerInvariantError({
      message: first.message,
      violationCode: first.violationCode,
      accountId: first.accountId,
      txId: first.txId,
      observedBalanceVnd: first.observedBalanceVnd,
    });
  }
  return check.balances;
};

export const applyLedgerBalancesToAccounts = (
  accounts: Account[],
  ledgerEntries: LedgerEntryRecord[]
): Account[] => {
  if (ledgerEntries.length === 0) return accounts;
  const computed = computeAccountBalancesFromLedger(accounts, ledgerEntries);
  return accounts.map((acc) => ({
    ...acc,
    balanceVnd: computed.get(acc.id) ?? acc.balanceVnd,
  }));
};

export const verifyDoubleEntryBalanceInvariant = (
  ledgerEntries: LedgerEntryRecord[]
): { balanced: boolean; totalDebitVnd: number; totalCreditVnd: number } => {
  let totalDebitVnd = 0;
  let totalCreditVnd = 0;
  for (const entry of ledgerEntries) {
    if (entry.entryType === 'DEBIT') totalDebitVnd += entry.amountVnd;
    if (entry.entryType === 'CREDIT') totalCreditVnd += entry.amountVnd;
  }
  return {
    balanced: totalDebitVnd === totalCreditVnd,
    totalDebitVnd,
    totalCreditVnd,
  };
};

export const resolveSenderAccount = (
  accounts: Account[],
  senderAccountId?: string,
  senderName?: string
): Account => {
  if (senderAccountId) {
    const cleanId = senderAccountId.trim().toUpperCase();
    const byId = accounts.find(
      (a) => a.id.toUpperCase() === cleanId || a.accountNumber.toUpperCase() === cleanId
    );
    if (byId) return byId;
    throw new LedgerValidationError(`Tài khoản nguồn "${senderAccountId}" không tồn tại trên hệ thống.`);
  }

  if (senderName) {
    const cleanName = senderName.trim().toLowerCase();
    const byName = accounts.find(
      (a) => a.ownerName.toLowerCase() === cleanName || a.ownerName.toLowerCase().includes(cleanName)
    );
    if (byName) return byName;
  }

  return (
    accounts.find((a) => a.id === DEFAULT_VICTIM_WALLET_ACCOUNT_ID) ??
    accounts.find((a) => a.accountType === 'CONSUMER') ??
    accounts[0]!
  );
};

export const resolveRecipientAccountRef = (
  accounts: Account[],
  recipientAccountIdOrNumber: string
): { receiverAccountId: string; account?: Account } => {
  const clean = recipientAccountIdOrNumber.trim().toUpperCase();
  const matched = accounts.find(
    (a) => a.accountNumber.toUpperCase() === clean || a.id.toUpperCase() === clean
  );
  if (matched) {
    return { receiverAccountId: matched.id, account: matched };
  }
  return { receiverAccountId: `EXT-${clean}` };
};

export const buildBalancedLedgerPair = (params: {
  txId: string;
  debitAccountId: string;
  creditAccountId: string;
  amountVnd: number;
  status: 'SETTLED' | 'REVERSED';
  idempotencyKey?: string;
  noteVi?: string;
  createdAt: string;
}): [LedgerEntryRecord, LedgerEntryRecord] => {
  const amount = toIntegerVnd(params.amountVnd);
  return [
    {
      id: `LDG-${params.txId}-D`,
      txId: params.txId,
      accountId: params.debitAccountId,
      entryType: 'DEBIT',
      amountVnd: amount,
      currency: 'VND',
      status: params.status,
      idempotencyKey: params.idempotencyKey,
      noteVi: params.noteVi,
      createdAt: params.createdAt,
    },
    {
      id: `LDG-${params.txId}-C`,
      txId: params.txId,
      accountId: params.creditAccountId,
      entryType: 'CREDIT',
      amountVnd: amount,
      currency: 'VND',
      status: params.status,
      idempotencyKey: params.idempotencyKey,
      noteVi: params.noteVi,
      createdAt: params.createdAt,
    },
  ];
};

export const computeClawbackRecoveryPlan = (params: {
  alertTransactions: Transaction[];
  sourceMuleAccount?: Account;
  victimAccountId?: string;
  sourceMuleAccountId?: string;
  originalTxId?: string;
  requestedAmountVnd?: number;
  alreadyReversedAmountVnd?: number;
}): {
  totalOriginalSettledVnd: number;
  remainingRefundableVnd: number;
  requestedAmountVnd: number;
  recoveredAmountVnd: number;
  missingAmountVnd: number;
  recoveryStatus: ClawbackRecoveryStatus;
  recoverableTxIds: string[];
} => {
  // CR-2.1 Invariants #1-#4: Strictly ONLY original SETTLED / COMPLETED transactions
  // (never BLOCKED, HELD, PENDING, FAILED, REVERSED, or prior CLAWBACK_REVERSAL) are eligible.
  const candidateTxs = params.alertTransactions.filter((t) => {
    if (t.txKind === 'CLAWBACK_REVERSAL') return false;
    if (t.status !== 'COMPLETED' && t.status !== 'SETTLED') return false;
    if (params.originalTxId && t.id !== params.originalTxId) return false;
    if (params.victimAccountId && t.senderAccountId !== params.victimAccountId) return false;
    if (params.sourceMuleAccountId && t.receiverAccountId !== params.sourceMuleAccountId) {
      return false;
    }
    return true;
  });

  const totalOriginalSettledVnd = candidateTxs.reduce(
    (sum, t) => sum + Math.round(t.amountVnd),
    0
  );
  const priorReversed = Math.max(0, Math.round(params.alreadyReversedAmountVnd ?? 0));
  const remainingRefundableVnd = Math.max(0, totalOriginalSettledVnd - priorReversed);
  const availableOnMule = Math.max(0, Math.round(params.sourceMuleAccount?.balanceVnd ?? 0));

  if (candidateTxs.length === 0 || remainingRefundableVnd <= 0) {
    return {
      totalOriginalSettledVnd,
      remainingRefundableVnd: 0,
      requestedAmountVnd: 0,
      recoveredAmountVnd: 0,
      missingAmountVnd: 0,
      recoveryStatus: 'FAILED',
      recoverableTxIds: [],
    };
  }

  let requestedAmountVnd = remainingRefundableVnd;
  if (params.requestedAmountVnd !== undefined) {
    const explicitReq = toIntegerVnd(params.requestedAmountVnd);
    if (explicitReq > remainingRefundableVnd) {
      throw new LedgerValidationError(
        `Số tiền thu hồi yêu cầu (${explicitReq.toLocaleString('vi-VN')} ₫) vượt quá số tiền gốc còn đủ điều kiện hoàn trả (${remainingRefundableVnd.toLocaleString('vi-VN')} ₫).`
      );
    }
    requestedAmountVnd = explicitReq;
  }

  const recoveredAmountVnd = Math.min(requestedAmountVnd, availableOnMule);
  const missingAmountVnd = Math.max(0, requestedAmountVnd - recoveredAmountVnd);
  const recoveryStatus: ClawbackRecoveryStatus =
    recoveredAmountVnd === 0
      ? 'FAILED'
      : missingAmountVnd === 0
        ? 'RECOVERED'
        : 'PARTIALLY_RECOVERED';

  return {
    totalOriginalSettledVnd,
    remainingRefundableVnd,
    requestedAmountVnd,
    recoveredAmountVnd,
    missingAmountVnd,
    recoveryStatus,
    recoverableTxIds: candidateTxs.map((t) => t.id),
  };
};
