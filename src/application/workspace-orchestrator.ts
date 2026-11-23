import { computeCrossCaseCorrelations } from '@/domain/campaign-correlator';
import { buildComplianceIncidentDossier } from '@/domain/compliance-report';
import { sha256Hex } from '@/domain/crypto-hash';
import {
  runDeterministicForensicsSuite,
  type ForensicContext,
} from '@/domain/forensics-analyzers';
import {
  buildHitlContextSignature,
  clampHitlRiskAdjustment,
  hasDuplicateActiveFeedback,
} from '@/domain/hitl-feedback-engine';
import {
  InsufficientBalanceError,
  LedgerValidationError,
  buildBalancedLedgerPair,
  computeAccountBalancesFromLedger,
  computeClawbackRecoveryPlan,
  resolveRecipientAccountRef,
  resolveSenderAccount,
  toIntegerVnd,
} from '@/domain/ledger-engine';
import {
  verifyMerchantBillReceipt,
  type MerchantBillVerificationResult,
} from '@/domain/merchant-verifier';
import { synthesizeSandboxCase } from '@/domain/sandbox-synthesizer';
import { evaluateConsumerTransfer } from '@/domain/shield-evaluator';
import type {
  Account,
  AnalystOverrideRecord,
  ClawbackReceiptRecord,
  ConsumerTransferDecision,
  ConsumerTransferRequest,
  ForensicSuiteOutput,
  HitlFeedbackDecision,
  HitlFeedbackMemoryRecord,
  HitlFeedbackReasonCode,
  HitlFeedbackTargetScope,
  IdempotencyTransferRecord,
  InvestigationReport,
  OperatorRole,
  SessionDeltaSnapshot,
  ShieldRule,
  SimoReceiptRecord,
  StandardCaseInputSpec,
  Transaction,
} from '@/domain/types';
import {
  askGeminiCopilotOnCase,
  extractSandboxEntitiesWithGeminiVision,
  runGeminiInvestigationWithFallback,
} from '@/infrastructure/gemini-agent';
import {
  getAllAcceptedPiiPseudonyms,
  getCurrentPiiHmacKeyId,
  pseudonymizePiiWithHmacSha256,
  pseudonymizePiiWithPreviousKey,
} from '@/infrastructure/privacy-hasher';
import {
  materializeWorkspaceState,
  resetSessionDelta,
  saveSessionDelta,
  type MaterializedWorkspaceState,
} from '@/infrastructure/workspace-store';

export interface AlertDetailBundle {
  forensics: ForensicSuiteOutput;
  report?: InvestigationReport;
}

const buildTargetFingerprintsMap = (
  accounts: Account[]
): {
  current: Record<string, string>;
  legacy: Record<string, string[]>;
} => {
  const current: Record<string, string> = {};
  const legacy: Record<string, string[]> = {};
  for (const acc of accounts) {
    const raw = acc.accountNumber || acc.id;
    current[acc.id] = pseudonymizePiiWithHmacSha256(raw);
    const prev = pseudonymizePiiWithPreviousKey(raw);
    if (prev && prev !== current[acc.id]) {
      legacy[acc.id] = [prev];
    }
  }
  return { current, legacy };
};

export const getWorkspaceBootstrap = (
  sessionId: string,
  clientDelta?: Partial<SessionDeltaSnapshot> | null
): {
  state: MaterializedWorkspaceState;
  forensicsByAlertId: Record<string, ForensicSuiteOutput>;
} => {
  const state = materializeWorkspaceState(sessionId, clientDelta);
  const forensicsByAlertId: Record<string, ForensicSuiteOutput> = {};
  const { current: targetFingerprintsByAccountId, legacy: legacyTargetFingerprintsByAccountId } =
    buildTargetFingerprintsMap(state.accounts);

  for (const alert of state.alerts) {
    const ctx: ForensicContext = {
      alert,
      accounts: state.accounts,
      devices: state.devices,
      authLogs: state.authLogs,
      transactions: state.transactions,
      apiEvents: state.apiEvents,
      evidences: state.evidences,
      feedbackMemory: state.delta.hitlFeedbackMemory ?? [],
      targetFingerprintsByAccountId,
      legacyTargetFingerprintsByAccountId,
      activeShieldRules: state.delta.activeShieldRules,
    };
    forensicsByAlertId[alert.id] = runDeterministicForensicsSuite(ctx);
  }

  return { state, forensicsByAlertId };
};

export const executeAlertInvestigation = async (params: {
  sessionId: string;
  alertId: string;
  clientDelta?: Partial<SessionDeltaSnapshot> | null;
}): Promise<{
  report: InvestigationReport;
  forensics: ForensicSuiteOutput;
  delta: SessionDeltaSnapshot;
}> => {
  const state = materializeWorkspaceState(params.sessionId, params.clientDelta);
  const alert = state.alerts.find((a) => a.id === params.alertId) ?? state.alerts[0];
  if (!alert) {
    throw new Error('No alert available for investigation');
  }

  const { current: targetFingerprintsByAccountId, legacy: legacyTargetFingerprintsByAccountId } =
    buildTargetFingerprintsMap(state.accounts);
  const forensics = runDeterministicForensicsSuite({
    alert,
    accounts: state.accounts,
    devices: state.devices,
    authLogs: state.authLogs,
    transactions: state.transactions,
    apiEvents: state.apiEvents,
    evidences: state.evidences,
    feedbackMemory: state.delta.hitlFeedbackMemory ?? [],
    targetFingerprintsByAccountId,
    legacyTargetFingerprintsByAccountId,
    activeShieldRules: state.delta.activeShieldRules,
  });

  const alertEvidences = state.evidences.filter((e) => e.alertId === alert.id);
  const evidenceTranscript = alertEvidences.map((e) => `${e.title}: ${e.textContent}`).join('\n');
  const firstImage = alertEvidences.find((e) => Boolean(e.imageDataUrl))?.imageDataUrl;

  const report = await runGeminiInvestigationWithFallback({
    alert,
    forensics,
    evidenceTranscript,
    imageDataUrl: firstImage,
  });

  const nextDelta: SessionDeltaSnapshot = {
    ...state.delta,
    alertStatuses: {
      ...state.delta.alertStatuses,
      [alert.id]:
        state.delta.alertStatuses[alert.id] === 'MITIGATED' ||
          state.delta.alertStatuses[alert.id] === 'DISMISSED_SAFE'
          ? state.delta.alertStatuses[alert.id]!
          : 'INVESTIGATING',
    },
    reportsByAlertId: {
      ...state.delta.reportsByAlertId,
      [alert.id]: report,
    },
    auditLogs: [
      ...state.delta.auditLogs,
      {
        id: `AUD-INV-${Date.now().toString().slice(-5)}`,
        alertId: alert.id,
        actor: 'AI_AGENT',
        action: 'INVESTIGATION_COMPLETED',
        detailsVi: `AI (${report.modelUsed}) hoàn tất điều tra ${alert.id} trong ${report.latencyMs}ms → ${report.classification} (Trích dẫn: ${report.citedEvidenceIds.join(', ')}).`,
        timestamp: new Date().toISOString(),
      },
    ],
  };

  const committedDelta = saveSessionDelta(params.sessionId, nextDelta);
  return { report, forensics, delta: committedDelta };
};

export class SelfApprovalForbiddenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SelfApprovalForbiddenError';
  }
}

export class IdempotencyKeyConflictError extends Error {
  public readonly idempotencyKey: string;

  constructor(message: string, idempotencyKey: string) {
    super(message);
    this.name = 'IdempotencyKeyConflictError';
    this.idempotencyKey = idempotencyKey;
  }
}

const makeAuditId = (prefix: string): string =>
  `${prefix}-${Date.now().toString(36).toUpperCase().slice(-5)}-${Math.random()
    .toString(36)
    .slice(2, 6)
    .toUpperCase()}`;

export const executePlaybookApproval = (params: {
  sessionId: string;
  alertId: string;
  selectedActionIds?: string[];
  mode?: 'PROPOSE_L1' | 'APPROVE_L2';
  actorPrincipalId?: string;
  clientDelta?: Partial<SessionDeltaSnapshot> | null;
}): {
  delta: SessionDeltaSnapshot;
  createdShieldRule?: ShieldRule;
  newStatus: 'INVESTIGATING' | 'MITIGATED' | 'DISMISSED_SAFE';
  proposedForL2?: boolean;
} => {
  const state = materializeWorkspaceState(params.sessionId, params.clientDelta);
  const alert = state.alerts.find((a) => a.id === params.alertId);
  if (!alert) {
    throw new Error(`Alert ${params.alertId} not found`);
  }

  // Maker-Checker Governance: L1 Maker proposes Playbook to L2 Checker without freezing accounts yet
  if (params.mode === 'PROPOSE_L1') {
    const makerPrincipal = params.actorPrincipalId?.trim() || 'demo-l1-maker';
    const pendingIds = Array.from(
      new Set([...(state.delta.pendingL2ApprovalAlertIds ?? []), alert.id])
    );
    const l1Delta: SessionDeltaSnapshot = {
      ...state.delta,
      pendingL2ApprovalAlertIds: pendingIds,
      makerPrincipalByAlertId: {
        ...(state.delta.makerPrincipalByAlertId ?? {}),
        [alert.id]: makerPrincipal,
      },
      alertStatuses: {
        ...state.delta.alertStatuses,
        [alert.id]:
          state.delta.alertStatuses[alert.id] === 'MITIGATED' ||
            state.delta.alertStatuses[alert.id] === 'DISMISSED_SAFE'
            ? state.delta.alertStatuses[alert.id]!
            : 'INVESTIGATING',
      },
      auditLogs: [
        ...state.delta.auditLogs,
        {
          id: `AUD-L1-${Date.now().toString().slice(-5)}`,
          alertId: alert.id,
          actor: 'OPS_ANALYST',
          action: 'L1_MAKER_PROPOSED_PLAYBOOK',
          detailsVi: `Chuyên viên L1 (${makerPrincipal}) đã trình Playbook vụ ${alert.id} chờ L2 (Checker) phê duyệt (4-Eyes).`,
          timestamp: new Date().toISOString(),
        },
      ],
    };
    const committedL1 = saveSessionDelta(params.sessionId, l1Delta);
    return { delta: committedL1, newStatus: 'INVESTIGATING', proposedForL2: true };
  }

  // Enforce strict Maker !== Checker separation whenever actorPrincipalId is supplied
  const recordedMaker = state.delta.makerPrincipalByAlertId?.[alert.id];
  if (recordedMaker && params.actorPrincipalId && recordedMaker === params.actorPrincipalId) {
    throw new SelfApprovalForbiddenError(
      `Từ chối tự phê duyệt (HTTP 403): Principal "${params.actorPrincipalId}" là người đề xuất L1 của vụ ${alert.id} nên không được phép tự duyệt L2.`
    );
  }

  const { current: targetFingerprintsByAccountId, legacy: legacyTargetFingerprintsByAccountId } =
    buildTargetFingerprintsMap(state.accounts);

  const forensics = runDeterministicForensicsSuite({
    alert,
    accounts: state.accounts,
    devices: state.devices,
    authLogs: state.authLogs,
    transactions: state.transactions,
    apiEvents: state.apiEvents,
    evidences: state.evidences,
    feedbackMemory: state.delta.hitlFeedbackMemory ?? [],
    targetFingerprintsByAccountId,
    legacyTargetFingerprintsByAccountId,
    activeShieldRules: state.delta.activeShieldRules,
  });

  const cachedReport = state.delta.reportsByAlertId[alert.id];
  const reportStaleAgainstForensics =
    Boolean(cachedReport) &&
    (cachedReport!.deterministicRiskScore !== forensics.deterministicRiskScore ||
      cachedReport!.classification !== forensics.fallbackReport.classification);

  const report: InvestigationReport =
    cachedReport && !reportStaleAgainstForensics
      ? cachedReport
      : cachedReport
        ? {
          ...cachedReport,
          classification: forensics.fallbackReport.classification,
          deterministicRiskScore: forensics.deterministicRiskScore,
          recommendedActions: forensics.fallbackReport.recommendedActions,
        }
        : forensics.fallbackReport;

  const syncedReportsByAlertId = cachedReport
    ? { ...state.delta.reportsByAlertId, [alert.id]: report }
    : state.delta.reportsByAlertId;

  const remainingPending = (state.delta.pendingL2ApprovalAlertIds ?? []).filter(
    (id) => id !== alert.id
  );
  const remainingMakers = { ...(state.delta.makerPrincipalByAlertId ?? {}) };
  delete remainingMakers[alert.id];
  const isFalsePositive = forensics.fallbackReport.classification === 'FALSE_POSITIVE_SAFE';

  if (isFalsePositive) {
    const safeDelta: SessionDeltaSnapshot = {
      ...state.delta,
      pendingL2ApprovalAlertIds: remainingPending,
      makerPrincipalByAlertId: remainingMakers,
      alertStatuses: { ...state.delta.alertStatuses, [alert.id]: 'DISMISSED_SAFE' },
      reportsByAlertId: syncedReportsByAlertId,
      auditLogs: [
        ...state.delta.auditLogs,
        {
          id: makeAuditId('AUD-SAFE'),
          alertId: alert.id,
          actor: 'OPS_ANALYST',
          action: 'MARKED_SAFE_FALSE_POSITIVE',
          detailsVi: `Quản lý L2 xác nhận ${alert.id} là giao dịch hợp lệ (Báo động giả). Đã bảo vệ khách hàng khỏi bị khóa tài khoản oan.`,
          timestamp: new Date().toISOString(),
        },
      ],
    };
    const committedSafe = saveSessionDelta(params.sessionId, safeDelta);
    return { delta: committedSafe, newStatus: 'DISMISSED_SAFE' };
  }

  const targetAccount = state.accounts.find((a) => a.id === alert.targetRecipientAccountId);
  const targetAccountNumber = targetAccount?.accountNumber ?? alert.targetRecipientAccountId;
  const targetOwnerName = targetAccount?.ownerName ?? alert.targetRecipientAccountId;

  // Also freeze all mule accounts in the same transaction graph for this alert
  const alertReceiverIds = state.transactions
    .filter((t) => t.alertId === alert.id)
    .map((t) => t.receiverAccountId);

  const newlyFrozen = Array.from(
    new Set([
      ...state.delta.frozenAccountIds,
      alert.targetRecipientAccountId,
      ...alertReceiverIds,
    ])
  );

  const shieldRule: ShieldRule = {
    id: `SHD-${alert.id}`,
    alertId: alert.id,
    targetAccountId: alert.targetRecipientAccountId,
    targetAccountNumber,
    targetOwnerName,
    targetDeviceId: targetAccount?.primaryDeviceId,
    ruleType: 'BLOCK_RECIPIENT_MULE',
    userWarningVi:
      report.userShieldWarningVi ||
      `CẢNH BÁO ĐỎ AEGIS SHIELD: Tài khoản ${targetAccountNumber} (${targetOwnerName}) vừa bị phong tỏa do nằm trong đường dây lừa đảo/chiếm đoạt tài khoản. Giao dịch của bạn đã được chặn tự động!`,
    active: true,
    createdAt: new Date().toISOString(),
  };

  const existingShields = state.delta.activeShieldRules.filter((r) => r.id !== shieldRule.id);

  const nextDelta: SessionDeltaSnapshot = {
    ...state.delta,
    pendingL2ApprovalAlertIds: remainingPending,
    makerPrincipalByAlertId: remainingMakers,
    alertStatuses: { ...state.delta.alertStatuses, [alert.id]: 'MITIGATED' },
    frozenAccountIds: newlyFrozen,
    activeShieldRules: [shieldRule, ...existingShields],
    reportsByAlertId: syncedReportsByAlertId,
    auditLogs: [
      ...state.delta.auditLogs,
      {
        id: makeAuditId('AUD-PLAY'),
        alertId: alert.id,
        actor: 'OPS_ANALYST',
        action: 'PLAYBOOK_APPROVED_AND_SHIELD_ACTIVE',
        detailsVi: `Quản lý L2 phê duyệt Playbook 1-Click cho ${alert.id}: Đóng băng TK đích ${targetAccountNumber} (${targetOwnerName}) & kích hoạt Lá chắn Cộng đồng ${shieldRule.id}.`,
        timestamp: new Date().toISOString(),
      },
    ],
  };

  const committed = saveSessionDelta(params.sessionId, nextDelta);
  return { delta: committed, createdShieldRule: shieldRule, newStatus: 'MITIGATED' };
};

export const simulateWalletTransferInSession = (params: {
  sessionId: string;
  transfer: ConsumerTransferRequest;
  clientDelta?: Partial<SessionDeltaSnapshot> | null;
}): {
  decision: ConsumerTransferDecision;
  transaction: Transaction;
  senderBalanceVnd: number;
  receiverBalanceVnd: number | null;
  delta: SessionDeltaSnapshot;
} => {
  const state = materializeWorkspaceState(params.sessionId, params.clientDelta);
  const amountVnd = toIntegerVnd(params.transfer.amountVnd);
  const senderAccount = resolveSenderAccount(
    state.accounts,
    params.transfer.senderAccountId,
    params.transfer.senderName
  );
  const { receiverAccountId, account: recipientAccount } = resolveRecipientAccountRef(
    state.accounts,
    params.transfer.recipientAccountIdOrNumber
  );

  const normalizedMessage = (params.transfer.message ?? '').trim() || 'Chuyển tiền Ví MoMo';
  const normalizedRecipientInput = params.transfer.recipientAccountIdOrNumber.trim().toUpperCase();
  const canonicalPayload = {
    senderAccountId: senderAccount.id,
    receiverAccountId,
    recipientAccountIdOrNumber: normalizedRecipientInput,
    amountVnd,
    message: normalizedMessage,
  };
  const requestSignature = sha256Hex(
    JSON.stringify({
      senderAccountId: canonicalPayload.senderAccountId,
      receiverAccountId: canonicalPayload.receiverAccountId,
      amountVnd: canonicalPayload.amountVnd,
      message: canonicalPayload.message,
    })
  );

  // Idempotency Replay Check (returns exact historical decision; rejects payload mismatch with HTTP 409)
  const cleanIdemKey = params.transfer.idempotencyKey?.trim();
  if (cleanIdemKey) {
    const existingRecord = state.delta.idempotencyRecordsByKey?.[cleanIdemKey];
    const existingTxId =
      existingRecord?.txId ?? state.delta.processedIdempotencyKeys?.[cleanIdemKey];

    if (existingTxId) {
      const existingTx = state.transactions.find((t) => t.id === existingTxId);

      if (existingRecord) {
        if (existingRecord.requestSignature !== requestSignature) {
          throw new IdempotencyKeyConflictError(
            `Xung đột khóa Idempotency "${cleanIdemKey}" (HTTP 409): Payload yêu cầu (số tiền, người nhận hoặc nội dung) khác với giao dịch gốc "${existingRecord.txId}".`,
            cleanIdemKey
          );
        }
        if (existingTx) {
          return {
            decision: {
              ...existingRecord.decisionSnapshot,
              idempotentReplay: true,
            },
            transaction: existingTx,
            senderBalanceVnd: existingRecord.senderBalanceVnd,
            receiverBalanceVnd: existingRecord.receiverBalanceVnd,
            delta: state.delta,
          };
        }
      } else if (existingTx) {
        const legacyMsg = (existingTx.message ?? '').trim() || 'Chuyển tiền Ví MoMo';
        if (
          existingTx.senderAccountId !== senderAccount.id ||
          existingTx.receiverAccountId !== receiverAccountId ||
          existingTx.amountVnd !== amountVnd ||
          legacyMsg !== normalizedMessage
        ) {
          throw new IdempotencyKeyConflictError(
            `Xung đột khóa Idempotency "${cleanIdemKey}" (HTTP 409): Payload yêu cầu khác với giao dịch gốc "${existingTx.id}".`,
            cleanIdemKey
          );
        }

        const historicalDecisionType: ConsumerTransferDecision['decision'] =
          existingTx.status === 'BLOCKED'
            ? 'BLOCKED_BY_SHIELD'
            : existingTx.status === 'HELD'
              ? 'WARN_COOLING_OFF'
              : 'ALLOWED_SAFE';
        const receiverBalanceVnd = recipientAccount ? recipientAccount.balanceVnd : null;
        return {
          decision: {
            decision: historicalDecisionType,
            matchedRuleId: existingTx.status === 'BLOCKED' ? existingTx.alertId : undefined,
            transactionId: existingTx.id,
            transactionStatus: existingTx.status,
            senderAccountId: existingTx.senderAccountId,
            recipientAccountId: existingTx.receiverAccountId,
            recipientAccountNumber: recipientAccount?.accountNumber ?? normalizedRecipientInput,
            recipientName: recipientAccount?.ownerName ?? existingTx.receiverAccountId,
            amountVnd: existingTx.amountVnd,
            senderBalanceVnd: senderAccount.balanceVnd,
            receiverBalanceVnd: receiverBalanceVnd ?? undefined,
            idempotentReplay: true,
            titleVi:
              historicalDecisionType === 'BLOCKED_BY_SHIELD'
                ? 'GIAO DỊCH ĐÃ ĐƯỢC CHẶN BỞI LÁ CHẮN AEGIS SHIELD'
                : historicalDecisionType === 'WARN_COOLING_OFF'
                  ? 'CẢNH BÁO LÀM NGUỘI TÂM LÝ (SMART COOLING-OFF)'
                  : 'GIAO DỊCH HỢP LỆ — KHÔNG CÓ CẢNH BÁO RỦI RO',
            explanationVi: `Phản hồi idempotent từ giao dịch gốc ${existingTx.id} (trạng thái lịch sử: ${existingTx.status}).`,
            coolingOffQuestionsVi: [],
            responseTimeMs: 1,
          },
          transaction: existingTx,
          senderBalanceVnd: senderAccount.balanceVnd,
          receiverBalanceVnd,
          delta: state.delta,
        };
      }
    }
  }

  if (senderAccount.status === 'FROZEN') {
    throw new LedgerValidationError(
      `Tài khoản nguồn ${senderAccount.accountNumber} (${senderAccount.ownerName}) hiện đang bị phong tỏa.`
    );
  }

  if (receiverAccountId === senderAccount.id) {
    throw new LedgerValidationError('Không thể tự chuyển tiền cho chính tài khoản nguồn.');
  }

  if (senderAccount.balanceVnd < amountVnd) {
    throw new InsufficientBalanceError(
      `Số dư khả dụng (${senderAccount.balanceVnd.toLocaleString('vi-VN')} ₫) không đủ để chuyển ${amountVnd.toLocaleString('vi-VN')} ₫.`,
      senderAccount.balanceVnd,
      amountVnd
    );
  }

  const { current: targetFingerprints, legacy: legacyTargetFingerprints } =
    buildTargetFingerprintsMap(state.accounts);
  const rawDecision = evaluateConsumerTransfer(
    { ...params.transfer, amountVnd, message: normalizedMessage },
    state.delta.activeShieldRules,
    state.accounts,
    {
      hitlFeedbackMemory: state.delta.hitlFeedbackMemory ?? [],
      targetFingerprintsByAccountId: targetFingerprints,
      legacyTargetFingerprintsByAccountId: legacyTargetFingerprints,
    }
  );

  const nowIso = new Date().toISOString();
  const uniqueSuffix = `${Date.now().toString(36).toUpperCase()}-${Math.random()
    .toString(36)
    .slice(2, 6)
    .toUpperCase()}`;
  const txId = `TXN-WAL-${uniqueSuffix}`;
  const isBlocked = rawDecision.decision === 'BLOCKED_BY_SHIELD';
  const isCoolingOffHeld = rawDecision.decision === 'WARN_COOLING_OFF';
  const shouldSettleLedger = !isBlocked && !isCoolingOffHeld;

  const newTx: Transaction = {
    id: txId,
    alertId: rawDecision.matchedRuleId ?? 'CONSUMER_WALLET',
    senderAccountId: senderAccount.id,
    receiverAccountId,
    amountVnd,
    channel: 'P2P_WALLET',
    message: normalizedMessage,
    deviceId: senderAccount.primaryDeviceId,
    hopIndex: 1,
    status: isBlocked ? 'BLOCKED' : isCoolingOffHeld ? 'HELD' : 'SETTLED',
    timestamp: nowIso,
    idempotencyKey: cleanIdemKey,
    txKind: 'P2P_TRANSFER',
  };

  const newLedgerPair = shouldSettleLedger
    ? buildBalancedLedgerPair({
      txId,
      debitAccountId: senderAccount.id,
      creditAccountId: receiverAccountId,
      amountVnd,
      status: 'SETTLED',
      idempotencyKey: cleanIdemKey,
      noteVi: `Chuyển khoản P2P ${txId}: ${senderAccount.id} → ${receiverAccountId}`,
      createdAt: nowIso,
    })
    : [];

  const refreshedBalances = computeAccountBalancesFromLedger(state.accounts, newLedgerPair);
  const senderBalanceVnd = refreshedBalances.get(senderAccount.id) ?? senderAccount.balanceVnd;
  const receiverBalanceVnd = recipientAccount
    ? (refreshedBalances.get(recipientAccount.id) ?? recipientAccount.balanceVnd)
    : null;

  const finalDecision: ConsumerTransferDecision = {
    ...rawDecision,
    transactionId: newTx.id,
    transactionStatus: newTx.status,
    senderAccountId: senderAccount.id,
    recipientAccountId: receiverAccountId,
    senderBalanceVnd,
    receiverBalanceVnd: receiverBalanceVnd ?? undefined,
    idempotentReplay: false,
  };

  const nextLedgerEntries = [...(state.delta.ledgerEntries ?? []), ...newLedgerPair];
  const nextCustomTransactions = [newTx, ...state.delta.customTransactions];
  const nextIdempotencyMap = cleanIdemKey
    ? { ...(state.delta.processedIdempotencyKeys ?? {}), [cleanIdemKey]: txId }
    : state.delta.processedIdempotencyKeys;
  const nextIdempotencyRecords: Record<string, IdempotencyTransferRecord> | undefined = cleanIdemKey
    ? {
      ...(state.delta.idempotencyRecordsByKey ?? {}),
      [cleanIdemKey]: {
        idempotencyKey: cleanIdemKey,
        txId,
        requestSignature,
        canonicalPayload,
        decisionSnapshot: finalDecision,
        senderBalanceVnd,
        receiverBalanceVnd,
        recordedAt: nowIso,
      },
    }
    : state.delta.idempotencyRecordsByKey;

  const updatedAuditLogs = isBlocked
    ? [
      ...state.delta.auditLogs,
      {
        id: makeAuditId('AUD-WAL'),
        alertId: rawDecision.matchedRuleId ?? 'CONSUMER_WALLET',
        actor: 'CONSUMER_SHIELD' as const,
        action: 'REALTIME_WALLET_TRANSFER_INTERCEPTED',
        detailsVi: `Lá chắn Ví Người dùng chặn đứng lệnh chuyển ${amountVnd.toLocaleString('vi-VN')} ₫ (${txId}) tới ${rawDecision.recipientAccountNumber} (${rawDecision.recipientName}) trong ${rawDecision.responseTimeMs}ms — Tiền không rời Sổ cái!`,
        timestamp: nowIso,
      },
    ]
    : isCoolingOffHeld
      ? [
        ...state.delta.auditLogs,
        {
          id: makeAuditId('AUD-WAL'),
          alertId: 'CONSUMER_WALLET',
          actor: 'CONSUMER_SHIELD' as const,
          action: 'COOLING_OFF_TRANSFER_HELD',
          detailsVi: `Cảnh báo Làm nguội (Smart Cooling-Off / HITL): Tạm giữ lệnh chuyển ${amountVnd.toLocaleString('vi-VN')} ₫ (${txId}) tới ${rawDecision.recipientAccountNumber} ở trạng thái HELD — Chưa hạch toán trừ số dư ví.`,
          timestamp: nowIso,
        },
      ]
      : [
        ...state.delta.auditLogs,
        {
          id: makeAuditId('AUD-WAL'),
          alertId: 'CONSUMER_WALLET',
          actor: 'CONSUMER_SHIELD' as const,
          action: 'P2P_LEDGER_SETTLED',
          detailsVi: `Hạch toán kép Sổ cái Hợp nhất (${txId}): Ghi nợ ${senderAccount.id} / Ghi có ${receiverAccountId} số tiền ${amountVnd.toLocaleString('vi-VN')} ₫.`,
          timestamp: nowIso,
        },
      ];

  const nextDelta: SessionDeltaSnapshot = {
    ...state.delta,
    customTransactions: nextCustomTransactions,
    ledgerEntries: nextLedgerEntries,
    processedIdempotencyKeys: nextIdempotencyMap,
    idempotencyRecordsByKey: nextIdempotencyRecords,
    auditLogs: updatedAuditLogs,
  };

  const committed = saveSessionDelta(params.sessionId, nextDelta);

  return {
    decision: finalDecision,
    transaction: newTx,
    senderBalanceVnd,
    receiverBalanceVnd,
    delta: committed,
  };
};

export const recordVictimSelfRescueInSession = (params: {
  sessionId: string;
  recipientAccount: string;
  amountVnd: number;
  clientDelta?: Partial<SessionDeltaSnapshot> | null;
}): { delta: SessionDeltaSnapshot; savedTotalVnd: number } => {
  const state = materializeWorkspaceState(params.sessionId, params.clientDelta);
  const nextSaved = (state.delta.selfRescuedAmountVnd ?? 0) + Math.max(0, params.amountVnd);
  const nextDelta: SessionDeltaSnapshot = {
    ...state.delta,
    selfRescuedAmountVnd: nextSaved,
    auditLogs: [
      ...state.delta.auditLogs,
      {
        id: `AUD-RESC-${Date.now().toString().slice(-5)}`,
        alertId: 'CONSUMER_WALLET',
        actor: 'CONSUMER_SHIELD',
        action: 'VICTIM_SELF_RESCUED_DEESCALATION',
        detailsVi: `Khách hàng trên Ví MoMo đã đọc Thẻ Gỡ bùa Tâm lý và chủ động HỦY lệnh chuyển ${params.amountVnd.toLocaleString('vi-VN')} ₫ tới ${params.recipientAccount} (Bảo toàn 100% số dư).`,
        timestamp: new Date().toISOString(),
      },
    ],
  };
  const committed = saveSessionDelta(params.sessionId, nextDelta);
  return { delta: committed, savedTotalVnd: nextSaved };
};

export const toggleShieldRuleInSession = (params: {
  sessionId: string;
  ruleId: string;
  clientDelta?: Partial<SessionDeltaSnapshot> | null;
}): { delta: SessionDeltaSnapshot; updatedRule: ShieldRule } => {
  const state = materializeWorkspaceState(params.sessionId, params.clientDelta);
  const target = state.delta.activeShieldRules.find((r) => r.id === params.ruleId);
  if (!target) {
    throw new Error(`Không tìm thấy quy tắc Lá chắn ${params.ruleId}`);
  }
  const toggledActive = !target.active;
  const updatedRule: ShieldRule = { ...target, active: toggledActive };
  const nextRules = state.delta.activeShieldRules.map((r) =>
    r.id === params.ruleId ? updatedRule : r
  );

  const nextFrozen = toggledActive
    ? Array.from(new Set([...state.delta.frozenAccountIds, target.targetAccountId]))
    : state.delta.frozenAccountIds.filter(
      (id) => id !== target.targetAccountId && id !== target.targetAccountNumber
    );

  const nextDelta: SessionDeltaSnapshot = {
    ...state.delta,
    frozenAccountIds: nextFrozen,
    activeShieldRules: nextRules,
    auditLogs: [
      ...state.delta.auditLogs,
      {
        id: `AUD-SHD-${Date.now().toString().slice(-5)}`,
        alertId: target.alertId,
        actor: 'OPS_ANALYST',
        action: toggledActive ? 'SHIELD_RULE_RESUMED' : 'SHIELD_RULE_PAUSED',
        detailsVi: `Quản lý L2 đã ${toggledActive ? 'BẬT LẠI' : 'TẠM DỪNG'} quy tắc Lá chắn ${target.id} (STK ${target.targetAccountNumber}).`,
        timestamp: new Date().toISOString(),
      },
    ],
  };

  const committed = saveSessionDelta(params.sessionId, nextDelta);
  return { delta: committed, updatedRule };
};

export const addCustomShieldRuleInSession = (params: {
  sessionId: string;
  targetAccountNumber: string;
  targetOwnerName?: string;
  reasonVi?: string;
  clientDelta?: Partial<SessionDeltaSnapshot> | null;
}): { delta: SessionDeltaSnapshot; createdShieldRule: ShieldRule } => {
  const state = materializeWorkspaceState(params.sessionId, params.clientDelta);
  const cleanAcc = params.targetAccountNumber.trim();
  const cleanName = params.targetOwnerName?.trim() || 'Tài khoản Nghi vấn Chặn Thủ công';
  const ruleId = `SHD-CUS-${Date.now().toString().slice(-4)}`;

  const createdShieldRule: ShieldRule = {
    id: ruleId,
    alertId: 'MANUAL-L2-RULE',
    targetAccountId: cleanAcc,
    targetAccountNumber: cleanAcc,
    targetOwnerName: cleanName,
    ruleType: 'BLOCK_RECIPIENT_MULE',
    userWarningVi:
      params.reasonVi?.trim() ||
      `CẢNH BÁO ĐỎ AEGIS SHIELD: Tài khoản ${cleanAcc} (${cleanName}) đã được Quản lý L2 đưa vào danh sách chặn khẩn cấp. Giao dịch đã được ngăn chặn!`,
    active: true,
    createdAt: new Date().toISOString(),
  };

  const nextRules = [
    createdShieldRule,
    ...state.delta.activeShieldRules.filter((r) => r.targetAccountNumber !== cleanAcc),
  ];

  const nextDelta: SessionDeltaSnapshot = {
    ...state.delta,
    frozenAccountIds: Array.from(new Set([...state.delta.frozenAccountIds, cleanAcc])),
    activeShieldRules: nextRules,
    auditLogs: [
      ...state.delta.auditLogs,
      {
        id: `AUD-ADD-${Date.now().toString().slice(-5)}`,
        alertId: 'MANUAL-L2-RULE',
        actor: 'OPS_ANALYST',
        action: 'CUSTOM_SHIELD_RULE_CREATED',
        detailsVi: `Quản lý L2 đã thêm nhanh STK ${cleanAcc} (${cleanName}) vào Lá chắn Cộng đồng ${ruleId}.`,
        timestamp: new Date().toISOString(),
      },
    ],
  };

  const committed = saveSessionDelta(params.sessionId, nextDelta);
  return { delta: committed, createdShieldRule };
};

export const ingestCustomSandboxAlert = async (params: {
  sessionId: string;
  customTitle?: string;
  rawTranscript: string;
  imageDataUrl?: string;
  recipientAccountNumber?: string;
  recipientOwnerName?: string;
  amountVnd?: number;
  caseInputSpec?: Partial<StandardCaseInputSpec>;
  clientDelta?: Partial<SessionDeltaSnapshot> | null;
}): Promise<{
  createdAlertId: string;
  extractedRecipientAccountNumber: string;
  report: InvestigationReport;
  forensics: ForensicSuiteOutput;
  delta: SessionDeltaSnapshot;
}> => {
  const state = materializeWorkspaceState(params.sessionId, params.clientDelta);
  const visionExtracted = await extractSandboxEntitiesWithGeminiVision(
    params.caseInputSpec?.rawTranscript ?? params.rawTranscript,
    params.caseInputSpec?.imageDataUrl ?? params.imageDataUrl
  );

  const bundle = synthesizeSandboxCase({
    customTitle: params.customTitle,
    rawTranscript: params.rawTranscript,
    imageDataUrl: params.imageDataUrl,
    caseInputSpec: params.caseInputSpec,
    extractedOverrides: {
      ...visionExtracted,
      ...(params.recipientAccountNumber ? { recipientAccountNumber: params.recipientAccountNumber } : {}),
      ...(params.recipientOwnerName ? { recipientOwnerName: params.recipientOwnerName } : {}),
      ...(params.amountVnd && params.amountVnd > 0 ? { amountVnd: params.amountVnd } : {}),
    },
    existingAccounts: state.accounts,
  });

  const newAccounts = [bundle.senderAccount, bundle.suspectAccount, ...bundle.additionalAccounts];
  const newAccIds = new Set(newAccounts.map((a) => a.id));

  const updatedDeltaPreInv: SessionDeltaSnapshot = {
    ...state.delta,
    customAlerts: [bundle.alert, ...state.delta.customAlerts],
    customAccounts: [
      ...state.delta.customAccounts.filter((a) => !newAccIds.has(a.id)),
      ...newAccounts,
    ],
    customTransactions: [...bundle.transactions, ...state.delta.customTransactions],
    customEvidences: [bundle.evidence, ...state.delta.customEvidences],
    customDevices: [
      ...(state.delta.customDevices ?? []).filter((d) => d.id !== bundle.device.id),
      bundle.device,
    ],
    customAuthLogs: [...bundle.authLogs, ...(state.delta.customAuthLogs ?? [])],
    customApiEvents: [...bundle.apiEvents, ...(state.delta.customApiEvents ?? [])],
    customInputSpecsByAlertId: {
      ...(state.delta.customInputSpecsByAlertId ?? {}),
      [bundle.alert.id]: bundle.inputSpec,
    },
  };

  const committedPreInv = saveSessionDelta(params.sessionId, updatedDeltaPreInv);

  const invResult = await executeAlertInvestigation({
    sessionId: params.sessionId,
    alertId: bundle.alert.id,
    clientDelta: committedPreInv,
  });

  return {
    createdAlertId: bundle.alert.id,
    extractedRecipientAccountNumber: bundle.extracted.recipientAccountNumber,
    report: invResult.report,
    forensics: invResult.forensics,
    delta: invResult.delta,
  };
};

export const ingestBatchSandboxCases = (params: {
  sessionId: string;
  specs: Partial<StandardCaseInputSpec>[];
  fileName?: string;
  clientDelta?: Partial<SessionDeltaSnapshot> | null;
}): {
  importedCount: number;
  createdAlertIds: string[];
  delta: SessionDeltaSnapshot;
} => {
  const state = materializeWorkspaceState(params.sessionId, params.clientDelta);
  const capped = params.specs.slice(0, 15);
  const bundles = capped.map((spec, idx) =>
    synthesizeSandboxCase({
      customTitle: spec.customTitle,
      rawTranscript: spec.rawTranscript ?? '',
      caseInputSpec: spec,
      existingAccounts: state.accounts,
      batchIndex: idx,
    })
  );

  const newAlerts = bundles.map((b) => b.alert);
  const newAccounts = bundles.flatMap((b) => [
    b.senderAccount,
    b.suspectAccount,
    ...b.additionalAccounts,
  ]);
  const newAccIds = new Set(newAccounts.map((a) => a.id));
  const newTxs = bundles.flatMap((b) => b.transactions);
  const newEvs = bundles.map((b) => b.evidence);
  const newDevices = bundles.map((b) => b.device);
  const newDeviceIds = new Set(newDevices.map((d) => d.id));
  const newAuthLogs = bundles.flatMap((b) => b.authLogs);
  const newApiEvents = bundles.flatMap((b) => b.apiEvents);
  const newReports = Object.fromEntries(
    bundles.map((b) => [b.alert.id, b.computedForensics.fallbackReport])
  );
  const newSpecs = Object.fromEntries(bundles.map((b) => [b.alert.id, b.inputSpec]));

  const nextDelta: SessionDeltaSnapshot = {
    ...state.delta,
    customAlerts: [...newAlerts, ...state.delta.customAlerts],
    customAccounts: [
      ...state.delta.customAccounts.filter((a) => !newAccIds.has(a.id)),
      ...newAccounts,
    ],
    customTransactions: [...newTxs, ...state.delta.customTransactions],
    customEvidences: [...newEvs, ...state.delta.customEvidences],
    customDevices: [
      ...(state.delta.customDevices ?? []).filter((d) => !newDeviceIds.has(d.id)),
      ...newDevices,
    ],
    customAuthLogs: [...newAuthLogs, ...(state.delta.customAuthLogs ?? [])],
    customApiEvents: [...newApiEvents, ...(state.delta.customApiEvents ?? [])],
    reportsByAlertId: {
      ...state.delta.reportsByAlertId,
      ...newReports,
    },
    customInputSpecsByAlertId: {
      ...(state.delta.customInputSpecsByAlertId ?? {}),
      ...newSpecs,
    },
    auditLogs: [
      ...state.delta.auditLogs,
      {
        id: `AUD-BAT-${Date.now().toString().slice(-5)}`,
        alertId: newAlerts[0]?.id ?? 'BATCH',
        actor: 'AI_AGENT',
        action: 'BATCH_CASES_IMPORTED',
        detailsVi: `Đã nhập hàng loạt ${bundles.length} hồ sơ kiểm thử từ ${params.fileName ?? 'CSV/JSON'} & chạy 5 công cụ định lượng cho toàn bộ lô.`,
        timestamp: new Date().toISOString(),
      },
    ],
  };

  const committed = saveSessionDelta(params.sessionId, nextDelta);
  return {
    importedCount: bundles.length,
    createdAlertIds: newAlerts.map((a) => a.id),
    delta: committed,
  };
};

export const executeBatchTriageInSession = (params: {
  sessionId: string;
  clientDelta?: Partial<SessionDeltaSnapshot> | null;
}): {
  clusteredMitigatedIds: string[];
  autoClearedSafeIds: string[];
  delta: SessionDeltaSnapshot;
} => {
  const { state, forensicsByAlertId } = getWorkspaceBootstrap(
    params.sessionId,
    params.clientDelta
  );
  const triage = computeCrossCaseCorrelations(state.alerts, forensicsByAlertId);
  const clusterAlertIds = Array.from(
    new Set(triage.linkedCampaignClusters.flatMap((c) => c.alertIds))
  );

  let workingDelta: SessionDeltaSnapshot = state.delta;
  const clusteredMitigatedIds: string[] = [];
  const autoClearedSafeIds: string[] = [];

  for (const id of clusterAlertIds) {
    const al = state.alerts.find((a) => a.id === id);
    if (al && al.status !== 'MITIGATED' && al.status !== 'DISMISSED_SAFE') {
      const res = executePlaybookApproval({
        sessionId: params.sessionId,
        alertId: id,
        mode: 'APPROVE_L2',
        clientDelta: workingDelta,
      });
      workingDelta = res.delta;
      clusteredMitigatedIds.push(id);
    }
  }

  for (const id of triage.autoClearCandidateIds) {
    const al = state.alerts.find((a) => a.id === id);
    if (al && al.status !== 'DISMISSED_SAFE') {
      const res = executePlaybookApproval({
        sessionId: params.sessionId,
        alertId: id,
        mode: 'APPROVE_L2',
        clientDelta: workingDelta,
      });
      workingDelta = res.delta;
      autoClearedSafeIds.push(id);
    }
  }

  const finalDelta: SessionDeltaSnapshot = {
    ...workingDelta,
    auditLogs: [
      ...workingDelta.auditLogs,
      {
        id: `AUD-BTR-${Date.now().toString().slice(-5)}`,
        alertId: clusteredMitigatedIds[0] ?? 'BATCH_TRIAGE',
        actor: 'OPS_ANALYST',
        action: 'BATCH_CAMPAIGN_TRIAGE_EXECUTED',
        detailsVi: `Xử lý gom nhóm 1-Chạm: Khóa cụm chiến dịch (${clusteredMitigatedIds.join(', ') || 'Đã khóa sẵn'}) & Auto-Clear an toàn (${autoClearedSafeIds.join(', ') || '0 ca'}).`,
        timestamp: new Date().toISOString(),
      },
    ],
  };

  const committed = saveSessionDelta(params.sessionId, finalDelta);
  return {
    clusteredMitigatedIds,
    autoClearedSafeIds,
    delta: committed,
  };
};

export const executeAnalystOverrideInSession = (params: {
  sessionId: string;
  alertId: string;
  targetVerdict: 'OVERRIDE_SAFE' | 'FORCE_BLOCK';
  reasonVi: string;
  clientDelta?: Partial<SessionDeltaSnapshot> | null;
}): {
  overrideRecord: AnalystOverrideRecord;
  delta: SessionDeltaSnapshot;
} => {
  const state = materializeWorkspaceState(params.sessionId, params.clientDelta);
  const alert = state.alerts.find((a) => a.id === params.alertId);
  if (!alert) {
    throw new Error(`Alert ${params.alertId} not found`);
  }

  const targetAcc = state.accounts.find((a) => a.id === alert.targetRecipientAccountId);
  const targetAccNum = targetAcc?.accountNumber ?? alert.targetRecipientAccountId;
  const overrideRecord: AnalystOverrideRecord = {
    alertId: alert.id,
    overriddenTo: params.targetVerdict,
    reasonVi:
      params.reasonVi.trim() ||
      (params.targetVerdict === 'OVERRIDE_SAFE'
        ? 'Chuyên viên xác minh trực tiếp với khách hàng — Gỡ khóa oan.'
        : 'Chuyên viên cưỡng chế phong tỏa theo nghiệp vụ khẩn cấp.'),
    timestamp: new Date().toISOString(),
  };

  const nextFeedbackCount = (state.delta.analystFeedbackCount ?? 0) + 1;
  const remainingPending = (state.delta.pendingL2ApprovalAlertIds ?? []).filter(
    (id) => id !== alert.id
  );
  const remainingMakers = { ...(state.delta.makerPrincipalByAlertId ?? {}) };
  delete remainingMakers[alert.id];

  if (params.targetVerdict === 'OVERRIDE_SAFE') {
    const nextShields = state.delta.activeShieldRules.filter((r) => r.alertId !== alert.id);
    const nextFrozen = state.delta.frozenAccountIds.filter(
      (id) => id !== alert.targetRecipientAccountId && id !== targetAccNum
    );
    const nextDelta: SessionDeltaSnapshot = {
      ...state.delta,
      pendingL2ApprovalAlertIds: remainingPending,
      makerPrincipalByAlertId: remainingMakers,
      alertStatuses: { ...state.delta.alertStatuses, [alert.id]: 'DISMISSED_SAFE' },
      frozenAccountIds: nextFrozen,
      activeShieldRules: nextShields,
      analystFeedbackCount: nextFeedbackCount,
      analystOverridesByAlertId: {
        ...(state.delta.analystOverridesByAlertId ?? {}),
        [alert.id]: overrideRecord,
      },
      auditLogs: [
        ...state.delta.auditLogs,
        {
          id: `AUD-OVR-${Date.now().toString().slice(-5)}`,
          alertId: alert.id,
          actor: 'OPS_ANALYST',
          action: 'HITL_ANALYST_OVERRIDE_SAFE',
          detailsVi: `Chuyên viên GHI ĐÈ kết luận AI cho ${alert.id} → Đánh dấu AN TOÀN (Không khóa oan). Lý do: ${overrideRecord.reasonVi}`,
          timestamp: overrideRecord.timestamp,
        },
      ],
    };
    const committedSafe = saveSessionDelta(params.sessionId, nextDelta);
    return { overrideRecord, delta: committedSafe };
  }

  // FORCE_BLOCK override
  const shieldRule: ShieldRule = {
    id: `SHD-${alert.id}`,
    alertId: alert.id,
    targetAccountId: alert.targetRecipientAccountId,
    targetAccountNumber: targetAccNum,
    targetOwnerName: targetAcc?.ownerName ?? alert.targetRecipientAccountId,
    ruleType: 'BLOCK_RECIPIENT_MULE',
    userWarningVi: `CẢNH BÁO ĐỎ AEGIS SHIELD (Cưỡng chế HITL): Tài khoản ${targetAccNum} vừa bị Chuyên viên phong tỏa thủ công (${overrideRecord.reasonVi}).`,
    active: true,
    createdAt: overrideRecord.timestamp,
  };

  const nextDelta: SessionDeltaSnapshot = {
    ...state.delta,
    pendingL2ApprovalAlertIds: remainingPending,
    makerPrincipalByAlertId: remainingMakers,
    alertStatuses: { ...state.delta.alertStatuses, [alert.id]: 'MITIGATED' },
    frozenAccountIds: Array.from(
      new Set([...state.delta.frozenAccountIds, alert.targetRecipientAccountId])
    ),
    activeShieldRules: [
      shieldRule,
      ...state.delta.activeShieldRules.filter((r) => r.id !== shieldRule.id),
    ],
    analystFeedbackCount: nextFeedbackCount,
    analystOverridesByAlertId: {
      ...(state.delta.analystOverridesByAlertId ?? {}),
      [alert.id]: overrideRecord,
    },
    auditLogs: [
      ...state.delta.auditLogs,
      {
        id: `AUD-OVR-${Date.now().toString().slice(-5)}`,
        alertId: alert.id,
        actor: 'OPS_ANALYST',
        action: 'HITL_ANALYST_OVERRIDE_BLOCK',
        detailsVi: `Chuyên viên GHI ĐÈ kết luận cho ${alert.id} → Cưỡng chế Phong tỏa & Bật Lá chắn (${overrideRecord.reasonVi}).`,
        timestamp: overrideRecord.timestamp,
      },
    ],
  };
  const committedBlock = saveSessionDelta(params.sessionId, nextDelta);
  return { overrideRecord, delta: committedBlock };
};

export const pushDossierToSimoInSession = (params: {
  sessionId: string;
  alertId: string;
  clientDelta?: Partial<SessionDeltaSnapshot> | null;
}): {
  receipt: SimoReceiptRecord;
  delta: SessionDeltaSnapshot;
} => {
  const { state, forensicsByAlertId } = getWorkspaceBootstrap(
    params.sessionId,
    params.clientDelta
  );
  const alert = state.alerts.find((a) => a.id === params.alertId);
  if (!alert) {
    throw new Error(`Alert ${params.alertId} not found`);
  }

  const forensics = forensicsByAlertId[alert.id]!;
  const dossier = buildComplianceIncidentDossier({
    alert,
    forensics,
    report: state.delta.reportsByAlertId[alert.id] ?? null,
    auditLogs: state.delta.auditLogs,
    accounts: state.accounts,
    transactions: state.transactions,
    authLogs: state.authLogs,
    devices: state.devices,
  });

  const existing = (state.delta.simoAckReceipts ?? []).find((r) => r.alertId === alert.id);
  const receipt: SimoReceiptRecord = existing ?? {
    receiptId: `SIMO-ACK-2026-${Date.now().toString().slice(-4)}`,
    alertId: alert.id,
    dossierId: dossier.dossierId,
    complianceStandard: dossier.simoPiiMaskedPayload.complianceStandard,
    victimIdentityHashSha256: dossier.simoPiiMaskedPayload.victimIdentityHashSha256,
    victimPseudonymHmacSha256: pseudonymizePiiWithHmacSha256(alert.primaryAccountId),
    dossierIntegritySha256: dossier.simoPiiMaskedPayload.dossierIntegrityHashSha256,
    pushedAt: new Date().toISOString(),
  };

  const nextReceipts = [
    receipt,
    ...(state.delta.simoAckReceipts ?? []).filter((r) => r.alertId !== alert.id),
  ];

  const nextDelta: SessionDeltaSnapshot = {
    ...state.delta,
    simoAckReceipts: nextReceipts,
    auditLogs: existing
      ? state.delta.auditLogs
      : [
        ...state.delta.auditLogs,
        {
          id: `AUD-SIMO-${Date.now().toString().slice(-5)}`,
          alertId: alert.id,
          actor: 'OPS_ANALYST',
          action: 'PUSHED_TO_SBV_SIMO_REGISTRY',
          detailsVi: `Đã tạo biên nhận đồng bộ SIMO cục bộ (SIMULATED — chưa kết nối mạng NHNN/A05 thực tế) với mã giả danh PII HMAC-SHA-256 (tham chiếu Luật 91/2025/QH15 & NĐ 356/2025/NĐ-CP) cho vụ ${alert.id} • Biên nhận mô phỏng: ${receipt.receiptId}.`,
          timestamp: receipt.pushedAt,
        },
      ],
  };

  const committedSimo = saveSessionDelta(params.sessionId, nextDelta);
  return { receipt, delta: committedSimo };
};

export const executeClawbackAndRefundInSession = (params: {
  sessionId: string;
  alertId: string;
  originalTxId?: string;
  requestedAmountVnd?: number;
  idempotencyKey?: string;
  clientDelta?: Partial<SessionDeltaSnapshot> | null;
}): {
  clawbackReceipt: ClawbackReceiptRecord;
  delta: SessionDeltaSnapshot;
  idempotentReplay: boolean;
  victimBalanceVnd?: number;
  muleBalanceVnd?: number;
} => {
  const { state, forensicsByAlertId } = getWorkspaceBootstrap(
    params.sessionId,
    params.clientDelta
  );
  const alert = state.alerts.find((a) => a.id === params.alertId);
  if (!alert) {
    throw new Error(`Alert ${params.alertId} not found`);
  }

  const forensics = forensicsByAlertId[alert.id]!;
  if (forensics.fallbackReport.classification === 'FALSE_POSITIVE_SAFE') {
    throw new LedgerValidationError(
      'Không thể thu hồi tiền với giao dịch hợp lệ đã xác nhận an toàn.'
    );
  }

  const cleanIdemKey = params.idempotencyKey?.trim();
  const cleanOriginalTxId = params.originalTxId?.trim();
  const existingReceipts = state.delta.clawbackReceipts ?? [];

  // 1. Explicit clawback idempotency key check (replay identical request; HTTP 409 on payload mismatch)
  if (cleanIdemKey) {
    const matchedByKey = existingReceipts.find((c) => c.idempotencyKey === cleanIdemKey);
    if (matchedByKey) {
      const sameAlert = matchedByKey.alertId === alert.id;
      const sameOriginalTx =
        !cleanOriginalTxId || matchedByKey.txIds.includes(cleanOriginalTxId);
      const sameRequested =
        params.requestedAmountVnd === undefined ||
        matchedByKey.requestedAmountVnd === Math.round(params.requestedAmountVnd);
      if (!sameAlert || !sameOriginalTx || !sameRequested) {
        throw new IdempotencyKeyConflictError(
          `Xung đột khóa Idempotency Clawback "${cleanIdemKey}" (HTTP 409): Tham số thu hồi khác với biên nhận gốc "${matchedByKey.clawbackId}".`,
          cleanIdemKey
        );
      }
      const replayVictim = state.accounts.find((a) => a.id === matchedByKey.victimAccountId);
      const replayMule = state.accounts.find((a) => a.id === matchedByKey.sourceMuleAccountId);
      return {
        clawbackReceipt: matchedByKey,
        delta: state.delta,
        idempotentReplay: true,
        victimBalanceVnd: replayVictim?.balanceVnd,
        muleBalanceVnd: replayMule?.balanceVnd,
      };
    }
  }

  // 2. Default 1-Click alert clawback idempotency (when no explicit partial amount or originalTxId override)
  if (!cleanIdemKey && !cleanOriginalTxId && params.requestedAmountVnd === undefined) {
    const existingForAlert = existingReceipts.find((c) => c.alertId === alert.id);
    if (existingForAlert) {
      const replayVictim = state.accounts.find((a) => a.id === existingForAlert.victimAccountId);
      const replayMule = state.accounts.find((a) => a.id === existingForAlert.sourceMuleAccountId);
      return {
        clawbackReceipt: existingForAlert,
        delta: state.delta,
        idempotentReplay: true,
        victimBalanceVnd: replayVictim?.balanceVnd,
        muleBalanceVnd: replayMule?.balanceVnd,
      };
    }
  }

  // 3. Resolve eligible original SETTLED / COMPLETED transaction(s) — NEVER BLOCKED or HELD!
  let targetVictimAccountId = alert.primaryAccountId;
  let targetSourceMuleAccountId = alert.targetRecipientAccountId;
  let candidateSourceTxs: Transaction[];

  if (cleanOriginalTxId) {
    const originalTx = state.transactions.find((t) => t.id === cleanOriginalTxId);
    if (!originalTx) {
      throw new LedgerValidationError(
        `Không tìm thấy giao dịch gốc "${cleanOriginalTxId}" trên Sổ cái để thực hiện thu hồi.`
      );
    }
    if (originalTx.txKind === 'CLAWBACK_REVERSAL') {
      throw new LedgerValidationError(
        `Giao dịch "${cleanOriginalTxId}" là bút toán đảo sổ Clawback, không thể thu hồi lại.`
      );
    }
    if (originalTx.status === 'BLOCKED' || originalTx.status === 'HELD') {
      throw new LedgerValidationError(
        `Từ chối Clawback: Giao dịch "${cleanOriginalTxId}" đang ở trạng thái ${originalTx.status} (chưa hạch toán trừ tiền trên Sổ cái), không đủ điều kiện hoàn tiền.`
      );
    }
    if (originalTx.status === 'REVERSED') {
      throw new LedgerValidationError(
        `Từ chối Clawback: Giao dịch "${cleanOriginalTxId}" đã được đảo sổ hoàn toàn (REVERSED), không thể hoàn tiền hai lần.`
      );
    }
    if (originalTx.status !== 'COMPLETED' && originalTx.status !== 'SETTLED') {
      throw new LedgerValidationError(
        `Từ chối Clawback: Giao dịch "${cleanOriginalTxId}" có trạng thái ${originalTx.status} không phải giao dịch đã hạch toán.`
      );
    }
    targetVictimAccountId = originalTx.senderAccountId;
    targetSourceMuleAccountId = originalTx.receiverAccountId;
    candidateSourceTxs = [originalTx];
  } else {
    candidateSourceTxs = state.transactions.filter(
      (t) =>
        t.alertId === alert.id &&
        t.senderAccountId === targetVictimAccountId &&
        t.receiverAccountId === targetSourceMuleAccountId
    );
  }

  const victimAcc = state.accounts.find((a) => a.id === targetVictimAccountId);
  const sourceMuleAcc = state.accounts.find((a) => a.id === targetSourceMuleAccountId);

  const candidateEligibleIds = new Set(
    candidateSourceTxs
      .filter(
        (t) =>
          t.txKind !== 'CLAWBACK_REVERSAL' &&
          (t.status === 'COMPLETED' || t.status === 'SETTLED')
      )
      .map((t) => t.id)
  );

  // Sum all prior recovered amounts already reversed against these exact original transaction(s)
  const alreadyReversedAmountVnd = existingReceipts
    .filter((rec) => rec.txIds.some((id) => candidateEligibleIds.has(id)))
    .reduce((sum, rec) => sum + Math.round(rec.recoveredAmountVnd), 0);

  const recoveryPlan = computeClawbackRecoveryPlan({
    alertTransactions: candidateSourceTxs,
    sourceMuleAccount: sourceMuleAcc,
    victimAccountId: targetVictimAccountId,
    sourceMuleAccountId: targetSourceMuleAccountId,
    originalTxId: cleanOriginalTxId,
    requestedAmountVnd: params.requestedAmountVnd,
    alreadyReversedAmountVnd,
  });

  if (recoveryPlan.recoverableTxIds.length === 0 || recoveryPlan.requestedAmountVnd <= 0) {
    throw new LedgerValidationError(
      `Không có giao dịch đã hạch toán (SETTLED/COMPLETED) đủ điều kiện thu hồi cho vụ ${alert.id} (giao dịch BLOCKED, HELD hoặc đã REVERSED hoàn toàn không được phát sinh hoàn tiền).`
    );
  }

  const nowIso = new Date().toISOString();
  const suffix = `${Date.now().toString(36).toUpperCase().slice(-4)}${Math.random()
    .toString(36)
    .slice(2, 5)
    .toUpperCase()}`;
  const reversalTxId =
    recoveryPlan.recoveredAmountVnd > 0 ? `TXN-REV-${alert.id}-${suffix}` : undefined;

  const reversalTx: Transaction | null = reversalTxId
    ? {
      id: reversalTxId,
      alertId: alert.id,
      senderAccountId: targetSourceMuleAccountId,
      receiverAccountId: targetVictimAccountId,
      amountVnd: recoveryPlan.recoveredAmountVnd,
      channel: 'P2P_WALLET',
      message: `Clawback reversal SLA cho ${alert.id} (GD gốc: ${recoveryPlan.recoverableTxIds.join(', ')})`,
      deviceId: sourceMuleAcc?.primaryDeviceId ?? 'AEGIS-CORE-LEDGER',
      hopIndex: 99,
      status: 'REVERSED',
      timestamp: nowIso,
      idempotencyKey: cleanIdemKey,
      relatedTxId: recoveryPlan.recoverableTxIds[0],
      txKind: 'CLAWBACK_REVERSAL',
    }
    : null;

  const reversalEntries = reversalTxId
    ? buildBalancedLedgerPair({
      txId: reversalTxId,
      debitAccountId: targetSourceMuleAccountId,
      creditAccountId: targetVictimAccountId,
      amountVnd: recoveryPlan.recoveredAmountVnd,
      status: 'REVERSED',
      idempotencyKey: cleanIdemKey,
      noteVi: `Hoàn trả Clawback ${alert.id} (${recoveryPlan.recoveryStatus}, GD gốc ${recoveryPlan.recoverableTxIds.join(', ')}): ${targetSourceMuleAccountId} → ${targetVictimAccountId}`,
      createdAt: nowIso,
    })
    : [];

  const clawbackReceipt: ClawbackReceiptRecord = {
    clawbackId: `CLAWBACK-2026-${suffix}`,
    alertId: alert.id,
    idempotencyKey: cleanIdemKey,
    requestedAmountVnd: recoveryPlan.requestedAmountVnd,
    recoveredAmountVnd: recoveryPlan.recoveredAmountVnd,
    missingAmountVnd: recoveryPlan.missingAmountVnd,
    recoveryStatus: recoveryPlan.recoveryStatus,
    reversalTxId,
    victimAccountId: targetVictimAccountId,
    victimOwnerName: victimAcc?.ownerName ?? targetVictimAccountId,
    sourceMuleAccountId: targetSourceMuleAccountId,
    txIds: recoveryPlan.recoverableTxIds,
    executedAt: nowIso,
  };

  const statusNoteVi =
    recoveryPlan.recoveryStatus === 'RECOVERED'
      ? 'Thu hồi 100% phần yêu cầu'
      : recoveryPlan.recoveryStatus === 'PARTIALLY_RECOVERED'
        ? `Thu hồi MỘT PHẦN (thiếu hụt ${recoveryPlan.missingAmountVnd.toLocaleString('vi-VN')} ₫ do TK nhận đã rút bớt)`
        : 'THU HỒI THẤT BẠI (TK nhận còn 0 ₫)';

  const nextDelta: SessionDeltaSnapshot = {
    ...state.delta,
    clawbackReceipts: [clawbackReceipt, ...existingReceipts],
    customTransactions: reversalTx
      ? [reversalTx, ...state.delta.customTransactions]
      : state.delta.customTransactions,
    ledgerEntries: [...(state.delta.ledgerEntries ?? []), ...reversalEntries],
    auditLogs: [
      ...state.delta.auditLogs,
      {
        id: makeAuditId('AUD-CLW'),
        alertId: alert.id,
        actor: 'OPS_ANALYST',
        action: 'CLAWBACK_AND_VICTIM_REFUND_EXECUTED',
        detailsVi: `${statusNoteVi}: đã thu hồi ${recoveryPlan.recoveredAmountVnd.toLocaleString('vi-VN')} ₫ / ${recoveryPlan.requestedAmountVnd.toLocaleString('vi-VN')} ₫ từ TK ${targetSourceMuleAccountId} về Ví "${clawbackReceipt.victimOwnerName}" (GD gốc: ${recoveryPlan.recoverableTxIds.join(', ')}, Đảo sổ: ${reversalTxId ?? 'NO_FUNDS'}) • Biên nhận: ${clawbackReceipt.clawbackId}.`,
        timestamp: clawbackReceipt.executedAt,
      },
    ],
  };

  // Validate double-entry ledger & non-negative balance invariants BEFORE persisting nextDelta
  // so any ledger failure leaves stored wallet balances and ledger entries completely untouched.
  const afterBalances = computeAccountBalancesFromLedger(state.accounts, reversalEntries);
  const committedClawback = saveSessionDelta(params.sessionId, nextDelta);
  return {
    clawbackReceipt,
    delta: committedClawback,
    idempotentReplay: false,
    victimBalanceVnd: afterBalances.get(targetVictimAccountId),
    muleBalanceVnd: afterBalances.get(targetSourceMuleAccountId),
  };
};

export const handleCopilotQuestion = async (params: {
  sessionId: string;
  alertId: string;
  question: string;
  clientDelta?: Partial<SessionDeltaSnapshot> | null;
}) => {
  const { state, forensicsByAlertId } = getWorkspaceBootstrap(
    params.sessionId,
    params.clientDelta
  );
  const alert = state.alerts.find((a) => a.id === params.alertId) ?? state.alerts[0];
  if (!alert) {
    throw new Error('Alert not found');
  }
  const forensics = forensicsByAlertId[alert.id]!;
  const report = state.delta.reportsByAlertId[alert.id];
  return askGeminiCopilotOnCase({
    question: params.question,
    alert,
    forensics,
    report,
  });
};

export class ForbiddenFeedbackActionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ForbiddenFeedbackActionError';
  }
}

export const createHitlFeedbackInSession = (params: {
  sessionId: string;
  alertId: string;
  feedbackDecision: HitlFeedbackDecision;
  targetScope: HitlFeedbackTargetScope;
  reasonCode: HitlFeedbackReasonCode;
  analystRationale: string;
  evidenceReferences?: string[];
  ttlHours?: number;
  actorPrincipalId: string;
  actorRole: OperatorRole;
  clientDelta?: Partial<SessionDeltaSnapshot> | null;
}): {
  feedbackRecord: HitlFeedbackMemoryRecord;
  delta: SessionDeltaSnapshot;
} => {
  if (params.actorRole === 'END_USER') {
    throw new ForbiddenFeedbackActionError(
      'Khách hàng Ví (END_USER) không có quyền tạo phản hồi Adaptive HITL.'
    );
  }

  const state = materializeWorkspaceState(params.sessionId, params.clientDelta);
  const alert = state.alerts.find((a) => a.id === params.alertId);
  if (!alert) {
    throw new Error(`Alert ${params.alertId} not found`);
  }

  const targetAcc = state.accounts.find((a) => a.id === alert.targetRecipientAccountId);
  const alertTx = state.transactions.find((t) => t.alertId === alert.id);
  const rawIdentifier = targetAcc?.accountNumber || alert.targetRecipientAccountId;
  const acceptedFingerprints = getAllAcceptedPiiPseudonyms(rawIdentifier);
  const targetFingerprint = acceptedFingerprints[0]!;
  const legacyTargetFingerprints = acceptedFingerprints.slice(1);
  const hmacKeyVersion = getCurrentPiiHmacKeyId();
  const contextSignature = buildHitlContextSignature({
    scenarioCode: alert.scenarioCode,
    recipientAccountType: targetAcc?.accountType,
    channel: alertTx?.channel,
  });

  const existingMemory = state.delta.hitlFeedbackMemory ?? [];
  if (
    hasDuplicateActiveFeedback({
      existing: existingMemory,
      targetFingerprint,
      legacyTargetFingerprints,
      contextSignature,
      feedbackDecision: params.feedbackDecision,
      targetScope: params.targetScope,
      sourceAlertId: alert.id,
    })
  ) {
    throw new Error(
      `Đã tồn tại bản ghi HITL ${params.feedbackDecision} đang hoạt động hoặc chờ duyệt cho cùng phạm vi (${params.targetScope}) trong phiên này.`
    );
  }

  const nowMs = Date.now();
  const safeTtlHours = Math.max(1, Math.min(168, Math.round(params.ttlHours ?? 24)));
  const nowIso = new Date(nowMs).toISOString();
  const expiresAt = new Date(nowMs + safeTtlHours * 3600_000).toISOString();
  const suffix = `${nowMs.toString(36).toUpperCase().slice(-5)}${Math.random()
    .toString(36)
    .slice(2, 5)
    .toUpperCase()}`;

  const isL2Direct = params.actorRole === 'L2_CHECKER';
  const feedbackRecord: HitlFeedbackMemoryRecord = {
    feedbackId: `HITL-${suffix}`,
    sourceAlertId: alert.id,
    targetScope: params.targetScope,
    targetFingerprint,
    hmacKeyVersion,
    targetDisplayLabel: `${targetAcc?.ownerName ?? alert.targetRecipientAccountId} (HMAC:${targetFingerprint.slice(0, 10)}...)`,
    recipientAccountId: alert.targetRecipientAccountId,
    contextSignature,
    feedbackDecision: params.feedbackDecision,
    reasonCode: params.reasonCode,
    analystRationale:
      params.analystRationale.trim() ||
      (params.feedbackDecision === 'OVERRIDE_SAFE'
        ? 'Chuyên viên xác minh đối tác/giao dịch hợp lệ trong phạm vi ngữ cảnh này.'
        : 'Chuyên viên xác nhận mẫu rủi ro đáng ngờ cần tăng điểm cảnh giác.'),
    evidenceReferences:
      params.evidenceReferences && params.evidenceReferences.length > 0
        ? params.evidenceReferences
        : state.evidences.filter((e) => e.alertId === alert.id).map((e) => e.id).slice(0, 4),
    actorPrincipalId: params.actorPrincipalId,
    actorRole: params.actorRole,
    approvedByPrincipalId: isL2Direct ? params.actorPrincipalId : undefined,
    approvedAt: isL2Direct ? nowIso : undefined,
    createdAt: nowIso,
    expiresAt,
    status: isL2Direct ? 'APPROVED_ACTIVE' : 'PENDING_APPROVAL',
    riskAdjustment: clampHitlRiskAdjustment(params.feedbackDecision),
    memoryVersion: 1,
  };

  const nextDelta: SessionDeltaSnapshot = {
    ...state.delta,
    analystFeedbackCount: (state.delta.analystFeedbackCount ?? 0) + 1,
    hitlFeedbackMemory: [feedbackRecord, ...existingMemory],
    auditLogs: [
      ...state.delta.auditLogs,
      {
        id: `AUD-HITL-${nowMs.toString().slice(-5)}`,
        alertId: alert.id,
        actor: 'OPS_ANALYST',
        action: isL2Direct ? 'HITL_MEMORY_CREATED_ACTIVE' : 'HITL_MEMORY_PROPOSED_L1',
        detailsVi: `${params.actorRole} (${params.actorPrincipalId}) đã tạo bộ nhớ HITL ${feedbackRecord.feedbackId} (${params.feedbackDecision}, Phạm vi ${params.targetScope}, Điều chỉnh ${feedbackRecord.riskAdjustment > 0 ? `+${feedbackRecord.riskAdjustment}` : feedbackRecord.riskAdjustment}đ, TTL ${safeTtlHours}h) — Trạng thái: ${feedbackRecord.status}.`,
        timestamp: nowIso,
      },
    ],
  };

  const committed = saveSessionDelta(params.sessionId, nextDelta);
  return { feedbackRecord, delta: committed };
};

export const moderateHitlFeedbackInSession = (params: {
  sessionId: string;
  feedbackId: string;
  moderationAction: 'APPROVE' | 'REJECT' | 'REVOKE';
  rejectReasonVi?: string;
  actorPrincipalId: string;
  actorRole: OperatorRole;
  clientDelta?: Partial<SessionDeltaSnapshot> | null;
}): {
  feedbackRecord: HitlFeedbackMemoryRecord;
  delta: SessionDeltaSnapshot;
} => {
  if (params.actorRole !== 'L2_CHECKER') {
    throw new ForbiddenFeedbackActionError(
      `Từ chối truy cập (HTTP 403): Vai trò ${params.actorRole} không có quyền ${params.moderationAction} bộ nhớ HITL.`
    );
  }

  const state = materializeWorkspaceState(params.sessionId, params.clientDelta);
  const existingMemory = state.delta.hitlFeedbackMemory ?? [];
  const idx = existingMemory.findIndex((f) => f.feedbackId === params.feedbackId);
  if (idx < 0) {
    throw new Error(`Không tìm thấy bản ghi HITL ${params.feedbackId}.`);
  }

  const current = existingMemory[idx]!;
  const nowIso = new Date().toISOString();

  if (params.moderationAction === 'APPROVE') {
    if (current.status !== 'PENDING_APPROVAL') {
      throw new Error(`Bản ghi ${current.feedbackId} đang ở trạng thái ${current.status}, không thể phê duyệt.`);
    }
    if (current.actorPrincipalId === params.actorPrincipalId) {
      throw new SelfApprovalForbiddenError(
        `Từ chối vi phạm Kiểm soát kép 4-Eyes (HTTP 403): Principal "${params.actorPrincipalId}" không thể tự phê duyệt phản hồi HITL do chính mình đề xuất.`
      );
    }
  } else if (params.moderationAction === 'REJECT') {
    if (current.status !== 'PENDING_APPROVAL') {
      throw new Error(`Chỉ bản ghi PENDING_APPROVAL mới có thể từ chối.`);
    }
  } else if (params.moderationAction === 'REVOKE') {
    if (current.status !== 'APPROVED_ACTIVE') {
      throw new Error(`Chỉ bản ghi APPROVED_ACTIVE mới có thể thu hồi.`);
    }
  }

  const updated: HitlFeedbackMemoryRecord = {
    ...current,
    status:
      params.moderationAction === 'APPROVE'
        ? 'APPROVED_ACTIVE'
        : params.moderationAction === 'REJECT'
          ? 'REJECTED'
          : 'REVOKED',
    approvedByPrincipalId:
      params.moderationAction === 'APPROVE' ? params.actorPrincipalId : current.approvedByPrincipalId,
    approvedAt: params.moderationAction === 'APPROVE' ? nowIso : current.approvedAt,
    rejectedReasonVi:
      params.moderationAction === 'REJECT'
        ? params.rejectReasonVi?.trim() || 'Quản lý L2 từ chối đề xuất phản hồi.'
        : current.rejectedReasonVi,
    revokedByPrincipalId:
      params.moderationAction === 'REVOKE' ? params.actorPrincipalId : current.revokedByPrincipalId,
    revokedAt: params.moderationAction === 'REVOKE' ? nowIso : current.revokedAt,
    memoryVersion: current.memoryVersion + 1,
  };

  const nextMemory = existingMemory.map((item) =>
    item.feedbackId === updated.feedbackId ? updated : item
  );

  const nextDelta: SessionDeltaSnapshot = {
    ...state.delta,
    hitlFeedbackMemory: nextMemory,
    auditLogs: [
      ...state.delta.auditLogs,
      {
        id: `AUD-MOD-${Date.now().toString().slice(-5)}`,
        alertId: updated.sourceAlertId,
        actor: 'OPS_ANALYST',
        action: `HITL_MEMORY_${params.moderationAction}D`,
        detailsVi: `Quản lý L2 (${params.actorPrincipalId}) đã thực hiện ${params.moderationAction} cho bộ nhớ HITL ${updated.feedbackId} (${updated.feedbackDecision}) → ${updated.status}.`,
        timestamp: nowIso,
      },
    ],
  };

  const committed = saveSessionDelta(params.sessionId, nextDelta);
  return { feedbackRecord: updated, delta: committed };
};

export const verifyMerchantReceiptInSession = (params: {
  sessionId: string;
  claimedTxId: string;
  claimedAmountVnd: number;
  merchantAccountIdOrNumber?: string;
  clientDelta?: Partial<SessionDeltaSnapshot> | null;
}): {
  verification: MerchantBillVerificationResult;
  delta: SessionDeltaSnapshot;
} => {
  const state = materializeWorkspaceState(params.sessionId, params.clientDelta);
  const verification = verifyMerchantBillReceipt({
    claimedTxId: params.claimedTxId,
    claimedAmountVnd: params.claimedAmountVnd,
    merchantAccountIdOrNumber: params.merchantAccountIdOrNumber,
    ledgerTransactions: state.transactions,
    accounts: state.accounts,
  });

  const nowIso = new Date().toISOString();
  const nextDelta: SessionDeltaSnapshot = {
    ...state.delta,
    auditLogs: [
      ...state.delta.auditLogs,
      {
        id: makeAuditId('AUD-MVF'),
        alertId: verification.claimedTxId || 'MERCHANT_VERIFY',
        actor: 'CONSUMER_SHIELD',
        action: `MERCHANT_RECEIPT_${verification.verdict}`,
        detailsVi: `Đối soát Bill Tiểu thương (${verification.claimedTxId} • Khai báo ${verification.claimedAmountVnd.toLocaleString('vi-VN')} ₫ → TK nhận ${verification.expectedMerchantAccountId ?? 'Mặc định'}): ${verification.verdict} (Sổ cái thực nhận: ${verification.actualLedgerAmountVnd.toLocaleString('vi-VN')} ₫, trạng thái [${verification.ledgerStatus}]).`,
        timestamp: nowIso,
      },
    ],
  };

  const committed = saveSessionDelta(params.sessionId, nextDelta);
  return { verification, delta: committed };
};

export const resetWorkspaceForSession = (sessionId: string) => {
  const freshDelta = resetSessionDelta(sessionId);
  return getWorkspaceBootstrap(sessionId, freshDelta);
};
