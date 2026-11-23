import type {
  Account,
  AnalystOverrideRecord,
  ApiSecurityEvent,
  AuditLogEntry,
  AuthSessionLog,
  ClawbackReceiptRecord,
  DeviceFingerprint,
  EvidenceArtifact,
  FraudAlert,
  HitlFeedbackMemoryRecord,
  IdempotencyTransferRecord,
  LedgerEntryRecord,
  SessionDeltaSnapshot,
  ShieldRule,
  SimoReceiptRecord,
  Transaction,
} from '@/domain/types';
import { applyLedgerBalancesToAccounts } from '@/domain/ledger-engine';
import {
  SEED_ACCOUNTS,
  SEED_ALERTS,
  SEED_API_EVENTS,
  SEED_AUTH_LOGS,
  SEED_DEVICES,
  SEED_EVIDENCES,
  SEED_TRANSACTIONS,
} from './seed-scenarios';
import {
  ConcurrentStateConflictError,
  PersistenceUnavailableError,
  SessionRevokedError,
  getWorkspacePersistenceAdapter,
} from './persistence-adapter';
import {
  SESSION_TTL_MS,
  computeDeltaIntegrityTag,
  verifyDeltaIntegrityTag,
} from './session-auth';

export {
  ConcurrentStateConflictError,
  PersistenceUnavailableError,
  SessionRevokedError,
};

/**
 * Per-Session Isolated Store with Signed Revision-Authoritative Delta Merging.
 *
 * DISTRIBUTED ARCHITECTURE LIMITATION:
 * `serverSessionMap` stores committed state in local instance memory (`Map`).
 * Because `saveSessionDelta` signs every snapshot with HMAC-SHA-256 (`deltaIntegrityTag`),
 * a client CANNOT forge a higher `stateRevision` (e.g. `999999`) or fake `frozenAccountIds`
 * to overwrite warm server state. However, on multi-container serverless deployments without a shared DB:
 * - Two concurrent requests from different clients hitting two different containers will NOT see each
 *   other's memory writes; full multi-instance ACID synchronization requires a shared DB (out of Wave 1.1 scope).
 */

export class InvalidStateIntegrityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidStateIntegrityError';
  }
}

const serverSessionMap = new Map<string, SessionDeltaSnapshot>();

const normalizeRevision = (rev: unknown): number => {
  if (typeof rev === 'number' && Number.isInteger(rev) && rev >= 0 && rev <= 1_000_000) {
    return rev;
  }
  return 0;
};

export const createEmptyDelta = (sessionId: string): SessionDeltaSnapshot => ({
  sessionId,
  stateRevision: 0,
  makerPrincipalByAlertId: {},
  alertStatuses: {},
  pendingL2ApprovalAlertIds: [],
  frozenAccountIds: [],
  activeShieldRules: [],
  selfRescuedAmountVnd: 0,
  analystFeedbackCount: 0,
  analystOverridesByAlertId: {},
  hitlFeedbackMemory: [],
  simoAckReceipts: [],
  clawbackReceipts: [],
  ledgerEntries: [],
  processedIdempotencyKeys: {},
  idempotencyRecordsByKey: {},
  reportsByAlertId: {},
  customAlerts: [],
  customAccounts: [],
  customTransactions: [],
  customEvidences: [],
  customDevices: [],
  customAuthLogs: [],
  customApiEvents: [],
  customInputSpecsByAlertId: {},
  auditLogs: [
    {
      id: 'AUD-INIT-001',
      alertId: 'ALT-APP-003',
      actor: 'AI_AGENT',
      action: 'WORKSPACE_INITIALIZED',
      detailsVi: 'Khởi tạo phiên làm việc cô lập AegisOps & nạp 4 kịch bản thực chiến.',
      timestamp: '2026-11-20T14:22:00+07:00',
    },
  ],
  updatedAt: new Date().toISOString(),
});

export const mergeSessionDeltas = (
  sessionId: string,
  serverDelta?: SessionDeltaSnapshot,
  clientDelta?: Partial<SessionDeltaSnapshot> | null
): SessionDeltaSnapshot => {
  const base = serverDelta ?? createEmptyDelta(sessionId);
  if (!clientDelta) return base;

  const baseRev = normalizeRevision(base.stateRevision);
  const clientRev = normalizeRevision(clientDelta.stateRevision);

  // Verify HMAC integrity tag if client claims a server-committed revision (> 0)
  if (clientRev > 0) {
    const validMac = verifyDeltaIntegrityTag(clientDelta, sessionId);
    if (!validMac) {
      throw new InvalidStateIntegrityError(
        'Chữ ký toàn vẹn trạng thái (deltaIntegrityTag) không hợp lệ hoặc revision bị giả mạo.'
      );
    }
  }

  const clientIsAuthoritative = !serverDelta ? clientRev > 0 : clientRev > baseRev;

  const authoritativeAlertStatuses = clientIsAuthoritative
    ? { ...(clientDelta.alertStatuses ?? base.alertStatuses) }
    : { ...base.alertStatuses };

  const authoritativePendingL2 = Array.from(
    new Set(
      clientIsAuthoritative
        ? (clientDelta.pendingL2ApprovalAlertIds ?? base.pendingL2ApprovalAlertIds ?? [])
        : (base.pendingL2ApprovalAlertIds ?? [])
    )
  );

  const authoritativeFrozenAccounts = Array.from(
    new Set(
      clientIsAuthoritative
        ? (clientDelta.frozenAccountIds ?? base.frozenAccountIds)
        : base.frozenAccountIds
    )
  );

  const authoritativeMakerPrincipals = clientIsAuthoritative
    ? { ...(clientDelta.makerPrincipalByAlertId ?? base.makerPrincipalByAlertId ?? {}) }
    : { ...(base.makerPrincipalByAlertId ?? {}) };

  const authoritativeShieldRules: ShieldRule[] = (() => {
    const source = clientIsAuthoritative
      ? (clientDelta.activeShieldRules ?? base.activeShieldRules)
      : base.activeShieldRules;
    const dedup = new Map<string, ShieldRule>();
    source.forEach((r) => dedup.set(r.id, r));
    return Array.from(dedup.values());
  })();

  const customAlertsMap = new Map<string, FraudAlert>();
  base.customAlerts.forEach((a) => customAlertsMap.set(a.id, a));
  (clientDelta.customAlerts ?? []).forEach((a) => customAlertsMap.set(a.id, a));

  const customAccMap = new Map<string, Account>();
  base.customAccounts.forEach((a) => customAccMap.set(a.id, a));
  (clientDelta.customAccounts ?? []).forEach((a) => customAccMap.set(a.id, a));

  const customTxMap = new Map<string, Transaction>();
  base.customTransactions.forEach((t) => customTxMap.set(t.id, t));
  (clientDelta.customTransactions ?? []).forEach((t) => customTxMap.set(t.id, t));

  const customEvdMap = new Map<string, EvidenceArtifact>();
  base.customEvidences.forEach((e) => customEvdMap.set(e.id, e));
  (clientDelta.customEvidences ?? []).forEach((e) => customEvdMap.set(e.id, e));

  const customDevMap = new Map<string, DeviceFingerprint>();
  (base.customDevices ?? []).forEach((d) => customDevMap.set(d.id, d));
  (clientDelta.customDevices ?? []).forEach((d) => customDevMap.set(d.id, d));

  const customAuthMap = new Map<string, AuthSessionLog>();
  (base.customAuthLogs ?? []).forEach((l) => customAuthMap.set(l.id, l));
  (clientDelta.customAuthLogs ?? []).forEach((l) => customAuthMap.set(l.id, l));

  const customApiMap = new Map<string, ApiSecurityEvent>();
  (base.customApiEvents ?? []).forEach((e) => customApiMap.set(e.id, e));
  (clientDelta.customApiEvents ?? []).forEach((e) => customApiMap.set(e.id, e));

  const auditMap = new Map<string, AuditLogEntry>();
  base.auditLogs.forEach((l) => auditMap.set(l.id, l));
  (clientDelta.auditLogs ?? []).forEach((l) => auditMap.set(l.id, l));

  const simoMap = new Map<string, SimoReceiptRecord>();
  (base.simoAckReceipts ?? []).forEach((s) => simoMap.set(s.alertId, s));
  (clientDelta.simoAckReceipts ?? []).forEach((s) => simoMap.set(s.alertId, s));

  const authoritativeClawbacks = clientIsAuthoritative
    ? (clientDelta.clawbackReceipts ?? base.clawbackReceipts ?? [])
    : (base.clawbackReceipts ?? []);
  const clawbackMap = new Map<string, ClawbackReceiptRecord>();
  (base.clawbackReceipts ?? []).forEach((c) => clawbackMap.set(c.clawbackId, c));
  authoritativeClawbacks.forEach((c) => clawbackMap.set(c.clawbackId, c));

  const ledgerMap = new Map<string, LedgerEntryRecord>();
  const authoritativeLedgerSource = clientIsAuthoritative
    ? (clientDelta.ledgerEntries ?? base.ledgerEntries ?? [])
    : (base.ledgerEntries ?? []);
  (base.ledgerEntries ?? []).forEach((e) => ledgerMap.set(e.id, e));
  authoritativeLedgerSource.forEach((e) => ledgerMap.set(e.id, e));

  const authoritativeIdempotencyMap: Record<string, string> = clientIsAuthoritative
    ? { ...(base.processedIdempotencyKeys ?? {}), ...(clientDelta.processedIdempotencyKeys ?? {}) }
    : { ...(base.processedIdempotencyKeys ?? {}) };

  const authoritativeIdempotencyRecords: Record<string, IdempotencyTransferRecord> =
    clientIsAuthoritative
      ? { ...(base.idempotencyRecordsByKey ?? {}), ...(clientDelta.idempotencyRecordsByKey ?? {}) }
      : { ...(base.idempotencyRecordsByKey ?? {}) };

  const hitlMap = new Map<string, HitlFeedbackMemoryRecord>();
  const upsertHitl = (rec: HitlFeedbackMemoryRecord) => {
    const prev = hitlMap.get(rec.feedbackId);
    if (!prev || rec.memoryVersion >= prev.memoryVersion) {
      hitlMap.set(rec.feedbackId, rec);
    }
  };
  const authoritativeHitlSource = clientIsAuthoritative
    ? (clientDelta.hitlFeedbackMemory ?? base.hitlFeedbackMemory ?? [])
    : (base.hitlFeedbackMemory ?? []);
  (base.hitlFeedbackMemory ?? []).forEach(upsertHitl);
  authoritativeHitlSource.forEach(upsertHitl);

  const overrideMap: Record<string, AnalystOverrideRecord> = clientIsAuthoritative
    ? {
        ...(base.analystOverridesByAlertId ?? {}),
        ...(clientDelta.analystOverridesByAlertId ?? {}),
      }
    : {
        ...(clientDelta.analystOverridesByAlertId ?? {}),
        ...(base.analystOverridesByAlertId ?? {}),
      };

  const merged: SessionDeltaSnapshot = {
    sessionId,
    stateRevision: Math.max(baseRev, clientRev),
    makerPrincipalByAlertId: authoritativeMakerPrincipals,
    alertStatuses: authoritativeAlertStatuses,
    pendingL2ApprovalAlertIds: authoritativePendingL2,
    frozenAccountIds: authoritativeFrozenAccounts,
    activeShieldRules: authoritativeShieldRules,
    selfRescuedAmountVnd: Math.max(
      base.selfRescuedAmountVnd ?? 0,
      clientDelta.selfRescuedAmountVnd ?? 0
    ),
    analystFeedbackCount: Math.max(
      base.analystFeedbackCount ?? 0,
      clientDelta.analystFeedbackCount ?? 0
    ),
    analystOverridesByAlertId: overrideMap,
    hitlFeedbackMemory: Array.from(hitlMap.values()),
    simoAckReceipts: Array.from(simoMap.values()),
    clawbackReceipts: Array.from(clawbackMap.values()),
    ledgerEntries: Array.from(ledgerMap.values()),
    processedIdempotencyKeys: authoritativeIdempotencyMap,
    idempotencyRecordsByKey: authoritativeIdempotencyRecords,
    reportsByAlertId: clientIsAuthoritative
      ? { ...base.reportsByAlertId, ...(clientDelta.reportsByAlertId ?? {}) }
      : { ...(clientDelta.reportsByAlertId ?? {}), ...base.reportsByAlertId },
    customAlerts: Array.from(customAlertsMap.values()),
    customAccounts: Array.from(customAccMap.values()),
    customTransactions: Array.from(customTxMap.values()),
    customEvidences: Array.from(customEvdMap.values()),
    customDevices: Array.from(customDevMap.values()),
    customAuthLogs: Array.from(customAuthMap.values()),
    customApiEvents: Array.from(customApiMap.values()),
    customInputSpecsByAlertId: {
      ...(base.customInputSpecsByAlertId ?? {}),
      ...(clientDelta.customInputSpecsByAlertId ?? {}),
    },
    auditLogs: Array.from(auditMap.values()).slice(-200),
    updatedAt: base.updatedAt,
  };

  merged.deltaIntegrityTag = computeDeltaIntegrityTag(merged, sessionId);
  serverSessionMap.set(sessionId, merged);
  return merged;
};

export const getOrInitSessionDelta = (
  sessionId: string,
  clientDelta?: Partial<SessionDeltaSnapshot> | null
): SessionDeltaSnapshot => {
  const existing = serverSessionMap.get(sessionId);
  return mergeSessionDeltas(sessionId, existing, clientDelta);
};

export const saveSessionDelta = (
  sessionId: string,
  delta: SessionDeltaSnapshot
): SessionDeltaSnapshot => {
  const current = serverSessionMap.get(sessionId);
  const nextRevision =
    Math.max(normalizeRevision(current?.stateRevision), normalizeRevision(delta.stateRevision)) + 1;
  const committed: SessionDeltaSnapshot = {
    ...delta,
    stateRevision: nextRevision,
    updatedAt: new Date().toISOString(),
  };
  committed.deltaIntegrityTag = computeDeltaIntegrityTag(committed, sessionId);
  serverSessionMap.set(sessionId, committed);
  return committed;
};

export const resetSessionDelta = (sessionId: string): SessionDeltaSnapshot => {
  const fresh = createEmptyDelta(sessionId);
  fresh.deltaIntegrityTag = computeDeltaIntegrityTag(fresh, sessionId);
  serverSessionMap.set(sessionId, fresh);
  return fresh;
};

/** Test-only helper simulating serverless cold-start eviction of in-memory instance cache. */
export const evictServerSessionForColdStartTest = (sessionId: string): void => {
  serverSessionMap.delete(sessionId);
};

export const hasExistingWarmSession = (sessionId: string): boolean => {
  return serverSessionMap.has(sessionId);
};

/**
 * Loads the authoritative session delta from shared persistence (PostgreSQL / Memory adapter)
 * into local instance cache BEFORE any read or mutation so cold-started serverless containers
 * cannot let stale signed client snapshots resurrect revoked HITL records or rolled-back states.
 */
export const hydrateSessionFromPersistence = async (
  sessionId: string
): Promise<{ preMutationRevision: number; hydratedFromAdapter: boolean }> => {
  const adapter = getWorkspacePersistenceAdapter();
  const envelope = await adapter.loadSession(sessionId);

  if (envelope && (envelope.status === 'REVOKED' || envelope.status === 'EXPIRED')) {
    serverSessionMap.delete(sessionId);
    throw new SessionRevokedError();
  }
  if (await adapter.isSessionRevoked(sessionId)) {
    serverSessionMap.delete(sessionId);
    throw new SessionRevokedError();
  }

  const local = serverSessionMap.get(sessionId);
  if (envelope && envelope.status === 'ACTIVE') {
    const envRev = normalizeRevision(envelope.delta.stateRevision);
    const localRev = normalizeRevision(local?.stateRevision);
    if (!local || envRev >= localRev) {
      serverSessionMap.set(sessionId, envelope.delta);
    }
    return {
      preMutationRevision: Math.max(envRev, localRev),
      hydratedFromAdapter: true,
    };
  }

  return {
    preMutationRevision: normalizeRevision(local?.stateRevision),
    hydratedFromAdapter: false,
  };
};

/**
 * Atomically commits the updated session snapshot to shared persistence using Compare-And-Swap
 * (`expectedRevision`) so concurrent requests across serverless instances fail safely (HTTP 409)
 * instead of overwriting newer HITL revocations or ledger entries.
 */
export const commitSessionToPersistence = async (params: {
  sessionId: string;
  principalId: string;
  expectedRevision: number;
  committedDelta?: SessionDeltaSnapshot;
}): Promise<SessionDeltaSnapshot> => {
  const adapter = getWorkspacePersistenceAdapter();
  const candidate = params.committedDelta ?? serverSessionMap.get(params.sessionId);
  if (!candidate) {
    return createEmptyDelta(params.sessionId);
  }
  const expiresAtIso = new Date(Date.now() + SESSION_TTL_MS).toISOString();
  const persisted = await adapter.commitSession({
    sessionId: params.sessionId,
    principalId: params.principalId,
    expectedRevision: params.expectedRevision,
    nextDelta: candidate,
    expiresAtIso,
  });
  serverSessionMap.set(params.sessionId, persisted);
  return persisted;
};

export const resetAuthoritativeSession = async (
  sessionId: string,
  principalId: string
): Promise<SessionDeltaSnapshot> => {
  const { preMutationRevision } = await hydrateSessionFromPersistence(sessionId);
  const fresh = createEmptyDelta(sessionId);
  const nextRevision = preMutationRevision + 1;
  const resetSnapshot: SessionDeltaSnapshot = {
    ...fresh,
    stateRevision: nextRevision,
    updatedAt: new Date().toISOString(),
  };
  resetSnapshot.deltaIntegrityTag = computeDeltaIntegrityTag(resetSnapshot, sessionId);
  serverSessionMap.set(sessionId, resetSnapshot);
  return commitSessionToPersistence({
    sessionId,
    principalId,
    expectedRevision: preMutationRevision,
    committedDelta: resetSnapshot,
  });
};

export interface MaterializedWorkspaceState {
  sessionId: string;
  alerts: FraudAlert[];
  accounts: Account[];
  devices: DeviceFingerprint[];
  authLogs: AuthSessionLog[];
  transactions: Transaction[];
  apiEvents: ApiSecurityEvent[];
  evidences: EvidenceArtifact[];
  delta: SessionDeltaSnapshot;
}

export const materializeWorkspaceState = (
  sessionId: string,
  clientDelta?: Partial<SessionDeltaSnapshot> | null
): MaterializedWorkspaceState => {
  const delta = getOrInitSessionDelta(sessionId, clientDelta);
  const frozenSet = new Set(delta.frozenAccountIds);

  const rawAccounts: Account[] = [...SEED_ACCOUNTS, ...delta.customAccounts].map((acc) => ({
    ...acc,
    status: frozenSet.has(acc.id) ? 'FROZEN' : acc.status,
  }));
  const allAccounts = applyLedgerBalancesToAccounts(rawAccounts, delta.ledgerEntries ?? []);

  const allAlerts: FraudAlert[] = [...delta.customAlerts, ...SEED_ALERTS].map((al) => ({
    ...al,
    status: delta.alertStatuses[al.id] ?? al.status,
  }));

  const devMap = new Map<string, DeviceFingerprint>();
  SEED_DEVICES.forEach((d) => devMap.set(d.id, d));
  (delta.customDevices ?? []).forEach((d) => {
    const existing = devMap.get(d.id);
    if (existing) {
      devMap.set(d.id, {
        ...existing,
        linkedAccountIds: Array.from(new Set([...existing.linkedAccountIds, ...d.linkedAccountIds])),
      });
    } else {
      devMap.set(d.id, d);
    }
  });

  // Compute cumulative reversed amount per original settled transaction so fully-reversed
  // transactions reflect status === 'REVERSED' in materialized ledger state.
  const reversedAmountByTxId = new Map<string, number>();
  for (const receipt of delta.clawbackReceipts ?? []) {
    if (receipt.recoveredAmountVnd <= 0 || receipt.txIds.length === 0) continue;
    if (receipt.txIds.length === 1) {
      const origId = receipt.txIds[0]!;
      reversedAmountByTxId.set(
        origId,
        (reversedAmountByTxId.get(origId) ?? 0) + Math.round(receipt.recoveredAmountVnd)
      );
    } else if (receipt.recoveryStatus === 'RECOVERED' && (receipt.missingAmountVnd ?? 0) === 0) {
      for (const origId of receipt.txIds) {
        reversedAmountByTxId.set(origId, Number.MAX_SAFE_INTEGER);
      }
    }
  }

  const materializedTransactions: Transaction[] = [
    ...SEED_TRANSACTIONS,
    ...delta.customTransactions,
  ].map((tx) => {
    if (
      tx.txKind !== 'CLAWBACK_REVERSAL' &&
      (tx.status === 'COMPLETED' || tx.status === 'SETTLED')
    ) {
      const reversedTotal = reversedAmountByTxId.get(tx.id) ?? 0;
      if (reversedTotal >= Math.round(tx.amountVnd)) {
        return { ...tx, status: 'REVERSED' as const };
      }
    }
    return tx;
  });

  return {
    sessionId,
    alerts: allAlerts,
    accounts: allAccounts,
    devices: Array.from(devMap.values()),
    authLogs: [...SEED_AUTH_LOGS, ...(delta.customAuthLogs ?? [])],
    transactions: materializedTransactions,
    apiEvents: [...SEED_API_EVENTS, ...(delta.customApiEvents ?? [])],
    evidences: [...SEED_EVIDENCES, ...delta.customEvidences],
    delta,
  };
};
