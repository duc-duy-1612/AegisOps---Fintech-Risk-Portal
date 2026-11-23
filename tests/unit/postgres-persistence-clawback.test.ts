import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { executeClawbackAndRefundInSession } from '@/application/workspace-orchestrator';
import type { ClawbackReceiptRecord, SessionDeltaSnapshot, Transaction } from '@/domain/types';
import {
  ConcurrentStateConflictError,
  type PgQueryableClient,
  type PgQueryablePool,
  PostgresPersistenceAdapter,
  setPersistenceAdapterForTest,
} from '@/infrastructure/persistence-adapter';
import { createEmptyDelta } from '@/infrastructure/workspace-store';

interface SimulatedSessionRow {
  session_id: string;
  principal_id: string;
  state_revision: number;
  status: string;
  delta_integrity_tag: string;
  delta_json: SessionDeltaSnapshot;
  expires_at: string;
  revoked_at: string | null;
}

interface SimulatedTxRow {
  tx_id: string;
  session_id: string;
  alert_id: string;
  sender_account_id: string;
  receiver_account_id: string;
  amount_vnd: number;
  status: string;
  idempotency_key: string | null;
  tx_kind: string | null;
  created_at: string;
}

interface SimulatedClawbackRow {
  clawback_id: string;
  session_id: string;
  alert_id: string;
  idempotency_key: string | null;
  requested_amount_vnd: number;
  recovered_amount_vnd: number;
  missing_amount_vnd: number;
  recovery_status: string;
  reversal_tx_id: string | null;
  victim_account_id: string | null;
  victim_owner_name: string | null;
  source_mule_account_id: string | null;
  original_tx_ids: string[];
  executed_at: string;
}

interface SimulatedLedgerEntryRow {
  entry_id: string;
  session_id: string;
  tx_id: string;
  account_id: string;
  entry_type: string;
  amount_vnd: number;
  status: string;
  created_at: string;
}

/**
 * High-fidelity transactional PostgreSQL simulator modeling migration 001 + 002 semantics:
 * - Explicit BEGIN / COMMIT / ROLLBACK with staged snapshots (rolled back cleanly on any error).
 * - Session CAS (`state_revision` + `status = 'ACTIVE'`).
 * - `aegis_clawback_receipts` keyed by `clawback_id` PK with partial unique indexes
 *   `uq_aegis_clawback_session_idem (session_id, idempotency_key)` and
 *   `uq_aegis_clawback_session_reversal_tx (session_id, reversal_tx_id)`, PLUS guarded
 *   `ON CONFLICT (clawback_id) DO UPDATE ... WHERE ... RETURNING clawback_id`.
 * - `aegis_ledger_transactions` keyed by `tx_id` PK with partial unique index
 *   `uq_aegis_ledger_session_idem (session_id, idempotency_key)` and guarded monotonic
 *   `ON CONFLICT (tx_id) DO UPDATE SET status = EXCLUDED.status WHERE ...` transition semantics.
 *
 * NOTE: This is a white-box unit/adapter simulator (not a live PostgreSQL server).
 */
class TransactionalMigration002PostgresSimulator implements PgQueryablePool {
  public sessions = new Map<string, SimulatedSessionRow>();
  public transactions = new Map<string, SimulatedTxRow>();
  public ledgerEntries = new Map<string, SimulatedLedgerEntryRow>();
  public clawbacks = new Map<string, SimulatedClawbackRow>();
  public auditLogIds = new Set<string>();

  public readonly executedSql: string[] = [];
  public failNextQueryContaining: string | null = null;
  public simulateNextSessionCasZeroRows = false;

  private makePgError(message: string, code: string): Error & { code: string } {
    const err = new Error(message) as Error & { code: string };
    err.code = code;
    return err;
  }

  private cloneState() {
    return {
      sessions: new Map(Array.from(this.sessions.entries()).map(([k, v]) => [k, structuredClone(v)])),
      transactions: new Map(
        Array.from(this.transactions.entries()).map(([k, v]) => [k, structuredClone(v)])
      ),
      ledgerEntries: new Map(
        Array.from(this.ledgerEntries.entries()).map(([k, v]) => [k, structuredClone(v)])
      ),
      clawbacks: new Map(
        Array.from(this.clawbacks.entries()).map(([k, v]) => [k, structuredClone(v)])
      ),
      auditLogIds: new Set(this.auditLogIds),
    };
  }

  async query(text: string, values: unknown[] = []) {
    return this.executeOnState(
      {
        sessions: this.sessions,
        transactions: this.transactions,
        ledgerEntries: this.ledgerEntries,
        clawbacks: this.clawbacks,
        auditLogIds: this.auditLogIds,
      },
      text,
      values
    );
  }

  private executeOnState(
    state: {
      sessions: Map<string, SimulatedSessionRow>;
      transactions: Map<string, SimulatedTxRow>;
      ledgerEntries: Map<string, SimulatedLedgerEntryRow>;
      clawbacks: Map<string, SimulatedClawbackRow>;
      auditLogIds: Set<string>;
    },
    text: string,
    values: unknown[] = []
  ) {
    const normalized = text.replace(/\s+/g, ' ').trim();
    this.executedSql.push(normalized);

    if (this.failNextQueryContaining && normalized.includes(this.failNextQueryContaining)) {
      this.failNextQueryContaining = null;
      throw new Error('Simulated PostgreSQL transient write failure');
    }

    if (normalized === 'BEGIN' || normalized === 'COMMIT' || normalized === 'ROLLBACK') {
      return { rows: [], rowCount: 0 };
    }

    if (normalized.includes('SELECT 1 AS ok')) {
      return { rows: [{ ok: 1 }], rowCount: 1 };
    }

    if (normalized.includes('FROM aegis_workspace_sessions') && normalized.includes('FOR UPDATE')) {
      const sid = String(values[0]);
      const row = state.sessions.get(sid);
      return { rows: row ? [row] : [], rowCount: row ? 1 : 0 };
    }

    if (normalized.includes('FROM aegis_workspace_sessions') && normalized.includes('delta_json')) {
      const sid = String(values[0]);
      const row = state.sessions.get(sid);
      return { rows: row ? [row] : [], rowCount: row ? 1 : 0 };
    }

    if (normalized.includes('INSERT INTO aegis_workspace_sessions')) {
      if (this.simulateNextSessionCasZeroRows) {
        this.simulateNextSessionCasZeroRows = false;
        return { rows: [], rowCount: 0 };
      }
      const sid = String(values[0]);
      const expectedRev = Number(values[6] ?? 0);
      const existing = state.sessions.get(sid);
      if (existing && (existing.state_revision !== expectedRev || existing.status !== 'ACTIVE')) {
        return { rows: [], rowCount: 0 };
      }
      const nextRev = Number(values[2]);
      state.sessions.set(sid, {
        session_id: sid,
        principal_id: String(values[1]),
        state_revision: nextRev,
        status: existing?.status ?? 'ACTIVE',
        delta_integrity_tag: String(values[3]),
        delta_json: JSON.parse(String(values[4])) as SessionDeltaSnapshot,
        expires_at: String(values[5]),
        revoked_at: existing?.revoked_at ?? null,
      });
      return { rows: [{ state_revision: nextRev }], rowCount: 1 };
    }

    if (normalized.includes('INSERT INTO aegis_ledger_transactions')) {
      const incoming: SimulatedTxRow = {
        tx_id: String(values[0]),
        session_id: String(values[1]),
        alert_id: String(values[2]),
        sender_account_id: String(values[3]),
        receiver_account_id: String(values[4]),
        amount_vnd: Number(values[5]),
        status: String(values[6]),
        idempotency_key: values[7] == null ? null : String(values[7]),
        tx_kind: values[8] == null ? null : String(values[8]),
        created_at: String(values[9]),
      };

      const existing = state.transactions.get(incoming.tx_id);
      if (!existing) {
        if (incoming.idempotency_key !== null) {
          for (const other of state.transactions.values()) {
            if (
              other.session_id === incoming.session_id &&
              other.idempotency_key === incoming.idempotency_key &&
              other.tx_id !== incoming.tx_id
            ) {
              throw this.makePgError(
                'duplicate key value violates unique constraint "uq_aegis_ledger_session_idem"',
                '23505'
              );
            }
          }
        }
        state.transactions.set(incoming.tx_id, incoming);
        return { rows: [], rowCount: 1 };
      }

      // Evaluate ON CONFLICT (tx_id) DO UPDATE SET status = CASE ... WHERE <session & immutable fields match> RETURNING tx_id, status
      if (normalized.includes('ON CONFLICT (tx_id) DO UPDATE SET')) {
        const immutableFieldsMatch =
          existing.session_id === incoming.session_id &&
          existing.alert_id === incoming.alert_id &&
          existing.sender_account_id === incoming.sender_account_id &&
          existing.receiver_account_id === incoming.receiver_account_id &&
          existing.amount_vnd === incoming.amount_vnd &&
          existing.idempotency_key === incoming.idempotency_key &&
          existing.tx_kind === incoming.tx_kind;

        if (!immutableFieldsMatch) {
          return { rows: [], rowCount: 0 };
        }

        const nextStatus =
          (existing.status === 'SETTLED' || existing.status === 'COMPLETED') &&
          incoming.status === 'REVERSED'
            ? 'REVERSED'
            : existing.status;

        state.transactions.set(existing.tx_id, {
          ...existing,
          status: nextStatus,
        });
        return { rows: [{ tx_id: existing.tx_id, status: nextStatus }], rowCount: 1 };
      }
      return { rows: [], rowCount: 0 };
    }

    if (normalized.includes('INSERT INTO aegis_ledger_entries')) {
      const entryId = String(values[0]);
      if (!state.ledgerEntries.has(entryId)) {
        state.ledgerEntries.set(entryId, {
          entry_id: entryId,
          session_id: String(values[1]),
          tx_id: String(values[2]),
          account_id: String(values[3]),
          entry_type: String(values[4]),
          amount_vnd: Number(values[5]),
          status: String(values[6]),
          created_at: String(values[7]),
        });
        return { rows: [], rowCount: 1 };
      }
      return { rows: [], rowCount: 0 };
    }

    if (normalized.includes('INSERT INTO aegis_clawback_receipts')) {
      const incoming: SimulatedClawbackRow = {
        clawback_id: String(values[0]),
        session_id: String(values[1]),
        alert_id: String(values[2]),
        idempotency_key: values[3] == null ? null : String(values[3]),
        requested_amount_vnd: Number(values[4]),
        recovered_amount_vnd: Number(values[5]),
        missing_amount_vnd: Number(values[6]),
        recovery_status: String(values[7]),
        reversal_tx_id: values[8] == null ? null : String(values[8]),
        victim_account_id: values[9] == null ? null : String(values[9]),
        victim_owner_name: values[10] == null ? null : String(values[10]),
        source_mule_account_id: values[11] == null ? null : String(values[11]),
        original_tx_ids: JSON.parse(String(values[12] ?? '[]')) as string[],
        executed_at: String(values[13]),
      };

      const existing = state.clawbacks.get(incoming.clawback_id);
      if (!existing) {
        // Enforce migration 002 partial unique indexes (NOT legacy UNIQUE (session_id, alert_id)).
        if (incoming.idempotency_key !== null) {
          for (const other of state.clawbacks.values()) {
            if (
              other.session_id === incoming.session_id &&
              other.idempotency_key === incoming.idempotency_key
            ) {
              throw this.makePgError(
                'duplicate key value violates unique constraint "uq_aegis_clawback_session_idem"',
                '23505'
              );
            }
          }
        }
        if (incoming.reversal_tx_id !== null) {
          for (const other of state.clawbacks.values()) {
            if (
              other.session_id === incoming.session_id &&
              other.reversal_tx_id === incoming.reversal_tx_id
            ) {
              throw this.makePgError(
                'duplicate key value violates unique constraint "uq_aegis_clawback_session_reversal_tx"',
                '23505'
              );
            }
          }
        }
        state.clawbacks.set(incoming.clawback_id, incoming);
        return { rows: [{ clawback_id: incoming.clawback_id }], rowCount: 1 };
      }

      // Evaluate ON CONFLICT (clawback_id) DO UPDATE ... WHERE ... RETURNING clawback_id
      const matchesGuardedPredicate =
        existing.session_id === incoming.session_id &&
        existing.alert_id === incoming.alert_id &&
        existing.requested_amount_vnd === incoming.requested_amount_vnd &&
        existing.recovered_amount_vnd === incoming.recovered_amount_vnd &&
        existing.missing_amount_vnd === incoming.missing_amount_vnd &&
        existing.recovery_status === incoming.recovery_status &&
        existing.reversal_tx_id === incoming.reversal_tx_id &&
        (existing.idempotency_key === null ||
          existing.idempotency_key === incoming.idempotency_key) &&
        (existing.victim_account_id === null ||
          existing.victim_account_id === incoming.victim_account_id) &&
        (existing.source_mule_account_id === null ||
          existing.source_mule_account_id === incoming.source_mule_account_id);

      if (!matchesGuardedPredicate) {
        return { rows: [], rowCount: 0 };
      }

      // Check secondary unique indexes if legacy NULL idempotency_key is being backfilled
      const nextIdemKey = existing.idempotency_key ?? incoming.idempotency_key;
      if (existing.idempotency_key === null && nextIdemKey !== null) {
        for (const other of state.clawbacks.values()) {
          if (
            other.clawback_id !== existing.clawback_id &&
            other.session_id === existing.session_id &&
            other.idempotency_key === nextIdemKey
          ) {
            throw this.makePgError(
              'duplicate key value violates unique constraint "uq_aegis_clawback_session_idem"',
              '23505'
            );
          }
        }
      }

      state.clawbacks.set(existing.clawback_id, {
        ...existing,
        idempotency_key: nextIdemKey,
        victim_account_id: existing.victim_account_id ?? incoming.victim_account_id,
        victim_owner_name: existing.victim_owner_name ?? incoming.victim_owner_name,
        source_mule_account_id: existing.source_mule_account_id ?? incoming.source_mule_account_id,
        original_tx_ids:
          existing.original_tx_ids.length === 0 ? incoming.original_tx_ids : existing.original_tx_ids,
      });
      return { rows: [{ clawback_id: existing.clawback_id }], rowCount: 1 };
    }

    if (normalized.includes('INSERT INTO aegis_audit_logs')) {
      state.auditLogIds.add(String(values[0]));
      return { rows: [], rowCount: 1 };
    }

    return { rows: [], rowCount: 0 };
  }

  async connect(): Promise<PgQueryableClient> {
    let staged: ReturnType<TransactionalMigration002PostgresSimulator['cloneState']> | null = null;
    return {
      query: async (text: string, values?: unknown[]) => {
        const normalized = text.replace(/\s+/g, ' ').trim();
        if (normalized === 'BEGIN') {
          staged = this.cloneState();
          this.executedSql.push('BEGIN');
          return { rows: [], rowCount: 0 };
        }
        if (normalized === 'COMMIT') {
          if (staged) {
            this.sessions = staged.sessions;
            this.transactions = staged.transactions;
            this.ledgerEntries = staged.ledgerEntries;
            this.clawbacks = staged.clawbacks;
            this.auditLogIds = staged.auditLogIds;
            staged = null;
          }
          this.executedSql.push('COMMIT');
          return { rows: [], rowCount: 0 };
        }
        if (normalized === 'ROLLBACK') {
          staged = null;
          this.executedSql.push('ROLLBACK');
          return { rows: [], rowCount: 0 };
        }
        const target = staged ?? {
          sessions: this.sessions,
          transactions: this.transactions,
          ledgerEntries: this.ledgerEntries,
          clawbacks: this.clawbacks,
          auditLogIds: this.auditLogIds,
        };
        return this.executeOnState(target, text, values);
      },
      release: () => undefined,
    };
  }
}

const makeDelta = (
  sessionId: string,
  stateRevision: number,
  overrides: Partial<SessionDeltaSnapshot> = {}
): SessionDeltaSnapshot => ({
  ...createEmptyDelta(sessionId),
  stateRevision,
  deltaIntegrityTag: `tag-rev-${stateRevision}`,
  ...overrides,
});

const makeTx = (overrides: Partial<Transaction>): Transaction => ({
  id: 'TXN-CUSTOM-001',
  alertId: 'ALT-APP-003',
  senderAccountId: 'ACC-USR-103',
  receiverAccountId: 'ACC-MULE-903',
  amountVnd: 25_000_000,
  channel: 'VIETQR',
  message: 'Transfer to suspect mule',
  deviceId: 'DEV-IOS-303',
  hopIndex: 1,
  status: 'SETTLED',
  timestamp: '2026-11-22T10:00:00+07:00',
  txKind: 'P2P_TRANSFER',
  ...overrides,
});

const makeClawback = (overrides: Partial<ClawbackReceiptRecord>): ClawbackReceiptRecord => ({
  clawbackId: 'CLAWBACK-2026-AAA1',
  alertId: 'ALT-APP-003',
  idempotencyKey: 'idem-clw-1',
  requestedAmountVnd: 25_000_000,
  recoveredAmountVnd: 25_000_000,
  missingAmountVnd: 0,
  recoveryStatus: 'RECOVERED',
  reversalTxId: 'TXN-REV-ALT-APP-003-AAA1',
  victimAccountId: 'ACC-USR-103',
  victimOwnerName: 'Nguyễn Thị Thu Hà (Nạn nhân APP Fraud #1)',
  sourceMuleAccountId: 'ACC-MULE-903',
  txIds: ['TXN-9011'],
  executedAt: '2026-11-22T10:05:00+07:00',
  ...overrides,
});

const EXPIRES_ISO = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

afterEach(() => {
  setPersistenceAdapterForTest(null);
});

describe('Wave 4.2.1A — Neon Persistence Integrity Remediation (NEON-01 & NEON-02)', () => {
  describe('NEON-01: Multi-victim & partial clawback receipt persistence', () => {
    it('persists both multi-victim clawbacks under ALT-APP-003 (TXN-9011 -> ACC-USR-103 and TXN-9012 -> ACC-USR-105) without collision via real orchestrator', async () => {
      const sim = new TransactionalMigration002PostgresSimulator();
      const adapter = new PostgresPersistenceAdapter(sim);
      const sessionId = 'sess-multivictim-alt-app-003';

      // Execute Victim #1 clawback (TXN-9011 -> ACC-USR-103, 25M) via real domain orchestrator
      const resVictim1 = executeClawbackAndRefundInSession({
        sessionId,
        alertId: 'ALT-APP-003',
        originalTxId: 'TXN-9011',
        idempotencyKey: 'mv-victim-1-txn9011',
      });
      await adapter.commitSession({
        sessionId,
        principalId: 'l2-checker-1',
        expectedRevision: 0,
        nextDelta: resVictim1.delta,
        expiresAtIso: EXPIRES_ISO,
      });

      // Execute Victim #2 clawback (TXN-9012 -> ACC-USR-105, 17M) on the SAME (session_id, alert_id)
      const resVictim2 = executeClawbackAndRefundInSession({
        sessionId,
        alertId: 'ALT-APP-003',
        originalTxId: 'TXN-9012',
        idempotencyKey: 'mv-victim-2-txn9012',
        clientDelta: resVictim1.delta,
      });
      await adapter.commitSession({
        sessionId,
        principalId: 'l2-checker-1',
        expectedRevision: resVictim1.delta.stateRevision!,
        nextDelta: resVictim2.delta,
        expiresAtIso: EXPIRES_ISO,
      });

      expect(sim.clawbacks.size).toBe(2);
      const row1 = sim.clawbacks.get(resVictim1.clawbackReceipt.clawbackId)!;
      const row2 = sim.clawbacks.get(resVictim2.clawbackReceipt.clawbackId)!;
      expect(row1).toMatchObject({
        session_id: sessionId,
        alert_id: 'ALT-APP-003',
        idempotency_key: 'mv-victim-1-txn9011',
        requested_amount_vnd: 25_000_000,
        recovered_amount_vnd: 25_000_000,
        missing_amount_vnd: 0,
        recovery_status: 'RECOVERED',
        reversal_tx_id: resVictim1.clawbackReceipt.reversalTxId,
        victim_account_id: 'ACC-USR-103',
        source_mule_account_id: 'ACC-MULE-903',
        original_tx_ids: ['TXN-9011'],
      });
      expect(row2).toMatchObject({
        session_id: sessionId,
        alert_id: 'ALT-APP-003',
        idempotency_key: 'mv-victim-2-txn9012',
        requested_amount_vnd: 17_000_000,
        recovered_amount_vnd: 17_000_000,
        missing_amount_vnd: 0,
        recovery_status: 'RECOVERED',
        reversal_tx_id: resVictim2.clawbackReceipt.reversalTxId,
        victim_account_id: 'ACC-USR-105',
        source_mule_account_id: 'ACC-MULE-903',
        original_tx_ids: ['TXN-9012'],
      });
      // Relational receipts stay consistent with delta_json
      const storedSession = sim.sessions.get(sessionId)!;
      expect(storedSession.delta_json.clawbackReceipts).toHaveLength(2);
    });

    it('persists multiple distinct partial clawbacks for the same original transaction, keeps retries idempotent, and rejects unexpected uniqueness/payload conflicts', async () => {
      const sim = new TransactionalMigration002PostgresSimulator();
      const adapter = new PostgresPersistenceAdapter(sim);
      const sessionId = 'sess-partial-clawbacks';

      const partial1 = makeClawback({
        clawbackId: 'CLAWBACK-2026-P1',
        idempotencyKey: 'partial-10m',
        requestedAmountVnd: 10_000_000,
        recoveredAmountVnd: 10_000_000,
        reversalTxId: 'TXN-REV-P1',
        txIds: ['TXN-9011'],
      });
      const partial2 = makeClawback({
        clawbackId: 'CLAWBACK-2026-P2',
        idempotencyKey: 'partial-15m',
        requestedAmountVnd: 15_000_000,
        recoveredAmountVnd: 15_000_000,
        reversalTxId: 'TXN-REV-P2',
        txIds: ['TXN-9011'],
        executedAt: '2026-11-22T10:10:00+07:00',
      });

      // Commit partial #1
      await adapter.commitSession({
        sessionId,
        principalId: 'checker-1',
        expectedRevision: 0,
        nextDelta: makeDelta(sessionId, 1, { clawbackReceipts: [partial1] }),
        expiresAtIso: EXPIRES_ISO,
      });
      expect(sim.clawbacks.size).toBe(1);

      // Commit partial #2 (includes partial #1 snapshot retry + new partial #2)
      await adapter.commitSession({
        sessionId,
        principalId: 'checker-1',
        expectedRevision: 1,
        nextDelta: makeDelta(sessionId, 2, { clawbackReceipts: [partial2, partial1] }),
        expiresAtIso: EXPIRES_ISO,
      });
      expect(sim.clawbacks.size).toBe(2);
      expect(sim.clawbacks.get('CLAWBACK-2026-P1')?.recovered_amount_vnd).toBe(10_000_000);
      expect(sim.clawbacks.get('CLAWBACK-2026-P2')?.recovered_amount_vnd).toBe(15_000_000);

      // Retrying identical clawback records in a later revision does not create duplicate records
      await adapter.commitSession({
        sessionId,
        principalId: 'checker-1',
        expectedRevision: 2,
        nextDelta: makeDelta(sessionId, 3, { clawbackReceipts: [partial2, partial1] }),
        expiresAtIso: EXPIRES_ISO,
      });
      expect(sim.clawbacks.size).toBe(2);

      // Unexpected uniqueness conflict: DIFFERENT clawbackId reusing an existing (session_id, idempotency_key)
      const duplicateIdemConflict = makeClawback({
        clawbackId: 'CLAWBACK-2026-P3-DUP-IDEM',
        idempotencyKey: 'partial-10m',
        requestedAmountVnd: 5_000_000,
        recoveredAmountVnd: 5_000_000,
        reversalTxId: 'TXN-REV-P3',
      });
      await expect(
        adapter.commitSession({
          sessionId,
          principalId: 'checker-1',
          expectedRevision: 3,
          nextDelta: makeDelta(sessionId, 4, {
            clawbackReceipts: [duplicateIdemConflict, partial2, partial1],
          }),
          expiresAtIso: EXPIRES_ISO,
        })
      ).rejects.toBeInstanceOf(ConcurrentStateConflictError);
      // Rollback preserved prior committed state (revision 3, 2 clawbacks)
      expect(sim.sessions.get(sessionId)?.state_revision).toBe(3);
      expect(sim.clawbacks.size).toBe(2);

      // Unexpected payload conflict: SAME clawbackId with tampered amount fails guarded WHERE (rowCount === 0)
      const tamperedSameId = makeClawback({
        ...partial1,
        recoveredAmountVnd: 99_000_000,
      });
      await expect(
        adapter.commitSession({
          sessionId,
          principalId: 'checker-1',
          expectedRevision: 3,
          nextDelta: makeDelta(sessionId, 4, { clawbackReceipts: [tamperedSameId, partial2] }),
          expiresAtIso: EXPIRES_ISO,
        })
      ).rejects.toBeInstanceOf(ConcurrentStateConflictError);
      expect(sim.sessions.get(sessionId)?.state_revision).toBe(3);
      expect(sim.clawbacks.get('CLAWBACK-2026-P1')?.recovered_amount_vnd).toBe(10_000_000);
    });
  });

  describe('NEON-02: Monotonic ledger transaction status transitions to REVERSED', () => {
    it('transitions SETTLED and COMPLETED rows to REVERSED, keeps repeated REVERSED idempotent, rejects stale regressions, and preserves immutable columns', async () => {
      const sim = new TransactionalMigration002PostgresSimulator();
      const adapter = new PostgresPersistenceAdapter(sim);
      const sessionId = 'sess-tx-status-transitions';

      const settledTx = makeTx({
        id: 'TXN-LIVE-SETTLED-1',
        status: 'SETTLED',
        amountVnd: 10_000_000,
        idempotencyKey: 'tx-idem-settled-1',
      });
      const completedTx = makeTx({
        id: 'TXN-LIVE-COMPLETED-2',
        status: 'COMPLETED',
        amountVnd: 8_000_000,
        senderAccountId: 'ACC-USR-105',
        idempotencyKey: 'tx-idem-completed-2',
      });
      const heldTx = makeTx({
        id: 'TXN-LIVE-HELD-3',
        status: 'HELD',
        amountVnd: 6_000_000,
        idempotencyKey: 'tx-idem-held-3',
      });

      // Rev 1: Initial persistence of SETTLED, COMPLETED, and HELD transactions
      await adapter.commitSession({
        sessionId,
        principalId: 'checker-1',
        expectedRevision: 0,
        nextDelta: makeDelta(sessionId, 1, {
          customTransactions: [settledTx, completedTx, heldTx],
        }),
        expiresAtIso: EXPIRES_ISO,
      });
      expect(sim.transactions.get('TXN-LIVE-SETTLED-1')?.status).toBe('SETTLED');
      expect(sim.transactions.get('TXN-LIVE-COMPLETED-2')?.status).toBe('COMPLETED');
      expect(sim.transactions.get('TXN-LIVE-HELD-3')?.status).toBe('HELD');

      // Rev 2: Partial clawback (4M of 10M) keeps TXN-LIVE-SETTLED-1 as SETTLED
      const partialClaw = makeClawback({
        clawbackId: 'CLAW-PART-1',
        idempotencyKey: 'clw-part-1',
        requestedAmountVnd: 4_000_000,
        recoveredAmountVnd: 4_000_000,
        reversalTxId: 'TXN-REV-PART-1',
        txIds: ['TXN-LIVE-SETTLED-1'],
      });
      await adapter.commitSession({
        sessionId,
        principalId: 'checker-1',
        expectedRevision: 1,
        nextDelta: makeDelta(sessionId, 2, {
          customTransactions: [settledTx, completedTx, heldTx],
          clawbackReceipts: [partialClaw],
        }),
        expiresAtIso: EXPIRES_ISO,
      });
      expect(sim.transactions.get('TXN-LIVE-SETTLED-1')?.status).toBe('SETTLED');

      // Rev 3: Remaining partial clawback (6M -> cumulative 10M >= 10M) transitions SETTLED -> REVERSED,
      // and direct REVERSED on COMPLETED transitions COMPLETED -> REVERSED; HELD cannot transition to REVERSED.
      const finalPartialClaw = makeClawback({
        clawbackId: 'CLAW-PART-2',
        idempotencyKey: 'clw-part-2',
        requestedAmountVnd: 6_000_000,
        recoveredAmountVnd: 6_000_000,
        reversalTxId: 'TXN-REV-PART-2',
        txIds: ['TXN-LIVE-SETTLED-1'],
      });
      await adapter.commitSession({
        sessionId,
        principalId: 'checker-1',
        expectedRevision: 2,
        nextDelta: makeDelta(sessionId, 3, {
          customTransactions: [
            settledTx, // Still carries 'SETTLED' in delta array; derived as REVERSED from clawbackReceipts!
            { ...completedTx, status: 'REVERSED' },
            { ...heldTx, status: 'REVERSED' },
          ],
          clawbackReceipts: [finalPartialClaw, partialClaw],
        }),
        expiresAtIso: EXPIRES_ISO,
      });

      expect(sim.transactions.get('TXN-LIVE-SETTLED-1')?.status).toBe('REVERSED');
      // COMPLETED -> REVERSED succeeded while immutable columns (amount_vnd, sender_account_id) remained intact
      expect(sim.transactions.get('TXN-LIVE-COMPLETED-2')).toMatchObject({
        status: 'REVERSED',
        amount_vnd: 8_000_000,
        sender_account_id: 'ACC-USR-105',
      });
      // HELD was NOT allowed to transition to REVERSED
      expect(sim.transactions.get('TXN-LIVE-HELD-3')?.status).toBe('HELD');

      // Rev 4: Repeated REVERSED write is idempotent; stale SETTLED/COMPLETED snapshot CANNOT revert terminal REVERSED
      await adapter.commitSession({
        sessionId,
        principalId: 'checker-1',
        expectedRevision: 3,
        nextDelta: makeDelta(sessionId, 4, {
          customTransactions: [
            { ...settledTx, status: 'SETTLED' },
            { ...completedTx, status: 'COMPLETED' },
          ],
          clawbackReceipts: [], // Even with an empty clawback list in a stale snapshot
        }),
        expiresAtIso: EXPIRES_ISO,
      });
      expect(sim.transactions.get('TXN-LIVE-SETTLED-1')?.status).toBe('REVERSED');
      expect(sim.transactions.get('TXN-LIVE-COMPLETED-2')?.status).toBe('REVERSED');

      // Wave 4.2.1B LEDGER_TX_IDENTITY_GAP: Immutable attribute conflict on same tx_id MUST fail & roll back (never silently swallowed)
      await expect(
        adapter.commitSession({
          sessionId,
          principalId: 'checker-1',
          expectedRevision: 4,
          nextDelta: makeDelta(sessionId, 5, {
            customTransactions: [
              { ...completedTx, status: 'REVERSED', amountVnd: 999_999, senderAccountId: 'TAMPERED' },
            ],
          }),
          expiresAtIso: EXPIRES_ISO,
        })
      ).rejects.toBeInstanceOf(ConcurrentStateConflictError);
      expect(sim.sessions.get(sessionId)?.state_revision).toBe(4);
      expect(sim.transactions.get('TXN-LIVE-COMPLETED-2')).toMatchObject({
        status: 'REVERSED',
        amount_vnd: 8_000_000,
        sender_account_id: 'ACC-USR-105',
      });

      // Wave 4.2.1B LEDGER_TX_IDENTITY_GAP: Cross-session tx_id collision MUST fail with ConcurrentStateConflictError & ROLLBACK
      const otherSessionId = 'sess-tx-cross-session-attacker';
      await expect(
        adapter.commitSession({
          sessionId: otherSessionId,
          principalId: 'attacker-1',
          expectedRevision: 0,
          nextDelta: makeDelta(otherSessionId, 1, {
            customTransactions: [settledTx],
          }),
          expiresAtIso: EXPIRES_ISO,
        })
      ).rejects.toBeInstanceOf(ConcurrentStateConflictError);
      expect(sim.sessions.has(otherSessionId)).toBe(false);
      expect(sim.transactions.get('TXN-LIVE-SETTLED-1')?.session_id).toBe(sessionId);
    });
  });

  describe('Transaction atomicity, rollback, CAS, and Migration 002 / Rollback 002 DDL invariants', () => {
    it('executes session CAS, transaction updates, and clawback inserts in one ACID transaction and rolls back cleanly on mid-transaction or CAS failure', async () => {
      const sim = new TransactionalMigration002PostgresSimulator();
      const adapter = new PostgresPersistenceAdapter(sim);
      const sessionId = 'sess-atomicity';

      const baseTx = makeTx({ id: 'TXN-ATOM-1', status: 'SETTLED', amountVnd: 5_000_000 });
      await adapter.commitSession({
        sessionId,
        principalId: 'checker-1',
        expectedRevision: 0,
        nextDelta: makeDelta(sessionId, 1, { customTransactions: [baseTx] }),
        expiresAtIso: EXPIRES_ISO,
      });

      // Inject write failure on clawback insert: session rev & transaction status MUST roll back!
      sim.failNextQueryContaining = 'INSERT INTO aegis_clawback_receipts';
      const claw = makeClawback({
        clawbackId: 'CLAW-ATOM-1',
        idempotencyKey: 'clw-atom-1',
        requestedAmountVnd: 5_000_000,
        recoveredAmountVnd: 5_000_000,
        reversalTxId: 'TXN-REV-ATOM-1',
        txIds: ['TXN-ATOM-1'],
      });
      await expect(
        adapter.commitSession({
          sessionId,
          principalId: 'checker-1',
          expectedRevision: 1,
          nextDelta: makeDelta(sessionId, 2, {
            customTransactions: [baseTx],
            clawbackReceipts: [claw],
          }),
          expiresAtIso: EXPIRES_ISO,
        })
      ).rejects.toThrow('Simulated PostgreSQL transient write failure');

      expect(sim.executedSql).toContain('ROLLBACK');
      expect(sim.sessions.get(sessionId)?.state_revision).toBe(1);
      expect(sim.transactions.get('TXN-ATOM-1')?.status).toBe('SETTLED');
      expect(sim.clawbacks.size).toBe(0);

      // Failed CAS (wrong expectedRevision) does not touch relational tables
      await expect(
        adapter.commitSession({
          sessionId,
          principalId: 'checker-1',
          expectedRevision: 0,
          nextDelta: makeDelta(sessionId, 2, {
            customTransactions: [baseTx],
            clawbackReceipts: [claw],
          }),
          expiresAtIso: EXPIRES_ISO,
        })
      ).rejects.toBeInstanceOf(ConcurrentStateConflictError);
      expect(sim.sessions.get(sessionId)?.state_revision).toBe(1);
      expect(sim.transactions.get('TXN-ATOM-1')?.status).toBe('SETTLED');
      expect(sim.clawbacks.size).toBe(0);
    });

    it('verifies migration 002 and rollback 002 SQL scripts contain required additive, idempotent, and non-destructive safety guards', () => {
      const mig002 = readFileSync(
        join(process.cwd(), 'sql', 'migrations', '002_clawback_multi_victim_and_tx_status.sql'),
        'utf8'
      );
      const rb002 = readFileSync(
        join(process.cwd(), 'sql', 'migrations', '002_rollback.sql'),
        'utf8'
      );

      expect(mig002).toContain('BEGIN;');
      expect(mig002).toContain('COMMIT;');
      expect(mig002).toContain('DROP CONSTRAINT');
      expect(mig002).toContain('ADD COLUMN IF NOT EXISTS idempotency_key TEXT');
      expect(mig002).toContain('ADD COLUMN IF NOT EXISTS victim_account_id TEXT');
      expect(mig002).toContain('ADD COLUMN IF NOT EXISTS victim_owner_name TEXT');
      expect(mig002).toContain('ADD COLUMN IF NOT EXISTS source_mule_account_id TEXT');
      expect(mig002).toContain('ADD COLUMN IF NOT EXISTS original_tx_ids JSONB');
      expect(mig002).toContain('CREATE UNIQUE INDEX IF NOT EXISTS uq_aegis_clawback_session_idem');
      expect(mig002).toContain(
        'CREATE UNIQUE INDEX IF NOT EXISTS uq_aegis_clawback_session_reversal_tx'
      );
      expect(mig002).toContain('trg_aegis_ledger_tx_status_guard');
      expect(mig002).toContain("'002_clawback_multi_victim_and_tx_status'");
      expect(mig002).not.toMatch(/DROP\s+TABLE/i);

      expect(rb002).toContain('HAVING COUNT(*) > 1');
      expect(rb002).toContain('RAISE EXCEPTION');
      expect(rb002).not.toMatch(/DROP\s+TABLE/i);
      expect(rb002).not.toMatch(/DELETE\s+FROM\s+aegis_clawback_receipts/i);
      expect(rb002).not.toMatch(/DELETE\s+FROM\s+aegis_ledger_transactions/i);
    });
  });
});
