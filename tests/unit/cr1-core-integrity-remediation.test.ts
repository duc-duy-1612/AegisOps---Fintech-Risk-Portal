import { NextRequest } from 'next/server';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { GET as healthGet } from '@/app/api/health/route';
import { POST as merchantVerifyPost } from '@/app/api/merchant/verify/route';
import { POST as playbookPost } from '@/app/api/playbook/route';
import { POST as sessionPost } from '@/app/api/session/route';
import { POST as walletPost } from '@/app/api/wallet/route';
import {
  GET as workspaceGet,
  POST as workspacePost,
} from '@/app/api/workspace/route';
import {
  IdempotencyKeyConflictError,
  createHitlFeedbackInSession,
  executeAlertInvestigation,
  executePlaybookApproval,
  getWorkspaceBootstrap,
  moderateHitlFeedbackInSession,
  simulateWalletTransferInSession,
} from '@/application/workspace-orchestrator';
import {
  buildComplianceIncidentDossier,
  evaluateQd2345Compliance,
  evaluateTt77Compliance,
} from '@/domain/compliance-report';
import { computeDashboardKpiMetrics } from '@/domain/dashboard-kpis';
import {
  evaluateFlowVelocityMetrics,
  runDeterministicForensicsSuite,
} from '@/domain/forensics-analyzers';
import {
  LedgerInvariantError,
  buildBalancedLedgerPair,
  computeAccountBalancesFromLedger,
  evaluateLedgerBalanceInvariants,
} from '@/domain/ledger-engine';
import type {
  Account,
  FraudAlert,
  HitlFeedbackMemoryRecord,
  LedgerEntryRecord,
  SessionDeltaSnapshot,
  Transaction,
} from '@/domain/types';
import {
  type PgQueryableClient,
  type PgQueryablePool,
  PostgresPersistenceAdapter,
  setPersistenceAdapterForTest,
} from '@/infrastructure/persistence-adapter';
import {
  SEED_ACCOUNTS,
  SEED_ALERTS,
  SEED_API_EVENTS,
  SEED_AUTH_LOGS,
  SEED_DEVICES,
  SEED_EVIDENCES,
  SEED_TRANSACTIONS,
} from '@/infrastructure/seed-scenarios';
import { resetRateBucketsForTest } from '@/infrastructure/security-guard';
import {
  SESSION_COOKIE_NAME,
  SESSION_TTL_MS,
  createSignedSessionToken,
} from '@/infrastructure/session-auth';
import {
  createEmptyDelta,
  resetSessionDelta,
  saveSessionDelta,
} from '@/infrastructure/workspace-store';

const makeReq = (params: {
  url: string;
  method?: 'GET' | 'POST' | 'DELETE';
  body?: unknown;
  sessionId?: string;
  cookieToken?: string;
  extraHeaders?: Record<string, string>;
}): NextRequest => {
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    host: 'localhost:3000',
    origin: 'http://localhost:3000',
    'sec-fetch-site': 'same-origin',
    ...(params.extraHeaders ?? {}),
  };
  if (params.sessionId) headers['x-workspace-session'] = params.sessionId;
  if (params.cookieToken) headers.cookie = `${SESSION_COOKIE_NAME}=${params.cookieToken}`;

  return new NextRequest(params.url, {
    method: params.method ?? 'POST',
    headers,
    body: params.body !== undefined ? JSON.stringify(params.body) : undefined,
  });
};

class Cr1AuditSpyPool implements PgQueryablePool {
  public readonly sessions = new Map<
    string,
    {
      session_id: string;
      principal_id: string;
      state_revision: number;
      status: string;
      delta_integrity_tag: string;
      delta_json: unknown;
      expires_at: string;
      revoked_at: string | null;
    }
  >();
  public readonly auditRows = new Map<
    string,
    {
      audit_id: string;
      session_id: string;
      alert_id: string;
      actor: string;
      action: string;
      details_vi: string;
      created_at: string;
    }
  >();
  public readonly ledgerTxIds = new Set<string>();
  public readonly ledgerIdemKeys = new Map<string, string>();
  public failNextAuditInsert = false;
  public committedCount = 0;
  public rolledBackCount = 0;

  async connect(): Promise<PgQueryableClient> {
    let txSessionsSnapshot: Map<string, (typeof this.sessions extends Map<string, infer V> ? V : never)> | null = null;
    let txAuditSnapshot: Map<string, (typeof this.auditRows extends Map<string, infer V> ? V : never)> | null = null;
    let txLedgerTxSnapshot: Set<string> | null = null;
    let txLedgerIdemSnapshot: Map<string, string> | null = null;

    return {
      query: async (text: string, values: unknown[] = []) => {
        const sql = text.trim();
        if (sql === 'BEGIN') {
          txSessionsSnapshot = new Map(this.sessions);
          txAuditSnapshot = new Map(this.auditRows);
          txLedgerTxSnapshot = new Set(this.ledgerTxIds);
          txLedgerIdemSnapshot = new Map(this.ledgerIdemKeys);
          return { rows: [], rowCount: 0 };
        }
        if (sql === 'COMMIT') {
          this.committedCount += 1;
          txSessionsSnapshot = null;
          txAuditSnapshot = null;
          txLedgerTxSnapshot = null;
          txLedgerIdemSnapshot = null;
          return { rows: [], rowCount: 0 };
        }
        if (sql === 'ROLLBACK') {
          this.rolledBackCount += 1;
          if (txSessionsSnapshot) {
            this.sessions.clear();
            txSessionsSnapshot.forEach((v, k) => this.sessions.set(k, v));
          }
          if (txAuditSnapshot) {
            this.auditRows.clear();
            txAuditSnapshot.forEach((v, k) => this.auditRows.set(k, v));
          }
          if (txLedgerTxSnapshot) {
            this.ledgerTxIds.clear();
            txLedgerTxSnapshot.forEach((v) => this.ledgerTxIds.add(v));
          }
          if (txLedgerIdemSnapshot) {
            this.ledgerIdemKeys.clear();
            txLedgerIdemSnapshot.forEach((v, k) => this.ledgerIdemKeys.set(k, v));
          }
          return { rows: [], rowCount: 0 };
        }
        return this.query(text, values);
      },
      release: () => undefined,
    };
  }

  async query(text: string, values: unknown[] = []) {
    if (text.includes('SELECT 1 AS ok')) {
      return { rows: [{ ok: 1 }], rowCount: 1 };
    }
    if (text.includes('FROM aegis_workspace_sessions') && text.includes('FOR UPDATE')) {
      const row = this.sessions.get(String(values[0]));
      return { rows: row ? [row] : [], rowCount: row ? 1 : 0 };
    }
    if (text.includes('SELECT status, expires_at FROM aegis_workspace_sessions')) {
      const row = this.sessions.get(String(values[0]));
      return {
        rows: row ? [{ status: row.status, expires_at: row.expires_at }] : [],
        rowCount: row ? 1 : 0,
      };
    }
    if (text.includes('FROM aegis_workspace_sessions') && text.includes('delta_json')) {
      const row = this.sessions.get(String(values[0]));
      return { rows: row ? [row] : [], rowCount: row ? 1 : 0 };
    }
    if (text.includes('INSERT INTO aegis_workspace_sessions')) {
      const sid = String(values[0]);
      const expectedRev = Number(values[6] ?? 0);
      const existing = this.sessions.get(sid);
      if (existing && (existing.state_revision !== expectedRev || existing.status !== 'ACTIVE')) {
        return { rows: [], rowCount: 0 };
      }
      const nextRev = Number(values[2]);
      this.sessions.set(sid, {
        session_id: sid,
        principal_id: String(values[1]),
        state_revision: nextRev,
        status: existing?.status ?? 'ACTIVE',
        delta_integrity_tag: String(values[3]),
        delta_json: JSON.parse(String(values[4])),
        expires_at: String(values[5]),
        revoked_at: existing?.revoked_at ?? null,
      });
      return { rows: [{ state_revision: nextRev }], rowCount: 1 };
    }
    if (text.includes('INSERT INTO aegis_ledger_transactions')) {
      const txId = String(values[0]);
      const sid = String(values[1]);
      const idemKey = values[7] ? String(values[7]) : null;
      if (!this.ledgerTxIds.has(txId) && idemKey) {
        const comp = `${sid}:${idemKey}`;
        const prevTx = this.ledgerIdemKeys.get(comp);
        if (prevTx && prevTx !== txId) {
          const dupErr = new Error('duplicate key value violates unique constraint') as Error & {
            code: string;
          };
          dupErr.code = '23505';
          throw dupErr;
        }
        this.ledgerIdemKeys.set(comp, txId);
      }
      this.ledgerTxIds.add(txId);
      return { rows: [], rowCount: 1 };
    }
    if (text.includes('INSERT INTO aegis_audit_logs')) {
      if (this.failNextAuditInsert) {
        this.failNextAuditInsert = false;
        throw new Error('Simulated PostgreSQL audit log write failure');
      }
      const auditId = String(values[0]);
      if (!this.auditRows.has(auditId)) {
        this.auditRows.set(auditId, {
          audit_id: auditId,
          session_id: String(values[1]),
          alert_id: String(values[2]),
          actor: String(values[3]),
          action: String(values[4]),
          details_vi: String(values[5]),
          created_at: String(values[6]),
        });
      }
      return { rows: [], rowCount: 1 };
    }
    return { rows: [], rowCount: 1 };
  }
}

describe('CR-1 Remediation Suite — Workstreams A through H', () => {
  const savedEnv = { ...process.env };

  beforeEach(() => {
    resetRateBucketsForTest();
    setPersistenceAdapterForTest(null);
  });

  afterEach(() => {
    setPersistenceAdapterForTest(null);
    for (const key of Object.keys(process.env)) {
      if (!(key in savedEnv)) {
        delete process.env[key];
      }
    }
    Object.assign(process.env, savedEnv);
  });

  // ─── WORKSTREAM A: Adaptive HITL Propagation into Playbook Approval ───────────────────
  describe('Workstream A: Adaptive HITL Propagation into Playbook Approval', () => {
    const seedBorderlineCustomAlert = (sessionId: string): { alertId: string; delta: SessionDeltaSnapshot } => {
      resetSessionDelta(sessionId);
      const alertId = 'ALT-CR1-BORDERLINE';
      const customAccount: Account = {
        id: 'ACC-CR1-RECIP',
        ownerName: 'Cửa hàng Thiết bị Y tế Minh Tâm',
        accountNumber: '1903555444333',
        bankOrWalletName: 'Ví Điện Tử MoMo',
        accountType: 'CONSUMER',
        status: 'ACTIVE',
        balanceVnd: 15_000_000,
        avgTxAmountVnd: 3_000_000,
        kycLevel: 'LEVEL_2_BIOMETRIC',
        primaryDeviceId: 'DEV-CR1-CLEAN',
        accountAgeDays: 220,
      };
      const customAlert: FraudAlert = {
        id: alertId,
        title: 'Chuyển khoản 14.000.000 ₫ tới đối tác mới (Không có ATO/URL độc hại)',
        subtitle: 'Biên độ rủi ro trung bình (base score ~32)',
        scenarioCode: 'CUSTOM_SANDBOX',
        primaryAccountId: 'ACC-USR-104',
        targetRecipientAccountId: customAccount.id,
        severity: 'MEDIUM',
        status: 'OPEN',
        deterministicRiskScore: 32,
        tracks: ['ANTI_SCAM'],
        createdAt: '2026-11-22T10:00:00+07:00',
        traditionalRuleReason: 'Giao dịch vượt mức trung bình tài khoản',
      };
      const customTx: Transaction = {
        id: 'TXN-CR1-B1',
        alertId,
        senderAccountId: 'ACC-USR-104',
        receiverAccountId: customAccount.id,
        amountVnd: 35_000_000,
        channel: 'P2P_WALLET',
        message: 'Thanh toan don hang thiet bi y te',
        deviceId: 'DEV-IOS-404',
        hopIndex: 1,
        status: 'HELD',
        timestamp: '2026-11-22T10:00:00+07:00',
      };
      const base = createEmptyDelta(sessionId);
      const delta = saveSessionDelta(sessionId, {
        ...base,
        customAlerts: [customAlert],
        customAccounts: [customAccount],
        customTransactions: [customTx],
      });
      return { alertId, delta };
    };

    it('propagates approved OVERRIDE_SAFE and FORCE_BLOCK into playbook approval and keeps investigation + playbook consistent', async () => {
      // 1. Approved OVERRIDE_SAFE flips borderline alert (base=22? Wait verify base >= 28) -> FALSE_POSITIVE_SAFE in both investigation & playbook
      const sidSafe = `cr1-hitl-safe-${Date.now()}`;
      const { alertId, delta: seeded } = seedBorderlineCustomAlert(sidSafe);
      // Confirm without HITL it is >= 28? Wait: ACC-USR-104 avgTx=4.5M, 35M/4.5M=7.8x -> step1=22; add 2nd tx or higher base so base=32 -> let's verify!
      const baseBoot = getWorkspaceBootstrap(sidSafe, seeded);
      const baseScore = baseBoot.forensicsByAlertId[alertId]!.deterministicRiskScore;
      // Add a 2nd custom tx of 25M so step1=22 and step2=24? No, let's check baseScore directly and also test ALT-FPR-004 FORCE_BLOCK!
      expect(baseScore).toBeGreaterThanOrEqual(18);

      // Build a borderline case with exact base score = 34 (no hard critical signals: step1=22, step2=0, step5=0 -> custom sandbox with 1 warning device link? No, clean recipient with 2 transactions from 1 sender to new account)
      const sidBorder = `cr1-hitl-border-${Date.now()}`;
      resetSessionDelta(sidBorder);
      const borderAlertId = 'ALT-CR1-34';
      const borderRecip: Account = {
        id: 'ACC-CR1-34',
        ownerName: 'Đối tác Thanh toán Biên',
        accountNumber: '1903666777888',
        bankOrWalletName: 'Ngân hàng Nội địa',
        accountType: 'CONSUMER',
        status: 'ACTIVE',
        balanceVnd: 20_000_000,
        avgTxAmountVnd: 2_000_000,
        kycLevel: 'LEVEL_2_BIOMETRIC',
        primaryDeviceId: 'DEV-CR1-SHARED-CLEAN',
        accountAgeDays: 180,
      };
      const borderDelta = saveSessionDelta(sidBorder, {
        ...createEmptyDelta(sidBorder),
        customAlerts: [
          {
            id: borderAlertId,
            title: 'Biên rủi ro 34/100 (không có ATO/Webhook/URL độc hại)',
            subtitle: 'Test OVERRIDE_SAFE',
            scenarioCode: 'CUSTOM_SANDBOX',
            primaryAccountId: 'ACC-USR-104',
            targetRecipientAccountId: borderRecip.id,
            severity: 'MEDIUM',
            status: 'OPEN',
            deterministicRiskScore: 34,
            tracks: ['ANTI_SCAM'],
            createdAt: '2026-11-22T10:05:00+07:00',
            traditionalRuleReason: 'Outflow anomaly',
          },
        ],
        customAccounts: [borderRecip],
        customDevices: [
          {
            id: 'DEV-CR1-SHARED-CLEAN',
            osBrowser: 'iOS 18',
            ipAddress: '14.161.10.2',
            asnLocation: 'VN',
            isEmulatorOrRooted: false,
            linkedAccountIds: [borderRecip.id, 'ACC-USR-104'],
          },
        ],
        customTransactions: [
          {
            id: 'TXN-CR1-34-1',
            alertId: borderAlertId,
            senderAccountId: 'ACC-USR-104',
            receiverAccountId: borderRecip.id,
            amountVnd: 10_000_000,
            channel: 'P2P_WALLET',
            message: 'Thanh toan hop dong',
            deviceId: 'DEV-IOS-404',
            hopIndex: 1,
            status: 'HELD',
            timestamp: '2026-11-22T10:05:00+07:00',
          },
        ],
      });

      // Without HITL: step1 (5) + step2 (24) = 29 >= 28 -> CONFIRMED_APP_SCAM!
      const beforeInv = await executeAlertInvestigation({
        sessionId: sidBorder,
        alertId: borderAlertId,
        clientDelta: borderDelta,
      });
      expect(beforeInv.forensics.deterministicRiskScore).toBe(29);
      expect(beforeInv.report.classification).toBe('CONFIRMED_APP_SCAM');

      // L2 approves OVERRIDE_SAFE (-12 -> score 17 < 28 -> FALSE_POSITIVE_SAFE)
      const hitlSafe = createHitlFeedbackInSession({
        sessionId: sidBorder,
        alertId: borderAlertId,
        feedbackDecision: 'OVERRIDE_SAFE',
        targetScope: 'RECIPIENT_PATTERN',
        reasonCode: 'VERIFIED_LEGITIMATE_PARTNER',
        analystRationale: 'Đã gọi xác minh đối tác hợp lệ',
        actorPrincipalId: 'checker-cr1',
        actorRole: 'L2_CHECKER',
        clientDelta: beforeInv.delta,
      });

      // Even WITHOUT re-running /api/investigate first, executePlaybookApproval MUST see approved OVERRIDE_SAFE and mark DISMISSED_SAFE!
      const playSafe = executePlaybookApproval({
        sessionId: sidBorder,
        alertId: borderAlertId,
        mode: 'APPROVE_L2',
        actorPrincipalId: 'checker-cr1-b',
        clientDelta: hitlSafe.delta,
      });
      expect(playSafe.newStatus).toBe('DISMISSED_SAFE');
      expect(playSafe.createdShieldRule).toBeUndefined();
      // Cached report is reconciled to match playbook decision
      expect(playSafe.delta.reportsByAlertId[borderAlertId]?.classification).toBe('FALSE_POSITIVE_SAFE');

      // 2. Approved FORCE_BLOCK on ALT-FPR-004 (base score 14 -> +15 = 29 >= 28) flips playbook from DISMISSED_SAFE -> MITIGATED
      const sidForceBlock = `cr1-hitl-block-${Date.now()}`;
      resetSessionDelta(sidForceBlock);
      const hitlBlock = createHitlFeedbackInSession({
        sessionId: sidForceBlock,
        alertId: 'ALT-FPR-004',
        feedbackDecision: 'FORCE_BLOCK',
        targetScope: 'ALERT_CASE',
        reasonCode: 'ANALYST_ESCALATION',
        analystRationale: 'Phát hiện tài khoản nhận vừa bị báo cáo lừa đảo khẩn cấp',
        actorPrincipalId: 'checker-block',
        actorRole: 'L2_CHECKER',
      });
      const invAfterBlock = await executeAlertInvestigation({
        sessionId: sidForceBlock,
        alertId: 'ALT-FPR-004',
        clientDelta: hitlBlock.delta,
      });
      expect(invAfterBlock.forensics.deterministicRiskScore).toBe(29);
      expect(invAfterBlock.forensics.fallbackReport.classification).toBe('CONFIRMED_APP_SCAM');

      const playBlock = executePlaybookApproval({
        sessionId: sidForceBlock,
        alertId: 'ALT-FPR-004',
        mode: 'APPROVE_L2',
        actorPrincipalId: 'checker-block-2',
        clientDelta: invAfterBlock.delta,
      });
      expect(playBlock.newStatus).toBe('MITIGATED');
      expect(playBlock.createdShieldRule).toBeDefined();
    });

    it('ignores pending, revoked, and expired HITL feedback and lets hard security rules override unsafe feedback', () => {
      // 3. Pending feedback has NO effect on playbook
      const sidPending = `cr1-hitl-pending-${Date.now()}`;
      resetSessionDelta(sidPending);
      const pendingFb = createHitlFeedbackInSession({
        sessionId: sidPending,
        alertId: 'ALT-FPR-004',
        feedbackDecision: 'FORCE_BLOCK',
        targetScope: 'ALERT_CASE',
        reasonCode: 'ANALYST_ESCALATION',
        analystRationale: 'L1 pending proposal',
        actorPrincipalId: 'maker-1',
        actorRole: 'L1_MAKER',
      });
      expect(pendingFb.feedbackRecord.status).toBe('PENDING_APPROVAL');
      const playPending = executePlaybookApproval({
        sessionId: sidPending,
        alertId: 'ALT-FPR-004',
        mode: 'APPROVE_L2',
        actorPrincipalId: 'checker-1',
        clientDelta: pendingFb.delta,
      });
      expect(playPending.newStatus).toBe('DISMISSED_SAFE');

      // 4. Revoked feedback has NO effect on playbook
      const sidRevoked = `cr1-hitl-revoked-${Date.now()}`;
      resetSessionDelta(sidRevoked);
      const activeFb = createHitlFeedbackInSession({
        sessionId: sidRevoked,
        alertId: 'ALT-FPR-004',
        feedbackDecision: 'FORCE_BLOCK',
        targetScope: 'ALERT_CASE',
        reasonCode: 'ANALYST_ESCALATION',
        analystRationale: 'Temporarily flagged',
        actorPrincipalId: 'checker-1',
        actorRole: 'L2_CHECKER',
      });
      const revokedFb = moderateHitlFeedbackInSession({
        sessionId: sidRevoked,
        feedbackId: activeFb.feedbackRecord.feedbackId,
        moderationAction: 'REVOKE',
        actorPrincipalId: 'checker-1',
        actorRole: 'L2_CHECKER',
        clientDelta: activeFb.delta,
      });
      const playRevoked = executePlaybookApproval({
        sessionId: sidRevoked,
        alertId: 'ALT-FPR-004',
        mode: 'APPROVE_L2',
        actorPrincipalId: 'checker-2',
        clientDelta: revokedFb.delta,
      });
      expect(playRevoked.newStatus).toBe('DISMISSED_SAFE');

      // 5. Expired feedback has NO effect on playbook
      const sidExpired = `cr1-hitl-expired-${Date.now()}`;
      resetSessionDelta(sidExpired);
      const fbToExpire = createHitlFeedbackInSession({
        sessionId: sidExpired,
        alertId: 'ALT-FPR-004',
        feedbackDecision: 'FORCE_BLOCK',
        targetScope: 'ALERT_CASE',
        reasonCode: 'ANALYST_ESCALATION',
        analystRationale: 'Expired rule',
        actorPrincipalId: 'checker-1',
        actorRole: 'L2_CHECKER',
      });
      const expiredMem: HitlFeedbackMemoryRecord[] = (
        fbToExpire.delta.hitlFeedbackMemory ?? []
      ).map((rec) => ({
        ...rec,
        expiresAt: new Date(Date.now() - 60_000).toISOString(),
      }));
      const expiredDelta = saveSessionDelta(sidExpired, {
        ...fbToExpire.delta,
        hitlFeedbackMemory: expiredMem,
      });
      const playExpired = executePlaybookApproval({
        sessionId: sidExpired,
        alertId: 'ALT-FPR-004',
        mode: 'APPROVE_L2',
        actorPrincipalId: 'checker-2',
        clientDelta: expiredDelta,
      });
      expect(playExpired.newStatus).toBe('DISMISSED_SAFE');

      // 6. Hard security rules (ATO / Malicious URL) override unsafe OVERRIDE_SAFE feedback
      const sidHard = `cr1-hitl-hard-${Date.now()}`;
      resetSessionDelta(sidHard);
      const unsafeOverride = createHitlFeedbackInSession({
        sessionId: sidHard,
        alertId: 'ALT-ATO-001',
        feedbackDecision: 'OVERRIDE_SAFE',
        targetScope: 'ALERT_CASE',
        reasonCode: 'FALSE_POSITIVE_CONTEXT',
        analystRationale: 'Attempt unsafe override on ATO alert',
        actorPrincipalId: 'checker-1',
        actorRole: 'L2_CHECKER',
      });
      const playHard = executePlaybookApproval({
        sessionId: sidHard,
        alertId: 'ALT-ATO-001',
        mode: 'APPROVE_L2',
        actorPrincipalId: 'checker-2',
        clientDelta: unsafeOverride.delta,
      });
      expect(playHard.newStatus).toBe('MITIGATED');
      expect(playHard.createdShieldRule).toBeDefined();
    });
  });

  // ─── WORKSTREAM B: Financial Idempotency Replay Consistency ───────────────────────────
  describe('Workstream B: Financial Idempotency Replay Consistency', () => {
    it('returns exact historical settled decision even after recipient is later blocked, rejects payload mismatch with HTTP 409, and handles concurrent identical requests safely', async () => {
      const sid = `cr1-idem-${Date.now()}`;
      const token = createSignedSessionToken({
        sessionId: sid,
        role: 'L2_CHECKER',
        principalId: 'cr1-checker',
      });
      const idemKey = `CR1-IDEM-KEY-${Date.now()}`;

      // 1. First transfer settles successfully (5M to ACC-HOSP-800)
      const firstRes = await walletPost(
        makeReq({
          url: 'http://localhost:3000/api/wallet',
          sessionId: sid,
          cookieToken: token,
          body: {
            senderAccountId: 'ACC-USR-103',
            recipientAccountIdOrNumber: '1188999000888',
            amountVnd: 5_000_000,
            message: 'Thanh toan hoa don CR1',
            idempotencyKey: idemKey,
          },
        })
      );
      expect(firstRes.status).toBe(200);
      const firstData = await firstRes.json();
      expect(firstData.transaction.status).toBe('SETTLED');
      expect(firstData.decision.decision).toBe('ALLOWED_SAFE');
      expect(firstData.senderBalanceVnd).toBe(40_000_000);
      expect(firstData.delta.ledgerEntries).toHaveLength(2);

      // 2-4. Identical replay returns exact original result without changing balances or ledger entries
      const replayRes = await walletPost(
        makeReq({
          url: 'http://localhost:3000/api/wallet',
          sessionId: sid,
          cookieToken: token,
          body: {
            senderAccountId: 'ACC-USR-103',
            recipientAccountIdOrNumber: '1188999000888',
            amountVnd: 5_000_000,
            message: 'Thanh toan hoa don CR1',
            idempotencyKey: idemKey,
            clientDelta: firstData.delta,
          },
        })
      );
      expect(replayRes.status).toBe(200);
      const replayData = await replayRes.json();
      expect(replayData.transaction.id).toBe(firstData.transaction.id);
      expect(replayData.decision.decision).toBe('ALLOWED_SAFE');
      expect(replayData.decision.transactionStatus).toBe('SETTLED');
      expect(replayData.decision.explanationVi).toBe(firstData.decision.explanationVi);
      expect(replayData.decision.idempotentReplay).toBe(true);
      expect(replayData.senderBalanceVnd).toBe(40_000_000);
      expect(replayData.delta.ledgerEntries).toHaveLength(2);

      // 5. Block the recipient (1188999000888) AFTER first transfer settled, then replay SAME idempotencyKey
      const blockRuleRes = await playbookPost(
        makeReq({
          url: 'http://localhost:3000/api/playbook',
          sessionId: sid,
          cookieToken: token,
          body: {
            mode: 'ADD_CUSTOM_SHIELD',
            targetAccountNumber: '1188999000888',
            reasonVi: 'Test shield added after original settlement',
            clientDelta: replayData.delta,
          },
        })
      );
      expect(blockRuleRes.status).toBe(200);
      const afterBlockDelta = (await blockRuleRes.json()).delta;

      const replayAfterBlockRes = await walletPost(
        makeReq({
          url: 'http://localhost:3000/api/wallet',
          sessionId: sid,
          cookieToken: token,
          body: {
            senderAccountId: 'ACC-USR-103',
            recipientAccountIdOrNumber: '1188999000888',
            amountVnd: 5_000_000,
            message: 'Thanh toan hoa don CR1',
            idempotencyKey: idemKey,
            clientDelta: afterBlockDelta,
          },
        })
      );
      expect(replayAfterBlockRes.status).toBe(200);
      const replayAfterBlock = await replayAfterBlockRes.json();
      expect(replayAfterBlock.transaction.id).toBe(firstData.transaction.id);
      expect(replayAfterBlock.decision.decision).toBe('ALLOWED_SAFE');
      expect(replayAfterBlock.decision.transactionStatus).toBe('SETTLED');
      expect(replayAfterBlock.decision.idempotentReplay).toBe(true);

      // 6. Reusing same idempotencyKey with a DIFFERENT amount -> HTTP 409 conflict
      const diffAmountRes = await walletPost(
        makeReq({
          url: 'http://localhost:3000/api/wallet',
          sessionId: sid,
          cookieToken: token,
          body: {
            senderAccountId: 'ACC-USR-103',
            recipientAccountIdOrNumber: '1188999000888',
            amountVnd: 7_500_000,
            message: 'Thanh toan hoa don CR1',
            idempotencyKey: idemKey,
            clientDelta: afterBlockDelta,
          },
        })
      );
      expect(diffAmountRes.status).toBe(409);
      expect((await diffAmountRes.json()).code).toBe('IDEMPOTENCY_KEY_CONFLICT');

      // 7. Reusing same idempotencyKey with a DIFFERENT recipient -> HTTP 409 conflict
      const diffRecipRes = await walletPost(
        makeReq({
          url: 'http://localhost:3000/api/wallet',
          sessionId: sid,
          cookieToken: token,
          body: {
            senderAccountId: 'ACC-USR-103',
            recipientAccountIdOrNumber: '1903999888777',
            amountVnd: 5_000_000,
            message: 'Thanh toan hoa don CR1',
            idempotencyKey: idemKey,
            clientDelta: afterBlockDelta,
          },
        })
      );
      expect(diffRecipRes.status).toBe(409);
      expect((await diffRecipRes.json()).code).toBe('IDEMPOTENCY_KEY_CONFLICT');

      // Direct domain error check
      expect(() =>
        simulateWalletTransferInSession({
          sessionId: sid,
          transfer: {
            senderAccountId: 'ACC-USR-103',
            senderName: 'Test',
            recipientAccountIdOrNumber: '1903111222333',
            amountVnd: 5_000_000,
            message: 'Thanh toan hoa don CR1',
            idempotencyKey: idemKey,
          },
          clientDelta: afterBlockDelta,
        })
      ).toThrow(IdempotencyKeyConflictError);

      // 8. Concurrent identical requests create only ONE effective transaction and ONE ledger pair
      const concSid = `cr1-conc-idem-${Date.now()}`;
      const concToken = createSignedSessionToken({
        sessionId: concSid,
        role: 'END_USER',
        principalId: 'conc-user',
      });
      const concKey = `CONC-KEY-${Date.now()}`;
      const [c1, c2] = await Promise.all([
        walletPost(
          makeReq({
            url: 'http://localhost:3000/api/wallet',
            sessionId: concSid,
            cookieToken: concToken,
            body: {
              senderAccountId: 'ACC-USR-103',
              recipientAccountIdOrNumber: '1188999000888',
              amountVnd: 3_000_000,
              message: 'Concurrent P2P',
              idempotencyKey: concKey,
            },
          })
        ),
        walletPost(
          makeReq({
            url: 'http://localhost:3000/api/wallet',
            sessionId: concSid,
            cookieToken: concToken,
            body: {
              senderAccountId: 'ACC-USR-103',
              recipientAccountIdOrNumber: '1188999000888',
              amountVnd: 3_000_000,
              message: 'Concurrent P2P',
              idempotencyKey: concKey,
            },
          })
        ),
      ]);
      expect(c1.status).toBe(200);
      expect(c2.status).toBe(200);
      const j1 = await c1.json();
      const j2 = await c2.json();
      expect(j1.transaction.id).toBe(j2.transaction.id);
      expect(j1.senderBalanceVnd).toBe(42_000_000);
      expect(j2.senderBalanceVnd).toBe(42_000_000);
      expect(j2.delta.ledgerEntries).toHaveLength(2);
    });
  });

  // ─── WORKSTREAM C: /api/workspace Auth & Cross-Session Isolation ──────────────────────
  describe('Workstream C: /api/workspace Authentication & Cross-Session Isolation', () => {
    it('enforces signed cookie auth, rejects forged headers & cross-session access, preserves /api/session bootstrap, and blocks judge-default-session in strict mode', async () => {
      const sidA = `cr1-user-a-${Date.now()}`;
      const sidB = `cr1-user-b-${Date.now()}`;

      // 1. GET without authentication -> 401
      const noAuthGet = await workspaceGet(
        makeReq({ url: 'http://localhost:3000/api/workspace', method: 'GET' })
      );
      expect(noAuthGet.status).toBe(401);

      // 2. POST without authentication -> 401
      const noAuthPost = await workspacePost(
        makeReq({ url: 'http://localhost:3000/api/workspace', method: 'POST', body: {} })
      );
      expect(noAuthPost.status).toBe(401);

      // 3. Forged x-workspace-session header without signed cookie -> 401
      const forgedHeaderGet = await workspaceGet(
        makeReq({
          url: 'http://localhost:3000/api/workspace',
          method: 'GET',
          sessionId: sidB,
        })
      );
      expect(forgedHeaderGet.status).toBe(401);

      // 8. Bootstrap through /api/session for User A and User B
      const bootARes = await sessionPost(
        makeReq({
          url: 'http://localhost:3000/api/session',
          body: { sessionId: sidA, role: 'L2_CHECKER' },
        })
      );
      expect(bootARes.status).toBe(200);
      const cookieA = bootARes.cookies.get(SESSION_COOKIE_NAME)?.value!;
      expect(cookieA).toBeTruthy();

      const bootBRes = await sessionPost(
        makeReq({
          url: 'http://localhost:3000/api/session',
          body: { sessionId: sidB, role: 'L2_CHECKER' },
        })
      );
      expect(bootBRes.status).toBe(200);
      const cookieB = bootBRes.cookies.get(SESSION_COOKIE_NAME)?.value!;

      // User B mutates its own workspace so sidB exists on server
      const mutateB = await playbookPost(
        makeReq({
          url: 'http://localhost:3000/api/playbook',
          sessionId: sidB,
          cookieToken: cookieB,
          body: { alertId: 'ALT-APP-003', mode: 'APPROVE_L2' },
        })
      );
      expect(mutateB.status).toBe(200);
      const deltaB = (await mutateB.json()).delta;

      // 4. User A cannot read User B's workspace (mismatched header -> 401)
      const crossReadRes = await workspaceGet(
        makeReq({
          url: 'http://localhost:3000/api/workspace',
          method: 'GET',
          sessionId: sidB,
          cookieToken: cookieA,
        })
      );
      expect(crossReadRes.status).toBe(401);

      // 5. User A cannot overwrite User B's workspace via header OR clientDelta.sessionId OR /api/session takeover
      const crossPostHeaderRes = await workspacePost(
        makeReq({
          url: 'http://localhost:3000/api/workspace',
          method: 'POST',
          sessionId: sidB,
          cookieToken: cookieA,
          body: { clientDelta: deltaB },
        })
      );
      expect(crossPostHeaderRes.status).toBe(401);

      const crossPostBodyRes = await workspacePost(
        makeReq({
          url: 'http://localhost:3000/api/workspace',
          method: 'POST',
          sessionId: sidA,
          cookieToken: cookieA,
          body: { clientDelta: { ...deltaB, sessionId: sidB } },
        })
      );
      expect(crossPostBodyRes.status).toBe(403);

      // Unauthenticated attacker trying to mint a cookie for existing sidB via /api/session -> 403 SESSION_OWNERSHIP_REQUIRED
      const hijackSessionRes = await sessionPost(
        makeReq({
          url: 'http://localhost:3000/api/session',
          body: { sessionId: sidB, role: 'L2_CHECKER' },
        })
      );
      expect(hijackSessionRes.status).toBe(403);

      // 6. Invalid or expired cookie -> 401
      const expiredCookie = createSignedSessionToken({
        sessionId: sidA,
        role: 'L2_CHECKER',
        issuedAtMs: Date.now() - SESSION_TTL_MS - 10_000,
      });
      expect(
        (
          await workspaceGet(
            makeReq({
              url: 'http://localhost:3000/api/workspace',
              method: 'GET',
              sessionId: sidA,
              cookieToken: expiredCookie,
            })
          )
        ).status
      ).toBe(401);
      expect(
        (
          await workspaceGet(
            makeReq({
              url: 'http://localhost:3000/api/workspace',
              method: 'GET',
              sessionId: sidA,
              cookieToken: `${cookieA}tampered`,
            })
          )
        ).status
      ).toBe(401);

      // 7. Valid session cookie accesses its own workspace -> 200
      const ownWsRes = await workspaceGet(
        makeReq({
          url: 'http://localhost:3000/api/workspace',
          method: 'GET',
          sessionId: sidA,
          cookieToken: cookieA,
        })
      );
      expect(ownWsRes.status).toBe(200);
      const ownWsJson = await ownWsRes.json();
      expect(ownWsJson.state.sessionId).toBe(sidA);

      // 9. Demo persona switch on own session preserves session isolation (cannot switch to sidB)
      const switchSelfRes = await sessionPost(
        makeReq({
          url: 'http://localhost:3000/api/session',
          sessionId: sidA,
          cookieToken: cookieA,
          body: { sessionId: sidA, role: 'L1_MAKER' },
        })
      );
      expect(switchSelfRes.status).toBe(200);
      const crossSwitchRes = await sessionPost(
        makeReq({
          url: 'http://localhost:3000/api/session',
          sessionId: sidA,
          cookieToken: cookieA,
          body: { sessionId: sidB, role: 'L2_CHECKER' },
        })
      );
      expect(crossSwitchRes.status).toBe(403);

      // 10. Production strict mode never falls back to judge-default-session
      process.env.AEGIS_REQUIRE_STRICT_SECRETS = 'true';
      process.env.AEGIS_SESSION_SECRET = 'cr1-strict-session-secret-0123456789abcdef';
      process.env.AEGIS_PII_HMAC_KEY = 'cr1-strict-pii-hmac-secret-fedcba9876543210';

      const defaultSidRejected = await sessionPost(
        makeReq({
          url: 'http://localhost:3000/api/session',
          body: { sessionId: 'judge-default-session', role: 'L2_CHECKER' },
        })
      );
      expect(defaultSidRejected.status).toBe(403);

      const omittedSidRandom = await sessionPost(
        makeReq({
          url: 'http://localhost:3000/api/session',
          body: { role: 'L2_CHECKER' },
        })
      );
      expect(omittedSidRandom.status).toBe(200);
      const omittedBody = await omittedSidRandom.json();
      expect(omittedBody.sessionId).not.toBe('judge-default-session');
      expect(omittedBody.sessionId).toMatch(/^sess-[0-9a-f]{24}$/);
    });
  });

  // ─── WORKSTREAM D: QĐ 2345 & TT 77/2025 Compliance Accuracy ───────────────────────────
  describe('Workstream D: QĐ 2345/QĐ-NHNN and TT 77/2025/TT-NHNN Compliance Accuracy', () => {
    it('evaluates all 10 required QĐ 2345 and TT 77/2025 scenarios accurately without overclaiming verification or certification', () => {
      // 1. Below-threshold transaction (G = 9,999,999 VND)
      const below = evaluateQd2345Compliance({
        customerType: 'INDIVIDUAL',
        transactionCategory: 'INTERPERSONAL_P2P_AND_VIETQR_TRANSFER',
        singleTransactionAmountVnd: 9_999_999,
      });
      expect(below.biometricVerificationRequired).toBe(false);
      expect(below.biometricVerificationStatus).toBe('NOT_REQUIRED');

      // 2. Exactly at threshold (G = 10,000,000 VND -> QĐ 2345 requires > 10M)
      const exact = evaluateQd2345Compliance({
        customerType: 'INDIVIDUAL',
        transactionCategory: 'INTERPERSONAL_P2P_AND_VIETQR_TRANSFER',
        singleTransactionAmountVnd: 10_000_000,
      });
      expect(exact.biometricVerificationRequired).toBe(false);
      expect(exact.biometricVerificationStatus).toBe('NOT_REQUIRED');

      // 3. Above-threshold transaction (G = 10,000,001 VND)
      const above = evaluateQd2345Compliance({
        customerType: 'INDIVIDUAL',
        transactionCategory: 'INTERPERSONAL_P2P_AND_VIETQR_TRANSFER',
        singleTransactionAmountVnd: 10_000_001,
        hasAuthTelemetry: true,
      });
      expect(above.biometricVerificationRequired).toBe(true);
      // 8. Requirement-triggered does NOT equal VERIFIED
      expect(above.biometricVerificationStatus).toBe('REQUIRED');
      expect(above.biometricVerificationEvidence).toEqual([]);

      // 4. Daily accumulated amount reaches/exceeds T_ksth > 20,000,000 VND (three 8M transfers = 24M)
      const dailyExceeds = evaluateQd2345Compliance({
        customerType: 'INDIVIDUAL',
        transactionCategory: 'INTERPERSONAL_P2P_AND_VIETQR_TRANSFER',
        singleTransactionAmountVnd: 8_000_000,
        dailyPriorTransactions: [
          { amountVnd: 8_000_000, timestamp: '2026-11-22T08:00:00+07:00', authenticationCategory: 'TYPE_B_OTP' },
          { amountVnd: 8_000_000, timestamp: '2026-11-22T09:00:00+07:00', authenticationCategory: 'TYPE_B_OTP' },
        ],
        hasAuthTelemetry: true,
      });
      expect(dailyExceeds.dailyAccumulatedTotalTVnd).toBe(24_000_000);
      expect(dailyExceeds.dailyAccumulatedUnauthenticatedTksthVnd).toBe(24_000_000);
      expect(dailyExceeds.biometricVerificationRequired).toBe(true);

      // 5. Accumulated T_ksth resets to 0 after biometric authentication category (TYPE_C_BIOMETRIC)
      const dailyReset = evaluateQd2345Compliance({
        customerType: 'INDIVIDUAL',
        transactionCategory: 'INTERPERSONAL_P2P_AND_VIETQR_TRANSFER',
        singleTransactionAmountVnd: 8_000_000,
        dailyPriorTransactions: [
          { amountVnd: 15_000_000, timestamp: '2026-11-22T08:00:00+07:00', authenticationCategory: 'TYPE_C_BIOMETRIC' },
          { amountVnd: 8_000_000, timestamp: '2026-11-22T09:00:00+07:00', authenticationCategory: 'TYPE_B_OTP' },
        ],
      });
      expect(dailyReset.dailyAccumulatedTotalTVnd).toBe(31_000_000);
      expect(dailyReset.dailyAccumulatedUnauthenticatedTksthVnd).toBe(16_000_000);
      expect(dailyReset.biometricVerificationRequired).toBe(false);

      // 6. Different transaction groups use appropriate classification (merchant goods/services 35M <= 100M -> not required; self-owned -> not required; new device 500k -> required)
      const merchantGoods = evaluateQd2345Compliance({
        customerType: 'INDIVIDUAL',
        transactionCategory: 'GOODS_SERVICES_PAYMENT_LEGAL_MERCHANT',
        singleTransactionAmountVnd: 35_000_000,
      });
      expect(merchantGoods.applicableSingleTxThresholdVnd).toBe(100_000_000);
      expect(merchantGoods.biometricVerificationRequired).toBe(false);

      const newDeviceSmall = evaluateQd2345Compliance({
        customerType: 'INDIVIDUAL',
        transactionCategory: 'INTERPERSONAL_P2P_AND_VIETQR_TRANSFER',
        singleTransactionAmountVnd: 500_000,
        isFirstTimeOrNewDevice: true,
      });
      expect(newDeviceSmall.biometricVerificationRequired).toBe(true);

      // 7. Individual and organizational customer rules are NOT conflated
      const orgTx = evaluateQd2345Compliance({
        customerType: 'ORGANIZATION',
        singleTransactionAmountVnd: 50_000_000,
      });
      expect(orgTx.applicableAuthenticationCategory).toBe('TYPE_ORG_DIGITAL_SIGNATURE');
      expect(orgTx.biometricVerificationRequired).toBe(false);

      // 9 & 10. TT 77/2025 Article 8(4) simulated signals vs browser limitation & Article 11(5)(c) PAD certification never claimed verified
      const tt77 = evaluateTt77Compliance({
        devices: SEED_DEVICES,
        authLogs: SEED_AUTH_LOGS,
        flaggedDeviceId: 'DEV-EMU-666',
      });
      expect(tt77.article8Clause4.mappingStatus).toBe('REQUIREMENT_MAPPED');
      expect(tt77.article8Clause4.controls.find((c) => c.indicator === 'emulatorOrVirtualMachine')?.status).toBe(
        'SIMULATED_SIGNAL'
      );
      expect(tt77.article8Clause4.controls.find((c) => c.indicator === 'adbEnabled')?.status).toBe(
        'NOT_IMPLEMENTED'
      );
      // Article 8(4) must NOT list virtual camera as an explicit Article 8(4) control
      expect(
        tt77.article8Clause4.controls.some((c) => String(c.indicator).toLowerCase().includes('camera'))
      ).toBe(false);
      expect(tt77.article11Clause5cPad.certificationStatus).toBe('CERTIFICATION_NOT_VERIFIED');

      // Full dossier verification for low-amount alert (ALT-BLG-002 = 6,000,000 VND <= 10M -> q2345BiometricThresholdTriggered MUST be false!)
      const blgAlert = SEED_ALERTS.find((a) => a.id === 'ALT-BLG-002')!;
      const blgForensics = runDeterministicForensicsSuite({
        alert: blgAlert,
        accounts: SEED_ACCOUNTS,
        devices: SEED_DEVICES,
        authLogs: SEED_AUTH_LOGS,
        transactions: SEED_TRANSACTIONS,
        apiEvents: SEED_API_EVENTS,
        evidences: SEED_EVIDENCES,
      });
      const blgDossier = buildComplianceIncidentDossier({
        alert: blgAlert,
        forensics: blgForensics,
        auditLogs: [],
        accounts: SEED_ACCOUNTS,
        transactions: SEED_TRANSACTIONS,
        authLogs: SEED_AUTH_LOGS,
        devices: SEED_DEVICES,
      });
      expect(blgDossier.simoPiiMaskedPayload.q2345BiometricThresholdTriggered).toBe(false);
      expect(blgDossier.simoPiiMaskedPayload.biometricVerificationStatus).toBe('NOT_REQUIRED');
      expect(blgDossier.simoPiiMaskedPayload.tt77PadCertificationStatus).toBe('CERTIFICATION_NOT_VERIFIED');
    });
  });

  // ─── WORKSTREAM E: Evidence Integrity, Dashboard KPIs & Forensics Metrics ─────────────
  describe('Workstream E: Dashboard KPIs, Dynamic Forensics Summary & Timestamp Flow Velocity', () => {
    it('computes honest dashboard KPIs with zero fabricated offsets across empty, single, and updated states', () => {
      // Empty state
      const emptyKpi = computeDashboardKpiMetrics({
        alerts: [],
        transactions: [],
        clawbackReceipts: [],
        reportsByAlertId: {},
        selfRescuedAmountVnd: 0,
      });
      expect(emptyKpi.alertsMarkedBenignCount).toBe(0);
      expect(emptyKpi.averageInvestigationLatencyMs).toBeNull();
      expect(emptyKpi.totalConfirmedBlockedAndRecoveredVnd).toBe(0);
      expect(emptyKpi.transactionsHeldForReviewVnd).toBe(0);

      // Mitigated alerts with ZERO blocked/held transactions must NOT fabricate 25,000,000 * mitigatedCount!
      const mitigatedNoTx = computeDashboardKpiMetrics({
        alerts: [{ ...SEED_ALERTS[0]!, status: 'MITIGATED' }],
        transactions: [],
        clawbackReceipts: [],
        reportsByAlertId: {},
      });
      expect(mitigatedNoTx.totalConfirmedBlockedAndRecoveredVnd).toBe(0);
      expect(mitigatedNoTx.alertsMarkedBenignCount).toBe(0);

      // Populated state with real measured reports & DISMISSED_SAFE alert
      const populated = computeDashboardKpiMetrics({
        alerts: [
          { ...SEED_ALERTS[0]!, status: 'MITIGATED' },
          { ...SEED_ALERTS[3]!, status: 'DISMISSED_SAFE' },
        ],
        transactions: [
          { ...SEED_TRANSACTIONS[0]!, status: 'BLOCKED', amountVnd: 18_000_000 },
          { ...SEED_TRANSACTIONS[2]!, status: 'HELD', amountVnd: 16_000_000 },
        ],
        clawbackReceipts: [],
        reportsByAlertId: {
          'ALT-APP-003': {
            alertId: 'ALT-APP-003',
            classification: 'CONFIRMED_APP_SCAM',
            confidenceScore: 95,
            deterministicRiskScore: 95,
            executiveSummaryVi: 'Test',
            keyFindingsVi: [],
            citedEvidenceIds: [],
            toolTraceSteps: [],
            recommendedActions: [],
            userShieldWarningVi: '',
            modelUsed: 'deterministic-forensics-engine-v2',
            latencyMs: 120,
            generatedAt: '2026-11-22T10:00:00Z',
          },
          'ALT-FPR-004': {
            alertId: 'ALT-FPR-004',
            classification: 'FALSE_POSITIVE_SAFE',
            confidenceScore: 96,
            deterministicRiskScore: 14,
            executiveSummaryVi: 'Safe',
            keyFindingsVi: [],
            citedEvidenceIds: [],
            toolTraceSteps: [],
            recommendedActions: [],
            userShieldWarningVi: '',
            modelUsed: 'deterministic-forensics-engine-v2',
            latencyMs: 80,
            generatedAt: '2026-11-22T10:01:00Z',
          },
        },
      });
      expect(populated.alertsMarkedBenignCount).toBe(1);
      expect(populated.averageInvestigationLatencyMs).toBe(100);
      expect(populated.confirmedBlockedTransactionVnd).toBe(18_000_000);
      expect(populated.transactionsHeldForReviewVnd).toBe(16_000_000);
    });

    it('synchronizes step2 summaryVi with computed metrics and evaluates timestamp-based flowVelocity edge cases', () => {
      // Dynamic narrative matches computed quantitative metrics (unequal split amounts -> Entropy != 0.99!)
      const customAlert: FraudAlert = {
        ...SEED_ALERTS[0]!,
        id: 'ALT-CR1-UNEVEN',
      };
      const unevenTxs: Transaction[] = [
        { ...SEED_TRANSACTIONS[0]!, id: 'TX-U1', alertId: customAlert.id, amountVnd: 5_000_000, timestamp: '2026-11-22T10:02:00Z' },
        { ...SEED_TRANSACTIONS[1]!, id: 'TX-U2', alertId: customAlert.id, amountVnd: 20_000_000, timestamp: '2026-11-22T10:00:00Z' },
        { ...SEED_TRANSACTIONS[2]!, id: 'TX-U3', alertId: customAlert.id, amountVnd: 35_000_000, timestamp: '2026-11-22T10:04:00Z' },
      ];
      const suite = runDeterministicForensicsSuite({
        alert: customAlert,
        accounts: SEED_ACCOUNTS,
        devices: SEED_DEVICES,
        authLogs: SEED_AUTH_LOGS,
        transactions: unevenTxs,
        apiEvents: [],
        evidences: [],
      });
      const step2 = suite.toolTraceSteps.find((s) => s.toolName === 'trace_money_flow_graph')!;
      expect(step2.summaryVi).toContain(
        `Entropy = ${suite.quantitativeMetrics.smurfingEntropyIndex.toFixed(2)}`
      );
      expect(step2.summaryVi).not.toContain('Entropy = 0.99');
      // Out-of-order events spanning 4 minutes (60M / 4 min = 15M VND/min)
      expect(suite.quantitativeMetrics.flowVelocityStatus).toBe('MEASURED_INTERVAL');
      expect(suite.quantitativeMetrics.flowVelocityVndPerMin).toBe(15_000_000);

      // Edge cases for evaluateFlowVelocityMetrics
      expect(evaluateFlowVelocityMetrics([]).status).toBe('NO_TRANSACTIONS');
      expect(
        evaluateFlowVelocityMetrics([unevenTxs[0]!]).status
      ).toBe('SINGLE_EVENT_NO_WINDOW');
      expect(
        evaluateFlowVelocityMetrics([
          { ...unevenTxs[0]!, timestamp: '2026-11-22T10:00:00Z' },
          { ...unevenTxs[1]!, timestamp: '2026-11-22T10:00:00Z' },
        ]).status
      ).toBe('ZERO_ELAPSED_TIME');
      const malformed = evaluateFlowVelocityMetrics([
        { ...unevenTxs[0]!, timestamp: 'not-a-date' },
        { ...unevenTxs[1]!, timestamp: '' },
      ]);
      expect(malformed.status).toBe('INVALID_TIMESTAMP_DATA');
      expect(malformed.velocityVndPerMin).toBe(0);
    });
  });

  // ─── WORKSTREAM F: Ledger Invariants & SQL Audit Log Persistence ──────────────────────
  describe('Workstream F: Ledger Balance Invariants & SQL Audit Log Persistence', () => {
    it('throws LedgerInvariantError on negative intermediate balance or unbalanced entry sequence instead of silently clamping to 0', () => {
      const accounts: Account[] = [
        { ...SEED_ACCOUNTS[0]!, id: 'ACC-A', balanceVnd: 1_000_000 },
        { ...SEED_ACCOUNTS[1]!, id: 'ACC-B', balanceVnd: 5_000_000 },
      ];

      // Overdraft attempt: debit 2,000,000 from ACC-A (only has 1,000,000) before any credit arrives
      const overdraftPair = buildBalancedLedgerPair({
        txId: 'TXN-OVERDRAFT-1',
        debitAccountId: 'ACC-A',
        creditAccountId: 'ACC-B',
        amountVnd: 2_000_000,
        status: 'SETTLED',
        createdAt: '2026-11-22T10:00:00Z',
      });
      const creditLaterPair = buildBalancedLedgerPair({
        txId: 'TXN-CREDIT-LATER',
        debitAccountId: 'ACC-B',
        creditAccountId: 'ACC-A',
        amountVnd: 3_000_000,
        status: 'SETTLED',
        createdAt: '2026-11-22T10:01:00Z',
      });

      const invCheck = evaluateLedgerBalanceInvariants(accounts, [
        ...overdraftPair,
        ...creditLaterPair,
      ]);
      expect(invCheck.valid).toBe(false);
      expect(invCheck.violations[0]?.violationCode).toBe('NEGATIVE_INTERMEDIATE_BALANCE');
      expect(invCheck.violations[0]?.observedBalanceVnd).toBe(-1_000_000);

      expect(() =>
        computeAccountBalancesFromLedger(accounts, [...overdraftPair, ...creditLaterPair])
      ).toThrow(LedgerInvariantError);

      // Malformed single-legged entry sequence (unbalanced DEBIT without CREDIT)
      const unbalancedEntry: LedgerEntryRecord[] = [
        {
          id: 'LDG-UNBAL-1',
          txId: 'TXN-UNBAL-1',
          accountId: 'ACC-A',
          entryType: 'DEBIT',
          amountVnd: 500_000,
          currency: 'VND',
          status: 'SETTLED',
          createdAt: '2026-11-22T10:00:00Z',
        },
      ];
      expect(() => computeAccountBalancesFromLedger(accounts, unbalancedEntry)).toThrow(
        LedgerInvariantError
      );
    });

    it('persists audit logs atomically to aegis_audit_logs, deduplicates retries, and rolls back the entire transaction on audit write failure', async () => {
      const spyPool = new Cr1AuditSpyPool();
      const adapter = new PostgresPersistenceAdapter(spyPool);
      setPersistenceAdapterForTest(adapter);

      const sid = `cr1-sql-audit-${Date.now()}`;
      const delta1 = saveSessionDelta(sid, {
        ...createEmptyDelta(sid),
        auditLogs: [
          ...createEmptyDelta(sid).auditLogs,
          {
            id: 'AUD-CR1-001',
            alertId: 'ALT-APP-003',
            actor: 'OPS_ANALYST',
            action: 'PLAYBOOK_APPROVED_AND_SHIELD_ACTIVE',
            detailsVi: 'L2 approved CR1 test',
            timestamp: '2026-11-22T11:00:00Z',
          },
        ],
      });

      await adapter.commitSession({
        sessionId: sid,
        principalId: 'checker-sql',
        expectedRevision: 0,
        nextDelta: delta1,
        expiresAtIso: new Date(Date.now() + 86_400_000).toISOString(),
      });

      // Verify both audit rows persisted with session-scoped keys and matching actor/timestamp
      expect(spyPool.auditRows.size).toBe(2);
      const inserted = spyPool.auditRows.get(`${sid}:AUD-CR1-001`);
      expect(inserted?.actor).toBe('OPS_ANALYST');
      expect(inserted?.created_at).toBe('2026-11-22T11:00:00Z');
      expect(inserted?.action).toBe('PLAYBOOK_APPROVED_AND_SHIELD_ACTIVE');

      // Duplicate audit event on next revision does NOT create duplicate SQL rows
      const delta2 = saveSessionDelta(sid, {
        ...delta1,
        auditLogs: [
          ...delta1.auditLogs,
          {
            id: 'AUD-CR1-002',
            alertId: 'ALT-APP-003',
            actor: 'CONSUMER_SHIELD',
            action: 'REALTIME_WALLET_TRANSFER_INTERCEPTED',
            detailsVi: 'Shield blocked test',
            timestamp: '2026-11-22T11:01:00Z',
          },
        ],
      });
      await adapter.commitSession({
        sessionId: sid,
        principalId: 'checker-sql',
        expectedRevision: delta1.stateRevision!,
        nextDelta: delta2,
        expiresAtIso: new Date(Date.now() + 86_400_000).toISOString(),
      });
      expect(spyPool.auditRows.size).toBe(3);

      // Failed audit write rolls back the entire critical mutation (session revision stays at rev 2!)
      spyPool.failNextAuditInsert = true;
      const delta3 = saveSessionDelta(sid, {
        ...delta2,
        frozenAccountIds: ['ACC-MULE-903'],
        auditLogs: [
          ...delta2.auditLogs,
          {
            id: 'AUD-CR1-FAIL',
            alertId: 'ALT-APP-003',
            actor: 'OPS_ANALYST',
            action: 'SHOULD_ROLLBACK',
            detailsVi: 'Must roll back',
            timestamp: '2026-11-22T11:02:00Z',
          },
        ],
      });

      await expect(
        adapter.commitSession({
          sessionId: sid,
          principalId: 'checker-sql',
          expectedRevision: delta2.stateRevision!,
          nextDelta: delta3,
          expiresAtIso: new Date(Date.now() + 86_400_000).toISOString(),
        })
      ).rejects.toThrow(/Simulated PostgreSQL audit log write failure/);

      expect(spyPool.rolledBackCount).toBe(1);
      expect(spyPool.sessions.get(sid)?.state_revision).toBe(delta2.stateRevision);
      expect(spyPool.auditRows.has(`${sid}:AUD-CR1-FAIL`)).toBe(false);
    });
  });

  // ─── WORKSTREAM G: Merchant Manual Verification Server Boundary ───────────────────────
  describe('Workstream G: Merchant Manual Verification Server Boundary (/api/merchant/verify)', () => {
    it('rejects unauthenticated requests (401) and records server-side audit events across all 5 cases A-E', async () => {
      // Unauthorized -> 401
      const unauthRes = await merchantVerifyPost(
        makeReq({
          url: 'http://localhost:3000/api/merchant/verify',
          body: { claimedTxId: 'TXN-MERCH-OK', claimedAmountVnd: 4_850_000 },
        })
      );
      expect(unauthRes.status).toBe(401);

      const sid = `cr1-merch-srv-${Date.now()}`;
      const token = createSignedSessionToken({
        sessionId: sid,
        role: 'END_USER',
        principalId: 'merchant-cashier-1',
      });

      const cases = [
        { claimedTxId: 'TXN-MERCH-OK', claimedAmountVnd: 4_850_000, merchant: 'ACC-HOSP-800', expected: 'VERIFIED_LEDGER_MATCH' },
        { claimedTxId: 'TXN-MERCH-1K', claimedAmountVnd: 15_000_000, merchant: 'ACC-HOSP-800', expected: 'FORGED_PHOTOSHOP_AMOUNT_MISMATCH' },
        { claimedTxId: 'TXN-GHOST-999', claimedAmountVnd: 12_500_000, merchant: 'ACC-HOSP-800', expected: 'FAKE_RECEIPT_NOT_IN_LEDGER' },
        { claimedTxId: 'TXN-8843', claimedAmountVnd: 16_000_000, merchant: 'ACC-MULE-903', expected: 'BLOCKED_TRANSACTION_NO_SETTLEMENT' },
        { claimedTxId: 'TXN-MERCH-OK', claimedAmountVnd: 4_850_000, merchant: 'ACC-USR-104', expected: 'WRONG_MERCHANT_RECIPIENT' },
      ] as const;

      let lastDelta: SessionDeltaSnapshot | undefined;
      for (const c of cases) {
        const res = await merchantVerifyPost(
          makeReq({
            url: 'http://localhost:3000/api/merchant/verify',
            sessionId: sid,
            cookieToken: token,
            body: {
              claimedTxId: c.claimedTxId,
              claimedAmountVnd: c.claimedAmountVnd,
              merchantAccountIdOrNumber: c.merchant,
              clientDelta: lastDelta,
            },
          })
        );
        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body.verification.verdict).toBe(c.expected);
        expect(body.delta).toBeDefined();
        lastDelta = body.delta;
        expect(
          lastDelta!.auditLogs.some((l) => l.action === `MERCHANT_RECEIPT_${c.expected}`)
        ).toBe(true);
      }
    });
  });

  // ─── WORKSTREAM H: Demo Persona Production Guard ──────────────────────────────────────
  describe('Workstream H: Demo Persona Production Guard', () => {
    it('allows switching in demo mode, blocks switching when AEGIS_ENABLE_DEMO_PERSONA_SWITCH=false or production strict mode, and fails strict readiness if enabled', async () => {
      const sid = `cr1-persona-guard-${Date.now()}`;

      // 1. Demo mode can switch personas (200)
      delete process.env.AEGIS_ENABLE_DEMO_PERSONA_SWITCH;
      delete process.env.AEGIS_PRODUCTION_STRICT_READINESS;
      const demoRes = await sessionPost(
        makeReq({
          url: 'http://localhost:3000/api/session',
          body: { sessionId: sid, role: 'L1_MAKER' },
        })
      );
      expect(demoRes.status).toBe(200);

      // 2. Explicit AEGIS_ENABLE_DEMO_PERSONA_SWITCH=false rejects role switching (403)
      process.env.AEGIS_ENABLE_DEMO_PERSONA_SWITCH = 'false';
      const disabledRes = await sessionPost(
        makeReq({
          url: 'http://localhost:3000/api/session',
          body: { sessionId: `${sid}-2`, role: 'L2_CHECKER' },
        })
      );
      expect(disabledRes.status).toBe(403);
      expect((await disabledRes.json()).code).toBe('DEMO_PERSONA_SWITCH_DISABLED');

      // 3. Production strict readiness rejects demo persona switching (403)
      delete process.env.AEGIS_ENABLE_DEMO_PERSONA_SWITCH;
      process.env.AEGIS_PRODUCTION_STRICT_READINESS = 'true';
      process.env.AEGIS_SESSION_SECRET = 'cr1-prod-strict-session-secret-0123456789';
      process.env.AEGIS_PII_HMAC_KEY = 'cr1-prod-strict-pii-hmac-secret-9876543210';

      const strictSwitchRes = await sessionPost(
        makeReq({
          url: 'http://localhost:3000/api/session',
          body: { sessionId: `${sid}-3`, role: 'L2_CHECKER' },
        })
      );
      expect(strictSwitchRes.status).toBe(403);

      // 4. Production strict readiness FAILS health check (503) if AEGIS_ENABLE_DEMO_PERSONA_SWITCH=true is misconfigured
      process.env.AEGIS_ENABLE_DEMO_PERSONA_SWITCH = 'true';
      const misconfiguredHealth = await healthGet(
        new NextRequest('http://localhost:3000/api/health')
      );
      expect(misconfiguredHealth.status).toBe(503);
      const misBody = await misconfiguredHealth.json();
      expect(misBody.dependencies.demoPersonaGuardReady).toBe(false);

      // 5. Direct API calls still enforce Maker-Checker & Four-Eyes even when demo persona switch is disabled
      delete process.env.AEGIS_PRODUCTION_STRICT_READINESS;
      process.env.AEGIS_ENABLE_DEMO_PERSONA_SWITCH = 'false';
      const fourEyesSid = `cr1-four-eyes-${Date.now()}`;
      const makerToken = createSignedSessionToken({
        sessionId: fourEyesSid,
        role: 'L1_MAKER',
        principalId: 'sso-user-alice',
      });

      // L1 cannot directly approve L2 (403 FORBIDDEN_RBAC)
      const directL2Bypass = await playbookPost(
        makeReq({
          url: 'http://localhost:3000/api/playbook',
          sessionId: fourEyesSid,
          cookieToken: makerToken,
          body: { alertId: 'ALT-APP-003', mode: 'APPROVE_L2' },
        })
      );
      expect(directL2Bypass.status).toBe(403);

      // L1 proposes -> same principal holding L2 token still blocked (403 SELF_APPROVAL_FORBIDDEN)
      const propRes = await playbookPost(
        makeReq({
          url: 'http://localhost:3000/api/playbook',
          sessionId: fourEyesSid,
          cookieToken: makerToken,
          body: { alertId: 'ALT-APP-003', mode: 'PROPOSE_L1' },
        })
      );
      expect(propRes.status).toBe(200);
      const propDelta = (await propRes.json()).delta;

      const samePrincipalL2 = createSignedSessionToken({
        sessionId: fourEyesSid,
        role: 'L2_CHECKER',
        principalId: 'sso-user-alice',
      });
      const selfApproveRes = await playbookPost(
        makeReq({
          url: 'http://localhost:3000/api/playbook',
          sessionId: fourEyesSid,
          cookieToken: samePrincipalL2,
          body: { alertId: 'ALT-APP-003', mode: 'APPROVE_L2', clientDelta: propDelta },
        })
      );
      expect(selfApproveRes.status).toBe(403);
      expect((await selfApproveRes.json()).code).toBe('SELF_APPROVAL_FORBIDDEN');
    });
  });
});
