import { NextRequest } from 'next/server';
import { describe, expect, it } from 'vitest';
import { POST as batchImportPost } from '@/app/api/batch-import/route';
import { POST as copilotPost } from '@/app/api/copilot/route';
import { GET as healthGet } from '@/app/api/health/route';
import { POST as investigatePost } from '@/app/api/investigate/route';
import { POST as merchantVerifyPost } from '@/app/api/merchant/verify/route';
import { POST as playbookPost } from '@/app/api/playbook/route';
import { GET as sessionGet, POST as sessionPost } from '@/app/api/session/route';
import { POST as sandboxPost } from '@/app/api/sandbox/route';
import { POST as walletPost } from '@/app/api/wallet/route';
import { GET as workspaceGet } from '@/app/api/workspace/route';
import { verifyDoubleEntryBalanceInvariant } from '@/domain/ledger-engine';
import type { SessionDeltaSnapshot } from '@/domain/types';
import {
  SESSION_COOKIE_NAME,
  createSignedSessionToken,
} from '@/infrastructure/session-auth';

const makeAuthenticatedRequest = (params: {
  url: string;
  method?: 'GET' | 'POST' | 'DELETE';
  sessionId: string;
  role: 'L1_MAKER' | 'L2_CHECKER' | 'END_USER';
  principalId: string;
  body?: Record<string, unknown>;
}): NextRequest => {
  const token = createSignedSessionToken({
    sessionId: params.sessionId,
    role: params.role,
    principalId: params.principalId,
  });

  return new NextRequest(params.url, {
    method: params.method ?? 'POST',
    headers: {
      'content-type': 'application/json',
      host: 'localhost:3000',
      origin: 'http://localhost:3000',
      'sec-fetch-site': 'same-origin',
      'x-workspace-session': params.sessionId,
      cookie: `${SESSION_COOKIE_NAME}=${token}`,
    },
    body: params.body ? JSON.stringify(params.body) : undefined,
  });
};

describe('Wave 2 IMP-05 & IMP-07: Unified Double-Entry Ledger, Merchant 5-Case & API Contracts', () => {
  it('enforces P2P balance integrity, double-entry ledger, idempotency, and insufficient-balance rejection', async () => {
    const sid = `w2-p2p-${Date.now()}`;

    // 1. Transfer 5,000,000 VND from ACC-USR-103 (45M) to ACC-HOSP-800 (950M)
    const idemKey = `idem-p2p-${Date.now()}`;
    const res1 = await walletPost(
      makeAuthenticatedRequest({
        url: 'http://localhost:3000/api/wallet',
        sessionId: sid,
        role: 'END_USER',
        principalId: 'usr-103',
        body: {
          senderAccountId: 'ACC-USR-103',
          recipientAccountIdOrNumber: '1188999000888',
          amountVnd: 5_000_000,
          message: 'Thanh toan vien phi',
          idempotencyKey: idemKey,
        },
      })
    );
    expect(res1.status).toBe(200);
    const data1 = await res1.json();
    expect(data1.transaction.status).toBe('SETTLED');
    expect(data1.transaction.id).toMatch(/^TXN-WAL-/);
    expect(data1.senderBalanceVnd).toBe(40_000_000);
    expect(data1.receiverBalanceVnd).toBe(955_000_000);
    expect(data1.decision.idempotentReplay).toBe(false);

    const delta1: SessionDeltaSnapshot = data1.delta;
    expect(delta1.ledgerEntries?.length).toBe(2);
    expect(verifyDoubleEntryBalanceInvariant(delta1.ledgerEntries ?? []).balanced).toBe(true);

    // 2. Duplicate submit with SAME idempotencyKey MUST replay without second debit
    const resReplay = await walletPost(
      makeAuthenticatedRequest({
        url: 'http://localhost:3000/api/wallet',
        sessionId: sid,
        role: 'END_USER',
        principalId: 'usr-103',
        body: {
          senderAccountId: 'ACC-USR-103',
          recipientAccountIdOrNumber: '1188999000888',
          amountVnd: 5_000_000,
          message: 'Thanh toan vien phi',
          idempotencyKey: idemKey,
          clientDelta: delta1,
        },
      })
    );
    expect(resReplay.status).toBe(200);
    const dataReplay = await resReplay.json();
    expect(dataReplay.transaction.id).toBe(data1.transaction.id);
    expect(dataReplay.senderBalanceVnd).toBe(40_000_000);
    expect(dataReplay.decision.idempotentReplay).toBe(true);

    // 3. Insufficient balance must be rejected with HTTP 400 INSUFFICIENT_BALANCE
    const resInsufficient = await walletPost(
      makeAuthenticatedRequest({
        url: 'http://localhost:3000/api/wallet',
        sessionId: sid,
        role: 'END_USER',
        principalId: 'usr-103',
        body: {
          senderAccountId: 'ACC-USR-103',
          recipientAccountIdOrNumber: '1188999000888',
          amountVnd: 99_000_000,
          message: 'Vuot qua so du',
          clientDelta: delta1,
        },
      })
    );
    expect(resInsufficient.status).toBe(400);
    const errIns = await resInsufficient.json();
    expect(errIns.code).toBe('INSUFFICIENT_BALANCE');

    // 4. Decimal amount or self-transfer rejected
    const resDecimal = await walletPost(
      makeAuthenticatedRequest({
        url: 'http://localhost:3000/api/wallet',
        sessionId: sid,
        role: 'END_USER',
        principalId: 'usr-103',
        body: {
          senderAccountId: 'ACC-USR-103',
          recipientAccountIdOrNumber: 'ACC-USR-103',
          amountVnd: 1000.5,
          message: 'Tu chuyen',
        },
      })
    );
    expect(resDecimal.status).toBe(400);
  });

  it('verifies all 5 mandatory Merchant Soundbox ledger cases (A-E) against live unified ledger', async () => {
    const sid = `w2-merch-${Date.now()}`;

    // Create a valid settled TXN: ACC-USR-103 -> ACC-HOSP-800 (5,000,000 VND)
    const settleRes = await walletPost(
      makeAuthenticatedRequest({
        url: 'http://localhost:3000/api/wallet',
        sessionId: sid,
        role: 'END_USER',
        principalId: 'usr-103',
        body: {
          senderAccountId: 'ACC-USR-103',
          recipientAccountIdOrNumber: 'ACC-HOSP-800',
          amountVnd: 5_000_000,
          message: 'Thanh toan hoa don A',
          idempotencyKey: `merch-ok-${Date.now()}`,
        },
      })
    );
    const settledData = await settleRes.json();
    const settledTxId: string = settledData.transaction.id;
    let currentDelta: SessionDeltaSnapshot = settledData.delta;

    // Activate shield on ALT-APP-003 (1903999888777) by L2_CHECKER
    const shieldRes = await playbookPost(
      makeAuthenticatedRequest({
        url: 'http://localhost:3000/api/playbook',
        sessionId: sid,
        role: 'L2_CHECKER',
        principalId: 'checker-merch',
        body: { alertId: 'ALT-APP-003', mode: 'APPROVE_L2', clientDelta: currentDelta },
      })
    );
    expect(shieldRes.status).toBe(200);
    currentDelta = (await shieldRes.json()).delta;

    // Attempt blocked transfer to 1903999888777 -> BLOCKED TXN with NO ledger balance drop
    const blockedRes = await walletPost(
      makeAuthenticatedRequest({
        url: 'http://localhost:3000/api/wallet',
        sessionId: sid,
        role: 'END_USER',
        principalId: 'usr-103',
        body: {
          senderAccountId: 'ACC-USR-103',
          recipientAccountIdOrNumber: '1903999888777',
          amountVnd: 18_000_000,
          message: 'Thu chuyen toi tai khoan bi chan',
          clientDelta: currentDelta,
        },
      })
    );
    expect(blockedRes.status).toBe(200);
    const blockedData = await blockedRes.json();
    expect(blockedData.transaction.status).toBe('BLOCKED');
    expect(blockedData.senderBalanceVnd).toBe(40_000_000); // Unchanged!
    const blockedTxId: string = blockedData.transaction.id;
    currentDelta = blockedData.delta;

    // Case A: Valid SETTLED + exact amount + exact merchant (ACC-HOSP-800)
    const caseA = await (
      await merchantVerifyPost(
        makeAuthenticatedRequest({
          url: 'http://localhost:3000/api/merchant/verify',
          sessionId: sid,
          role: 'END_USER',
          principalId: 'merchant-1',
          body: {
            claimedTxId: settledTxId,
            claimedAmountVnd: 5_000_000,
            merchantAccountIdOrNumber: 'ACC-HOSP-800',
            clientDelta: currentDelta,
          },
        })
      )
    ).json();
    expect(caseA.verification.verdict).toBe('VERIFIED_LEDGER_MATCH');

    // Case B: Forged Photoshop amount mismatch (claimed 50M vs actual 5M)
    const caseB = await (
      await merchantVerifyPost(
        makeAuthenticatedRequest({
          url: 'http://localhost:3000/api/merchant/verify',
          sessionId: sid,
          role: 'END_USER',
          principalId: 'merchant-1',
          body: {
            claimedTxId: settledTxId,
            claimedAmountVnd: 50_000_000,
            merchantAccountIdOrNumber: 'ACC-HOSP-800',
            clientDelta: currentDelta,
          },
        })
      )
    ).json();
    expect(caseB.verification.verdict).toBe('FORGED_PHOTOSHOP_AMOUNT_MISMATCH');
    expect(caseB.verification.headlineVi).toContain('CẢNH BÁO BILL SỬA SỐ TIỀN');

    // Case C: Non-existent transaction ID
    const caseC = await (
      await merchantVerifyPost(
        makeAuthenticatedRequest({
          url: 'http://localhost:3000/api/merchant/verify',
          sessionId: sid,
          role: 'END_USER',
          principalId: 'merchant-1',
          body: {
            claimedTxId: 'TXN-NO-SUCH-ID-404',
            claimedAmountVnd: 10_000_000,
            merchantAccountIdOrNumber: 'ACC-HOSP-800',
            clientDelta: currentDelta,
          },
        })
      )
    ).json();
    expect(caseC.verification.verdict).toBe('FAKE_RECEIPT_NOT_IN_LEDGER');
    expect(caseC.verification.headlineVi).toContain('KHÔNG TÌM THẤY GIAO DỊCH');

    // Case D: BLOCKED transaction must say money did NOT enter ledger
    const caseD = await (
      await merchantVerifyPost(
        makeAuthenticatedRequest({
          url: 'http://localhost:3000/api/merchant/verify',
          sessionId: sid,
          role: 'END_USER',
          principalId: 'merchant-1',
          body: {
            claimedTxId: blockedTxId,
            claimedAmountVnd: 18_000_000,
            merchantAccountIdOrNumber: '1903999888777',
            clientDelta: currentDelta,
          },
        })
      )
    ).json();
    expect(caseD.verification.verdict).toBe('BLOCKED_TRANSACTION_NO_SETTLEMENT');
    expect(caseD.verification.headlineVi).toContain('GIAO DỊCH ĐÃ BỊ CHẶN – TIỀN KHÔNG VÀO SỔ CÁI');
    expect(caseD.verification.actualLedgerAmountVnd).toBe(0);

    // Case E: Settled TX belongs to ACC-HOSP-800, NOT merchant ACC-USR-104
    const caseE = await (
      await merchantVerifyPost(
        makeAuthenticatedRequest({
          url: 'http://localhost:3000/api/merchant/verify',
          sessionId: sid,
          role: 'END_USER',
          principalId: 'merchant-2',
          body: {
            claimedTxId: settledTxId,
            claimedAmountVnd: 5_000_000,
            merchantAccountIdOrNumber: 'ACC-USR-104',
            clientDelta: currentDelta,
          },
        })
      )
    ).json();
    expect(caseE.verification.verdict).toBe('WRONG_MERCHANT_RECIPIENT');
    expect(caseE.verification.headlineVi).toContain('KHÔNG KHỚP NGƯỜI NHẬN');
  });

  it('executes Full & Partial Clawback into unified ledger with strict single-refund idempotency', async () => {
    const sid = `w2-claw-${Date.now()}`;

    // L1 Maker must receive 403 on CLAWBACK_REFUND
    const l1Attempt = await playbookPost(
      makeAuthenticatedRequest({
        url: 'http://localhost:3000/api/playbook',
        sessionId: sid,
        role: 'L1_MAKER',
        principalId: 'maker-1',
        body: { alertId: 'ALT-APP-003', mode: 'CLAWBACK_REFUND' },
      })
    );
    expect(l1Attempt.status).toBe(403);

    // Full Clawback on ALT-APP-003 for primary victim ACC-USR-103:
    // Only TXN-9011 (25,000,000 VND, COMPLETED, ACC-USR-103 -> ACC-MULE-903) belongs to ACC-USR-103.
    // TXN-9012 (17,000,000 VND) belongs to Victim #2 (ACC-USR-105) and MUST NOT be misallocated to ACC-USR-103!
    const fullRes = await playbookPost(
      makeAuthenticatedRequest({
        url: 'http://localhost:3000/api/playbook',
        sessionId: sid,
        role: 'L2_CHECKER',
        principalId: 'checker-1',
        body: { alertId: 'ALT-APP-003', mode: 'CLAWBACK_REFUND' },
      })
    );
    expect(fullRes.status).toBe(200);
    const fullData = await fullRes.json();
    expect(fullData.clawbackReceipt.recoveryStatus).toBe('RECOVERED');
    expect(fullData.clawbackReceipt.recoveredAmountVnd).toBe(25_000_000);
    expect(fullData.clawbackReceipt.missingAmountVnd).toBe(0);
    expect(fullData.clawbackReceipt.txIds).toEqual(['TXN-9011']);
    expect(fullData.clawbackReceipt.reversalTxId).toMatch(/^TXN-REV-ALT-APP-003-/);
    expect(fullData.victimBalanceVnd).toBe(70_000_000); // 45M + 25M (exact TXN-9011 recovery)
    expect(fullData.muleBalanceVnd).toBe(33_000_000); // 58M - 25M
    expect(fullData.idempotentReplay).toBe(false);

    // Repeat CLAWBACK_REFUND on ALT-APP-003 -> MUST NOT double refund!
    const repeatRes = await playbookPost(
      makeAuthenticatedRequest({
        url: 'http://localhost:3000/api/playbook',
        sessionId: sid,
        role: 'L2_CHECKER',
        principalId: 'checker-1',
        body: {
          alertId: 'ALT-APP-003',
          mode: 'CLAWBACK_REFUND',
          clientDelta: fullData.delta,
        },
      })
    );
    expect(repeatRes.status).toBe(200);
    const repeatData = await repeatRes.json();
    expect(repeatData.idempotentReplay).toBe(true);
    expect(repeatData.victimBalanceVnd).toBe(70_000_000);

    // Clawback on HELD transaction TXN-8843 (ALT-ATO-001 -> ACC-MULE-903) MUST be rejected (no settlement posting)!
    const heldRejectRes = await playbookPost(
      makeAuthenticatedRequest({
        url: 'http://localhost:3000/api/playbook',
        sessionId: sid,
        role: 'L2_CHECKER',
        principalId: 'checker-1',
        body: {
          alertId: 'ALT-ATO-001',
          mode: 'CLAWBACK_REFUND',
          originalTxId: 'TXN-8843',
          clientDelta: repeatData.delta,
        },
      })
    );
    expect(heldRejectRes.status).toBe(400);

    // Simulate Mule ACC-MULE-901 (balance 16.2M, received COMPLETED TXN-8841 = 16M from ACC-USR-101)
    // dispersing 6,200,000 VND out (leaving 10,000,000 remaining against 16,000,000 settled TXN-8841)
    const drainRes = await walletPost(
      makeAuthenticatedRequest({
        url: 'http://localhost:3000/api/wallet',
        sessionId: sid,
        role: 'END_USER',
        principalId: 'mule-drain',
        body: {
          senderAccountId: 'ACC-MULE-901',
          recipientAccountIdOrNumber: '999900001111',
          amountVnd: 6_200_000,
          message: 'Tau tan tien ra ngoai he thong',
          clientDelta: repeatData.delta,
        },
      })
    );
    expect(drainRes.status).toBe(200);
    const drainDelta = (await drainRes.json()).delta;

    // Partial Clawback on settled TXN-8841 (16,000,000 COMPLETED requested, ACC-MULE-901 only holds 10,000,000 remaining)
    const partialRes = await playbookPost(
      makeAuthenticatedRequest({
        url: 'http://localhost:3000/api/playbook',
        sessionId: sid,
        role: 'L2_CHECKER',
        principalId: 'checker-1',
        body: {
          alertId: 'ALT-ATO-001',
          mode: 'CLAWBACK_REFUND',
          originalTxId: 'TXN-8841',
          clientDelta: drainDelta,
        },
      })
    );
    expect(partialRes.status).toBe(200);
    const partialData = await partialRes.json();
    expect(partialData.clawbackReceipt.recoveryStatus).toBe('PARTIALLY_RECOVERED');
    expect(partialData.clawbackReceipt.recoveredAmountVnd).toBe(10_000_000);
    expect(partialData.clawbackReceipt.missingAmountVnd).toBe(6_000_000);
    expect(partialData.clawbackReceipt.txIds).toEqual(['TXN-8841']);
    expect(partialData.muleBalanceVnd).toBe(0); // Never negative!
    expect(partialData.victimBalanceVnd).toBe(72_000_000); // 62M + 10M
    expect(verifyDoubleEntryBalanceInvariant(partialData.delta.ledgerEntries ?? []).balanced).toBe(
      true
    );
  });

  it('validates remaining HTTP API contracts across Health, Session, Workspace, Investigate, Sandbox, Copilot, and Batch Import', async () => {
    const sid = `w2-contract-${Date.now()}`;

    const healthRes = await healthGet();
    expect(healthRes.status).toBe(200);
    const healthJson = await healthRes.json();
    expect(healthJson.status).toBe('ok');

    const sessSwitchRes = await sessionPost(
      makeAuthenticatedRequest({
        url: 'http://localhost:3000/api/session',
        sessionId: sid,
        role: 'L2_CHECKER',
        principalId: 'checker-contract',
        body: { sessionId: sid, role: 'L2_CHECKER', principalId: 'checker-contract' },
      })
    );
    expect(sessSwitchRes.status).toBe(200);
    const sessCookie = sessSwitchRes.cookies.get(SESSION_COOKIE_NAME)?.value;
    expect(typeof sessCookie).toBe('string');

    const sessGetRes = await sessionGet(
      new NextRequest('http://localhost:3000/api/session', {
        headers: { cookie: `${SESSION_COOKIE_NAME}=${sessCookie}` },
      })
    );
    expect(sessGetRes.status).toBe(200);

    const wsRes = await workspaceGet(
      makeAuthenticatedRequest({
        url: 'http://localhost:3000/api/workspace',
        method: 'GET',
        sessionId: sid,
        role: 'L2_CHECKER',
        principalId: 'checker-contract',
      })
    );
    expect(wsRes.status).toBe(200);
    const wsJson = await wsRes.json();
    expect(wsJson.state.alerts.length).toBeGreaterThanOrEqual(4);

    const invRes = await investigatePost(
      makeAuthenticatedRequest({
        url: 'http://localhost:3000/api/investigate',
        sessionId: sid,
        role: 'L2_CHECKER',
        principalId: 'checker-contract',
        body: { alertId: 'ALT-APP-003' },
      })
    );
    expect(invRes.status).toBe(200);

    const copRes = await copilotPost(
      makeAuthenticatedRequest({
        url: 'http://localhost:3000/api/copilot',
        sessionId: sid,
        role: 'L2_CHECKER',
        principalId: 'checker-contract',
        body: { alertId: 'ALT-APP-003', question: 'Tai sao bi canh bao do?' },
      })
    );
    expect(copRes.status).toBe(200);

    const sbRes = await sandboxPost(
      makeAuthenticatedRequest({
        url: 'http://localhost:3000/api/sandbox',
        sessionId: sid,
        role: 'L2_CHECKER',
        principalId: 'checker-contract',
        body: {
          customTitle: 'Test Sandbox API Contract',
          rawTranscript: 'Chuyen 12000000 den STK 1903999888777 ngay',
          recipientAccountNumber: '1903999888777',
          amountVnd: 12_000_000,
        },
      })
    );
    expect(sbRes.status).toBe(200);

    const batchBad = await batchImportPost(
      makeAuthenticatedRequest({
        url: 'http://localhost:3000/api/batch-import',
        sessionId: sid,
        role: 'L2_CHECKER',
        principalId: 'checker-contract',
        body: { rawContent: '', fileName: 'empty.csv' },
      })
    );
    expect(batchBad.status).toBe(400);
  });
});
