import { createHash } from 'node:crypto';
import { NextRequest } from 'next/server';
import { beforeEach, describe, expect, it } from 'vitest';
import { POST as batchImportPost } from '@/app/api/batch-import/route';
import { POST as copilotPost } from '@/app/api/copilot/route';
import { GET as healthGet } from '@/app/api/health/route';
import { POST as investigatePost } from '@/app/api/investigate/route';
import { POST as playbookPost } from '@/app/api/playbook/route';
import { POST as sandboxPost } from '@/app/api/sandbox/route';
import { POST as sessionPost } from '@/app/api/session/route';
import { POST as walletPost } from '@/app/api/wallet/route';
import { POST as workspacePost } from '@/app/api/workspace/route';
import {
  executePlaybookApproval,
  toggleShieldRuleInSession,
} from '@/application/workspace-orchestrator';
import { exportCasesToCsv, generateSampleBatchCsv, parseBatchCasesPayload } from '@/domain/batch-io';
import { buildComplianceIncidentDossier } from '@/domain/compliance-report';
import { sha256Hex } from '@/domain/crypto-hash';
import { runDeterministicForensicsSuite } from '@/domain/forensics-analyzers';
import { extractJsonFromGeminiResponse, runGeminiInvestigationWithFallback } from '@/infrastructure/gemini-agent';
import { pseudonymizePiiWithHmacSha256 } from '@/infrastructure/privacy-hasher';
import {
  checkRateLimit,
  getRateBucketCount,
  pruneExpiredRateBuckets,
  resetRateBucketsForTest,
} from '@/infrastructure/security-guard';
import {
  SEED_ACCOUNTS,
  SEED_ALERTS,
  SEED_API_EVENTS,
  SEED_AUTH_LOGS,
  SEED_DEVICES,
  SEED_EVIDENCES,
  SEED_TRANSACTIONS,
} from '@/infrastructure/seed-scenarios';
import { createSignedSessionToken, SESSION_COOKIE_NAME } from '@/infrastructure/session-auth';
import { createEmptyDelta, mergeSessionDeltas, resetSessionDelta } from '@/infrastructure/workspace-store';

const makeJsonRequest = (
  url: string,
  body: unknown,
  opts?: { sessionId?: string; roleCookieToken?: string }
): NextRequest => {
  const headers: Record<string, string> = {
    'content-type': 'application/json',
  };
  if (opts?.sessionId) {
    headers['x-workspace-session'] = opts.sessionId;
  }
  if (opts?.roleCookieToken) {
    headers['cookie'] = `${SESSION_COOKIE_NAME}=${opts.roleCookieToken}`;
  }
  return new NextRequest(url, {
    method: 'POST',
    headers,
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
};

describe('Wave 1 — Layer 1 & 2 Verification: RBAC, State Merge, Crypto Hash, Zod Validation, Rate Limit & Reliability', () => {
  beforeEach(() => {
    resetRateBucketsForTest();
  });

  // ─── 1. IMP-01.A: Server-side RBAC & Signed Session Verification ───────────────────
  it('IMP-01.A RBAC: rejects missing/tampered/mismatched sessions with HTTP 401 and denies L1_MAKER / END_USER privileged actions with HTTP 403', async () => {
    const sid = 'rbac-test-session';

    // 1. Missing signed cookie -> 401 Unauthorized
    const noAuthRes = await playbookPost(
      makeJsonRequest('http://localhost/api/playbook', { alertId: 'ALT-APP-003', mode: 'APPROVE_L2' }, { sessionId: sid })
    );
    expect(noAuthRes.status).toBe(401);

    // 2. Tampered HMAC cookie -> 401 Unauthorized
    const validL2Token = createSignedSessionToken({ sessionId: sid, role: 'L2_CHECKER' });
    const tamperedToken = `${validL2Token.slice(0, -4)}AAAA`;
    const tamperedRes = await playbookPost(
      makeJsonRequest(
        'http://localhost/api/playbook',
        { alertId: 'ALT-APP-003', mode: 'APPROVE_L2' },
        { sessionId: sid, roleCookieToken: tamperedToken }
      )
    );
    expect(tamperedRes.status).toBe(401);

    // 3. Session binding mismatch (signed cookie for sid-A, header claims sid-B) -> 401
    const mismatchRes = await playbookPost(
      makeJsonRequest(
        'http://localhost/api/playbook',
        { alertId: 'ALT-APP-003', mode: 'APPROVE_L2' },
        { sessionId: 'other-hijacked-sid', roleCookieToken: validL2Token }
      )
    );
    expect(mismatchRes.status).toBe(401);

    // 4. L1_MAKER token: allowed PROPOSE_L1 (200), BLOCKED on ALL L2 privileged actions (403)
    const l1Token = createSignedSessionToken({ sessionId: sid, role: 'L1_MAKER' });
    const l1Propose = await playbookPost(
      makeJsonRequest(
        'http://localhost/api/playbook',
        { alertId: 'ALT-APP-003', mode: 'PROPOSE_L1' },
        { sessionId: sid, roleCookieToken: l1Token }
      )
    );
    expect(l1Propose.status).toBe(200);

    for (const forbiddenAction of [
      { alertId: 'ALT-APP-003', mode: 'APPROVE_L2' },
      { mode: 'BATCH_TRIAGE' },
      { mode: 'TOGGLE_SHIELD', ruleId: 'SHD-ALT-APP-003' },
      { mode: 'ADD_CUSTOM_SHIELD', targetAccountNumber: '1903000111222' },
      { alertId: 'ALT-APP-003', mode: 'CLAWBACK_REFUND' },
      { alertId: 'ALT-APP-003', mode: 'ANALYST_OVERRIDE', targetVerdict: 'OVERRIDE_SAFE' },
      { alertId: 'ALT-APP-003', mode: 'PUSH_SIMO' },
    ]) {
      const deniedRes = await playbookPost(
        makeJsonRequest('http://localhost/api/playbook', forbiddenAction, {
          sessionId: sid,
          roleCookieToken: l1Token,
        })
      );
      expect(deniedRes.status).toBe(403);
    }

    // 5. Client attempting to inject operatorRole in body while holding L1 cookie -> blocked 400 strict schema
    const spoofBodyRes = await playbookPost(
      makeJsonRequest(
        'http://localhost/api/playbook',
        { alertId: 'ALT-APP-003', mode: 'APPROVE_L2', operatorRole: 'L2_CHECKER' },
        { sessionId: sid, roleCookieToken: l1Token }
      )
    );
    expect(spoofBodyRes.status).toBe(400);

    // 6. END_USER token -> blocked 403 on playbook AND internal investigate/copilot/batch-import
    const endUserToken = createSignedSessionToken({ sessionId: sid, role: 'END_USER' });
    expect(
      (
        await playbookPost(
          makeJsonRequest('http://localhost/api/playbook', { alertId: 'ALT-APP-003', mode: 'PROPOSE_L1' }, { sessionId: sid, roleCookieToken: endUserToken })
        )
      ).status
    ).toBe(403);
    expect(
      (
        await investigatePost(
          makeJsonRequest('http://localhost/api/investigate', { alertId: 'ALT-APP-003' }, { sessionId: sid, roleCookieToken: endUserToken })
        )
      ).status
    ).toBe(403);
    expect(
      (
        await copilotPost(
          makeJsonRequest('http://localhost/api/copilot', { alertId: 'ALT-APP-003', question: 'Test' }, { sessionId: sid, roleCookieToken: endUserToken })
        )
      ).status
    ).toBe(403);
    expect(
      (
        await batchImportPost(
          makeJsonRequest('http://localhost/api/batch-import', { rawContent: generateSampleBatchCsv() }, { sessionId: sid, roleCookieToken: endUserToken })
        )
      ).status
    ).toBe(403);

    // 7. L2_CHECKER token -> succeeds 200 on APPROVE_L2
    const l2ApproveRes = await playbookPost(
      makeJsonRequest(
        'http://localhost/api/playbook',
        { alertId: 'ALT-APP-003', mode: 'APPROVE_L2' },
        { sessionId: sid, roleCookieToken: validL2Token }
      )
    );
    expect(l2ApproveRes.status).toBe(200);
  });

  // ─── 2. IMP-01.B: Revision-Authoritative Delta Merge Regression ────────────────────
  it('IMP-01.B State Merge: stale lower-revision clientDelta NEVER resurrects unfrozen accounts, pending L2 requests, or paused shield rules', () => {
    const sid = 'state-merge-regression';
    resetSessionDelta(sid);

    // Step 1: L1 proposes -> pendingL2ApprovalAlertIds = ['ALT-APP-003'], rev 1
    const l1 = executePlaybookApproval({ sessionId: sid, alertId: 'ALT-APP-003', mode: 'PROPOSE_L1' });
    expect(l1.delta.stateRevision).toBe(1);

    // Step 2: L2 approves -> pendingL2ApprovalAlertIds cleared, ACC-MULE-903 frozen, rule active, rev 2
    const l2 = executePlaybookApproval({
      sessionId: sid,
      alertId: 'ALT-APP-003',
      mode: 'APPROVE_L2',
      clientDelta: l1.delta,
    });
    expect(l2.delta.stateRevision).toBeGreaterThan(1);
    expect(l2.delta.pendingL2ApprovalAlertIds).not.toContain('ALT-APP-003');
    expect(l2.delta.frozenAccountIds).toContain('ACC-MULE-903');

    // Step 3: L2 pauses shield -> ACC-MULE-903 UNFROZEN, rule.active = false, rev 3
    const paused = toggleShieldRuleInSession({
      sessionId: sid,
      ruleId: l2.createdShieldRule!.id,
      clientDelta: l2.delta,
    });
    expect(paused.delta.frozenAccountIds).not.toContain('ACC-MULE-903');
    expect(paused.updatedRule.active).toBe(false);

    // Regression Attack: Stale browser tab sends old rev 2 (frozen!) or rev 1 (pending L2!) snapshot
    const mergedAfterStaleRev2 = mergeSessionDeltas(sid, paused.delta, l2.delta);
    expect(mergedAfterStaleRev2.frozenAccountIds).not.toContain('ACC-MULE-903');
    expect(mergedAfterStaleRev2.activeShieldRules.find((r) => r.id === l2.createdShieldRule!.id)?.active).toBe(false);

    const mergedAfterStaleRev1 = mergeSessionDeltas(sid, paused.delta, l1.delta);
    expect(mergedAfterStaleRev1.pendingL2ApprovalAlertIds).not.toContain('ALT-APP-003');

    // Invalid negative/NaN revision handled safely without throwing
    const malformedRevMerged = mergeSessionDeltas(sid, paused.delta, {
      ...createEmptyDelta(sid),
      stateRevision: -99 as number,
      frozenAccountIds: ['ACC-MULE-903'],
    });
    expect(malformedRevMerged.frozenAccountIds).not.toContain('ACC-MULE-903');
  });

  // ─── 3. IMP-02: Real FIPS 180-4 SHA-256 & Eliminate Hardcoded Identifiers ──────────
  it('IMP-02 Crypto Hash & No Hardcoded Identifiers: matches NIST SHA-256 vectors (64 hex), uses server HMAC for PII, and removes hardcoded DEV-EMU-666', () => {
    // 1. Known NIST FIPS 180-4 SHA-256 Test Vectors compared against node:crypto
    const vectors = [
      { input: '', expected: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
      { input: 'abc', expected: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad' },
      {
        input: 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
        expected: '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
      },
      { input: 'ACC-USR-103-Tiếng-Việt-UTF8', expected: createHash('sha256').update('ACC-USR-103-Tiếng-Việt-UTF8', 'utf8').digest('hex') },
    ];
    for (const v of vectors) {
      const digest = sha256Hex(v.input);
      expect(digest).toBe(v.expected);
      expect(digest).toMatch(/^[0-9a-f]{64}$/);
    }
    expect(sha256Hex('0908111222')).not.toBe(sha256Hex('0908111223'));

    // 2. Server-side keyed HMAC-SHA-256 pseudonymization
    const hmac1 = pseudonymizePiiWithHmacSha256('1903999888777');
    const hmac2 = pseudonymizePiiWithHmacSha256('1903999888778');
    expect(hmac1).toMatch(/^[0-9a-f]{64}$/);
    expect(hmac1).not.toBe(hmac2);
    expect(hmac1).not.toBe(sha256Hex('1903999888777'));

    // 3. No hardcoded DEV-EMU-666: ALT-FPR-004 (clean hospital payment) emits null device & null fingerprint hash
    const fprAlert = SEED_ALERTS.find((a) => a.id === 'ALT-FPR-004')!;
    const fprForensics = runDeterministicForensicsSuite({
      alert: fprAlert,
      accounts: SEED_ACCOUNTS,
      devices: SEED_DEVICES,
      authLogs: SEED_AUTH_LOGS,
      transactions: SEED_TRANSACTIONS,
      apiEvents: SEED_API_EVENTS,
      evidences: SEED_EVIDENCES,
    });
    const fprDossier = buildComplianceIncidentDossier({
      alert: fprAlert,
      forensics: fprForensics,
      auditLogs: [],
    });
    expect(fprDossier.simoPiiMaskedPayload.flaggedDeviceId).toBeNull();
    expect(fprDossier.simoPiiMaskedPayload.flaggedDeviceFingerprintHash).toBeNull();
    expect(fprDossier.simoPiiMaskedPayload.dossierIntegrityHashSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(fprDossier.simoPiiMaskedPayload)).not.toContain('sha256_');

    // 4. Custom ATO case on DEV-CUSTOM-999 cites DEV-CUSTOM-999 rather than hardcoded DEV-EMU-666
    const customAtoAlert = {
      id: 'ALT-CUS-ATO',
      title: 'Custom ATO',
      subtitle: 'Custom',
      scenarioCode: 'CYBER_ATO_MULE' as const,
      primaryAccountId: 'ACC-CUS-1',
      targetRecipientAccountId: 'ACC-CUS-MULE',
      severity: 'CRITICAL' as const,
      status: 'OPEN' as const,
      deterministicRiskScore: 90,
      tracks: ['CYBERSECURITY' as const],
      createdAt: '2026-11-21T00:00:00Z',
      traditionalRuleReason: 'Test',
    };
    const customAccounts = [
      {
        id: 'ACC-CUS-1',
        ownerName: 'User 1',
        accountNumber: '0901000111',
        bankOrWalletName: 'MoMo',
        accountType: 'CONSUMER' as const,
        status: 'ACTIVE' as const,
        balanceVnd: 50_000_000,
        avgTxAmountVnd: 500_000,
        kycLevel: 'LEVEL_2_BIOMETRIC' as const,
        primaryDeviceId: 'DEV-CUSTOM-999',
        accountAgeDays: 200,
      },
      {
        id: 'ACC-CUS-MULE',
        ownerName: 'Mule Custom',
        accountNumber: '1903999000111',
        bankOrWalletName: 'Bank',
        accountType: 'MULE_SUSPECT' as const,
        status: 'ACTIVE' as const,
        balanceVnd: 10_000_000,
        avgTxAmountVnd: 100_000,
        kycLevel: 'LEVEL_1' as const,
        primaryDeviceId: 'DEV-CUSTOM-999',
        accountAgeDays: 3,
      },
    ];
    const customAtoForensics = runDeterministicForensicsSuite({
      alert: customAtoAlert,
      accounts: customAccounts,
      devices: [
        {
          id: 'DEV-CUSTOM-999',
          osBrowser: 'Rooted Emulator X',
          ipAddress: '1.2.3.4',
          asnLocation: 'Proxy',
          isEmulatorOrRooted: true,
          linkedAccountIds: ['ACC-CUS-1', 'ACC-CUS-MULE'],
        },
      ],
      authLogs: [
        {
          id: 'LOG-CUS-1',
          accountId: 'ACC-CUS-1',
          deviceId: 'DEV-CUSTOM-999',
          eventType: 'SESSION_SURVIVED_RESET',
          sessionFamilyId: 'FAM-1',
          survivedCredentialReset: true,
          ipAddress: '1.2.3.4',
          location: 'Proxy',
          timestamp: '2026-11-21T00:00:00Z',
          summary: 'Survived reset',
        },
      ],
      transactions: [
        {
          id: 'TXN-CUS-1',
          alertId: 'ALT-CUS-ATO',
          senderAccountId: 'ACC-CUS-1',
          receiverAccountId: 'ACC-CUS-MULE',
          amountVnd: 20_000_000,
          channel: 'P2P_WALLET',
          message: 'Test',
          deviceId: 'DEV-CUSTOM-999',
          hopIndex: 1,
          status: 'HELD',
          timestamp: '2026-11-21T00:00:00Z',
        },
      ],
      apiEvents: [],
      evidences: [],
    });
    const revokeAction = customAtoForensics.fallbackReport.recommendedActions.find(
      (a) => a.actionType === 'REVOKE_TOKEN_FAMILY'
    );
    expect(revokeAction?.labelVi).toContain('DEV-CUSTOM-999');
    expect(revokeAction?.labelVi).not.toContain('DEV-EMU-666');

    const customDossier = buildComplianceIncidentDossier({
      alert: customAtoAlert,
      forensics: customAtoForensics,
      auditLogs: [],
    });
    expect(customDossier.simoPiiMaskedPayload.flaggedDeviceId).toBe('DEV-CUSTOM-999');
    expect(customDossier.simoPiiMaskedPayload.flaggedDeviceFingerprintHash).toBe(sha256Hex('DEV-CUSTOM-999'));
  });

  // ─── 4. IMP-03.A: Zod Runtime API Validation Across All POST Routes ──────────────
  it('IMP-03.A Zod Validation: rejects malformed JSON, missing fields, wrong types, oversized strings, and strict unexpected keys with HTTP 400', async () => {
    const sid = 'zod-test-session';
    const token = createSignedSessionToken({ sessionId: sid, role: 'L2_CHECKER' });

    // 1. Wallet route: negative/zero/string amount or missing recipient -> 400
    expect(
      (
        await walletPost(
          makeJsonRequest(
            'http://localhost/api/wallet',
            { recipientAccountIdOrNumber: '1903999888777', amountVnd: -500 },
            { sessionId: sid, roleCookieToken: token }
          )
        )
      ).status
    ).toBe(400);
    expect(
      (
        await walletPost(
          makeJsonRequest('http://localhost/api/wallet', '{broken-json', {
            sessionId: sid,
            roleCookieToken: token,
          })
        )
      ).status
    ).toBe(400);

    // 2. Sandbox route: malformed nested caseInputSpec enum / oversized transcript -> 400
    expect(
      (
        await sandboxPost(
          makeJsonRequest(
            'http://localhost/api/sandbox',
            { caseInputSpec: { channel: 'CRYPTO_INVALID_CHANNEL', amountVnd: 100000 } },
            { sessionId: sid, roleCookieToken: token }
          )
        )
      ).status
    ).toBe(400);
    expect(
      (
        await sandboxPost(
          makeJsonRequest(
            'http://localhost/api/sandbox',
            { rawTranscript: 'A'.repeat(3500) },
            { sessionId: sid, roleCookieToken: token }
          )
        )
      ).status
    ).toBe(400);

    // 3. Copilot route: empty question -> 400
    expect(
      (
        await copilotPost(
          makeJsonRequest(
            'http://localhost/api/copilot',
            { alertId: 'ALT-APP-003', question: '   ' },
            { sessionId: sid, roleCookieToken: token }
          )
        )
      ).status
    ).toBe(400);

    // 4. Batch-import route: empty rawContent -> 400
    expect(
      (
        await batchImportPost(
          makeJsonRequest(
            'http://localhost/api/batch-import',
            { rawContent: '   ', fileName: 'empty.csv' },
            { sessionId: sid, roleCookieToken: token }
          )
        )
      ).status
    ).toBe(400);

    // 5. Workspace route: unexpected field under strict schema -> 400 (with valid signed cookie)
    expect(
      (
        await workspacePost(
          makeJsonRequest(
            'http://localhost/api/workspace',
            { unexpectedField: 123 },
            { sessionId: sid, roleCookieToken: token }
          )
        )
      ).status
    ).toBe(400);

    // 6. Session route: invalid role enum -> 400
    expect(
      (
        await sessionPost(
          makeJsonRequest('http://localhost/api/session', { role: 'SUPER_ADMIN_HACK' })
        )
      ).status
    ).toBe(400);
  });

  // ─── 5. IMP-03.B: Rate Limiting & Memory Bound Pruning ─────────────────────────────
  it('IMP-03.B Rate Limiting: resists header spoofing on Playbook/Wallet routes and prunes expired/overflow buckets', async () => {
    // 1. Expired pruning + hard MAX_RATE_BUCKETS=2000 bound
    const baseNow = 1_700_000_000_000;
    for (let i = 0; i < 2100; i += 1) {
      checkRateLimit(`flood-ip-${i}`, 10, baseNow);
    }
    expect(getRateBucketCount()).toBeLessThanOrEqual(2000);
    const pruned = pruneExpiredRateBuckets(baseNow + 65_000);
    expect(pruned).toBeGreaterThan(0);
    expect(getRateBucketCount()).toBe(0);

    // 2. Spoofing different x-workspace-session headers on direct/unproxied route still hits single IP rate bucket -> 429
    for (let i = 0; i < 35; i += 1) {
      const sid = `spoof-sid-${i}`;
      const tok = createSignedSessionToken({ sessionId: sid, role: 'L2_CHECKER' });
      const res = await playbookPost(
        makeJsonRequest(
          'http://localhost/api/playbook',
          { alertId: 'ALT-APP-003', mode: 'APPROVE_L2' },
          { sessionId: sid, roleCookieToken: tok }
        )
      );
      expect(res.status).toBe(200);
    }
    const blockedSid = 'spoof-sid-36th';
    const blockedTok = createSignedSessionToken({ sessionId: blockedSid, role: 'L2_CHECKER' });
    const rateLimitedRes = await playbookPost(
      makeJsonRequest(
        'http://localhost/api/playbook',
        { alertId: 'ALT-APP-003', mode: 'APPROVE_L2' },
        { sessionId: blockedSid, roleCookieToken: blockedTok }
      )
    );
    expect(rateLimitedRes.status).toBe(429);
  });

  // ─── 6. IMP-06: Gemini Fence Stripper, CSV Backward Compat & Health Endpoint ───────
  it('IMP-06 Reliability: strips ONLY outer Gemini markdown fences, handles CSV deepfake field with backward compat, and exposes /api/health', async () => {
    // 1. Gemini outer fence extraction
    const plain = '{"classification":"CONFIRMED_APP_SCAM"}';
    const fenced = '```json\n{"classification":"CONFIRMED_APP_SCAM","summary":"Code: ```abc``` inside text"}\n```';
    expect(extractJsonFromGeminiResponse(plain)).toBe(plain);
    const extracted = JSON.parse(extractJsonFromGeminiResponse(fenced)) as { summary: string };
    expect(extracted.summary).toBe('Code: ```abc``` inside text');
    expect(extractJsonFromGeminiResponse('   ')).toBe('');

    // Ensure fallback engine works safely when no key/offline
    const alert = SEED_ALERTS[0]!;
    const forensics = runDeterministicForensicsSuite({
      alert,
      accounts: SEED_ACCOUNTS,
      devices: SEED_DEVICES,
      authLogs: SEED_AUTH_LOGS,
      transactions: SEED_TRANSACTIONS,
      apiEvents: SEED_API_EVENTS,
      evidences: SEED_EVIDENCES,
    });
    const prevKey = process.env.GEMINI_API_KEY;
    process.env.GEMINI_API_KEY = '';
    const fallbackReport = await runGeminiInvestigationWithFallback({
      alert,
      forensics,
      evidenceTranscript: 'test',
    });
    process.env.GEMINI_API_KEY = prevKey;
    expect(fallbackReport.modelUsed).toBe('deterministic-forensics-engine-v2');
    expect(fallbackReport.citedEvidenceIds.length).toBeGreaterThan(0);

    // 2. CSV Deepfake column + backward compatibility for legacy CSV without the column
    const legacyCsv = 'customTitle,recipientAccountNumber,amountVnd\nTest Legacy,1903777666555,15000000';
    const legacyParsed = parseBatchCasesPayload(legacyCsv, 'legacy.csv');
    expect(legacyParsed.specs[0]?.deepfakeOrVirtualCamDetected).toBe(false);

    const newCsv = 'customTitle,recipientAccountNumber,amountVnd,deepfakeOrVirtualCamDetected\nTest Deepfake,1903777666555,20000000,true';
    const newParsed = parseBatchCasesPayload(newCsv, 'deepfake.csv');
    expect(newParsed.specs[0]?.deepfakeOrVirtualCamDetected).toBe(true);

    const exportedCsv = exportCasesToCsv(SEED_ALERTS, SEED_ACCOUNTS, {});
    expect(exportedCsv).toContain('DeepfakeVirtualCamDetected');

    // 3. Health GET contract
    const healthRes = await healthGet();
    expect(healthRes.status).toBe(200);
    const healthBody = (await healthRes.json()) as { status: string; primaryModel: string };
    expect(healthBody.status).toBe('ok');
    expect(healthBody.primaryModel).toBeTruthy();
  });
});
