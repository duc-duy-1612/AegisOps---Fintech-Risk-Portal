import { NextRequest } from 'next/server';
import { describe, expect, it } from 'vitest';
import { POST as feedbackPost } from '@/app/api/feedback/route';
import { POST as walletPost } from '@/app/api/wallet/route';
import {
  createHitlFeedbackInSession,
  executeAlertInvestigation,
  getWorkspaceBootstrap,
  moderateHitlFeedbackInSession,
} from '@/application/workspace-orchestrator';
import { evaluateAdaptiveHitlFeedback } from '@/domain/hitl-feedback-engine';
import { validateStrictMerchantReceiptImage } from '@/infrastructure/security-guard';
import { SEED_ACCOUNTS, SEED_ALERTS } from '@/infrastructure/seed-scenarios';
import { SESSION_COOKIE_NAME, createSignedSessionToken } from '@/infrastructure/session-auth';
import {
  evictServerSessionForColdStartTest,
  materializeWorkspaceState,
} from '@/infrastructure/workspace-store';

const makeAuthReq = (params: {
  url: string;
  sessionId: string;
  role: 'L1_MAKER' | 'L2_CHECKER' | 'END_USER';
  principalId: string;
  body: Record<string, unknown>;
}): NextRequest => {
  const token = createSignedSessionToken({
    sessionId: params.sessionId,
    role: params.role,
    principalId: params.principalId,
  });
  return new NextRequest(params.url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      host: 'localhost:3000',
      origin: 'http://localhost:3000',
      'sec-fetch-site': 'same-origin',
      'x-workspace-session': params.sessionId,
      cookie: `${SESSION_COOKIE_NAME}=${token}`,
    },
    body: JSON.stringify(params.body),
  });
};

describe('Wave 3.1 Acceptance Gate: HITL State Integrity, Replay, Risk Semantics & Corrupt Image Guards', () => {
  it('prevents stale snapshot replay from resurrecting REVOKED feedback on warm instance and documents cold-start replay boundary', async () => {
    const sid = `w31-stale-${Date.now()}`;

    // 1. L2 creates APPROVED_ACTIVE feedback (revision 1)
    const createRes = await feedbackPost(
      makeAuthReq({
        url: 'http://localhost:3000/api/feedback',
        sessionId: sid,
        role: 'L2_CHECKER',
        principalId: 'checker-w31',
        body: {
          action: 'CREATE',
          alertId: 'ALT-FPR-004',
          feedbackDecision: 'OVERRIDE_SAFE',
          targetScope: 'RECIPIENT_PATTERN',
          analystRationale: 'Valid medical invoice verified',
          ttlHours: 24,
        },
      })
    );
    expect(createRes.status).toBe(200);
    const createdJson = await createRes.json();
    const staleActiveDelta = createdJson.delta;
    const feedbackId: string = createdJson.feedbackRecord.feedbackId;
    expect(createdJson.feedbackRecord.status).toBe('APPROVED_ACTIVE');

    // 2. L2 revokes feedback (revision 2)
    const revokeRes = await feedbackPost(
      makeAuthReq({
        url: 'http://localhost:3000/api/feedback',
        sessionId: sid,
        role: 'L2_CHECKER',
        principalId: 'checker-w31',
        body: {
          action: 'REVOKE',
          feedbackId,
          clientDelta: staleActiveDelta,
        },
      })
    );
    expect(revokeRes.status).toBe(200);
    const revokedJson = await revokeRes.json();
    expect(revokedJson.feedbackRecord.status).toBe('REVOKED');
    expect(revokedJson.feedbackRecord.memoryVersion).toBe(2);

    // 3. Stale client replays revision-1 APPROVED_ACTIVE snapshot onto warm instance -> MUST keep REVOKED!
    const materializedAfterReplay = materializeWorkspaceState(sid, staleActiveDelta);
    const replayedRec = materializedAfterReplay.delta.hitlFeedbackMemory?.find(
      (f) => f.feedbackId === feedbackId
    );
    expect(replayedRec?.status).toBe('REVOKED');
    expect(replayedRec?.memoryVersion).toBe(2);
    expect(materializedAfterReplay.delta.stateRevision).toBe(revokedJson.delta.stateRevision);

    // 4. Concurrent updates: another feedback for a different alert does not drop revoked item
    const secondCreate = createHitlFeedbackInSession({
      sessionId: sid,
      alertId: 'ALT-BLG-002',
      feedbackDecision: 'FORCE_BLOCK',
      targetScope: 'ALERT_CASE',
      reasonCode: 'CONFIRMED_MULE_PATTERN',
      analystRationale: 'Second concurrent rule',
      actorPrincipalId: 'checker-w31',
      actorRole: 'L2_CHECKER',
      clientDelta: staleActiveDelta, // stale caller still must NOT undo rev 2 revocation!
    });
    const bothList = secondCreate.delta.hitlFeedbackMemory ?? [];
    expect(bothList.find((f) => f.feedbackId === feedbackId)?.status).toBe('REVOKED');
    expect(bothList.some((f) => f.sourceAlertId === 'ALT-BLG-002' && f.status === 'APPROVED_ACTIVE')).toBe(
      true
    );

    // 5. Explicitly verify in-memory serverless cold-start limitation:
    // If instance cache is completely evicted (e.g. second container), signed rev-1 client snapshot could replay rev-1 state.
    evictServerSessionForColdStartTest(sid);
    const coldRestart = materializeWorkspaceState(sid, staleActiveDelta);
    expect(coldRestart.delta.hitlFeedbackMemory?.find((f) => f.feedbackId === feedbackId)?.status).toBe(
      'APPROVED_ACTIVE'
    );
  });

  it('enforces risk bounds [5..99], non-leakage across alerts, and distinguishes WARN_COOLING_OFF from BLOCKED', async () => {
    const sid = `w31-sem-${Date.now()}`;
    const safeAlert = SEED_ALERTS.find((a) => a.id === 'ALT-FPR-004')!;
    const scamAlert = SEED_ALERTS.find((a) => a.id === 'ALT-APP-003')!;

    // Extreme lower/upper clamps stay inside [5..99]
    const activeSafe = createHitlFeedbackInSession({
      sessionId: sid,
      alertId: safeAlert.id,
      feedbackDecision: 'OVERRIDE_SAFE',
      targetScope: 'RECIPIENT_PATTERN',
      reasonCode: 'VERIFIED_LEGITIMATE_PARTNER',
      analystRationale: 'Bound test',
      actorPrincipalId: 'checker-1',
      actorRole: 'L2_CHECKER',
    });

    const lowBound = evaluateAdaptiveHitlFeedback({
      baseScore: 2,
      alert: safeAlert,
      targetAccount: SEED_ACCOUNTS.find((a) => a.id === safeAlert.targetRecipientAccountId),
      targetFingerprint: activeSafe.feedbackRecord.targetFingerprint,
      currentContextSignature: activeSafe.feedbackRecord.contextSignature,
      feedbackMemory: [activeSafe.feedbackRecord],
      hardCriticalSignalsPresent: false,
    });
    expect(lowBound.finalScore).toBeGreaterThanOrEqual(5);

    const activeBlock = createHitlFeedbackInSession({
      sessionId: sid,
      alertId: scamAlert.id,
      feedbackDecision: 'FORCE_BLOCK',
      targetScope: 'RECIPIENT_PATTERN',
      reasonCode: 'CONFIRMED_MULE_PATTERN',
      analystRationale: 'Mule risk warning',
      actorPrincipalId: 'checker-1',
      actorRole: 'L2_CHECKER',
      clientDelta: activeSafe.delta,
    });

    const highBound = evaluateAdaptiveHitlFeedback({
      baseScore: 95,
      alert: scamAlert,
      targetAccount: SEED_ACCOUNTS.find((a) => a.id === scamAlert.targetRecipientAccountId),
      targetFingerprint: activeBlock.feedbackRecord.targetFingerprint,
      currentContextSignature: activeBlock.feedbackRecord.contextSignature,
      feedbackMemory: [activeBlock.feedbackRecord],
      hardCriticalSignalsPresent: false,
    });
    expect(highBound.finalScore).toBeLessThanOrEqual(99);

    // Non-leakage in isolated session: SAFE feedback on ALT-FPR-004 never alters ALT-APP-003
    const isolatedSid = `w31-iso-${Date.now()}`;
    const isolatedSafe = createHitlFeedbackInSession({
      sessionId: isolatedSid,
      alertId: safeAlert.id,
      feedbackDecision: 'OVERRIDE_SAFE',
      targetScope: 'RECIPIENT_PATTERN',
      reasonCode: 'VERIFIED_LEGITIMATE_PARTNER',
      analystRationale: 'Isolated non-leakage check',
      actorPrincipalId: 'checker-1',
      actorRole: 'L2_CHECKER',
    });
    const boot = getWorkspaceBootstrap(isolatedSid, isolatedSafe.delta);
    expect(boot.forensicsByAlertId['ALT-APP-003']?.adaptiveFeedbackSummary?.appliedRecords.length).toBe(0);
    expect(boot.forensicsByAlertId['ALT-ATO-001']?.adaptiveFeedbackSummary?.appliedRecords.length).toBe(0);

    // WARN_COOLING_OFF triggered by FORCE_BLOCK HITL must NOT be misrepresented as BLOCKED_BY_SHIELD / BLOCKED
    const warnTransferRes = await walletPost(
      makeAuthReq({
        url: 'http://localhost:3000/api/wallet',
        sessionId: sid,
        role: 'END_USER',
        principalId: 'usr-103',
        body: {
          senderAccountId: 'ACC-USR-103',
          recipientAccountIdOrNumber: '1903999888777',
          amountVnd: 2_000_000,
          message: 'Chuyen khoan binh thuong',
          clientDelta: activeBlock.delta,
        },
      })
    );
    expect(warnTransferRes.status).toBe(200);
    const warnJson = await warnTransferRes.json();
    expect(warnJson.decision.decision).toBe('WARN_COOLING_OFF');
    expect(warnJson.decision.decision).not.toBe('BLOCKED_BY_SHIELD');
    expect(warnJson.transaction.status).not.toBe('BLOCKED');

    // Persona switching boundary: L1 cannot reject or moderate even after previous L2 actions
    expect(() =>
      moderateHitlFeedbackInSession({
        sessionId: sid,
        feedbackId: activeBlock.feedbackRecord.feedbackId,
        moderationAction: 'REVOKE',
        actorPrincipalId: 'maker-1',
        actorRole: 'L1_MAKER',
        clientDelta: activeBlock.delta,
      })
    ).toThrow(/403|không có quyền/i);
  });

  it('rejects truncated JPEG and invalid WebP binary structures cleanly', async () => {
    const truncatedJpeg =
      'data:image/jpeg;base64,' + Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a]).toString('base64');
    expect(validateStrictMerchantReceiptImage(truncatedJpeg).valid).toBe(false);

    const fakeWebp =
      'data:image/webp;base64,' +
      Buffer.from('RIFF\x00\x00\x00\x00NOTWEBPXXXXXXXXXXXXXXXXXXXXXXXX').toString('base64');
    expect(validateStrictMerchantReceiptImage(fakeWebp).valid).toBe(false);

    // Investigation preserves deterministic score integrity even if feedback count incremented
    const inv = await executeAlertInvestigation({
      sessionId: `w31-inv-${Date.now()}`,
      alertId: 'ALT-FPR-004',
    });
    expect(inv.report.deterministicRiskScore).toBe(inv.forensics.deterministicRiskScore);
  });
});
