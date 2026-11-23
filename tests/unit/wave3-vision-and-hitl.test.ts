import { NextRequest } from 'next/server';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { POST as feedbackPost } from '@/app/api/feedback/route';
import { POST as merchantVisionPost } from '@/app/api/merchant/vision/route';
import { runDeterministicForensicsSuite } from '@/domain/forensics-analyzers';
import {
  evaluateAdaptiveHitlFeedback,
  buildHitlContextSignature,
  clampHitlRiskAdjustment,
} from '@/domain/hitl-feedback-engine';
import {
  crossVerifyMerchantVisionAgainstLedger,
  normalizeExtractedFields,
  normalizeVndAmountValue,
} from '@/domain/merchant-vision';
import { evaluateConsumerTransfer } from '@/domain/shield-evaluator';
import type { HitlFeedbackMemoryRecord, SessionDeltaSnapshot } from '@/domain/types';
import { SEED_ACCOUNTS, SEED_ALERTS, SEED_DEVICES, SEED_EVIDENCES, SEED_TRANSACTIONS, SEED_AUTH_LOGS, SEED_API_EVENTS } from '@/infrastructure/seed-scenarios';
import { validateStrictMerchantReceiptImage } from '@/infrastructure/security-guard';
import { SESSION_COOKIE_NAME, createSignedSessionToken } from '@/infrastructure/session-auth';

// Minimal valid 1x1 PNG binary (89 50 4E 47 ... IHDR 1x1)
const VALID_1X1_PNG_BASE64 =
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=';
const VALID_1X1_PNG_DATA_URL = `data:image/png;base64,${VALID_1X1_PNG_BASE64}`;

// Build minimal valid JPEG (SOI + APP0 JFIF + SOF0 16x16 + EOI, >= 40 bytes)
const buildValidJpegDataUrl = (width = 16, height = 16): string => {
  const bytes = Buffer.from([
    0xff, 0xd8, // SOI
    0xff, 0xe0, 0x00, 0x10, // APP0 len 16
    0x4a, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
    0xff, 0xc0, 0x00, 0x11, 0x08, // SOF0 header len 17, 8-bit
    (height >> 8) & 0xff, height & 0xff,
    (width >> 8) & 0xff, width & 0xff,
    0x03, 0x01, 0x11, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01,
    0xff, 0xd9, // EOI
  ]);
  return `data:image/jpeg;base64,${bytes.toString('base64')}`;
};

// Build PNG IHDR header claiming huge dimensions (decompression bomb guard test)
const buildGiantDimensionPngDataUrl = (width: number, height: number): string => {
  const buf = Buffer.from(VALID_1X1_PNG_BASE64, 'base64');
  const cloned = Buffer.from(buf);
  cloned.writeUInt32BE(width, 16);
  cloned.writeUInt32BE(height, 20);
  return `data:image/png;base64,${cloned.toString('base64')}`;
};

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

describe('Wave 3 Core Capability 01 & 02: Merchant Vision OCR & Adaptive HITL Feedback', () => {
  const originalFetch = global.fetch;
  const originalGeminiKey = process.env.GEMINI_API_KEY;

  afterEach(() => {
    global.fetch = originalFetch;
    process.env.GEMINI_API_KEY = originalGeminiKey;
    vi.restoreAllMocks();
  });

  it('enforces strict binary image validation (accepts PNG/JPEG, blocks SVG, corrupted binary, bombs, oversized)', () => {
    const okPng = validateStrictMerchantReceiptImage(VALID_1X1_PNG_DATA_URL);
    expect(okPng.valid).toBe(true);
    if (okPng.valid) {
      expect(okPng.mimeType).toBe('image/png');
      expect(okPng.width).toBe(1);
      expect(okPng.height).toBe(1);
    }

    const okJpeg = validateStrictMerchantReceiptImage(buildValidJpegDataUrl(320, 240));
    expect(okJpeg.valid).toBe(true);
    if (okJpeg.valid) {
      expect(okJpeg.mimeType).toBe('image/jpeg');
      expect(okJpeg.width).toBe(320);
      expect(okJpeg.height).toBe(240);
    }

    // SVG rejected strictly
    const badSvg = validateStrictMerchantReceiptImage(
      'data:image/svg+xml;base64,' + Buffer.from('<svg onload="alert(1)"></svg>').toString('base64')
    );
    expect(badSvg.valid).toBe(false);

    // PNG header spoofed over plain text rejected (magic mismatch)
    const spoofedPng = validateStrictMerchantReceiptImage(
      'data:image/png;base64,' + Buffer.from('THIS_IS_NOT_A_PNG_FILE_JUST_TEXT_DATA').toString('base64')
    );
    expect(spoofedPng.valid).toBe(false);

    // Decompression bomb pixel guard (9000x9000 = 81M pixels) rejected
    const giantPng = validateStrictMerchantReceiptImage(buildGiantDimensionPngDataUrl(9000, 9000));
    expect(giantPng.valid).toBe(false);

    // Empty / unsupported MIME rejected
    expect(validateStrictMerchantReceiptImage('').valid).toBe(false);
    expect(validateStrictMerchantReceiptImage('data:application/pdf;base64,JVBERi0xLjQK').valid).toBe(
      false
    );
  });

  it('normalizes Vietnamese VND amounts accurately and rejects decimals/non-VND', () => {
    expect(normalizeVndAmountValue('15.000.000 đ')).toBe(15_000_000);
    expect(normalizeVndAmountValue('4,850,000 VND')).toBe(4_850_000);
    expect(normalizeVndAmountValue('25000000₫')).toBe(25_000_000);
    expect(normalizeVndAmountValue(4_850_000)).toBe(4_850_000);
    expect(normalizeVndAmountValue('1500.5')).toBeNull();
    expect(normalizeVndAmountValue('-500000')).toBeNull();
    expect(normalizeVndAmountValue('USD 500')).toBeNull();
  });

  it('covers all MV-01..MV-09 Merchant Vision verification branches deterministically without letting AI touch ledger', async () => {
    const ledgerWithBlocked = [
      ...SEED_TRANSACTIONS,
      {
        id: 'TXN-BLOCKED-SHD',
        alertId: 'SHD-ALT-APP-003',
        senderAccountId: 'ACC-USR-103',
        receiverAccountId: 'ACC-MULE-903',
        amountVnd: 18_000_000,
        channel: 'P2P_WALLET' as const,
        message: 'Blocked scam',
        deviceId: 'DEV-IOS-303',
        hopIndex: 1,
        status: 'BLOCKED' as const,
        timestamp: '2026-11-21T10:00:00Z',
      },
    ];

    // MV-01 Verified Ledger Match
    const mv01 = crossVerifyMerchantVisionAgainstLedger({
      extracted: normalizeExtractedFields({
        claimedTransactionId: 'TXN-MERCH-OK',
        claimedAmountVnd: '4.850.000 đ',
        currency: 'VND',
        claimedRecipientAccount: 'ACC-HOSP-800',
        imageQualityStatus: 'CLEAR',
        fieldConfidence: { transactionId: 0.96, amountVnd: 0.97, recipientAccount: 0.9, overall: 0.95 },
      }),
      ocrOutcome: 'OK',
      merchantAccountIdOrNumber: 'ACC-HOSP-800',
      ledgerTransactions: ledgerWithBlocked,
      accounts: SEED_ACCOUNTS,
      modelUsed: 'mock-vision',
      latencyMs: 120,
    });
    expect(mv01.status).toBe('VERIFIED_LEDGER_MATCH');
    expect(mv01.ledgerComparison.actualAmountVnd).toBe(4_850_000);

    // MV-02 Amount Mismatch
    const mv02 = crossVerifyMerchantVisionAgainstLedger({
      extracted: normalizeExtractedFields({
        claimedTransactionId: 'TXN-MERCH-1K',
        claimedAmountVnd: '15.000.000 VNĐ',
        currency: 'VND',
        claimedRecipientAccount: 'ACC-HOSP-800',
        imageQualityStatus: 'CLEAR',
        fieldConfidence: { overall: 0.92 },
      }),
      ocrOutcome: 'OK',
      merchantAccountIdOrNumber: 'ACC-HOSP-800',
      ledgerTransactions: ledgerWithBlocked,
      accounts: SEED_ACCOUNTS,
      modelUsed: 'mock-vision',
      latencyMs: 110,
    });
    expect(mv02.status).toBe('AMOUNT_MISMATCH');
    expect(mv02.mismatchedFields).toContain('amountVnd');

    // MV-03 Transaction Not Found
    const mv03 = crossVerifyMerchantVisionAgainstLedger({
      extracted: normalizeExtractedFields({
        claimedTransactionId: 'TXN-GHOST-9999',
        claimedAmountVnd: 9_000_000,
        currency: 'VND',
        claimedRecipientAccount: 'ACC-HOSP-800',
        fieldConfidence: { overall: 0.9 },
      }),
      ocrOutcome: 'OK',
      merchantAccountIdOrNumber: 'ACC-HOSP-800',
      ledgerTransactions: ledgerWithBlocked,
      accounts: SEED_ACCOUNTS,
      modelUsed: 'mock-vision',
      latencyMs: 90,
    });
    expect(mv03.status).toBe('TRANSACTION_NOT_FOUND');

    // MV-04 Blocked / Not Settled
    const mv04 = crossVerifyMerchantVisionAgainstLedger({
      extracted: normalizeExtractedFields({
        claimedTransactionId: 'TXN-BLOCKED-SHD',
        claimedAmountVnd: 18_000_000,
        currency: 'VND',
        claimedRecipientAccount: 'ACC-MULE-903',
        fieldConfidence: { overall: 0.9 },
      }),
      ocrOutcome: 'OK',
      merchantAccountIdOrNumber: 'ACC-MULE-903',
      ledgerTransactions: ledgerWithBlocked,
      accounts: SEED_ACCOUNTS,
      modelUsed: 'mock-vision',
      latencyMs: 85,
    });
    expect(mv04.status).toBe('NOT_SETTLED');
    expect(mv04.ledgerComparison.actualAmountVnd).toBe(0);

    // MV-05 Recipient Mismatch
    const mv05 = crossVerifyMerchantVisionAgainstLedger({
      extracted: normalizeExtractedFields({
        claimedTransactionId: 'TXN-MERCH-OK',
        claimedAmountVnd: 4_850_000,
        currency: 'VND',
        claimedRecipientAccount: 'ACC-HOSP-800',
        fieldConfidence: { overall: 0.9 },
      }),
      ocrOutcome: 'OK',
      merchantAccountIdOrNumber: 'ACC-USR-104',
      ledgerTransactions: ledgerWithBlocked,
      accounts: SEED_ACCOUNTS,
      modelUsed: 'mock-vision',
      latencyMs: 95,
    });
    expect(mv05.status).toBe('RECIPIENT_MISMATCH');

    // MV-06 Blurry / Low Confidence / Missing TX ID -> NEEDS_MANUAL_REVIEW
    const mv06 = crossVerifyMerchantVisionAgainstLedger({
      extracted: normalizeExtractedFields({
        claimedTransactionId: null,
        claimedAmountVnd: 4_850_000,
        currency: 'VND',
        imageQualityStatus: 'BLURRY',
        fieldConfidence: { overall: 0.35 },
      }),
      ocrOutcome: 'OK',
      merchantAccountIdOrNumber: 'ACC-HOSP-800',
      ledgerTransactions: ledgerWithBlocked,
      accounts: SEED_ACCOUNTS,
      modelUsed: 'mock-vision',
      latencyMs: 80,
    });
    expect(mv06.status).toBe('NEEDS_MANUAL_REVIEW');

    // MV-09 Multiple conflicting TX IDs -> AMBIGUOUS_EXTRACTION
    const mv09 = crossVerifyMerchantVisionAgainstLedger({
      extracted: normalizeExtractedFields({
        claimedTransactionId: 'TXN-MERCH-OK',
        candidateTransactionIds: ['TXN-MERCH-OK', 'TXN-MERCH-1K'],
        claimedAmountVnd: 4_850_000,
        currency: 'VND',
        fieldConfidence: { overall: 0.85 },
      }),
      ocrOutcome: 'OK',
      merchantAccountIdOrNumber: 'ACC-HOSP-800',
      ledgerTransactions: ledgerWithBlocked,
      accounts: SEED_ACCOUNTS,
      modelUsed: 'mock-vision',
      latencyMs: 95,
    });
    expect(mv09.status).toBe('AMBIGUOUS_EXTRACTION');

    // API integration MV-07 (SVG rejected 400) & MV-08 (AI unavailable -> no crash, no fake VERIFIED, no image saved in delta)
    const sid = `w3-mv-${Date.now()}`;
    const badSvgApi = await merchantVisionPost(
      makeAuthReq({
        url: 'http://localhost:3000/api/merchant/vision',
        sessionId: sid,
        role: 'END_USER',
        principalId: 'merch-1',
        body: {
          imageDataUrl: 'data:image/svg+xml;base64,' + Buffer.from('<svg></svg>').toString('base64'),
          merchantAccountIdOrNumber: 'ACC-HOSP-800',
        },
      })
    );
    expect(badSvgApi.status).toBe(400);
    expect((await badSvgApi.json()).code).toBe('INVALID_IMAGE');

    // Simulate AI unavailable (missing key) via POST /api/merchant/vision
    process.env.GEMINI_API_KEY = '';
    const unavailApi = await merchantVisionPost(
      makeAuthReq({
        url: 'http://localhost:3000/api/merchant/vision',
        sessionId: sid,
        role: 'END_USER',
        principalId: 'merch-1',
        body: {
          imageDataUrl: VALID_1X1_PNG_DATA_URL,
          merchantAccountIdOrNumber: 'ACC-HOSP-800',
        },
      })
    );
    expect(unavailApi.status).toBe(200);
    const unavailJson = await unavailApi.json();
    expect(unavailJson.verification.status).toBe('AI_UNAVAILABLE');
    // Ensure transient image data is NEVER stored inside SessionDeltaSnapshot or auditLogs
    expect(JSON.stringify(unavailJson.delta)).not.toContain(VALID_1X1_PNG_BASE64);

    // Mock Gemini REST response via global.fetch -> test full API pipeline MV-02
    process.env.GEMINI_API_KEY = 'fake-test-key-for-mock';
    global.fetch = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          candidates: [
            {
              content: {
                parts: [
                  {
                    text: JSON.stringify({
                      claimedTransactionId: 'TXN-MERCH-1K',
                      claimedAmountVnd: '15.000.000 đ',
                      currency: 'VND',
                      claimedRecipientAccount: '1188999000888',
                      imageQualityStatus: 'CLEAR',
                      fieldConfidence: { overall: 0.94 },
                    }),
                  },
                ],
              },
            },
          ],
        }),
        { status: 200 }
      )
    ) as unknown as typeof fetch;

    const mockedOcrApi = await merchantVisionPost(
      makeAuthReq({
        url: 'http://localhost:3000/api/merchant/vision',
        sessionId: sid,
        role: 'END_USER',
        principalId: 'merch-1',
        body: {
          imageDataUrl: VALID_1X1_PNG_DATA_URL,
          merchantAccountIdOrNumber: 'ACC-HOSP-800',
          clientDelta: unavailJson.delta,
        },
      })
    );
    expect(mockedOcrApi.status).toBe(200);
    const mockedJson = await mockedOcrApi.json();
    expect(mockedJson.verification.status).toBe('AMOUNT_MISMATCH');
    expect(mockedJson.verification.ledgerComparison.actualAmountVnd).toBe(1_000);
    expect(mockedJson.verification.ledgerComparison.claimedAmountVnd).toBe(15_000_000);
    expect(JSON.stringify(mockedJson.delta)).not.toContain(VALID_1X1_PNG_BASE64);
  });

  it('enforces Adaptive HITL Memory authorization, Maker-Checker, bounds, conflict resolution, expiry, revocation & hard-rule precedence', async () => {
    const sidA = `w3-hitl-a-${Date.now()}`;
    const sidB = `w3-hitl-b-${Date.now()}`;

    // 1. END_USER forbidden from creating HITL memory (403)
    const endUserRes = await feedbackPost(
      makeAuthReq({
        url: 'http://localhost:3000/api/feedback',
        sessionId: sidA,
        role: 'END_USER',
        principalId: 'usr-1',
        body: { action: 'CREATE', alertId: 'ALT-FPR-004', feedbackDecision: 'OVERRIDE_SAFE' },
      })
    );
    expect(endUserRes.status).toBe(403);

    // 2. L1_MAKER creates PENDING_APPROVAL feedback (does NOT alter score until L2 approves!)
    const l1Res = await feedbackPost(
      makeAuthReq({
        url: 'http://localhost:3000/api/feedback',
        sessionId: sidA,
        role: 'L1_MAKER',
        principalId: 'maker-alpha',
        body: {
          action: 'CREATE',
          alertId: 'ALT-FPR-004',
          feedbackDecision: 'OVERRIDE_SAFE',
          targetScope: 'RECIPIENT_PATTERN',
          analystRationale: 'Da xac minh hoa don cap cuu benh vien',
          ttlHours: 24,
        },
      })
    );
    expect(l1Res.status).toBe(200);
    const l1Data = await l1Res.json();
    expect(l1Data.feedbackRecord.status).toBe('PENDING_APPROVAL');
    const feedbackId = l1Data.feedbackRecord.feedbackId;
    let deltaA: SessionDeltaSnapshot = l1Data.delta;

    // L1_MAKER cannot approve or revoke (403)
    const l1ApproveAttempt = await feedbackPost(
      makeAuthReq({
        url: 'http://localhost:3000/api/feedback',
        sessionId: sidA,
        role: 'L1_MAKER',
        principalId: 'maker-alpha',
        body: { action: 'APPROVE', feedbackId, clientDelta: deltaA },
      })
    );
    expect(l1ApproveAttempt.status).toBe(403);

    // Same principal even as L2_CHECKER blocked from self-approving (403 4-Eyes)
    const selfApproveAttempt = await feedbackPost(
      makeAuthReq({
        url: 'http://localhost:3000/api/feedback',
        sessionId: sidA,
        role: 'L2_CHECKER',
        principalId: 'maker-alpha',
        body: { action: 'APPROVE', feedbackId, clientDelta: deltaA },
      })
    );
    expect(selfApproveAttempt.status).toBe(403);

    // Different L2_CHECKER principal approves -> becomes APPROVED_ACTIVE
    const l2ApproveRes = await feedbackPost(
      makeAuthReq({
        url: 'http://localhost:3000/api/feedback',
        sessionId: sidA,
        role: 'L2_CHECKER',
        principalId: 'checker-beta',
        body: { action: 'APPROVE', feedbackId, clientDelta: deltaA },
      })
    );
    expect(l2ApproveRes.status).toBe(200);
    const l2ApprovedData = await l2ApproveRes.json();
    expect(l2ApprovedData.feedbackRecord.status).toBe('APPROVED_ACTIVE');
    deltaA = l2ApprovedData.delta;

    // Duplicate identical active feedback rejected (400)
    const dupRes = await feedbackPost(
      makeAuthReq({
        url: 'http://localhost:3000/api/feedback',
        sessionId: sidA,
        role: 'L2_CHECKER',
        principalId: 'checker-beta',
        body: {
          action: 'CREATE',
          alertId: 'ALT-FPR-004',
          feedbackDecision: 'OVERRIDE_SAFE',
          targetScope: 'RECIPIENT_PATTERN',
          analystRationale: 'Duplicate test',
          clientDelta: deltaA,
        },
      })
    );
    expect(dupRes.status).toBe(400);

    // 3. Domain checks: Bounds, Hard Rule Precedence, Context Isolation, Conflict NEEDS_REVIEW, Expiry & Revocation
    expect(clampHitlRiskAdjustment('OVERRIDE_SAFE', -99)).toBe(-18);
    expect(clampHitlRiskAdjustment('OVERRIDE_SAFE', -1)).toBe(-5);
    expect(clampHitlRiskAdjustment('FORCE_BLOCK', 99)).toBe(20);
    expect(clampHitlRiskAdjustment('FORCE_BLOCK', 2)).toBe(10);

    const safeHospitalAlert = SEED_ALERTS.find((a) => a.id === 'ALT-FPR-004')!;
    const hospitalAcc = SEED_ACCOUNTS.find((a) => a.id === 'ACC-HOSP-800')!;
    const matchingCtxSig = buildHitlContextSignature({
      scenarioCode: safeHospitalAlert.scenarioCode,
      recipientAccountType: hospitalAcc.accountType,
      channel: 'VIETQR',
    });

    const activeSafeRecord: HitlFeedbackMemoryRecord = {
      ...l2ApprovedData.feedbackRecord,
      riskAdjustment: -12,
    };

    // Matching context lowers bounded score cleanly (e.g. 40 -> 28)
    const appliedNormal = evaluateAdaptiveHitlFeedback({
      baseScore: 40,
      alert: safeHospitalAlert,
      targetAccount: hospitalAcc,
      targetFingerprint: activeSafeRecord.targetFingerprint,
      currentContextSignature: matchingCtxSig,
      feedbackMemory: [activeSafeRecord],
      hardCriticalSignalsPresent: false,
    });
    expect(appliedNormal.finalScore).toBe(28);
    expect(appliedNormal.summary.appliedRecords.length).toBe(1);

    // Different context signature -> NOT applied (no unconditional whitelist!)
    const mismatchedContext = evaluateAdaptiveHitlFeedback({
      baseScore: 70,
      alert: safeHospitalAlert,
      targetAccount: hospitalAcc,
      targetFingerprint: activeSafeRecord.targetFingerprint,
      currentContextSignature: 'CYBER_ATO_MULE:MULE_SUSPECT:P2P_WALLET',
      feedbackMemory: [activeSafeRecord],
      hardCriticalSignalsPresent: false,
    });
    expect(mismatchedContext.finalScore).toBe(70);
    expect(mismatchedContext.summary.appliedRecords.length).toBe(0);

    // Hard security rules block SAFE override (hardRuleBlockedOverride = true)
    const hardRuleBlocked = evaluateAdaptiveHitlFeedback({
      baseScore: 92,
      alert: safeHospitalAlert,
      targetAccount: hospitalAcc,
      targetFingerprint: activeSafeRecord.targetFingerprint,
      currentContextSignature: matchingCtxSig,
      feedbackMemory: [activeSafeRecord],
      hardCriticalSignalsPresent: true,
    });
    expect(hardRuleBlocked.finalScore).toBe(92);
    expect(hardRuleBlocked.summary.hardRuleBlockedOverride).toBe(true);

    // Conflict resolution: Simultaneous SAFE & FORCE_BLOCK -> NEEDS_REVIEW (no score drop)
    const conflictingBlockRecord: HitlFeedbackMemoryRecord = {
      ...activeSafeRecord,
      feedbackId: 'HITL-CONFLICT-BLK',
      feedbackDecision: 'FORCE_BLOCK',
      riskAdjustment: 15,
    };
    const conflictEval = evaluateAdaptiveHitlFeedback({
      baseScore: 55,
      alert: safeHospitalAlert,
      targetAccount: hospitalAcc,
      targetFingerprint: activeSafeRecord.targetFingerprint,
      currentContextSignature: matchingCtxSig,
      feedbackMemory: [activeSafeRecord, conflictingBlockRecord],
      hardCriticalSignalsPresent: false,
    });
    expect(conflictEval.summary.conflictDetected).toBe(true);
    expect(conflictEval.summary.needsReviewVi).toContain('NEEDS_REVIEW');
    expect(conflictEval.finalScore).toBe(55);

    // Expiry removes effect automatically without mutating history
    const expiredEval = evaluateAdaptiveHitlFeedback({
      baseScore: 40,
      alert: safeHospitalAlert,
      targetAccount: hospitalAcc,
      targetFingerprint: activeSafeRecord.targetFingerprint,
      currentContextSignature: matchingCtxSig,
      feedbackMemory: [activeSafeRecord],
      hardCriticalSignalsPresent: false,
      nowMs: Date.parse(activeSafeRecord.expiresAt) + 5000,
    });
    expect(expiredEval.finalScore).toBe(40);
    expect(expiredEval.summary.appliedRecords.length).toBe(0);

    // Consumer Shield integration: Active FORCE_BLOCK HITL elevates transfer to WARN_COOLING_OFF,
    // while OVERRIDE_SAFE never overrides hard Shield block!
    const muleAlert = SEED_ALERTS.find((a) => a.id === 'ALT-APP-003')!;
    const muleAcc = SEED_ACCOUNTS.find((a) => a.id === 'ACC-MULE-903')!;
    const blockDecision = evaluateConsumerTransfer(
      {
        senderName: 'Test User',
        recipientAccountIdOrNumber: muleAcc.accountNumber,
        amountVnd: 2_000_000,
        message: 'Chuyen tien thong thuong',
      },
      [],
      SEED_ACCOUNTS,
      {
        hitlFeedbackMemory: [
          {
            ...activeSafeRecord,
            feedbackId: 'HITL-MULE-BLK',
            sourceAlertId: muleAlert.id,
            recipientAccountId: muleAcc.id,
            feedbackDecision: 'FORCE_BLOCK',
            riskAdjustment: 15,
          },
        ],
      }
    );
    expect(blockDecision.decision).toBe('WARN_COOLING_OFF');

    // Hard Shield still BLOCKS even if OVERRIDE_SAFE memory exists!
    const hardShieldNotBypassed = evaluateConsumerTransfer(
      {
        senderName: 'Test User',
        recipientAccountIdOrNumber: muleAcc.accountNumber,
        amountVnd: 2_000_000,
        message: 'Chuyen tien thong thuong',
      },
      [
        {
          id: 'SHD-HARD',
          alertId: muleAlert.id,
          targetAccountId: muleAcc.id,
          targetAccountNumber: muleAcc.accountNumber,
          targetOwnerName: muleAcc.ownerName,
          ruleType: 'BLOCK_RECIPIENT_MULE',
          userWarningVi: 'Blocked',
          active: true,
          createdAt: new Date().toISOString(),
        },
      ],
      SEED_ACCOUNTS,
      {
        hitlFeedbackMemory: [
          {
            ...activeSafeRecord,
            recipientAccountId: muleAcc.id,
          },
        ],
      }
    );
    expect(hardShieldNotBypassed.decision).toBe('BLOCKED_BY_SHIELD');

    // 4. Revocation removes active adjustment cleanly & preserves history; Session B isolated
    const revokeRes = await feedbackPost(
      makeAuthReq({
        url: 'http://localhost:3000/api/feedback',
        sessionId: sidA,
        role: 'L2_CHECKER',
        principalId: 'checker-beta',
        body: { action: 'REVOKE', feedbackId, clientDelta: deltaA },
      })
    );
    expect(revokeRes.status).toBe(200);
    const revokedData = await revokeRes.json();
    expect(revokedData.feedbackRecord.status).toBe('REVOKED');
    deltaA = revokedData.delta;

    // Run Forensics with revoked record vs active record
    const baseForensicsSidB = runDeterministicForensicsSuite({
      alert: safeHospitalAlert,
      accounts: SEED_ACCOUNTS,
      devices: SEED_DEVICES,
      authLogs: SEED_AUTH_LOGS,
      transactions: SEED_TRANSACTIONS,
      apiEvents: SEED_API_EVENTS,
      evidences: SEED_EVIDENCES,
    });
    const afterRevokeForensics = runDeterministicForensicsSuite({
      alert: safeHospitalAlert,
      accounts: SEED_ACCOUNTS,
      devices: SEED_DEVICES,
      authLogs: SEED_AUTH_LOGS,
      transactions: SEED_TRANSACTIONS,
      apiEvents: SEED_API_EVENTS,
      evidences: SEED_EVIDENCES,
      feedbackMemory: deltaA.hitlFeedbackMemory,
      targetFingerprintsByAccountId: { [hospitalAcc.id]: activeSafeRecord.targetFingerprint },
    });
    expect(afterRevokeForensics.deterministicRiskScore).toBe(baseForensicsSidB.deterministicRiskScore);

    // 5. Forged hitlFeedbackMemory injection without valid HMAC deltaIntegrityTag blocked (400)
    const tamperedDelta = {
      ...deltaA,
      stateRevision: (deltaA.stateRevision ?? 1) + 5,
      hitlFeedbackMemory: [activeSafeRecord],
    };
    const forgedAttempt = await feedbackPost(
      makeAuthReq({
        url: 'http://localhost:3000/api/feedback',
        sessionId: sidB,
        role: 'L2_CHECKER',
        principalId: 'attacker',
        body: { action: 'REVOKE', feedbackId, clientDelta: tamperedDelta },
      })
    );
    expect(forgedAttempt.status).toBe(400);
    expect((await forgedAttempt.json()).code).toBe('FORGED_STATE_REVISION');
  });
});
