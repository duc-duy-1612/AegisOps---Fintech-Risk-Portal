import { describe, expect, it } from 'vitest';
import { NextRequest } from 'next/server';
import { POST as merchantVisionPost } from '@/app/api/merchant/vision/route';
import { GET as sessionGet, POST as sessionPost } from '@/app/api/session/route';
import { POST as walletPost } from '@/app/api/wallet/route';
import {
  CopilotRequestSchema,
  DEFAULT_MAX_JSON_BODY_BYTES,
  MEDIA_MAX_JSON_BODY_BYTES,
  MerchantVerifyRequestSchema,
  MerchantVisionVerifyRequestSchema,
  PlaybookRequestSchema,
  SessionRoleSwitchSchema,
  WalletRequestSchema,
  WorkspaceSyncRequestSchema,
  parseRequestJsonWithSchema,
} from '@/domain/api-schemas';
import { MerchantOcrRawExtractionSchema } from '@/domain/merchant-vision';
import { GeminiStructuredBriefSchema } from '@/domain/types';
import { SESSION_COOKIE_NAME } from '@/infrastructure/session-auth';

const VALID_1X1_PNG_BASE64 =
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+X2m0AAAAASUVORK5CYII=';

const extractCookieHeader = (setCookieHeader: string | null): string => {
  if (!setCookieHeader) return '';
  return setCookieHeader
    .split(/,(?=\s*[a-zA-Z0-9_-]+=)/)
    .map((part) => part.split(';')[0]?.trim())
    .filter(Boolean)
    .join('; ');
};

describe('CR-1.1 — Dependency Security Remediation (Next.js 15.5.29 + Zod 4.6.7 + Input Bounds)', () => {
  it('preserves Zod v4 .strict() unexpected-key rejection and .trim().min(1) whitespace rejection', async () => {
    const reqWithUnknownKey = new NextRequest('http://localhost:3000/api/wallet', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        recipientAccountIdOrNumber: '0901234567',
        amountVnd: 100_000,
        injectedAdminFlag: true,
      }),
    });
    const unknownKeyRes = await parseRequestJsonWithSchema(reqWithUnknownKey, WalletRequestSchema);
    expect(unknownKeyRes.ok).toBe(false);
    if (!unknownKeyRes.ok) {
      expect(unknownKeyRes.response.status).toBe(400);
      const payload = (await unknownKeyRes.response.json()) as { code: string };
      expect(payload.code).toBe('VALIDATION_ERROR');
    }

    // Whitespace-only strings must fail .trim().min(1) under Zod v4 just like Zod v3
    expect(
      WalletRequestSchema.safeParse({
        recipientAccountIdOrNumber: '   ',
        amountVnd: 100_000,
      }).success
    ).toBe(false);
    expect(
      MerchantVerifyRequestSchema.safeParse({
        claimedTxId: '   ',
        claimedAmountVnd: 50_000,
      }).success
    ).toBe(false);
    expect(
      CopilotRequestSchema.safeParse({
        question: '   ',
      }).success
    ).toBe(false);

    // Non-finite, negative, and non-integer numbers must fail
    expect(
      WalletRequestSchema.safeParse({
        recipientAccountIdOrNumber: '0901234567',
        amountVnd: Number.POSITIVE_INFINITY,
      }).success
    ).toBe(false);
    expect(
      WalletRequestSchema.safeParse({
        recipientAccountIdOrNumber: '0901234567',
        amountVnd: 100.5,
      }).success
    ).toBe(false);
    expect(
      SessionRoleSwitchSchema.safeParse({
        role: 'L2_CHECKER',
        unexpectedField: 'nope',
      }).success
    ).toBe(false);
  });

  it('blocks oversized constrained collections and excessive record key counts fast without exhausting memory (GHSA-mrhx-c7xc-m3w5 defense-in-depth)', () => {
    const start = performance.now();

    const oversizedActions = Array.from({ length: 10_000 }, (_, i) => `ACT-${i}`);
    const playbookRes = PlaybookRequestSchema.safeParse({
      alertId: 'ALT-2026-001',
      mode: 'PROPOSE_L1',
      selectedActionIds: oversizedActions,
    });
    expect(playbookRes.success).toBe(false);

    const oversizedAlertStatuses: Record<string, 'OPEN'> = {};
    for (let i = 0; i < 150; i += 1) {
      oversizedAlertStatuses[`ALT-${i}`] = 'OPEN';
    }
    const oversizedRecordRes = WorkspaceSyncRequestSchema.safeParse({
      clientDelta: {
        alertStatuses: oversizedAlertStatuses,
      },
    });
    expect(oversizedRecordRes.success).toBe(false);

    const oversizedIdempotencyKeys: Record<string, string> = {};
    for (let i = 0; i < 250; i += 1) {
      oversizedIdempotencyKeys[`idem-key-${i}`] = `TX-${i}`;
    }
    const oversizedIdemRes = WorkspaceSyncRequestSchema.safeParse({
      clientDelta: {
        processedIdempotencyKeys: oversizedIdempotencyKeys,
      },
    });
    expect(oversizedIdemRes.success).toBe(false);

    const elapsedMs = performance.now() - start;
    expect(elapsedMs).toBeLessThan(500);
  });

  it('rejects oversized JSON request bodies with HTTP 413 via both Content-Length and raw byte checks while permitting valid media payloads', async () => {
    // 1. Content-Length fast-reject before body read
    const declaredOversizedReq = new NextRequest('http://localhost:3000/api/wallet', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': String(DEFAULT_MAX_JSON_BODY_BYTES + 1024),
      },
      body: JSON.stringify({
        recipientAccountIdOrNumber: '0901234567',
        amountVnd: 100_000,
      }),
    });
    const declaredRes = await parseRequestJsonWithSchema(declaredOversizedReq, WalletRequestSchema);
    expect(declaredRes.ok).toBe(false);
    if (!declaredRes.ok) {
      expect(declaredRes.response.status).toBe(413);
      const body = (await declaredRes.response.json()) as { code: string };
      expect(body.code).toBe('PAYLOAD_TOO_LARGE');
    }

    // 2. Actual oversized body without Content-Length header
    const oversizedPayload = JSON.stringify({
      recipientAccountIdOrNumber: '0901234567',
      amountVnd: 100_000,
      message: 'A'.repeat(DEFAULT_MAX_JSON_BODY_BYTES + 2048),
    });
    const actualOversizedReq = new NextRequest('http://localhost:3000/api/wallet', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: oversizedPayload,
    });
    const actualRes = await parseRequestJsonWithSchema(actualOversizedReq, WalletRequestSchema);
    expect(actualRes.ok).toBe(false);
    if (!actualRes.ok) {
      expect(actualRes.response.status).toBe(413);
    }

    // 3. Legitimate large image payload (> 512 KB, < 5.6 MB) succeeds under MEDIA_MAX_JSON_BODY_BYTES
    const mediumBase64Payload = `data:image/png;base64,${'A'.repeat(700_000)}`;
    const mediaReq = new NextRequest('http://localhost:3000/api/merchant/vision', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        imageDataUrl: mediumBase64Payload,
      }),
    });
    const mediaRes = await parseRequestJsonWithSchema(
      mediaReq,
      MerchantVisionVerifyRequestSchema,
      { maxBytes: MEDIA_MAX_JSON_BODY_BYTES }
    );
    expect(mediaRes.ok).toBe(true);
  });

  it('validates GeminiStructuredBriefSchema and MerchantOcrRawExtractionSchema cleanly under Zod 4.6.7', () => {
    const validBrief = GeminiStructuredBriefSchema.safeParse({
      classification: 'CONFIRMED_ATO_MULE',
      confidenceScore: 92,
      executiveSummaryVi: 'Phát hiện tài khoản đích có dấu hiệu luân chuyển tiền bất thường qua thiết bị giả lập.',
      keyFindingsVi: ['Thiết bị dùng chung với 4 tài khoản khác', 'Phiên đăng nhập còn sống sau đổi mật khẩu'],
      citedEvidenceIds: ['EVD-001', 'EVD-002'],
      userShieldWarningVi: 'Cảnh báo: Tài khoản nhận có dấu hiệu rủi ro cao.',
      recommendedActions: [
        {
          id: 'ACT-1',
          actionType: 'FREEZE_MULE_ACCOUNTS',
          labelVi: 'Đóng băng tài khoản nghi vấn',
          targetEntityId: 'ACC-MULE-01',
          recommended: true,
        },
      ],
    });
    expect(validBrief.success).toBe(true);

    const oversizedBrief = GeminiStructuredBriefSchema.safeParse({
      classification: 'CONFIRMED_ATO_MULE',
      confidenceScore: 92,
      executiveSummaryVi: 'Phát hiện tài khoản đích có dấu hiệu luân chuyển tiền bất thường.',
      keyFindingsVi: ['Bằng chứng 1'],
      citedEvidenceIds: Array.from({ length: 100 }, (_, i) => `EVD-${i}`),
      userShieldWarningVi: 'Cảnh báo',
      recommendedActions: [
        {
          id: 'ACT-1',
          actionType: 'FREEZE_MULE_ACCOUNTS',
          labelVi: 'Đóng băng tài khoản nghi vấn',
          targetEntityId: 'ACC-MULE-01',
          recommended: true,
        },
      ],
    });
    expect(oversizedBrief.success).toBe(false);

    const validOcr = MerchantOcrRawExtractionSchema.safeParse({
      claimedTransactionId: 'TX-2026-001',
      claimedAmountVnd: '250000',
      currency: 'VND',
      imageQualityStatus: 'CLEAR',
      fieldConfidence: { transactionId: 0.95, amountVnd: 0.98, recipientAccount: 0.9, overall: 0.95 },
    });
    expect(validOcr.success).toBe(true);
  });

  it('preserves Next.js 15.5.29 session auth, wallet strict validation/idempotency, and Merchant Vision binary image gate', async () => {
    const anonGet = await sessionGet(
      new NextRequest('http://localhost:3000/api/session', { method: 'GET' })
    );
    expect(anonGet.status).toBe(200);
    const anonBody = (await anonGet.json()) as { authenticated: boolean };
    expect(anonBody.authenticated).toBe(false);

    const loginRes = await sessionPost(
      new NextRequest('http://localhost:3000/api/session', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          origin: 'http://localhost:3000',
        },
        body: JSON.stringify({ role: 'L2_CHECKER' }),
      })
    );
    expect(loginRes.status).toBe(200);
    const cookieHeader = extractCookieHeader(loginRes.headers.get('set-cookie'));
    expect(cookieHeader).toContain(`${SESSION_COOKIE_NAME}=`);

    // Verify /api/session POST strict schema rejection
    const badRoleRes = await sessionPost(
      new NextRequest('http://localhost:3000/api/session', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          origin: 'http://localhost:3000',
          cookie: cookieHeader,
        },
        body: JSON.stringify({ role: 'L1_MAKER', extraProp: 'blocked' }),
      })
    );
    expect(badRoleRes.status).toBe(400);

    // Verify /api/wallet POST strict schema rejection + idempotent transfer replay
    const badWalletRes = await walletPost(
      new NextRequest('http://localhost:3000/api/wallet', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          origin: 'http://localhost:3000',
          cookie: cookieHeader,
        },
        body: JSON.stringify({
          recipientAccountIdOrNumber: '0909888777',
          amountVnd: 50_000,
          rogueField: 1,
        }),
      })
    );
    expect(badWalletRes.status).toBe(400);

    const idemKey = `cr11-idem-${Date.now()}`;
    const txPayload = JSON.stringify({
      recipientAccountIdOrNumber: 'ACC-MERCHANT-COFFEE',
      amountVnd: 55_000,
      message: 'CR-1.1 regression coffee payment',
      idempotencyKey: idemKey,
    });
    const firstTxRes = await walletPost(
      new NextRequest('http://localhost:3000/api/wallet', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          origin: 'http://localhost:3000',
          cookie: cookieHeader,
        },
        body: txPayload,
      })
    );
    expect(firstTxRes.status).toBe(200);
    const firstTxBody = (await firstTxRes.json()) as {
      decision: { transactionId?: string; senderBalanceVnd?: number };
    };
    expect(firstTxBody.decision.transactionId).toBeTruthy();

    const replayTxRes = await walletPost(
      new NextRequest('http://localhost:3000/api/wallet', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          origin: 'http://localhost:3000',
          cookie: cookieHeader,
        },
        body: txPayload,
      })
    );
    expect(replayTxRes.status).toBe(200);
    const replayTxBody = (await replayTxRes.json()) as {
      decision: { transactionId?: string; senderBalanceVnd?: number; idempotentReplay?: boolean };
    };
    expect(replayTxBody.decision.idempotentReplay).toBe(true);
    expect(replayTxBody.decision.transactionId).toBe(firstTxBody.decision.transactionId);
    expect(replayTxBody.decision.senderBalanceVnd).toBe(firstTxBody.decision.senderBalanceVnd);

    // Verify /api/merchant/vision rejects SVG payloads with 400 INVALID_IMAGE
    const svgRes = await merchantVisionPost(
      new NextRequest('http://localhost:3000/api/merchant/vision', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          origin: 'http://localhost:3000',
          cookie: cookieHeader,
        },
        body: JSON.stringify({
          imageDataUrl: `data:image/svg+xml;base64,${Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"></svg>').toString('base64')}`,
        }),
      })
    );
    expect(svgRes.status).toBe(400);
    const svgBody = (await svgRes.json()) as { code: string };
    expect(svgBody.code).toBe('INVALID_IMAGE');

    // Verify /api/merchant/vision accepts valid 1x1 binary PNG through security gate (status 200)
    const pngRes = await merchantVisionPost(
      new NextRequest('http://localhost:3000/api/merchant/vision', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          origin: 'http://localhost:3000',
          cookie: cookieHeader,
        },
        body: JSON.stringify({
          imageDataUrl: `data:image/png;base64,${VALID_1X1_PNG_BASE64}`,
        }),
      })
    );
    expect(pngRes.status).toBe(200);
    const pngBody = (await pngRes.json()) as { imageMeta: { mimeType: string; width: number; height: number } };
    expect(pngBody.imageMeta.mimeType).toBe('image/png');
    expect(pngBody.imageMeta.width).toBe(1);
    expect(pngBody.imageMeta.height).toBe(1);
  });
});
