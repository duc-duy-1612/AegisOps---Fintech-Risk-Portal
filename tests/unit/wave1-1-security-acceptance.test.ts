import { NextRequest } from 'next/server';
import { beforeEach, describe, expect, it } from 'vitest';
import { POST as playbookPost } from '@/app/api/playbook/route';
import { POST as sessionPost } from '@/app/api/session/route';
import { POST as walletPost } from '@/app/api/wallet/route';
import { POST as workspacePost, DELETE as workspaceDelete } from '@/app/api/workspace/route';
import {
  executePlaybookApproval,
  toggleShieldRuleInSession,
} from '@/application/workspace-orchestrator';
import { resetRateBucketsForTest } from '@/infrastructure/security-guard';
import {
  SESSION_COOKIE_NAME,
  SESSION_TTL_MS,
  createSignedSessionToken,
  verifySignedSessionToken,
} from '@/infrastructure/session-auth';
import {
  InvalidStateIntegrityError,
  evictServerSessionForColdStartTest,
  mergeSessionDeltas,
  resetSessionDelta,
} from '@/infrastructure/workspace-store';

const makeReq = (
  url: string,
  method: 'POST' | 'DELETE',
  body?: unknown,
  opts?: {
    sessionId?: string;
    cookieToken?: string;
    extraHeaders?: Record<string, string>;
  }
): NextRequest => {
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    host: 'localhost:3000',
    ...(opts?.extraHeaders ?? {}),
  };
  if (opts?.sessionId) headers['x-workspace-session'] = opts.sessionId;
  if (opts?.cookieToken) headers.cookie = `${SESSION_COOKIE_NAME}=${opts.cookieToken}`;

  return new NextRequest(url, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
};

describe('Wave 1.1 Security Acceptance Gate & Red-Team Verification', () => {
  beforeEach(() => {
    resetRateBucketsForTest();
  });

  // ─── 1. Token Expiry, Future Clock-Skew & Strict Fail-Closed Secrets ─────────────────
  it('Auth Gate: rejects expired tokens (>24h), future clock-skew tokens, and fails closed when AEGIS_REQUIRE_STRICT_SECRETS=true with weak secret', async () => {
    const sid = 'expiry-check-sid';

    // 1. Expired 25h old token
    const expiredToken = createSignedSessionToken({
      sessionId: sid,
      role: 'L2_CHECKER',
      issuedAtMs: Date.now() - SESSION_TTL_MS - 3600_000,
    });
    expect(verifySignedSessionToken(expiredToken)).toEqual({ valid: false, reason: 'EXPIRED' });
    const expiredRes = await playbookPost(
      makeReq(
        'http://localhost:3000/api/playbook',
        'POST',
        { alertId: 'ALT-APP-003', mode: 'APPROVE_L2' },
        { sessionId: sid, cookieToken: expiredToken }
      )
    );
    expect(expiredRes.status).toBe(401);

    // 2. Future clock-skew forged token (+10 min)
    const futureToken = createSignedSessionToken({
      sessionId: sid,
      role: 'L2_CHECKER',
      issuedAtMs: Date.now() + 600_000,
    });
    expect(verifySignedSessionToken(futureToken)).toEqual({ valid: false, reason: 'EXPIRED' });
    const futureRes = await playbookPost(
      makeReq(
        'http://localhost:3000/api/playbook',
        'POST',
        { alertId: 'ALT-APP-003', mode: 'APPROVE_L2' },
        { sessionId: sid, cookieToken: futureToken }
      )
    );
    expect(futureRes.status).toBe(401);

    // 3. Fail-Closed when strict secrets required and missing/weak
    const prevStrict = process.env.AEGIS_REQUIRE_STRICT_SECRETS;
    const prevSecret = process.env.AEGIS_SESSION_SECRET;
    try {
      process.env.AEGIS_REQUIRE_STRICT_SECRETS = 'true';
      process.env.AEGIS_SESSION_SECRET = 'too-short-weak-key';

      const strictSessionRes = await sessionPost(
        makeReq('http://localhost:3000/api/session', 'POST', { sessionId: sid, role: 'L2_CHECKER' })
      );
      expect(strictSessionRes.status).toBe(503);

      const strictPlaybookRes = await playbookPost(
        makeReq(
          'http://localhost:3000/api/playbook',
          'POST',
          { alertId: 'ALT-APP-003', mode: 'APPROVE_L2' },
          { sessionId: sid, cookieToken: 'abc.def' }
        )
      );
      expect(strictPlaybookRes.status).toBe(503);
    } finally {
      if (prevStrict === undefined) delete process.env.AEGIS_REQUIRE_STRICT_SECRETS;
      else process.env.AEGIS_REQUIRE_STRICT_SECRETS = prevStrict;
      if (prevSecret === undefined) delete process.env.AEGIS_SESSION_SECRET;
      else process.env.AEGIS_SESSION_SECRET = prevSecret;
    }
  });

  // ─── 2. CSRF & Same-Origin Enforcement + No Silent L2 Cookie Minting ──────────────────
  it('CSRF & Session Boundary: blocks cross-site Origin/Sec-Fetch-Site/Referer mutations (HTTP 403), allows same-origin, and stops silent L2 cookie minting on /api/workspace', async () => {
    const sid = 'csrf-test-sid';
    const token = createSignedSessionToken({ sessionId: sid, role: 'L2_CHECKER' });

    // 1. Sec-Fetch-Site: cross-site -> 403 across playbook, wallet, session, workspace DELETE
    expect(
      (
        await playbookPost(
          makeReq(
            'http://localhost:3000/api/playbook',
            'POST',
            { alertId: 'ALT-APP-003', mode: 'APPROVE_L2' },
            { sessionId: sid, cookieToken: token, extraHeaders: { 'sec-fetch-site': 'cross-site' } }
          )
        )
      ).status
    ).toBe(403);

    expect(
      (
        await walletPost(
          makeReq(
            'http://localhost:3000/api/wallet',
            'POST',
            { recipientAccountIdOrNumber: '1903999888777', amountVnd: 1000000 },
            { sessionId: sid, cookieToken: token, extraHeaders: { origin: 'https://evil-phish.example' } }
          )
        )
      ).status
    ).toBe(403);

    expect(
      (
        await sessionPost(
          makeReq(
            'http://localhost:3000/api/session',
            'POST',
            { role: 'L2_CHECKER' },
            { extraHeaders: { referer: 'https://evil-phish.example/attack.html' } }
          )
        )
      ).status
    ).toBe(403);

    expect(
      (
        await workspaceDelete(
          makeReq(
            'http://localhost:3000/api/workspace',
            'DELETE',
            undefined,
            { sessionId: sid, cookieToken: token, extraHeaders: { origin: 'http://attacker.local:9999' } }
          )
        )
      ).status
    ).toBe(403);

    // 2. Same-origin Origin passes -> 200
    const sameOriginRes = await playbookPost(
      makeReq(
        'http://localhost:3000/api/playbook',
        'POST',
        { alertId: 'ALT-APP-003', mode: 'APPROVE_L2' },
        {
          sessionId: sid,
          cookieToken: token,
          extraHeaders: { origin: 'http://localhost:3000', 'sec-fetch-site': 'same-origin' },
        }
      )
    );
    expect(sameOriginRes.status).toBe(200);

    // 3. /api/workspace POST without cookie MUST fail closed with HTTP 401 and NOT silently mint an L2_CHECKER cookie
    const wsRes = await workspacePost(makeReq('http://localhost:3000/api/workspace', 'POST', {}));
    expect(wsRes.status).toBe(401);
    expect(wsRes.headers.get('set-cookie')).toBeNull();
  });

  // ─── 3. Four-Eyes Separation: Block Same-Principal Self-Approval ──────────────────────
  it('Four-Eyes Enforcement: blocks same principalId from self-approving their own L1 proposal (HTTP 403), allows distinct L2 principal (HTTP 200)', async () => {
    const sid = 'four-eyes-sid';
    resetSessionDelta(sid);

    const aliceL1Token = createSignedSessionToken({
      sessionId: sid,
      role: 'L1_MAKER',
      principalId: 'analyst-alice',
    });

    // Alice proposes as L1_MAKER -> 200
    const proposeRes = await playbookPost(
      makeReq(
        'http://localhost:3000/api/playbook',
        'POST',
        { alertId: 'ALT-APP-003', mode: 'PROPOSE_L1' },
        { sessionId: sid, cookieToken: aliceL1Token }
      )
    );
    expect(proposeRes.status).toBe(200);
    const proposeJson = (await proposeRes.json()) as { delta: unknown };

    // Alice tries to switch/hold an L2_CHECKER token STILL carrying principalId 'analyst-alice' -> BLOCKED 403!
    const aliceSelfL2Token = createSignedSessionToken({
      sessionId: sid,
      role: 'L2_CHECKER',
      principalId: 'analyst-alice',
    });
    const selfApproveRes = await playbookPost(
      makeReq(
        'http://localhost:3000/api/playbook',
        'POST',
        { alertId: 'ALT-APP-003', mode: 'APPROVE_L2', clientDelta: proposeJson.delta },
        { sessionId: sid, cookieToken: aliceSelfL2Token }
      )
    );
    expect(selfApproveRes.status).toBe(403);
    const errBody = (await selfApproveRes.json()) as { code: string };
    expect(errBody.code).toBe('SELF_APPROVAL_FORBIDDEN');

    // Independent Checker 'manager-bob' approves -> 200 OK
    const bobL2Token = createSignedSessionToken({
      sessionId: sid,
      role: 'L2_CHECKER',
      principalId: 'manager-bob',
    });
    const bobApproveRes = await playbookPost(
      makeReq(
        'http://localhost:3000/api/playbook',
        'POST',
        { alertId: 'ALT-APP-003', mode: 'APPROVE_L2', clientDelta: proposeJson.delta },
        { sessionId: sid, cookieToken: bobL2Token }
      )
    );
    expect(bobApproveRes.status).toBe(200);
  });

  // ─── 4. Signed Delta Integrity Tag & Concurrency / Forged Revision Protection ──────────
  it('State Revision Integrity: rejects forged high stateRevision / tampered deltaIntegrityTag (HTTP 400) and survives out-of-order concurrent requests', async () => {
    const sid = 'delta-integrity-sid';
    resetSessionDelta(sid);
    const token = createSignedSessionToken({ sessionId: sid, role: 'L2_CHECKER' });

    // Server commits rev 1 (approve) and rev 2 (pause shield -> ACC-MULE-903 unfrozen)
    const approved = executePlaybookApproval({ sessionId: sid, alertId: 'ALT-APP-003', mode: 'APPROVE_L2' });
    const paused = toggleShieldRuleInSession({
      sessionId: sid,
      ruleId: approved.createdShieldRule!.id,
      clientDelta: approved.delta,
    });
    expect(paused.delta.stateRevision).toBe(2);
    expect(paused.delta.frozenAccountIds).not.toContain('ACC-MULE-903');

    // Attack 1: Client sends forged high stateRevision=999999 trying to resurrect frozen state or wipe shields -> 400!
    const forgedHighRevRes = await workspacePost(
      makeReq(
        'http://localhost:3000/api/workspace',
        'POST',
        {
          clientDelta: {
            stateRevision: 999999,
            frozenAccountIds: ['ACC-HACKED-999'],
            pendingL2ApprovalAlertIds: ['ALT-APP-003'],
            deltaIntegrityTag: 'forged.invalid.hmac',
          },
        },
        { sessionId: sid, cookieToken: token }
      )
    );
    expect(forgedHighRevRes.status).toBe(400);

    // Attack 2: Client takes genuine server-signed rev 2 delta and modifies frozenAccountIds without re-signing -> throws InvalidStateIntegrityError!
    expect(() =>
      mergeSessionDeltas('cold-instance-sid', undefined, {
        ...paused.delta,
        frozenAccountIds: ['ACC-MULE-903'],
      })
    ).toThrow(InvalidStateIntegrityError);

    // Out-of-order / concurrent older signed delta (approved rev 1 arriving after paused rev 2) -> ignored cleanly, unfreeze holds!
    const outOfOrderRes = await workspacePost(
      makeReq(
        'http://localhost:3000/api/workspace',
        'POST',
        { clientDelta: approved.delta },
        { sessionId: sid, cookieToken: token }
      )
    );
    expect(outOfOrderRes.status).toBe(200);
    const wsJson = (await outOfOrderRes.json()) as {
      state: { delta: { stateRevision: number; frozenAccountIds: string[] } };
    };
    expect(wsJson.state.delta.stateRevision).toBe(2);
    expect(wsJson.state.delta.frozenAccountIds).not.toContain('ACC-MULE-903');

    // Cross-session replay attack: copying delta-integrity-sid's signed delta into another sessionId MUST throw!
    expect(() => mergeSessionDeltas('hijack-other-sid', undefined, paused.delta)).toThrow(
      InvalidStateIntegrityError
    );

    // Cold instance starting empty for the SAME sessionId restores paused/unfrozen state faithfully
    evictServerSessionForColdStartTest(sid);
    const coldRestored = mergeSessionDeltas(sid, undefined, paused.delta);
    expect(coldRestored.stateRevision).toBe(2);
    expect(coldRestored.frozenAccountIds).not.toContain('ACC-MULE-903');
  });

  // ─── 5. Rate Limit Proxy Spoof Resistance & Session Abuse Bound ──────────────────────
  it('Rate Limit Verification: ignores spoofed X-Forwarded-For / X-Vercel-Forwarded-For outside Vercel and enforces 429 on /api/session flood', async () => {
    const prevVercel = process.env.VERCEL;
    const prevTrust = process.env.TRUST_PROXY_HEADERS;
    delete process.env.VERCEL;
    delete process.env.TRUST_PROXY_HEADERS;

    try {
      for (let i = 0; i < 45; i += 1) {
        const res = await sessionPost(
          makeReq(
            'http://localhost:3000/api/session',
            'POST',
            { sessionId: `sid-${i}`, role: 'L2_CHECKER' },
            {
              extraHeaders: {
                'x-forwarded-for': `203.0.113.${i % 250}`,
                'x-vercel-forwarded-for': `198.51.100.${i % 250}`,
                'x-real-ip': `192.0.2.${i % 250}`,
              },
            }
          )
        );
        expect(res.status).toBe(200);
      }

      // 46th request still throttled even with brand-new spoofed forwarding headers -> 429!
      const throttled = await sessionPost(
        makeReq(
          'http://localhost:3000/api/session',
          'POST',
          { sessionId: 'sid-46', role: 'L2_CHECKER' },
          {
            extraHeaders: {
              'x-forwarded-for': '10.20.30.40',
              'x-vercel-forwarded-for': '10.20.30.41',
              'x-real-ip': '10.20.30.42',
            },
          }
        )
      );
      expect(throttled.status).toBe(429);
    } finally {
      if (prevVercel !== undefined) process.env.VERCEL = prevVercel;
      if (prevTrust !== undefined) process.env.TRUST_PROXY_HEADERS = prevTrust;
    }
  });
});
