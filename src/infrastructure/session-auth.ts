import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type { NextRequest } from 'next/server';
import type { OperatorRole, SessionDeltaSnapshot } from '@/domain/types';
import { getPiiHmacStatus } from './privacy-hasher';

/**
 * Server-Side Signed Session Verification, Expiry Enforcement, CSRF Origin Check,
 * Delta Integrity MAC, and Deny-by-Default RBAC Enforcement.
 *
 * AUTHENTICATION & FOUR-EYES BOUNDARY DISCLOSURE:
 * 1. Cookie signatures verify token integrity & 24h TTL (`SESSION_TTL_MS`), and reject
 *    tampered tokens, expired tokens, clock-skewed tokens, header mismatches, and CSRF cross-site calls.
 * 2. Because the MoMo Tech Contest mandates "Không cần đăng nhập (1-Click Instant Access)",
 *    `/api/session` issues simulated demo persona tokens (`demo:<sid>:<role>`) without external SSO.
 *    If two requests share the same `principalId`, the backend strictly blocks L1 self-approval (HTTP 403),
 *    while acknowledging that single-browser persona switching relies on simulated demo principals.
 * 3. When `AEGIS_REQUIRE_STRICT_SECRETS=true`, missing or weak (<32 char) `AEGIS_SESSION_SECRET`
 *    triggers FAIL-CLOSED behavior instead of ephemeral process-local fallback.
 */

export const SESSION_COOKIE_NAME = 'aegis_auth_session';
export const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const CLOCK_SKEW_TOLERANCE_MS = 60_000;

const EPHEMERAL_SESSION_SECRET = randomBytes(32).toString('hex');

export type SecretConfigMode =
  | 'CONFIGURED_ENV'
  | 'EPHEMERAL_PROCESS_FALLBACK'
  | 'MISCONFIGURED_FAIL_CLOSED';

export const isStrictSecretsModeEnabled = (): boolean => {
  return (
    process.env.AEGIS_REQUIRE_STRICT_SECRETS === 'true' ||
    process.env.AEGIS_PRODUCTION_STRICT_READINESS === 'true'
  );
};

export const isDemoPersonaSwitchEnabled = (): boolean => {
  const explicit = process.env.AEGIS_ENABLE_DEMO_PERSONA_SWITCH?.trim().toLowerCase();
  if (explicit === 'false') {
    return false;
  }
  if (process.env.AEGIS_PRODUCTION_STRICT_READINESS === 'true') {
    return explicit === 'true';
  }
  return true;
};

export const isProductionStrictDemoGuardViolated = (): boolean => {
  return (
    process.env.AEGIS_PRODUCTION_STRICT_READINESS === 'true' &&
    process.env.AEGIS_ENABLE_DEMO_PERSONA_SWITCH?.trim().toLowerCase() === 'true'
  );
};

export const getSessionSecretStatus = (): { mode: SecretConfigMode; secret: string | null } => {
  const configured = process.env.AEGIS_SESSION_SECRET?.trim();
  if (configured && configured.length >= 32) {
    return { mode: 'CONFIGURED_ENV', secret: configured };
  }
  if (isStrictSecretsModeEnabled()) {
    return { mode: 'MISCONFIGURED_FAIL_CLOSED', secret: null };
  }
  return { mode: 'EPHEMERAL_PROCESS_FALLBACK', secret: EPHEMERAL_SESSION_SECRET };
};

export const validateStrictSecretsConfiguration = ():
  | { ok: true }
  | { ok: false; missingKeys: string[]; errorVi: string } => {
  if (!isStrictSecretsModeEnabled()) {
    return { ok: true };
  }
  const missingKeys: string[] = [];
  if (getSessionSecretStatus().mode === 'MISCONFIGURED_FAIL_CLOSED') {
    missingKeys.push('AEGIS_SESSION_SECRET');
  }
  if (getPiiHmacStatus().mode === 'MISCONFIGURED_FAIL_CLOSED') {
    missingKeys.push('AEGIS_PII_HMAC_KEY');
  }
  if (missingKeys.length > 0) {
    return {
      ok: false,
      missingKeys,
      errorVi: `Máy chủ Fail-Closed do thiếu khóa bảo mật bắt buộc (>= 32 ký tự): ${missingKeys.join(', ')}.`,
    };
  }
  return { ok: true };
};

const requireSigningSecret = (): string => {
  const status = getSessionSecretStatus();
  if (!status.secret) {
    throw new Error(
      'Server Fail-Closed: AEGIS_SESSION_SECRET (>= 32 chars) chưa được cấu hình ở chế độ Strict Secrets.'
    );
  }
  return status.secret;
};

export interface VerifiedSessionIdentity {
  sessionId: string;
  role: OperatorRole;
  principalId: string;
  issuedAtMs: number;
}

export type PlaybookMutationAction =
  | 'PROPOSE_L1'
  | 'APPROVE_L2'
  | 'BATCH_TRIAGE'
  | 'TOGGLE_SHIELD'
  | 'ADD_CUSTOM_SHIELD'
  | 'CLAWBACK_REFUND'
  | 'ANALYST_OVERRIDE'
  | 'PUSH_SIMO';

const PLAYBOOK_ROLE_PERMISSIONS: Readonly<Record<OperatorRole, ReadonlySet<PlaybookMutationAction>>> = {
  L2_CHECKER: new Set<PlaybookMutationAction>([
    'PROPOSE_L1',
    'APPROVE_L2',
    'BATCH_TRIAGE',
    'TOGGLE_SHIELD',
    'ADD_CUSTOM_SHIELD',
    'CLAWBACK_REFUND',
    'ANALYST_OVERRIDE',
    'PUSH_SIMO',
  ]),
  L1_MAKER: new Set<PlaybookMutationAction>(['PROPOSE_L1']),
  END_USER: new Set<PlaybookMutationAction>([]),
};

const signWithKey = (key: string, purposePrefix: string, data: string): string => {
  return createHmac('sha256', key)
    .update(`${purposePrefix}:${data}`)
    .digest('base64url');
};

const signWithServerKey = (purposePrefix: string, data: string): string => {
  return signWithKey(requireSigningSecret(), purposePrefix, data);
};

const getAcceptedSigningKeys = (): string[] => {
  const primary = requireSigningSecret();
  const prev = process.env.AEGIS_SESSION_SECRET_PREVIOUS?.trim();
  if (prev && prev.length >= 32 && prev !== primary) {
    return [primary, prev];
  }
  return [primary];
};

export const createSignedSessionToken = (params: {
  sessionId: string;
  role: OperatorRole;
  principalId?: string;
  issuedAtMs?: number;
}): string => {
  const trimmedSid = params.sessionId.trim();
  const cleanSessionId =
    trimmedSid ||
    (isStrictSecretsModeEnabled()
      ? `sess-${randomBytes(12).toString('hex')}`
      : 'judge-default-session');
  const cleanPrincipal =
    params.principalId?.trim() || `demo:${cleanSessionId}:${params.role.toLowerCase()}`;
  const payload: VerifiedSessionIdentity = {
    sessionId: cleanSessionId,
    role: params.role,
    principalId: cleanPrincipal,
    issuedAtMs: params.issuedAtMs ?? Date.now(),
  };
  const payloadB64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const signature = signWithServerKey('session-v1', payloadB64);
  return `${payloadB64}.${signature}`;
};

export const verifySignedSessionToken = (
  token: string | undefined | null,
  nowMs = Date.now()
):
  | { valid: true; identity: VerifiedSessionIdentity }
  | { valid: false; reason: 'MISSING' | 'MALFORMED' | 'INVALID_SIGNATURE' | 'EXPIRED' | 'MISCONFIGURED' } => {
  if (!token || typeof token !== 'string') {
    return { valid: false, reason: 'MISSING' };
  }
  const parts = token.split('.');
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    return { valid: false, reason: 'MALFORMED' };
  }

  let acceptedKeys: string[];
  try {
    acceptedKeys = getAcceptedSigningKeys();
  } catch {
    return { valid: false, reason: 'MISCONFIGURED' };
  }

  const providedBuf = Buffer.from(parts[1], 'utf8');
  const signatureMatched = acceptedKeys.some((key) => {
    const expectedSig = signWithKey(key, 'session-v1', parts[0]!);
    const expectedBuf = Buffer.from(expectedSig, 'utf8');
    return providedBuf.length === expectedBuf.length && timingSafeEqual(providedBuf, expectedBuf);
  });
  if (!signatureMatched) {
    return { valid: false, reason: 'INVALID_SIGNATURE' };
  }

  try {
    const decoded = JSON.parse(
      Buffer.from(parts[0], 'base64url').toString('utf8')
    ) as Partial<VerifiedSessionIdentity>;

    if (
      typeof decoded.sessionId !== 'string' ||
      !decoded.sessionId.trim() ||
      (decoded.role !== 'L2_CHECKER' &&
        decoded.role !== 'L1_MAKER' &&
        decoded.role !== 'END_USER') ||
      typeof decoded.principalId !== 'string' ||
      !decoded.principalId.trim() ||
      typeof decoded.issuedAtMs !== 'number' ||
      !Number.isFinite(decoded.issuedAtMs)
    ) {
      return { valid: false, reason: 'MALFORMED' };
    }

    // Strict TTL + Future Clock-Skew Check
    if (decoded.issuedAtMs > nowMs + CLOCK_SKEW_TOLERANCE_MS) {
      return { valid: false, reason: 'EXPIRED' };
    }
    if (nowMs - decoded.issuedAtMs > SESSION_TTL_MS) {
      return { valid: false, reason: 'EXPIRED' };
    }

    return {
      valid: true,
      identity: {
        sessionId: decoded.sessionId,
        role: decoded.role,
        principalId: decoded.principalId,
        issuedAtMs: decoded.issuedAtMs,
      },
    };
  } catch {
    return { valid: false, reason: 'MALFORMED' };
  }
};

export const verifySameOriginCsrf = (
  req: NextRequest
): { ok: true } | { ok: false; status: 403; errorVi: string } => {
  const secFetchSite = req.headers.get('sec-fetch-site')?.trim().toLowerCase();
  if (secFetchSite === 'cross-site') {
    return {
      ok: false,
      status: 403,
      errorVi: 'Từ chối yêu cầu CSRF cross-site (Sec-Fetch-Site: cross-site).',
    };
  }

  const host = req.headers.get('host')?.trim().toLowerCase();
  const origin = req.headers.get('origin')?.trim();
  if (origin && host) {
    try {
      const parsedOriginHost = new URL(origin).host.toLowerCase();
      if (parsedOriginHost !== host) {
        return {
          ok: false,
          status: 403,
          errorVi: `Từ chối Origin khác nguồn (${parsedOriginHost} != ${host}) để chống tấn công CSRF.`,
        };
      }
    } catch {
      return {
        ok: false,
        status: 403,
        errorVi: 'Header Origin không hợp lệ.',
      };
    }
  } else if (!origin && host) {
    const referer = req.headers.get('referer')?.trim();
    if (referer) {
      try {
        const refHost = new URL(referer).host.toLowerCase();
        if (refHost !== host) {
          return {
            ok: false,
            status: 403,
            errorVi: `Từ chối Referer khác nguồn (${refHost} != ${host}) để chống CSRF.`,
          };
        }
      } catch {
        return { ok: false, status: 403, errorVi: 'Header Referer không hợp lệ.' };
      }
    }
  }

  return { ok: true };
};

export const authenticateSessionFromRequest = (
  req: NextRequest
):
  | { authenticated: true; identity: VerifiedSessionIdentity }
  | { authenticated: false; status: 401 | 503; errorVi: string } => {
  const strictCheck = validateStrictSecretsConfiguration();
  if (!strictCheck.ok) {
    return {
      authenticated: false,
      status: 503,
      errorVi: strictCheck.errorVi,
    };
  }

  const cookieToken = req.cookies.get(SESSION_COOKIE_NAME)?.value;
  const check = verifySignedSessionToken(cookieToken);

  if (!check.valid) {
    if (check.reason === 'MISCONFIGURED') {
      return {
        authenticated: false,
        status: 503,
        errorVi: 'Máy chủ đang ở chế độ Fail-Closed do thiếu AEGIS_SESSION_SECRET hợp lệ.',
      };
    }
    return {
      authenticated: false,
      status: 401,
      errorVi:
        check.reason === 'EXPIRED'
          ? 'Phiên làm việc đã hết hạn (TTL 24h) hoặc timestamp không hợp lệ.'
          : 'Phiên làm việc chưa được xác thực hợp lệ hoặc chữ ký cookie không đúng.',
    };
  }

  const declaredSession = req.headers.get('x-workspace-session')?.trim();
  if (declaredSession && declaredSession !== check.identity.sessionId) {
    return {
      authenticated: false,
      status: 401,
      errorVi: 'Mã phiên trên header không khớp với token phiên đã được máy chủ ký xác thực.',
    };
  }

  return { authenticated: true, identity: check.identity };
};

export const authorizePlaybookMutation = (
  role: OperatorRole,
  action: PlaybookMutationAction
): { allowed: true } | { allowed: false; status: 403; errorVi: string } => {
  const allowedSet = PLAYBOOK_ROLE_PERMISSIONS[role];
  if (!allowedSet || !allowedSet.has(action)) {
    return {
      allowed: false,
      status: 403,
      errorVi: `Từ chối truy cập (HTTP 403): Vai trò ${role} không có quyền thực thi "${action}" theo nguyên tắc Kiểm soát kép Maker–Checker.`,
    };
  }
  return { allowed: true };
};

const canonicalStatePayload = (delta: Partial<SessionDeltaSnapshot>, sessionId: string): string => {
  const shieldSignatureList = (delta.activeShieldRules ?? [])
    .map((r) => `${r.id}:${r.targetAccountId}:${r.active ? '1' : '0'}`)
    .sort();
  const ledgerSignatureList = (delta.ledgerEntries ?? [])
    .map((e) => `${e.id}:${e.txId}:${e.accountId}:${e.entryType}:${e.amountVnd}:${e.status}`)
    .sort();
  const clawbackSignatureList = (delta.clawbackReceipts ?? [])
    .map((c) => `${c.clawbackId}:${c.alertId}:${c.recoveredAmountVnd}:${c.recoveryStatus ?? ''}`)
    .sort();
  const hitlSignatureList = (delta.hitlFeedbackMemory ?? [])
    .map(
      (f) =>
        `${f.feedbackId}:${f.targetFingerprint}:${f.feedbackDecision}:${f.status}:${f.riskAdjustment}:${f.memoryVersion}`
    )
    .sort();
  return JSON.stringify({
    sessionId,
    stateRevision: delta.stateRevision ?? 0,
    alertStatuses: Object.entries(delta.alertStatuses ?? {}).sort(([a], [b]) => a.localeCompare(b)),
    pendingL2ApprovalAlertIds: [...(delta.pendingL2ApprovalAlertIds ?? [])].sort(),
    frozenAccountIds: [...(delta.frozenAccountIds ?? [])].sort(),
    activeShieldRules: shieldSignatureList,
    makerPrincipalByAlertId: Object.entries(delta.makerPrincipalByAlertId ?? {}).sort(([a], [b]) =>
      a.localeCompare(b)
    ),
    ledgerEntries: ledgerSignatureList,
    clawbackReceipts: clawbackSignatureList,
    hitlFeedbackMemory: hitlSignatureList,
    processedIdempotencyKeys: Object.entries(delta.processedIdempotencyKeys ?? {}).sort(
      ([a], [b]) => a.localeCompare(b)
    ),
    idempotencyRecordsByKey: Object.entries(delta.idempotencyRecordsByKey ?? {})
      .map(
        ([k, rec]) =>
          `${k}:${rec.txId}:${rec.requestSignature}:${rec.decisionSnapshot.decision}:${rec.decisionSnapshot.transactionStatus ?? ''}`
      )
      .sort(),
  });
};

export const computeDeltaIntegrityTag = (
  delta: Partial<SessionDeltaSnapshot>,
  sessionId: string
): string => {
  const canonical = canonicalStatePayload(delta, sessionId);
  return signWithServerKey('delta-v1', canonical);
};

export const verifyDeltaIntegrityTag = (
  delta: Partial<SessionDeltaSnapshot>,
  sessionId: string
): boolean => {
  if (typeof delta.deltaIntegrityTag !== 'string' || !delta.deltaIntegrityTag) {
    return false;
  }
  try {
    const canonical = canonicalStatePayload(delta, sessionId);
    const providedBuf = Buffer.from(delta.deltaIntegrityTag, 'utf8');
    const keys = getAcceptedSigningKeys();
    return keys.some((key) => {
      const expected = signWithKey(key, 'delta-v1', canonical);
      const expectedBuf = Buffer.from(expected, 'utf8');
      if (providedBuf.length !== expectedBuf.length) return false;
      return timingSafeEqual(providedBuf, expectedBuf);
    });
  } catch {
    return false;
  }
};
