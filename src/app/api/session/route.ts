import { randomBytes } from 'node:crypto';
import { NextRequest, NextResponse } from 'next/server';
import { SessionRoleSwitchSchema, parseRequestJsonWithSchema } from '@/domain/api-schemas';
import { enforceDistributedRouteRateLimit } from '@/infrastructure/distributed-rate-limiter';
import { logStructuredEvent } from '@/infrastructure/observability';
import { getWorkspacePersistenceAdapter } from '@/infrastructure/persistence-adapter';
import { buildRateLimitErrorResponse } from '@/infrastructure/route-guards';
import { sanitizePlainText } from '@/infrastructure/security-guard';
import {
  SESSION_COOKIE_NAME,
  authenticateSessionFromRequest,
  createSignedSessionToken,
  getSessionSecretStatus,
  isDemoPersonaSwitchEnabled,
  isProductionStrictDemoGuardViolated,
  isStrictSecretsModeEnabled,
  validateStrictSecretsConfiguration,
  verifySameOriginCsrf,
} from '@/infrastructure/session-auth';
import { hasExistingWarmSession } from '@/infrastructure/workspace-store';

export async function GET(req: NextRequest) {
  const rate = await enforceDistributedRouteRateLimit(req, 'session-get', 60);
  const rateErr = buildRateLimitErrorResponse(
    rate,
    'Quá nhiều yêu cầu kiểm tra phiên.',
    '/api/session'
  );
  if (rateErr) return rateErr;

  const strictCheck = validateStrictSecretsConfiguration();
  if (!strictCheck.ok) {
    return NextResponse.json(
      {
        authenticated: false,
        sessionId: null,
        role: null,
        principalId: null,
        code: 'MISCONFIGURED_FAIL_CLOSED',
        errorVi: strictCheck.errorVi,
        secretMode: getSessionSecretStatus().mode,
      },
      { status: 503 }
    );
  }

  const auth = authenticateSessionFromRequest(req);
  if (!auth.authenticated) {
    return NextResponse.json(
      {
        authenticated: false,
        sessionId: null,
        role: null,
        principalId: null,
        demoPersonaSwitchEnabled: isDemoPersonaSwitchEnabled(),
        secretMode: getSessionSecretStatus().mode,
      },
      { status: auth.status === 503 ? 503 : 200 }
    );
  }
  try {
    const adapter = getWorkspacePersistenceAdapter();
    if (await adapter.isSessionRevoked(auth.identity.sessionId)) {
      return NextResponse.json(
        {
          authenticated: false,
          sessionId: null,
          role: null,
          principalId: null,
          revoked: true,
          secretMode: getSessionSecretStatus().mode,
        },
        { status: 401 }
      );
    }
  } catch {
    return NextResponse.json(
      {
        code: 'PERSISTENCE_UNAVAILABLE',
        errorVi: 'Không thể xác minh trạng thái phiên trên máy chủ.',
      },
      { status: 503 }
    );
  }
  return NextResponse.json({
    authenticated: true,
    sessionId: auth.identity.sessionId,
    role: auth.identity.role,
    principalId: auth.identity.principalId,
    authMode: 'SIMULATED_DEMO_PERSONA',
    demoPersonaSwitchEnabled: isDemoPersonaSwitchEnabled(),
    secretMode: getSessionSecretStatus().mode,
  });
}

export async function POST(req: NextRequest) {
  const csrf = verifySameOriginCsrf(req);
  if (!csrf.ok) {
    return NextResponse.json(
      { code: 'CSRF_ORIGIN_MISMATCH', errorVi: csrf.errorVi },
      { status: csrf.status }
    );
  }

  const strictCheck = validateStrictSecretsConfiguration();
  const secretStatus = getSessionSecretStatus();
  if (!strictCheck.ok || !secretStatus.secret) {
    return NextResponse.json(
      {
        code: 'MISCONFIGURED_FAIL_CLOSED',
        errorVi: strictCheck.ok
          ? 'Máy chủ từ chối cấp phiên vì thiếu AEGIS_SESSION_SECRET (>= 32 ký tự).'
          : strictCheck.errorVi,
      },
      { status: 503 }
    );
  }

  // Workstream H: Production strict guard — immediately reject demo persona switching when disabled (zero Redis I/O)
  if (!isDemoPersonaSwitchEnabled() || isProductionStrictDemoGuardViolated()) {
    return NextResponse.json(
      {
        code: 'DEMO_PERSONA_SWITCH_DISABLED',
        errorVi:
          'Từ chối chuyển đổi vai trò Demo (HTTP 403): Chế độ giả lập Persona (AEGIS_ENABLE_DEMO_PERSONA_SWITCH) đã bị khóa trong môi trường Production Strict. Môi trường thực tế yêu cầu xác thực SSO/OIDC.',
      },
      { status: 403 }
    );
  }

  const rate = await enforceDistributedRouteRateLimit(req, 'session', 45, {
    criticalMutation: true,
  });
  const rateErr = buildRateLimitErrorResponse(
    rate,
    'Quá nhiều yêu cầu chuyển phiên. Vui lòng thử lại sau.',
    '/api/session'
  );
  if (rateErr) return rateErr;

  const validated = await parseRequestJsonWithSchema(req, SessionRoleSwitchSchema);
  if (!validated.ok) return validated.response;

  const existingAuth = authenticateSessionFromRequest(req);
  const rawRequestedSid = sanitizePlainText(
    validated.data.sessionId ?? req.headers.get('x-workspace-session'),
    80
  );

  if (isStrictSecretsModeEnabled() && rawRequestedSid === 'judge-default-session') {
    return NextResponse.json(
      {
        code: 'PREDICTABLE_DEFAULT_SESSION_FORBIDDEN',
        errorVi:
          'Từ chối mã phiên mặc định judge-default-session trong chế độ bảo mật nghiêm ngặt.',
      },
      { status: 403 }
    );
  }

  // Authenticated caller cannot switch into another user's sessionId
  if (existingAuth.authenticated && rawRequestedSid && rawRequestedSid !== existingAuth.identity.sessionId) {
    return NextResponse.json(
      {
        code: 'CROSS_SESSION_SWITCH_FORBIDDEN',
        errorVi:
          'Từ chối truy cập chéo phiên (HTTP 403): Không thể chuyển cookie xác thực sang mã phiên của người dùng khác.',
      },
      { status: 403 }
    );
  }

  const sessionId =
    (existingAuth.authenticated ? existingAuth.identity.sessionId : null) ||
    rawRequestedSid ||
    `sess-${randomBytes(12).toString('hex')}`;

  try {
    const adapter = getWorkspacePersistenceAdapter();
    if (await adapter.isSessionRevoked(sessionId)) {
      return NextResponse.json(
        {
          code: 'SESSION_REVOKED',
          errorVi: 'Mã phiên này đã bị thu hồi trên máy chủ. Vui lòng khởi tạo phiên mới.',
        },
        { status: 401 }
      );
    }

    // Workstream C: Session identifier alone is NEVER a bearer credential.
    // If the requested session already exists on server/persistence, caller MUST hold a valid signed cookie for it.
    const existingPersisted = await adapter.loadSession(sessionId);
    const sessionAlreadyExists = Boolean(existingPersisted) || hasExistingWarmSession(sessionId);
    if (
      sessionAlreadyExists &&
      (!existingAuth.authenticated || existingAuth.identity.sessionId !== sessionId)
    ) {
      return NextResponse.json(
        {
          code: 'SESSION_OWNERSHIP_REQUIRED',
          errorVi:
            'Từ chối truy cập (HTTP 403): Phiên làm việc này đã tồn tại và thuộc quyền sở hữu của người dùng khác. Mã phiên không thể dùng làm chứng thực truy cập.',
        },
        { status: 403 }
      );
    }
  } catch {
    return NextResponse.json(
      { code: 'PERSISTENCE_UNAVAILABLE', errorVi: 'Hệ thống lưu trữ dùng chung chưa sẵn sàng.' },
      { status: 503 }
    );
  }

  const principalId =
    sanitizePlainText(validated.data.principalId, 80) ||
    `demo:${sessionId}:${validated.data.role.toLowerCase()}`;

  const token = createSignedSessionToken({
    sessionId,
    role: validated.data.role,
    principalId,
  });

  logStructuredEvent({
    route: '/api/session',
    action: 'ISSUE_DEMO_PERSONA_SESSION',
    status: '200',
    metadata: { role: validated.data.role, secretMode: secretStatus.mode },
  });

  const res = NextResponse.json({
    authenticated: true,
    sessionId,
    role: validated.data.role,
    principalId,
    authMode: 'SIMULATED_DEMO_PERSONA',
    demoPersonaSwitchEnabled: true,
    secretMode: secretStatus.mode,
    noteVi:
      'Phiên giả lập Demo được máy chủ ký HMAC-SHA-256 (HttpOnly cookie, TTL 24h). Trong sản phẩm thực tế cần tắt AEGIS_ENABLE_DEMO_PERSONA_SWITCH=false và tích hợp OIDC/SSO IdP.',
  });

  res.cookies.set(SESSION_COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 60 * 60 * 24,
  });

  return res;
}

export async function DELETE(req: NextRequest) {
  const rate = await enforceDistributedRouteRateLimit(req, 'session-delete', 30, {
    criticalMutation: true,
  });
  const rateErr = buildRateLimitErrorResponse(
    rate,
    'Quá nhiều yêu cầu thu hồi phiên.',
    '/api/session'
  );
  if (rateErr) return rateErr;

  const csrf = verifySameOriginCsrf(req);
  if (!csrf.ok) {
    return NextResponse.json(
      { code: 'CSRF_ORIGIN_MISMATCH', errorVi: csrf.errorVi },
      { status: csrf.status }
    );
  }
  const auth = authenticateSessionFromRequest(req);
  if (!auth.authenticated) {
    return NextResponse.json(
      { code: 'UNAUTHORIZED', errorVi: auth.errorVi },
      { status: auth.status }
    );
  }
  try {
    const adapter = getWorkspacePersistenceAdapter();
    await adapter.revokeSession(auth.identity.sessionId);
  } catch {
    return NextResponse.json(
      { code: 'PERSISTENCE_UNAVAILABLE', errorVi: 'Không thể thu hồi phiên trên máy chủ.' },
      { status: 503 }
    );
  }

  logStructuredEvent({
    route: '/api/session',
    action: 'REVOKE_SESSION',
    status: '200',
  });

  const res = NextResponse.json({ revoked: true, sessionId: auth.identity.sessionId });
  res.cookies.set(SESSION_COOKIE_NAME, '', {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 0,
  });
  return res;
}
