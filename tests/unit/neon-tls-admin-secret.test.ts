import { createRequire } from 'node:module';
import { afterEach, describe, expect, it } from 'vitest';
import { Client } from 'pg';
import {
  MIN_ADMIN_RESET_SECRET_LENGTH,
  authorizeAdminGeminiCircuitReset,
  createGeminiResilienceInstance,
  resetGeminiResilienceForTest,
  validateAdminResetSecretConfiguration,
} from '@/infrastructure/gemini-resilience';
import {
  FailClosedPersistenceAdapter,
  PostgresPersistenceAdapter,
  PostgresTlsConfigurationError,
  buildPostgresPoolConfig,
  closeWorkspacePersistenceAdapter,
  getWorkspacePersistenceAdapter,
  setPersistenceAdapterForTest,
} from '@/infrastructure/persistence-adapter';

const require = createRequire(import.meta.url);
const { parse: parsePgConnectionString } = require('pg-connection-string') as {
  parse: (str: string) => Record<string, unknown>;
};
const ConnectionParameters = require('pg/lib/connection-parameters') as new (
  config: Record<string, unknown>
) => { ssl: unknown; host: string; database: string };

const DUMMY_NEON_BASE = 'postgresql://dummy_user:dummy_pass@ep-synthetic-pooler.ap-southeast-1.aws.neon.tech/neondb';
const DUMMY_LOCAL_BASE = 'postgresql://local_user:local_pass@localhost:5432/aegis_local';

const originalEnv = { ...process.env };

afterEach(async () => {
  setPersistenceAdapterForTest(null);
  await closeWorkspacePersistenceAdapter();
  resetGeminiResilienceForTest();
  for (const k of Object.keys(process.env)) {
    if (!(k in originalEnv)) {
      delete process.env[k];
    }
  }
  Object.assign(process.env, originalEnv);
});

describe('Wave 4.2.1B — NEON-03 PostgreSQL TLS & Installed pg@8.23.1 Driver Verification', () => {
  it('verifies installed pg-connection-string@2.14.1 and pg@8.23.1 ConnectionParameters + Client behavior without opening network connections', () => {
    // 1. Raw pg-connection-string behavior: URL sslmode=disable or no-verify overwrites explicit ssl option if unstripped!
    const rawDisableCp = new ConnectionParameters({
      connectionString: `${DUMMY_NEON_BASE}?sslmode=disable`,
      ssl: { rejectUnauthorized: true },
    });
    expect(rawDisableCp.ssl).toBe(false);

    const rawNoVerifyCp = new ConnectionParameters({
      connectionString: `${DUMMY_NEON_BASE}?sslmode=no-verify`,
      ssl: { rejectUnauthorized: true },
    });
    expect(rawNoVerifyCp.ssl).toEqual({ rejectUnauthorized: false });

    // 2. Raw pg-connection-string parses channel_binding into config.channel_binding, NOT Client.enableChannelBinding
    const parsedVfCb = parsePgConnectionString(
      `${DUMMY_NEON_BASE}?sslmode=verify-full&channel_binding=require`
    );
    expect(parsedVfCb.ssl).toEqual({});
    expect(parsedVfCb.channel_binding).toBe('require');

    const rawClientWithoutExplicitCb = new Client({
      connectionString: `${DUMMY_NEON_BASE}?sslmode=verify-full&channel_binding=require`,
    });
    expect(
      (rawClientWithoutExplicitCb as unknown as { enableChannelBinding: boolean })
        .enableChannelBinding
    ).toBe(false);

    // 3. Passing our normalized buildPostgresPoolConfig() into pg@8.23.1 Client + ConnectionParameters
    //    guarantees explicit rejectUnauthorized: true AND enableChannelBinding: true!
    const resolved = buildPostgresPoolConfig(
      `${DUMMY_NEON_BASE}?sslmode=verify-full&channel_binding=require`,
      { strictProductionTls: true, poolMax: 1 }
    );
    expect(resolved.tlsEnabled).toBe(true);
    expect(resolved.rejectUnauthorized).toBe(true);
    expect(resolved.enableChannelBinding).toBe(true);
    expect(resolved.effectiveSslMode).toBe('verify-full');
    expect(resolved.poolConfig.ssl).toEqual({ rejectUnauthorized: true });
    expect(resolved.poolConfig.enableChannelBinding).toBe(true);
    expect(resolved.poolConfig.connectionString).not.toContain('sslmode=');
    expect(resolved.poolConfig.connectionString).not.toContain('channel_binding=');

    const hardenedCp = new ConnectionParameters(
      resolved.poolConfig as unknown as Record<string, unknown>
    );
    expect(hardenedCp.ssl).toEqual({ rejectUnauthorized: true });

    const hardenedClient = new Client(resolved.poolConfig);
    expect(
      (hardenedClient as unknown as { enableChannelBinding: boolean }).enableChannelBinding
    ).toBe(true);
    expect((hardenedClient as unknown as { ssl: unknown }).ssl).toEqual({
      rejectUnauthorized: true,
    });
  });

  it('fails closed in production strict mode for missing sslmode, sslmode=disable, require/verify-ca/prefer/no-verify, uselibpqcompat, channel_binding=disable, and rejectUnauthorized:false', () => {
    const rejectedCases: Array<{ url: string; reason: string }> = [
      { url: DUMMY_NEON_BASE, reason: 'MISSING_PRODUCTION_SSL_MODE' },
      { url: `${DUMMY_NEON_BASE}?sslmode=disable`, reason: 'DISALLOWED_SSL_MODE' },
      { url: `${DUMMY_NEON_BASE}?sslmode=prefer`, reason: 'DISALLOWED_SSL_MODE' },
      { url: `${DUMMY_NEON_BASE}?sslmode=require`, reason: 'DISALLOWED_SSL_MODE' },
      { url: `${DUMMY_NEON_BASE}?sslmode=verify-ca`, reason: 'DISALLOWED_SSL_MODE' },
      { url: `${DUMMY_NEON_BASE}?sslmode=no-verify`, reason: 'INSECURE_SSL_OPTION' },
      { url: `${DUMMY_NEON_BASE}?sslmode=bogus`, reason: 'DISALLOWED_SSL_MODE' },
      {
        url: `${DUMMY_NEON_BASE}?sslmode=verify-full&uselibpqcompat=true`,
        reason: 'INSECURE_SSL_OPTION',
      },
      {
        url: `${DUMMY_NEON_BASE}?sslmode=verify-full&ssl=0`,
        reason: 'INSECURE_SSL_OPTION',
      },
      {
        url: `${DUMMY_NEON_BASE}?sslmode=verify-full&channel_binding=disable`,
        reason: 'DISALLOWED_CHANNEL_BINDING',
      },
    ];

    for (const tc of rejectedCases) {
      let caught: unknown;
      try {
        buildPostgresPoolConfig(tc.url, { strictProductionTls: true });
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(PostgresTlsConfigurationError);
      const tlsErr = caught as PostgresTlsConfigurationError;
      expect(tlsErr.reasonCode).toBe(tc.reason);
      // Never expose credentials or full connection strings in error messages
      expect(tlsErr.message).not.toContain('dummy_pass');
      expect(tlsErr.message).not.toContain('dummy_user');
    }

    // Explicit sslOverride: { rejectUnauthorized: false } is rejected in production
    expect(() =>
      buildPostgresPoolConfig(`${DUMMY_NEON_BASE}?sslmode=verify-full`, {
        strictProductionTls: true,
        sslOverride: { rejectUnauthorized: false },
      })
    ).toThrow(PostgresTlsConfigurationError);

    // Via getWorkspacePersistenceAdapter(), insecure DATABASE_URL in strict mode fails closed cleanly
    process.env.AEGIS_PRODUCTION_STRICT_READINESS = 'true';
    process.env.DATABASE_URL = `${DUMMY_NEON_BASE}?sslmode=disable`;
    const adapter = getWorkspacePersistenceAdapter();
    expect(adapter).toBeInstanceOf(FailClosedPersistenceAdapter);
    expect(adapter.mode).toBe('MISCONFIGURED_FAIL_CLOSED');
  });

  it('preserves local development localhost connections without requiring a cloud Neon URL while still enforcing TLS when requested', async () => {
    const localPlain = buildPostgresPoolConfig(DUMMY_LOCAL_BASE, {
      strictProductionTls: false,
      poolMax: 2,
    });
    expect(localPlain.tlsEnabled).toBe(false);
    expect(localPlain.poolConfig.ssl).toBeUndefined();
    expect(localPlain.enableChannelBinding).toBe(false);

    const localTls = buildPostgresPoolConfig(
      `${DUMMY_LOCAL_BASE}?sslmode=verify-full&channel_binding=require`,
      { strictProductionTls: false, poolMax: 2 }
    );
    expect(localTls.tlsEnabled).toBe(true);
    expect(localTls.poolConfig.ssl).toEqual({ rejectUnauthorized: true });
    expect(localTls.enableChannelBinding).toBe(true);

    // Constructing PostgresPersistenceAdapter with a valid strict Neon URL succeeds without dialing the network
    const adapter = new PostgresPersistenceAdapter(
      `${DUMMY_NEON_BASE}?sslmode=verify-full&channel_binding=require`,
      { strictProductionTls: true, poolMax: 1 }
    );
    expect(adapter.resolvedPoolConfig?.rejectUnauthorized).toBe(true);
    expect(adapter.resolvedPoolConfig?.enableChannelBinding).toBe(true);
    await adapter.close();
  });
});

describe('Wave 4.2.1B — REDIS-02 Admin Reset Secret Domain Separation', () => {
  const SESSION_SECRET = 'synthetic-session-secret-0123456789abcdef012345';
  const DIAG_SECRET = 'synthetic-diagnostics-secret-abcdef0123456789ab';
  const PII_SECRET = 'synthetic-pii-hmac-secret-99887766554433221100';
  const ADMIN_SECRET = 'synthetic-admin-reset-secret-fedcba9876543210fe';

  it('rejects unset AEGIS_ADMIN_RESET_SECRET even when AEGIS_SESSION_SECRET is configured (no fallback)', async () => {
    delete process.env.AEGIS_ADMIN_RESET_SECRET;
    process.env.AEGIS_SESSION_SECRET = SESSION_SECRET;
    process.env.AEGIS_DIAGNOSTICS_SECRET = DIAG_SECRET;
    process.env.AEGIS_PII_HMAC_KEY = PII_SECRET;

    const validation = validateAdminResetSecretConfiguration();
    expect(validation).toEqual({ valid: false, reason: 'MISSING_ADMIN_RESET_SECRET' });

    const res = await authorizeAdminGeminiCircuitReset({ adminToken: SESSION_SECRET });
    expect(res).toEqual({
      ok: false,
      clearedCount: 0,
      errorCode: 'UNAUTHORIZED_ADMIN_RESET',
    });
  });

  it('rejects short admin reset secrets (< 32 chars) and rejects domain reuse of session, diagnostics, or PII secrets', async () => {
    process.env.AEGIS_SESSION_SECRET = SESSION_SECRET;
    process.env.AEGIS_DIAGNOSTICS_SECRET = DIAG_SECRET;
    process.env.AEGIS_PII_HMAC_KEY = PII_SECRET;

    // Short secret (< 32 chars, e.g. 24 chars which previously passed >= 16)
    const shortSecret = 'short-admin-secret-12345';
    expect(shortSecret.length).toBeLessThan(MIN_ADMIN_RESET_SECRET_LENGTH);
    process.env.AEGIS_ADMIN_RESET_SECRET = shortSecret;
    expect(validateAdminResetSecretConfiguration().reason).toBe('WEAK_ADMIN_RESET_SECRET');
    expect(
      (await authorizeAdminGeminiCircuitReset({ adminToken: shortSecret })).ok
    ).toBe(false);

    // Reusing AEGIS_SESSION_SECRET is rejected
    process.env.AEGIS_ADMIN_RESET_SECRET = SESSION_SECRET;
    expect(validateAdminResetSecretConfiguration().reason).toBe('SECRET_DOMAIN_COLLISION');
    expect(
      (await authorizeAdminGeminiCircuitReset({ adminToken: SESSION_SECRET })).ok
    ).toBe(false);

    // Reusing AEGIS_DIAGNOSTICS_SECRET is rejected
    process.env.AEGIS_ADMIN_RESET_SECRET = DIAG_SECRET;
    expect(validateAdminResetSecretConfiguration().reason).toBe('SECRET_DOMAIN_COLLISION');
    expect(
      (await authorizeAdminGeminiCircuitReset({ adminToken: DIAG_SECRET })).ok
    ).toBe(false);

    // Reusing AEGIS_PII_HMAC_KEY is rejected
    process.env.AEGIS_ADMIN_RESET_SECRET = PII_SECRET;
    expect(validateAdminResetSecretConfiguration().reason).toBe('SECRET_DOMAIN_COLLISION');
    expect(
      (await authorizeAdminGeminiCircuitReset({ adminToken: PII_SECRET })).ok
    ).toBe(false);
  });

  it('authorizes admin circuit reset ONLY with a distinct >= 32-char AEGIS_ADMIN_RESET_SECRET and preserves circuit-reset behavior', async () => {
    process.env.AEGIS_SESSION_SECRET = SESSION_SECRET;
    process.env.AEGIS_DIAGNOSTICS_SECRET = DIAG_SECRET;
    process.env.AEGIS_PII_HMAC_KEY = PII_SECRET;
    process.env.AEGIS_ADMIN_RESET_SECRET = ADMIN_SECRET;
    process.env.GEMINI_API_KEY = 'synthetic-gemini-key-0123456789abcdef';

    const validation = validateAdminResetSecretConfiguration();
    expect(validation.valid).toBe(true);

    const inst = createGeminiResilienceInstance('admin-reset-sep-test');

    // Wrong token (even if it matches session secret) is rejected
    const wrongRes = await inst.authorizeAdminCircuitReset({ adminToken: SESSION_SECRET });
    expect(wrongRes.ok).toBe(false);
    expect(wrongRes.errorCode).toBe('UNAUTHORIZED_ADMIN_RESET');

    // Distinct valid admin reset secret authorizes the reset cleanly
    const okRes = await inst.authorizeAdminCircuitReset({ adminToken: ADMIN_SECRET });
    expect(okRes.ok).toBe(true);
    expect(okRes.errorCode).toBeUndefined();
  });
});
