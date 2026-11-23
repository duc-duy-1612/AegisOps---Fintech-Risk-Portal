import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * Server-Side Only Cryptographic PII Pseudonymization & Key-Rotation Lineage
 * (Law 91/2025/QH15 & Decree 356/2025/NĐ-CP effective 2026-01-01, replacing repealed Decree 13/2023/NĐ-CP; SBV SIMO).
 * - Uses keyed HMAC-SHA-256 with a server-only secret key (>=32 chars / 256-bit) to resist dictionary/rainbow-table
 *   attacks on low-entropy identifiers (such as 10-digit phone numbers / bank accounts).
 * - IMPORTANT TERMINOLOGY: Keyed HMAC-SHA-256 produces a deterministic **pseudonym** (pseudonymization),
 *   NOT irreversible legal anonymization and NOT reversible encryption.
 * - Supports zero-downtime key rotation via `AEGIS_PII_HMAC_KEY_PREVIOUS` with non-reversible key version IDs (`kid:<12-hex>`).
 * - Fails closed if AEGIS_REQUIRE_STRICT_SECRETS=true and key is absent or weak.
 * - NEVER expose this module or key to client components.
 */

const EPHEMERAL_RUNTIME_KEY = randomBytes(32).toString('hex');

export type PiiSecretConfigMode =
  | 'CONFIGURED_ENV'
  | 'EPHEMERAL_PROCESS_FALLBACK'
  | 'MISCONFIGURED_FAIL_CLOSED';

export type PiiKeyLineageMatch = 'CURRENT_KEY' | 'PREVIOUS_KEY' | 'UNMATCHED';

const isStrictPiiSecretRequired = (): boolean => {
  return (
    process.env.AEGIS_REQUIRE_STRICT_SECRETS === 'true' ||
    process.env.AEGIS_PRODUCTION_STRICT_READINESS === 'true'
  );
};

export const getPiiHmacStatus = (): { mode: PiiSecretConfigMode; configured: boolean } => {
  const configured = process.env.AEGIS_PII_HMAC_KEY?.trim();
  if (configured && configured.length >= 32) {
    return { mode: 'CONFIGURED_ENV', configured: true };
  }
  if (isStrictPiiSecretRequired()) {
    return { mode: 'MISCONFIGURED_FAIL_CLOSED', configured: false };
  }
  return { mode: 'EPHEMERAL_PROCESS_FALLBACK', configured: false };
};

const getServerHmacSecret = (): string => {
  const configured = process.env.AEGIS_PII_HMAC_KEY?.trim();
  if (configured && configured.length >= 32) {
    return configured;
  }
  if (isStrictPiiSecretRequired()) {
    throw new Error(
      'Server Fail-Closed: AEGIS_PII_HMAC_KEY (>= 32 chars) chưa được cấu hình ở chế độ Strict Secrets.'
    );
  }
  return EPHEMERAL_RUNTIME_KEY;
};

const getValidPreviousHmacSecret = (): string | null => {
  const prev = process.env.AEGIS_PII_HMAC_KEY_PREVIOUS?.trim();
  if (!prev || prev.length < 32) return null;
  const current = getServerHmacSecret();
  return prev !== current ? prev : null;
};

const deriveKeyVersionTag = (secret: string): string => {
  const digest = createHash('sha256')
    .update(`aegis-pii-key-id-v1:${secret}`)
    .digest('hex')
    .slice(0, 12);
  return `kid:${digest}`;
};

export const getCurrentPiiHmacKeyId = (): string => {
  return deriveKeyVersionTag(getServerHmacSecret());
};

export const getPreviousPiiHmacKeyId = (): string | null => {
  const prev = getValidPreviousHmacSecret();
  return prev ? deriveKeyVersionTag(prev) : null;
};

export const pseudonymizePiiWithHmacSha256 = (identifier: string): string => {
  return createHmac('sha256', getServerHmacSecret())
    .update(identifier.trim())
    .digest('hex');
};

export const pseudonymizePiiWithPreviousKey = (identifier: string): string | null => {
  const prev = getValidPreviousHmacSecret();
  if (!prev) return null;
  return createHmac('sha256', prev)
    .update(identifier.trim())
    .digest('hex');
};

export const getAllAcceptedPiiPseudonyms = (identifier: string): string[] => {
  const primary = pseudonymizePiiWithHmacSha256(identifier);
  const legacy = pseudonymizePiiWithPreviousKey(identifier);
  return legacy && legacy !== primary ? [primary, legacy] : [primary];
};

const safeHexEquals = (a: string, b: string): boolean => {
  if (a.length !== b.length) return false;
  try {
    return timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
  } catch {
    return false;
  }
};

export const inspectPiiFingerprintKeyLineage = (
  identifier: string,
  storedFingerprint: string
): PiiKeyLineageMatch => {
  if (!storedFingerprint) return 'UNMATCHED';
  const currentDigest = pseudonymizePiiWithHmacSha256(identifier);
  if (safeHexEquals(currentDigest, storedFingerprint)) {
    return 'CURRENT_KEY';
  }
  const previousDigest = pseudonymizePiiWithPreviousKey(identifier);
  if (previousDigest && safeHexEquals(previousDigest, storedFingerprint)) {
    return 'PREVIOUS_KEY';
  }
  return 'UNMATCHED';
};

export const matchesPseudonymizedPiiAcrossRotation = (
  identifier: string,
  storedFingerprint: string
): boolean => {
  return inspectPiiFingerprintKeyLineage(identifier, storedFingerprint) !== 'UNMATCHED';
};
