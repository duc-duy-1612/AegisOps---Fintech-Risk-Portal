/**
 * Security Guard: Bounded In-Memory Rate Limiter, Trusted Proxy IP Resolution,
 * Multimodal Image Validator (<=4MB), and Input Sanitizer.
 *
 * NOTE ON DEPLOYMENT TOPOLOGY:
 * `rateBuckets` uses an in-memory Map bounded to MAX_RATE_BUCKETS entries with expired bucket pruning.
 * It enforces strict rate limits per serverless/Node instance, NOT distributed global rate limiting
 * across multiple parallel serverless containers (which would require a shared store such as Redis/Postgres).
 */
import { isIP } from 'node:net';
import type { NextRequest } from 'next/server';
import {
  MAX_IMAGE_BINARY_BYTES,
  MAX_IMAGE_DATA_URL_LENGTH,
} from '@/domain/api-schemas';

export { MAX_IMAGE_BINARY_BYTES, MAX_IMAGE_DATA_URL_LENGTH };

interface RateBucket {
  count: number;
  resetAt: number;
}

const MAX_RATE_BUCKETS = 2000;
const rateBuckets = new Map<string, RateBucket>();

export const pruneExpiredRateBuckets = (now = Date.now()): number => {
  let pruned = 0;
  for (const [key, bucket] of rateBuckets.entries()) {
    if (now >= bucket.resetAt) {
      rateBuckets.delete(key);
      pruned += 1;
    }
  }
  return pruned;
};

export const getRateBucketCount = (): number => rateBuckets.size;

export const resetRateBucketsForTest = (): void => {
  rateBuckets.clear();
};

const normalizeValidIp = (raw: string | null | undefined): string | null => {
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  if (!trimmed) return null;
  const version = isIP(trimmed);
  if (version === 4) return trimmed;
  if (version === 6) return trimmed.toLowerCase();
  return null;
};

const getNormalizedTrustProxyHeadersSetting = (): string =>
  (process.env.TRUST_PROXY_HEADERS ?? '').trim().toLowerCase();

const resolveDirectPeerFallback = (req: NextRequest): string => {
  const nextReqIp = normalizeValidIp((req as NextRequest & { ip?: string }).ip);
  if (nextReqIp) return nextReqIp;
  return 'direct-unproxied-client';
};

/**
 * Detects Netlify Functions runtime exclusively via the three documented
 * read-only runtime environment variables (`SITE_ID`, `SITE_NAME`, `URL`).
 * Does NOT rely on build-time-only `NETLIFY=true`.
 */
export const isNetlifyRuntime = (): boolean => {
  return Boolean(
    process.env.SITE_ID?.trim() &&
      process.env.SITE_NAME?.trim() &&
      process.env.URL?.trim()
  );
};

export const resolveTrustedClientIp = (req: NextRequest): string => {
  const trustProxySetting = getNormalizedTrustProxyHeadersSetting();

  // Explicit fail-closed override: disable trust in ALL proxy-supplied client IP headers
  if (trustProxySetting === 'false') {
    return resolveDirectPeerFallback(req);
  }

  // Only trust Vercel edge forwarding header when actually running on Vercel platform
  if (process.env.VERCEL === '1') {
    const vercelForwarded = req.headers.get('x-vercel-forwarded-for');
    if (vercelForwarded) {
      const first = normalizeValidIp(vercelForwarded.split(',')[0]);
      if (first) {
        return first;
      }
    }
  }

  // On Netlify Functions runtime, trust ONLY the edge-authoritative `x-nf-client-connection-ip` header.
  // Never fall back to `x-real-ip` or `x-forwarded-for` on Netlify (even when TRUST_PROXY_HEADERS=true)
  // because Netlify Edge preserves client-supplied `x-real-ip` values while setting `x-nf-client-connection-ip`.
  if (isNetlifyRuntime()) {
    const netlifyClientIp = normalizeValidIp(req.headers.get('x-nf-client-connection-ip'));
    if (netlifyClientIp) {
      return netlifyClientIp;
    }
    return resolveDirectPeerFallback(req);
  }

  // Only trust x-real-ip when behind explicitly trusted non-Netlify reverse proxy
  if (process.env.VERCEL === '1' || trustProxySetting === 'true') {
    const realIp = normalizeValidIp(req.headers.get('x-real-ip'));
    if (realIp) {
      return realIp;
    }
  }

  // Direct Node/local runtime: IGNORE spoofable x-forwarded-for, x-real-ip, x-nf-client-connection-ip, and x-workspace-session
  return resolveDirectPeerFallback(req);
};

export const checkRateLimit = (
  clientKey: string,
  maxPerMinute = Number(process.env.AI_RATE_LIMIT_PER_MIN ?? 30),
  now = Date.now()
): { allowed: boolean; remaining: number } => {
  const safeMax = Number.isFinite(maxPerMinute) && maxPerMinute > 0 ? Math.floor(maxPerMinute) : 30;
  const key = clientKey || 'direct-unproxied-client';
  const existing = rateBuckets.get(key);

  if (existing && now < existing.resetAt) {
    if (existing.count >= safeMax) {
      return { allowed: false, remaining: 0 };
    }
    existing.count += 1;
    return { allowed: true, remaining: safeMax - existing.count };
  }

  // Periodically prune expired buckets and enforce hard memory bound before inserting
  if (rateBuckets.size >= MAX_RATE_BUCKETS) {
    pruneExpiredRateBuckets(now);
    while (rateBuckets.size >= MAX_RATE_BUCKETS) {
      const oldestKey = rateBuckets.keys().next().value;
      if (oldestKey === undefined) break;
      rateBuckets.delete(oldestKey);
    }
  }

  rateBuckets.set(key, { count: 1, resetAt: now + 60_000 });
  return { allowed: true, remaining: safeMax - 1 };
};

export const enforceRouteRateLimit = (
  req: NextRequest,
  routeTag: string,
  maxPerMinute: number
): { allowed: boolean; remaining: number; keyUsed: string } => {
  const clientIp = resolveTrustedClientIp(req);
  const keyUsed = `${routeTag}:${clientIp}`;
  const res = checkRateLimit(keyUsed, maxPerMinute);
  return { ...res, keyUsed };
};

export const sanitizePlainText = (input: unknown, maxLength = 2000): string => {
  if (typeof input !== 'string') return '';
  return input
    .replace(/[<>]/g, '')
    .trim()
    .slice(0, maxLength);
};

const STRICT_BASE64_REGEX = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

const decodeStrictBase64 = (rawB64: string): Buffer | null => {
  const cleanB64 = rawB64.replace(/\s+/g, '');
  if (!cleanB64 || cleanB64.length % 4 !== 0 || !STRICT_BASE64_REGEX.test(cleanB64)) {
    return null;
  }
  try {
    return Buffer.from(cleanB64, 'base64');
  } catch {
    return null;
  }
};

const hasMatchingBinaryMagicPrefix = (
  mime: 'image/png' | 'image/jpeg' | 'image/webp',
  buf: Buffer
): boolean => {
  if (mime === 'image/png') {
    return (
      buf.length >= 8 &&
      buf[0] === 0x89 &&
      buf[1] === 0x50 &&
      buf[2] === 0x4e &&
      buf[3] === 0x47 &&
      buf[4] === 0x0d &&
      buf[5] === 0x0a &&
      buf[6] === 0x1a &&
      buf[7] === 0x0a
    );
  }
  if (mime === 'image/jpeg') {
    return buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff;
  }
  return (
    buf.length >= 12 &&
    buf.toString('ascii', 0, 4) === 'RIFF' &&
    buf.toString('ascii', 8, 12) === 'WEBP'
  );
};

export const validateImageDataUrl = (
  dataUrl: unknown
): {
  valid: boolean;
  cleaned?: string;
  byteLength?: number;
  errorCode?: 'PAYLOAD_TOO_LARGE' | 'INVALID_IMAGE';
  errorVi?: string;
} => {
  if (!dataUrl || typeof dataUrl !== 'string') {
    return { valid: true, cleaned: undefined };
  }
  const trimmed = dataUrl.trim();
  if (!trimmed) {
    return { valid: true, cleaned: undefined };
  }

  const lower = trimmed.toLowerCase();

  // Allow synthetic SVG samples used by Sandbox visual gallery while enforcing the 3,000,000-byte raw cap
  if (lower.startsWith('data:image/svg+xml;utf8,')) {
    const payload = trimmed.slice('data:image/svg+xml;utf8,'.length);
    const byteLength = Buffer.byteLength(payload, 'utf8');
    if (byteLength <= 0) {
      return { valid: false, errorCode: 'INVALID_IMAGE', errorVi: 'Tệp ảnh SVG rỗng.' };
    }
    if (byteLength > MAX_IMAGE_BINARY_BYTES || trimmed.length > MAX_IMAGE_DATA_URL_LENGTH) {
      return {
        valid: false,
        errorCode: 'PAYLOAD_TOO_LARGE',
        errorVi: 'Kích thước ảnh vượt quá giới hạn an toàn 3.000.000 bytes (3 MB). Vui lòng chọn hoặc nén ảnh nhỏ hơn.',
      };
    }
    return { valid: true, cleaned: trimmed, byteLength };
  }

  if (lower.startsWith('data:image/svg+xml;base64,')) {
    const rawB64 = trimmed.slice('data:image/svg+xml;base64,'.length);
    const decoded = decodeStrictBase64(rawB64);
    if (!decoded || decoded.length === 0) {
      return { valid: false, errorCode: 'INVALID_IMAGE', errorVi: 'Nội dung ảnh SVG base64 không hợp lệ hoặc rỗng.' };
    }
    if (decoded.length > MAX_IMAGE_BINARY_BYTES) {
      return {
        valid: false,
        errorCode: 'PAYLOAD_TOO_LARGE',
        errorVi: 'Kích thước ảnh giải mã vượt quá giới hạn 3.000.000 bytes (3 MB). Vui lòng chọn ảnh nhỏ hơn.',
      };
    }
    return { valid: true, cleaned: trimmed, byteLength: decoded.length };
  }

  const match = trimmed.match(/^data:(image\/(?:png|jpeg|jpg|webp));base64,(.+)$/is);
  if (!match || !match[1] || !match[2]) {
    return {
      valid: false,
      errorCode: 'INVALID_IMAGE',
      errorVi: 'Định dạng ảnh không hợp lệ (chỉ chấp nhận PNG, JPEG, WebP hoặc SVG mẫu).',
    };
  }

  const rawMime = match[1].toLowerCase();
  const normalizedMime: 'image/png' | 'image/jpeg' | 'image/webp' =
    rawMime === 'image/jpg' ? 'image/jpeg' : (rawMime as 'image/png' | 'image/jpeg' | 'image/webp');
  const buf = decodeStrictBase64(match[2]);
  if (!buf || buf.length === 0) {
    return {
      valid: false,
      errorCode: 'INVALID_IMAGE',
      errorVi: 'Nội dung ảnh base64 bị hỏng, sai định dạng hoặc rỗng.',
    };
  }
  if (buf.length > MAX_IMAGE_BINARY_BYTES) {
    return {
      valid: false,
      errorCode: 'PAYLOAD_TOO_LARGE',
      errorVi: 'Dung lượng ảnh giải mã vượt quá giới hạn an toàn 3.000.000 bytes (3 MB). Vui lòng nén hoặc chọn ảnh nhỏ hơn.',
    };
  }
  if (!hasMatchingBinaryMagicPrefix(normalizedMime, buf)) {
    return {
      valid: false,
      errorCode: 'INVALID_IMAGE',
      errorVi: 'Chữ ký tệp nhị phân không khớp định dạng MIME khai báo (PNG, JPEG hoặc WebP).',
    };
  }
  return {
    valid: true,
    cleaned: `data:${normalizedMime};base64,${match[2].replace(/\s+/g, '')}`,
    byteLength: buf.length,
  };
};

export const MAX_MERCHANT_IMAGE_BYTES = MAX_IMAGE_BINARY_BYTES;
const MAX_MERCHANT_IMAGE_DIM = 8192;
const MAX_MERCHANT_IMAGE_PIXELS = 25_000_000;

export interface ValidatedStrictReceiptImage {
  valid: true;
  mimeType: 'image/png' | 'image/jpeg' | 'image/webp';
  base64Data: string;
  byteLength: number;
  width: number;
  height: number;
  cleanedDataUrl: string;
}

const parsePngDimensions = (buf: Buffer): { width: number; height: number } | null => {
  if (buf.length < 24) return null;
  // Magic: 89 50 4E 47 0D 0A 1A 0A + IHDR chunk
  const magicOk =
    buf[0] === 0x89 &&
    buf[1] === 0x50 &&
    buf[2] === 0x4e &&
    buf[3] === 0x47 &&
    buf[4] === 0x0d &&
    buf[5] === 0x0a &&
    buf[6] === 0x1a &&
    buf[7] === 0x0a &&
    buf.toString('ascii', 12, 16) === 'IHDR';
  if (!magicOk) return null;
  return {
    width: buf.readUInt32BE(16),
    height: buf.readUInt32BE(20),
  };
};

const parseJpegDimensions = (buf: Buffer): { width: number; height: number } | null => {
  if (buf.length < 12 || buf[0] !== 0xff || buf[1] !== 0xd8 || buf[2] !== 0xff) {
    return null;
  }
  let offset = 2;
  while (offset + 4 < buf.length) {
    if (buf[offset] !== 0xff) {
      offset += 1;
      continue;
    }
    while (offset < buf.length && buf[offset] === 0xff) {
      offset += 1;
    }
    if (offset >= buf.length) break;
    const marker = buf[offset]!;
    offset += 1;
    if (marker === 0xd9 || marker === 0xda) break; // EOI / SOS
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) continue;
    if (offset + 2 > buf.length) return null;
    const segLen = buf.readUInt16BE(offset);
    if (segLen < 2 || offset + segLen > buf.length) return null;
    // SOF0..SOF3, SOF5..SOF7, SOF9..SOF11, SOF13..SOF15
    const isSof =
      (marker >= 0xc0 && marker <= 0xc3) ||
      (marker >= 0xc5 && marker <= 0xc7) ||
      (marker >= 0xc9 && marker <= 0xcb) ||
      (marker >= 0xcd && marker <= 0xcf);
    if (isSof) {
      if (segLen < 7) return null;
      return {
        height: buf.readUInt16BE(offset + 3),
        width: buf.readUInt16BE(offset + 5),
      };
    }
    offset += segLen;
  }
  return null;
};

const parseWebpDimensions = (buf: Buffer): { width: number; height: number } | null => {
  if (
    buf.length < 30 ||
    buf.toString('ascii', 0, 4) !== 'RIFF' ||
    buf.toString('ascii', 8, 12) !== 'WEBP'
  ) {
    return null;
  }
  const chunkTag = buf.toString('ascii', 12, 16);
  if (chunkTag === 'VP8X') {
    const w = 1 + (buf[24]! | (buf[25]! << 8) | (buf[26]! << 16));
    const h = 1 + (buf[27]! | (buf[28]! << 8) | (buf[29]! << 16));
    return { width: w, height: h };
  }
  if (chunkTag === 'VP8L') {
    const b0 = buf[21]!;
    const b1 = buf[22]!;
    const b2 = buf[23]!;
    const b3 = buf[24]!;
    const w = 1 + (((b1 & 0x3f) << 8) | b0);
    const h = 1 + (((b3 & 0x0f) << 10) | (b2 << 2) | ((b1 & 0xc0) >> 6));
    return { width: w, height: h };
  }
  if (chunkTag === 'VP8 ' && buf[23] === 0x9d && buf[24] === 0x01 && buf[25] === 0x2a) {
    const w = buf.readUInt16LE(26) & 0x3fff;
    const h = buf.readUInt16LE(28) & 0x3fff;
    return { width: w, height: h };
  }
  return null;
};

/**
 * Strict binary-level validator for Merchant Vision Bill receipts.
 * Rejects SVG/HTML/arbitrary payloads, checks magic signatures & image dimensions,
 * guards against oversized payloads and pixel decompression bombs.
 */
export const validateStrictMerchantReceiptImage = (
  dataUrl: unknown
):
  | ValidatedStrictReceiptImage
  | { valid: false; errorCode: 'PAYLOAD_TOO_LARGE' | 'INVALID_IMAGE'; errorVi: string } => {
  if (typeof dataUrl !== 'string' || !dataUrl.trim()) {
    return {
      valid: false,
      errorCode: 'INVALID_IMAGE',
      errorVi: 'Vui lòng tải lên hoặc chụp ảnh hóa đơn/bill chuyển khoản (PNG, JPEG hoặc WebP).',
    };
  }
  const trimmed = dataUrl.trim();

  const lower = trimmed.toLowerCase();
  if (lower.startsWith('data:image/svg')) {
    return {
      valid: false,
      errorCode: 'INVALID_IMAGE',
      errorVi: 'Không chấp nhận ảnh SVG cho đối soát Bill vì rủi ro nhúng mã script. Vui lòng dùng PNG, JPEG hoặc WebP.',
    };
  }

  const match = trimmed.match(/^data:(image\/(?:png|jpeg|jpg|webp));base64,(.+)$/is);
  if (!match || !match[1] || !match[2]) {
    return {
      valid: false,
      errorCode: 'INVALID_IMAGE',
      errorVi: 'Định dạng ảnh Bill không hợp lệ (chỉ chấp nhận nhị phân PNG, JPEG hoặc WebP).',
    };
  }

  const rawMime = match[1].toLowerCase();
  const normalizedMime: 'image/png' | 'image/jpeg' | 'image/webp' =
    rawMime === 'image/jpg' ? 'image/jpeg' : (rawMime as 'image/png' | 'image/jpeg' | 'image/webp');
  const cleanB64 = match[2].replace(/\s+/g, '');
  const buf = decodeStrictBase64(cleanB64);
  if (!buf || buf.length === 0) {
    return {
      valid: false,
      errorCode: 'INVALID_IMAGE',
      errorVi: 'Nội dung ảnh base64 bị hỏng, sai định dạng hoặc rỗng.',
    };
  }

  if (buf.length > MAX_MERCHANT_IMAGE_BYTES) {
    return {
      valid: false,
      errorCode: 'PAYLOAD_TOO_LARGE',
      errorVi: 'Dung lượng ảnh giải mã vượt quá giới hạn an toàn 3.000.000 bytes (3 MB). Vui lòng nén hoặc chọn ảnh nhỏ hơn.',
    };
  }

  if (buf.length < 24) {
    return {
      valid: false,
      errorCode: 'INVALID_IMAGE',
      errorVi: 'Tệp ảnh quá nhỏ hoặc bị cắt cụt.',
    };
  }

  const dims =
    normalizedMime === 'image/png'
      ? parsePngDimensions(buf)
      : normalizedMime === 'image/jpeg'
      ? parseJpegDimensions(buf)
      : parseWebpDimensions(buf);

  if (!dims || dims.width <= 0 || dims.height <= 0) {
    return {
      valid: false,
      errorCode: 'INVALID_IMAGE',
      errorVi: 'Chữ ký tệp (file signature) không khớp định dạng ảnh hoặc ảnh bị hỏng cấu trúc.',
    };
  }

  if (
    dims.width > MAX_MERCHANT_IMAGE_DIM ||
    dims.height > MAX_MERCHANT_IMAGE_DIM ||
    dims.width * dims.height > MAX_MERCHANT_IMAGE_PIXELS
  ) {
    return {
      valid: false,
      errorCode: 'INVALID_IMAGE',
      errorVi: 'Kích thước phân giải ảnh quá lớn (vượt ngưỡng chống decompression bomb).',
    };
  }

  return {
    valid: true,
    mimeType: normalizedMime,
    base64Data: cleanB64,
    byteLength: buf.length,
    width: dims.width,
    height: dims.height,
    cleanedDataUrl: `data:${normalizedMime};base64,${cleanB64}`,
  };
};
