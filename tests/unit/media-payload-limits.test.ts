import { NextRequest } from 'next/server';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { POST as merchantVisionPost } from '@/app/api/merchant/vision/route';
import { POST as sandboxPost } from '@/app/api/sandbox/route';
import {
  MAX_IMAGE_BINARY_BYTES,
  MAX_IMAGE_DATA_URL_LENGTH,
  MEDIA_MAX_JSON_BODY_BYTES,
  MerchantVisionVerifyRequestSchema,
  parseRequestJsonWithSchema,
  readRequestBodyTextWithByteLimit,
} from '@/domain/api-schemas';
import {
  validateImageDataUrl,
  validateStrictMerchantReceiptImage,
} from '@/infrastructure/security-guard';
import { SESSION_COOKIE_NAME, createSignedSessionToken } from '@/infrastructure/session-auth';
import {
  ADAPTIVE_COMPRESSION_LADDER,
  type ClientImageCompressionAdapter,
  prepareClientReceiptImageForUpload,
} from '@/presentation/utils/client-image-compressor';

const VALID_1X1_PNG_BYTES = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=',
  'base64'
);

/** Builds a valid PNG buffer (valid magic + 1x1 IHDR) padded to exact `targetByteLength`. */
const buildPaddedPngDataUrl = (targetByteLength: number): string => {
  const buf = Buffer.alloc(targetByteLength, 0);
  VALID_1X1_PNG_BYTES.copy(buf, 0, 0, Math.min(VALID_1X1_PNG_BYTES.length, targetByteLength));
  return `data:image/png;base64,${buf.toString('base64')}`;
};

const makeAuthMediaRequest = (params: {
  url: string;
  sessionId: string;
  body: string | ReadableStream<Uint8Array>;
  extraHeaders?: Record<string, string>;
}): NextRequest => {
  const token = createSignedSessionToken({
    sessionId: params.sessionId,
    role: 'L2_CHECKER',
    principalId: 'checker-media-test',
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
      ...(params.extraHeaders ?? {}),
    },
    body: params.body,
  });
};

afterEach(() => {
  vi.restoreAllMocks();
});

describe('Wave 4.2.1C — Media Payload Limits, Streamed Byte Boundary & Client Compression', () => {
  describe('A. Exact raw image binary limits (3,000,000 bytes)', () => {
    it('exports the exact conservative byte contract (3,000,000 B raw / 4,194,304 B JSON)', () => {
      expect(MAX_IMAGE_BINARY_BYTES).toBe(3_000_000);
      expect(MEDIA_MAX_JSON_BODY_BYTES).toBe(4 * 1024 * 1024);
      expect(MEDIA_MAX_JSON_BODY_BYTES).toBe(4_194_304);
      expect(MAX_IMAGE_DATA_URL_LENGTH).toBe(4_000_064);
    });

    it('accepts exactly 3,000,000 decoded bytes and rejects 3,000,001 bytes in both strict and sandbox validators', () => {
      const exactLimitDataUrl = buildPaddedPngDataUrl(3_000_000);
      const strictOk = validateStrictMerchantReceiptImage(exactLimitDataUrl);
      expect(strictOk.valid).toBe(true);
      if (strictOk.valid) {
        expect(strictOk.byteLength).toBe(3_000_000);
      }
      const sandboxOk = validateImageDataUrl(exactLimitDataUrl);
      expect(sandboxOk.valid).toBe(true);
      expect(sandboxOk.byteLength).toBe(3_000_000);

      const overByOneDataUrl = buildPaddedPngDataUrl(3_000_001);
      const strictOver = validateStrictMerchantReceiptImage(overByOneDataUrl);
      expect(strictOver.valid).toBe(false);
      if (!strictOver.valid) {
        expect(strictOver.errorCode).toBe('PAYLOAD_TOO_LARGE');
      }
      const sandboxOver = validateImageDataUrl(overByOneDataUrl);
      expect(sandboxOver.valid).toBe(false);
      expect(sandboxOver.errorCode).toBe('PAYLOAD_TOO_LARGE');
    });

    it('rejects zero-byte, malformed base64, unsupported MIME, and MIME/data-URL magic mismatches', () => {
      // Zero-byte / empty base64
      expect(validateStrictMerchantReceiptImage('data:image/png;base64,').valid).toBe(false);
      expect(validateImageDataUrl('data:image/png;base64,').valid).toBe(false);

      // Malformed base64 (invalid characters / broken padding)
      expect(validateStrictMerchantReceiptImage('data:image/png;base64,%%%NOT_BASE64%%%').valid).toBe(false);
      expect(validateStrictMerchantReceiptImage('data:image/png;base64,iVBORw0KGgo').valid).toBe(false);
      expect(validateImageDataUrl('data:image/png;base64,%%%NOT_BASE64%%%').valid).toBe(false);

      // Unsupported MIME
      expect(
        validateStrictMerchantReceiptImage(
          `data:application/pdf;base64,${Buffer.from('%PDF-1.7 test').toString('base64')}`
        ).valid
      ).toBe(false);
      expect(
        validateImageDataUrl(
          `data:application/pdf;base64,${Buffer.from('%PDF-1.7 test').toString('base64')}`
        ).valid
      ).toBe(false);

      // MIME / binary magic mismatch (PNG bytes declared as image/jpeg)
      const pngAsJpeg = `data:image/jpeg;base64,${VALID_1X1_PNG_BYTES.toString('base64')}`;
      expect(validateStrictMerchantReceiptImage(pngAsJpeg).valid).toBe(false);
      expect(validateImageDataUrl(pngAsJpeg).valid).toBe(false);
    });
  });

  describe('B. Complete UTF-8 JSON body limits (4,194,304 bytes) & streamed byte enforcement', () => {
    it('accepts exactly 4,194,304 UTF-8 bytes and rejects 4,194,305 bytes with HTTP 413', async () => {
      const prefix = '{"imageDataUrl":"data:image/png;base64,';
      const suffix = '"}';
      const exactPayloadLen = MEDIA_MAX_JSON_BODY_BYTES - prefix.length - suffix.length;
      // Use a small body budget test for exact byte precision (plus full 4,194,304 boundary test)
      const exactBody = `${prefix}${'A'.repeat(exactPayloadLen)}${suffix}`;
      expect(Buffer.byteLength(exactBody, 'utf8')).toBe(4_194_304);

      const exactReq = new NextRequest('http://localhost:3000/api/merchant/vision', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: exactBody,
      });
      const exactRead = await readRequestBodyTextWithByteLimit(exactReq, MEDIA_MAX_JSON_BODY_BYTES);
      expect(exactRead.ok).toBe(true);
      if (exactRead.ok) {
        expect(exactRead.byteLength).toBe(4_194_304);
      }

      const overByOneBody = `${prefix}${'A'.repeat(exactPayloadLen + 1)}${suffix}`;
      expect(Buffer.byteLength(overByOneBody, 'utf8')).toBe(4_194_305);
      const overReq = new NextRequest('http://localhost:3000/api/merchant/vision', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: overByOneBody,
      });
      const overRes = await parseRequestJsonWithSchema(
        overReq,
        MerchantVisionVerifyRequestSchema,
        { maxBytes: MEDIA_MAX_JSON_BODY_BYTES }
      );
      expect(overRes.ok).toBe(false);
      if (!overRes.ok) {
        expect(overRes.response.status).toBe(413);
        const json = (await overRes.response.json()) as { code: string; maxBytes: number };
        expect(json.code).toBe('PAYLOAD_TOO_LARGE');
        expect(json.maxBytes).toBe(4_194_304);
      }
    });

    it('counts multibyte UTF-8 Unicode bytes accurately, rejects invalid Content-Length, and cancels oversized streams early even with misleading Content-Length', async () => {
      // Multibyte Vietnamese Unicode: 'Đ' is 2 bytes, '₫' is 3 bytes in UTF-8
      const unicodeBody = JSON.stringify({ note: '₫'.repeat(100) }); // 100 chars -> 300 UTF-8 bytes + JSON wrapper
      const utf8Bytes = Buffer.byteLength(unicodeBody, 'utf8');
      expect(utf8Bytes).toBeGreaterThan(unicodeBody.length);

      const unicodeOverReq = new NextRequest('http://localhost:3000/api/sandbox', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: unicodeBody,
      });
      // Limit sits between JS char length and UTF-8 byte length -> MUST reject 413!
      const unicodeLimit = unicodeBody.length + 10;
      const unicodeRes = await readRequestBodyTextWithByteLimit(unicodeOverReq, unicodeLimit);
      expect(unicodeRes.ok).toBe(false);
      if (!unicodeRes.ok) {
        expect(unicodeRes.response.status).toBe(413);
      }

      // Invalid/negative Content-Length rejected cleanly (HTTP 400)
      const negClReq = new NextRequest('http://localhost:3000/api/sandbox', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'content-length': '-50' },
        body: '{}',
      });
      const negClRes = await readRequestBodyTextWithByteLimit(negClReq, 1024);
      expect(negClRes.ok).toBe(false);
      if (!negClRes.ok) {
        expect(negClRes.response.status).toBe(400);
      }

      // Underspecified/misleading Content-Length cannot bypass streamed byte enforcement, and stream cancels early!
      let chunksPulled = 0;
      let streamCancelled = false;
      const hugeStream = new ReadableStream<Uint8Array>({
        pull(controller) {
          chunksPulled += 1;
          if (chunksPulled > 20) {
            controller.close();
            return;
          }
          controller.enqueue(new Uint8Array(1024).fill(65));
        },
        cancel() {
          streamCancelled = true;
        },
      });
      const misleadingReq = new NextRequest('http://localhost:3000/api/merchant/vision', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'content-length': '100' },
        body: hugeStream,
      });
      const streamRes = await readRequestBodyTextWithByteLimit(misleadingReq, 3000);
      expect(streamRes.ok).toBe(false);
      if (!streamRes.ok) {
        expect(streamRes.response.status).toBe(413);
      }
      expect(streamCancelled).toBe(true);
      expect(chunksPulled).toBeLessThan(20);

      // Invalid JSON still returns 400 INVALID_JSON (not unhandled exception)
      const invalidJsonReq = new NextRequest('http://localhost:3000/api/merchant/vision', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: '{invalid-json',
      });
      const invalidJsonRes = await parseRequestJsonWithSchema(
        invalidJsonReq,
        MerchantVisionVerifyRequestSchema,
        { maxBytes: MEDIA_MAX_JSON_BODY_BYTES }
      );
      expect(invalidJsonRes.ok).toBe(false);
      if (!invalidJsonRes.ok) {
        expect(invalidJsonRes.response.status).toBe(400);
      }
    });
  });

  describe('C. Route integration (/api/merchant/vision & /api/sandbox)', () => {
    it('rejects oversized requests with HTTP 413 before Gemini transport on both /api/merchant/vision and /api/sandbox while keeping valid small uploads functional', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch');
      const sid = `media-route-${Date.now()}`;

      // 1. Oversized /api/merchant/vision (> 4 MiB JSON) -> 413, 0 Gemini calls
      const oversizedVisionBody = JSON.stringify({
        imageDataUrl: buildPaddedPngDataUrl(3_200_000),
        merchantAccountIdOrNumber: 'ACC-HOSP-800',
      });
      expect(Buffer.byteLength(oversizedVisionBody, 'utf8')).toBeGreaterThan(
        MEDIA_MAX_JSON_BODY_BYTES
      );
      const vision413 = await merchantVisionPost(
        makeAuthMediaRequest({
          url: 'http://localhost:3000/api/merchant/vision',
          sessionId: sid,
          body: oversizedVisionBody,
        })
      );
      expect(vision413.status).toBe(413);
      expect(((await vision413.json()) as { code: string }).code).toBe('PAYLOAD_TOO_LARGE');

      // 2. Oversized /api/sandbox (> 4 MiB JSON) -> 413, 0 Gemini calls
      const oversizedSandboxBody = JSON.stringify({
        rawTranscript: 'Transfer receipt test',
        imageDataUrl: buildPaddedPngDataUrl(3_200_000),
      });
      const sandbox413 = await sandboxPost(
        makeAuthMediaRequest({
          url: 'http://localhost:3000/api/sandbox',
          sessionId: sid,
          body: oversizedSandboxBody,
        })
      );
      expect(sandbox413.status).toBe(413);
      expect(((await sandbox413.json()) as { code: string }).code).toBe('PAYLOAD_TOO_LARGE');

      // 3. Raw image = 3,000,001 bytes (fits inside 4 MiB JSON at ~4,000,024 bytes, exceeds 3,000,000 B raw limit)
      //    -> Still rejected cleanly with HTTP 413 PAYLOAD_TOO_LARGE!
      const rawOverBody = JSON.stringify({
        imageDataUrl: buildPaddedPngDataUrl(3_000_001),
        merchantAccountIdOrNumber: 'ACC-HOSP-800',
      });
      expect(Buffer.byteLength(rawOverBody, 'utf8')).toBeLessThan(MEDIA_MAX_JSON_BODY_BYTES);
      const rawOverVisionRes = await merchantVisionPost(
        makeAuthMediaRequest({
          url: 'http://localhost:3000/api/merchant/vision',
          sessionId: sid,
          body: rawOverBody,
        })
      );
      expect(rawOverVisionRes.status).toBe(413);
      expect(((await rawOverVisionRes.json()) as { code: string }).code).toBe('PAYLOAD_TOO_LARGE');

      const rawOverSandboxRes = await sandboxPost(
        makeAuthMediaRequest({
          url: 'http://localhost:3000/api/sandbox',
          sessionId: sid,
          body: JSON.stringify({
            rawTranscript: 'Test over 3MB raw',
            imageDataUrl: buildPaddedPngDataUrl(3_000_001),
          }),
        })
      );
      expect(rawOverSandboxRes.status).toBe(413);
      expect(((await rawOverSandboxRes.json()) as { code: string }).code).toBe('PAYLOAD_TOO_LARGE');

      // Ensure zero external Gemini fetch calls occurred on any oversized request
      expect(fetchSpy).not.toHaveBeenCalled();

      // 4. Valid small 1x1 PNG still succeeds cleanly on /api/merchant/vision (deterministic fallback without key)
      const prevKey = process.env.GEMINI_API_KEY;
      process.env.GEMINI_API_KEY = '';
      try {
        const smallVisionRes = await merchantVisionPost(
          makeAuthMediaRequest({
            url: 'http://localhost:3000/api/merchant/vision',
            sessionId: sid,
            body: JSON.stringify({
              imageDataUrl: `data:image/png;base64,${VALID_1X1_PNG_BYTES.toString('base64')}`,
              merchantAccountIdOrNumber: 'ACC-HOSP-800',
            }),
          })
        );
        expect(smallVisionRes.status).toBe(200);
      } finally {
        process.env.GEMINI_API_KEY = prevKey;
      }
    });
  });

  describe('D. Client-side adaptive bounded compression policy', () => {
    it('does not recompress in-budget images, compresses oversized images within bounded attempts, preserves MIME accuracy, and fails cleanly when uncompressible', async () => {
      // 1. In-budget image (<= 3,000,000 bytes) is NEVER recompressed
      const smallFile = new File([VALID_1X1_PNG_BYTES], 'receipt.png', { type: 'image/png' });
      const encodeSpy = vi.fn();
      const adapterInBudget: ClientImageCompressionAdapter = {
        readFileAsDataUrl: async () =>
          `data:image/png;base64,${VALID_1X1_PNG_BYTES.toString('base64')}`,
        decodeImageDimensions: vi.fn(),
        encodeResizedImage: encodeSpy,
        supportsWebpEncode: () => true,
      };
      const inBudgetRes = await prepareClientReceiptImageForUpload(smallFile, {
        adapter: adapterInBudget,
      });
      expect(inBudgetRes.ok).toBe(true);
      if (inBudgetRes.ok) {
        expect(inBudgetRes.wasCompressed).toBe(false);
        expect(inBudgetRes.attempts).toBe(0);
        expect(inBudgetRes.mimeType).toBe('image/png');
      }
      expect(encodeSpy).not.toHaveBeenCalled();

      // 2. Oversized image (> 3,000,000 bytes) compresses within bounded attempts and reports accurate MIME
      const oversizedFakeFile = {
        name: 'big-receipt.png',
        size: 4_800_000,
        type: 'image/png',
      } as unknown as File;
      let encodeCalls = 0;
      const adapterSucceedsOn3rd: ClientImageCompressionAdapter = {
        readFileAsDataUrl: vi.fn(),
        decodeImageDimensions: async () => ({ width: 4000, height: 3000 }),
        encodeResizedImage: async ({ mimeType }) => {
          encodeCalls += 1;
          const bytes = encodeCalls < 3 ? 3_400_000 : 1_850_000;
          return {
            dataUrl: `data:${mimeType};base64,AAAA`,
            mimeType,
            byteLength: bytes,
          };
        },
        supportsWebpEncode: () => true,
      };
      const compressedRes = await prepareClientReceiptImageForUpload(oversizedFakeFile, {
        adapter: adapterSucceedsOn3rd,
      });
      expect(compressedRes.ok).toBe(true);
      if (compressedRes.ok) {
        expect(compressedRes.wasCompressed).toBe(true);
        expect(compressedRes.attempts).toBe(3);
        expect(compressedRes.mimeType).toBe('image/webp');
        expect(compressedRes.byteLength).toBe(1_850_000);
        expect(compressedRes.dataUrl.startsWith('data:image/webp;base64,')).toBe(true);
      }

      // 3. Uncompressible oversized image stops at bounded ladder length (6) with actionable error
      let failAttempts = 0;
      const adapterAlwaysTooBig: ClientImageCompressionAdapter = {
        readFileAsDataUrl: vi.fn(),
        decodeImageDimensions: async () => ({ width: 6000, height: 4000 }),
        encodeResizedImage: async ({ mimeType }) => {
          failAttempts += 1;
          return {
            dataUrl: `data:${mimeType};base64,AAAA`,
            mimeType,
            byteLength: 3_500_000,
          };
        },
        supportsWebpEncode: () => true,
      };
      const failedCompRes = await prepareClientReceiptImageForUpload(oversizedFakeFile, {
        adapter: adapterAlwaysTooBig,
      });
      expect(failedCompRes.ok).toBe(false);
      if (!failedCompRes.ok) {
        expect(failedCompRes.errorCode).toBe('COMPRESSED_STILL_TOO_LARGE');
        expect(failedCompRes.attempts).toBe(ADAPTIVE_COMPRESSION_LADDER.length);
      }
      expect(failAttempts).toBe(ADAPTIVE_COMPRESSION_LADDER.length);

      // 4. Unsupported type (SVG) rejected immediately
      const svgFile = { name: 'evil.svg', size: 512, type: 'image/svg+xml' } as unknown as File;
      const svgRes = await prepareClientReceiptImageForUpload(svgFile, {
        adapter: adapterInBudget,
      });
      expect(svgRes.ok).toBe(false);
      if (!svgRes.ok) {
        expect(svgRes.errorCode).toBe('UNSUPPORTED_TYPE');
      }
    });
  });
});
