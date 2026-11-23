/**
 * Wave 4.2.1C Native Browser Adaptive Image Compression & Client Upload Guard.
 *
 * - Keeps images already <= MAX_IMAGE_BINARY_BYTES (3,000,000 bytes) completely untouched (no recompression).
 * - Uses bounded adaptive downscaling + OCR-safe quality ladder (never cropping, quality floor 0.72,
 *   min long-edge cap 1280px, max 6 attempts) using native browser Canvas/ImageBitmap APIs (zero dependencies).
 * - Preserves EXIF orientation via `createImageBitmap(file, { imageOrientation: 'from-image' })` where supported.
 * - Distinguishes unsupported type, corrupt/unreadable image, oversized raw without compressor,
 *   compressed-still-too-large, and complete JSON payload > MEDIA_MAX_JSON_BODY_BYTES (4,194,304 bytes).
 */
import {
  MAX_IMAGE_BINARY_BYTES,
  MEDIA_MAX_JSON_BODY_BYTES,
} from '@/domain/api-schemas';

export type SupportedUploadImageMime = 'image/png' | 'image/jpeg' | 'image/webp';

export type ClientImageUploadErrorCode =
  | 'UNSUPPORTED_TYPE'
  | 'CORRUPT_OR_UNREADABLE'
  | 'RAW_TOO_LARGE_NO_COMPRESSOR'
  | 'COMPRESSED_STILL_TOO_LARGE'
  | 'PAYLOAD_TOO_LARGE';

export type ClientImagePreparationResult =
  | {
      ok: true;
      dataUrl: string;
      mimeType: SupportedUploadImageMime;
      byteLength: number;
      wasCompressed: boolean;
      attempts: number;
    }
  | {
      ok: false;
      errorCode: ClientImageUploadErrorCode;
      errorVi: string;
      attempts: number;
    };

export interface CompressionStepSpec {
  maxLongEdgePx: number;
  quality: number;
}

/** Bounded OCR-safe adaptive compression ladder (quality floor 0.72, min long edge 1280px, 6 attempts). */
export const ADAPTIVE_COMPRESSION_LADDER: readonly CompressionStepSpec[] = [
  { maxLongEdgePx: 2400, quality: 0.9 },
  { maxLongEdgePx: 2048, quality: 0.86 },
  { maxLongEdgePx: 1920, quality: 0.82 },
  { maxLongEdgePx: 1600, quality: 0.78 },
  { maxLongEdgePx: 1440, quality: 0.75 },
  { maxLongEdgePx: 1280, quality: 0.72 },
] as const;

export interface ClientImageCompressionAdapter {
  readFileAsDataUrl: (file: File) => Promise<string>;
  decodeImageDimensions: (file: File) => Promise<{ width: number; height: number; release?: () => void; source?: CanvasImageSource }>;
  encodeResizedImage: (params: {
    source?: CanvasImageSource;
    targetWidth: number;
    targetHeight: number;
    mimeType: SupportedUploadImageMime;
    quality: number;
  }) => Promise<{ dataUrl: string; mimeType: SupportedUploadImageMime; byteLength: number }>;
  supportsWebpEncode: () => boolean;
}

const normalizeUploadMime = (rawMime: string): SupportedUploadImageMime | null => {
  const lower = rawMime.trim().toLowerCase();
  if (lower === 'image/png') return 'image/png';
  if (lower === 'image/jpeg' || lower === 'image/jpg') return 'image/jpeg';
  if (lower === 'image/webp') return 'image/webp';
  return null;
};

export const computeDecodedBase64ByteLength = (dataUrl: string): number => {
  const commaIdx = dataUrl.indexOf(',');
  if (commaIdx < 0) return 0;
  const b64 = dataUrl.slice(commaIdx + 1).replace(/\s+/g, '');
  if (!b64) return 0;
  const padding = b64.endsWith('==') ? 2 : b64.endsWith('=') ? 1 : 0;
  return Math.max(0, Math.floor((b64.length * 3) / 4) - padding);
};

export const computeScaledDimensionsPreservingAspect = (
  width: number,
  height: number,
  maxLongEdgePx: number
): { width: number; height: number } => {
  const safeW = Math.max(1, Math.round(width));
  const safeH = Math.max(1, Math.round(height));
  const longEdge = Math.max(safeW, safeH);
  if (longEdge <= maxLongEdgePx) {
    return { width: safeW, height: safeH };
  }
  const scale = maxLongEdgePx / longEdge;
  return {
    width: Math.max(1, Math.round(safeW * scale)),
    height: Math.max(1, Math.round(safeH * scale)),
  };
};

export const measureUtf8JsonPayloadBytes = (payload: unknown): number => {
  const serialized = JSON.stringify(payload);
  if (typeof TextEncoder !== 'undefined') {
    return new TextEncoder().encode(serialized).byteLength;
  }
  return Buffer.byteLength(serialized, 'utf8');
};

export const isJsonPayloadWithinMediaLimit = (payload: unknown): boolean =>
  measureUtf8JsonPayloadBytes(payload) <= MEDIA_MAX_JSON_BODY_BYTES;

const createBrowserCompressionAdapter = (): ClientImageCompressionAdapter | null => {
  if (typeof window === 'undefined' || typeof FileReader === 'undefined') {
    return null;
  }

  const readFileAsDataUrl = (file: File): Promise<string> =>
    new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        if (typeof reader.result === 'string') {
          resolve(reader.result);
        } else {
          reject(new Error('UNREADABLE_FILE'));
        }
      };
      reader.onerror = () => reject(new Error('UNREADABLE_FILE'));
      reader.readAsDataURL(file);
    });

  const supportsWebpEncode = (): boolean => {
    try {
      const canvas = document.createElement('canvas');
      canvas.width = 2;
      canvas.height = 2;
      return canvas.toDataURL('image/webp').startsWith('data:image/webp');
    } catch {
      return false;
    }
  };

  const decodeImageDimensions = async (
    file: File
  ): Promise<{ width: number; height: number; release?: () => void; source?: CanvasImageSource }> => {
    if (typeof createImageBitmap === 'function') {
      try {
        const bitmap = await createImageBitmap(file, { imageOrientation: 'from-image' });
        return {
          width: bitmap.width,
          height: bitmap.height,
          source: bitmap,
          release: () => bitmap.close(),
        };
      } catch {
        // Fallback to HTMLImageElement below
      }
    }

    const objectUrl = URL.createObjectURL(file);
    return new Promise((resolve, reject) => {
      const img = new Image();
      img.onload = () => {
        resolve({
          width: img.naturalWidth || img.width,
          height: img.naturalHeight || img.height,
          source: img,
          release: () => URL.revokeObjectURL(objectUrl),
        });
      };
      img.onerror = () => {
        URL.revokeObjectURL(objectUrl);
        reject(new Error('CORRUPT_IMAGE'));
      };
      img.src = objectUrl;
    });
  };

  const encodeResizedImage: ClientImageCompressionAdapter['encodeResizedImage'] = async ({
    source,
    targetWidth,
    targetHeight,
    mimeType,
    quality,
  }) => {
    if (!source || typeof document === 'undefined') {
      throw new Error('NO_CANVAS_SUPPORT');
    }
    const canvas = document.createElement('canvas');
    canvas.width = targetWidth;
    canvas.height = targetHeight;
    const ctx = canvas.getContext('2d');
    if (!ctx) {
      throw new Error('NO_CANVAS_SUPPORT');
    }
    ctx.imageSmoothingEnabled = true;
    ctx.imageSmoothingQuality = 'high';
    if (mimeType === 'image/jpeg') {
      ctx.fillStyle = '#FFFFFF';
      ctx.fillRect(0, 0, targetWidth, targetHeight);
    }
    ctx.drawImage(source, 0, 0, targetWidth, targetHeight);

    const dataUrl = canvas.toDataURL(mimeType, quality);
    const actualMimeMatch = dataUrl.match(/^data:(image\/(?:png|jpeg|webp));base64,/i);
    const actualMime =
      (actualMimeMatch?.[1]?.toLowerCase() as SupportedUploadImageMime | undefined) ?? mimeType;
    const byteLength = computeDecodedBase64ByteLength(dataUrl);
    return { dataUrl, mimeType: actualMime, byteLength };
  };

  return {
    readFileAsDataUrl,
    decodeImageDimensions,
    encodeResizedImage,
    supportsWebpEncode,
  };
};

/**
 * Validates and (only when > 3,000,000 bytes) adaptively compresses a receipt or evidence image
 * on the client while preserving Vietnamese OCR legibility and strict MIME accuracy.
 */
export const prepareClientReceiptImageForUpload = async (
  file: File,
  options?: {
    maxBinaryBytes?: number;
    adapter?: ClientImageCompressionAdapter | null;
  }
): Promise<ClientImagePreparationResult> => {
  const maxBinaryBytes = options?.maxBinaryBytes ?? MAX_IMAGE_BINARY_BYTES;

  if (!file || typeof file.size !== 'number' || file.size <= 0) {
    return {
      ok: false,
      errorCode: 'CORRUPT_OR_UNREADABLE',
      errorVi: 'Tệp ảnh rỗng hoặc bị hỏng. Vui lòng chọn ảnh hợp lệ.',
      attempts: 0,
    };
  }

  const normalizedMime = normalizeUploadMime(file.type || '');
  if (!normalizedMime) {
    return {
      ok: false,
      errorCode: 'UNSUPPORTED_TYPE',
      errorVi: 'Chỉ hỗ trợ ảnh chụp màn hình PNG, JPEG hoặc WebP (không nhận SVG).',
      attempts: 0,
    };
  }

  const adapter =
    options?.adapter !== undefined ? options.adapter : createBrowserCompressionAdapter();

  // 1. In-budget image: DO NOT unnecessarily recompress!
  if (file.size <= maxBinaryBytes) {
    if (!adapter) {
      return {
        ok: false,
        errorCode: 'CORRUPT_OR_UNREADABLE',
        errorVi: 'Trình duyệt không hỗ trợ đọc tệp ảnh tải lên.',
        attempts: 0,
      };
    }
    try {
      const dataUrl = await adapter.readFileAsDataUrl(file);
      const decodedBytes = computeDecodedBase64ByteLength(dataUrl);
      if (decodedBytes <= 0) {
        return {
          ok: false,
          errorCode: 'CORRUPT_OR_UNREADABLE',
          errorVi: 'Không thể đọc nội dung ảnh. Tệp có thể bị hỏng.',
          attempts: 0,
        };
      }
      if (decodedBytes > maxBinaryBytes) {
        return {
          ok: false,
          errorCode: 'COMPRESSED_STILL_TOO_LARGE',
          errorVi: 'Dung lượng ảnh giải mã vượt quá giới hạn 3.000.000 bytes (3 MB). Vui lòng chọn ảnh nhỏ hơn.',
          attempts: 0,
        };
      }
      const actualMimeMatch = dataUrl.match(/^data:(image\/(?:png|jpeg|jpg|webp));base64,/i);
      const actualMime = normalizeUploadMime(actualMimeMatch?.[1] ?? normalizedMime) ?? normalizedMime;
      return {
        ok: true,
        dataUrl,
        mimeType: actualMime,
        byteLength: decodedBytes,
        wasCompressed: false,
        attempts: 0,
      };
    } catch {
      return {
        ok: false,
        errorCode: 'CORRUPT_OR_UNREADABLE',
        errorVi: 'Không thể đọc tệp ảnh tải lên. Tệp có thể bị lỗi hoặc không đúng định dạng.',
        attempts: 0,
      };
    }
  }

  // 2. Oversized raw image (> 3,000,000 bytes): bounded OCR-safe adaptive compression
  if (!adapter) {
    return {
      ok: false,
      errorCode: 'RAW_TOO_LARGE_NO_COMPRESSOR',
      errorVi:
        'Ảnh vượt quá giới hạn 3.000.000 bytes (3 MB) và trình duyệt không hỗ trợ nén tự động. Vui lòng chọn ảnh nhỏ hơn.',
      attempts: 0,
    };
  }

  let decoded: { width: number; height: number; release?: () => void; source?: CanvasImageSource };
  try {
    decoded = await adapter.decodeImageDimensions(file);
    if (decoded.width <= 0 || decoded.height <= 0) {
      decoded.release?.();
      return {
        ok: false,
        errorCode: 'CORRUPT_OR_UNREADABLE',
        errorVi: 'Không thể giải mã kích thước ảnh. Tệp ảnh có thể bị hỏng.',
        attempts: 0,
      };
    }
  } catch {
    return {
      ok: false,
      errorCode: 'CORRUPT_OR_UNREADABLE',
      errorVi: 'Ảnh bị hỏng hoặc không thể giải mã trên trình duyệt. Vui lòng chọn ảnh PNG/JPEG/WebP hợp lệ.',
      attempts: 0,
    };
  }

  // Prefer WebP for crisp receipt text/QR compression when supported (keeps PNG/WebP text sharper than JPEG),
  // otherwise use JPEG for oversized PNG/JPEG photos.
  const targetMime: SupportedUploadImageMime =
    normalizedMime === 'image/jpeg'
      ? 'image/jpeg'
      : adapter.supportsWebpEncode()
        ? 'image/webp'
        : 'image/jpeg';

  let attempts = 0;
  try {
    for (const step of ADAPTIVE_COMPRESSION_LADDER) {
      attempts += 1;
      const scaled = computeScaledDimensionsPreservingAspect(
        decoded.width,
        decoded.height,
        step.maxLongEdgePx
      );
      const encoded = await adapter.encodeResizedImage({
        source: decoded.source,
        targetWidth: scaled.width,
        targetHeight: scaled.height,
        mimeType: targetMime,
        quality: step.quality,
      });

      const actualBytes =
        encoded.byteLength > 0
          ? encoded.byteLength
          : computeDecodedBase64ByteLength(encoded.dataUrl);
      if (actualBytes > 0 && actualBytes <= maxBinaryBytes) {
        return {
          ok: true,
          dataUrl: encoded.dataUrl,
          mimeType: encoded.mimeType,
          byteLength: actualBytes,
          wasCompressed: true,
          attempts,
        };
      }
    }

    return {
      ok: false,
      errorCode: 'COMPRESSED_STILL_TOO_LARGE',
      errorVi:
        'Ảnh vẫn vượt quá giới hạn 3.000.000 bytes (3 MB) sau khi nén tối ưu giữ rõ chữ Bill. Vui lòng chụp lại hoặc chọn ảnh nhẹ hơn.',
      attempts,
    };
  } catch {
    return {
      ok: false,
      errorCode: 'CORRUPT_OR_UNREADABLE',
      errorVi: 'Không thể tối ưu hóa ảnh tải lên. Vui lòng chọn ảnh khác nhỏ hơn 3 MB.',
      attempts,
    };
  } finally {
    decoded.release?.();
  }
};
