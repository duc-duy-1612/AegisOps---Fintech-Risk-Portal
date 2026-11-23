import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, extname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * Static Gemini Transport Chokepoint Guard (CR-2.4):
 * - Enforces the architectural invariant that all direct Gemini Developer API REST transport
 *   and Google Gemini SDK integrations remain centralized inside `src/infrastructure/gemini-resilience.ts`
 *   so CR-2.2 E2E isolation, circuit breakers, and project-scoped quotas cannot be silently bypassed.
 * - Honest Limitation Disclosure: Static pattern scanning protects against common direct-integration
 *   mistakes (literal Gemini hostnames, direct Gemini REST endpoint paths, and known Gemini SDK imports);
 *   it is NOT a formal proof against obfuscated URL construction or an OS-level network firewall.
 */

const SOURCE_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx']);
const ALLOWED_CENTRAL_TRANSPORT_REL_PATH = 'src/infrastructure/gemini-resilience.ts';

interface TransportViolation {
  file: string;
  line: number;
  rule: 'GEMINI_API_HOST' | 'GEMINI_GENERATE_ENDPOINT' | 'GEMINI_SDK_IMPORT';
  excerpt: string;
}

const GUARD_RULES: ReadonlyArray<{
  rule: TransportViolation['rule'];
  pattern: RegExp;
}> = [
  {
    rule: 'GEMINI_API_HOST',
    pattern: /generativelanguage\.googleapis\.com/i,
  },
  {
    rule: 'GEMINI_GENERATE_ENDPOINT',
    pattern: /\/v1(?:beta)?\/models\/[^\s`'"]*(?:generateContent|streamGenerateContent|embedContent)/i,
  },
  {
    rule: 'GEMINI_SDK_IMPORT',
    pattern: /(?:from\s+['"]|require\(\s*['"]|import\(\s*['"])@google\/(?:genai|generative-ai)(?:\/[^'"]*)?['"]/i,
  },
];

const normalizeRelPath = (rootDir: string, fullPath: string): string =>
  relative(rootDir, fullPath).replace(/\\/g, '/');

const collectSourceFilesRecursively = (dirPath: string): string[] => {
  const results: string[] = [];
  for (const entry of readdirSync(dirPath, { withFileTypes: true })) {
    const full = join(dirPath, entry.name);
    if (entry.isDirectory()) {
      results.push(...collectSourceFilesRecursively(full));
    } else if (entry.isFile() && SOURCE_EXTENSIONS.has(extname(entry.name).toLowerCase())) {
      results.push(full);
    }
  }
  return results.sort();
};

const scanTreeForGeminiTransportDrift = (params: {
  repoRoot: string;
  srcSubdir?: string;
  allowedRelPath?: string;
}): {
  scannedFiles: string[];
  centralChokepointHasGeminiHost: boolean;
  violations: TransportViolation[];
} => {
  const srcRoot = join(params.repoRoot, params.srcSubdir ?? 'src');
  const allowedPath = (params.allowedRelPath ?? ALLOWED_CENTRAL_TRANSPORT_REL_PATH).replace(
    /\\/g,
    '/'
  );
  const fullPaths = collectSourceFilesRecursively(srcRoot);
  const scannedFiles: string[] = [];
  const violations: TransportViolation[] = [];
  let centralChokepointHasGeminiHost = false;

  for (const filePath of fullPaths) {
    const relPath = normalizeRelPath(params.repoRoot, filePath);
    scannedFiles.push(relPath);
    const content = readFileSync(filePath, 'utf8');
    const lines = content.split(/\r?\n/);

    if (relPath === allowedPath) {
      if (/generativelanguage\.googleapis\.com/i.test(content)) {
        centralChokepointHasGeminiHost = true;
      }
      continue;
    }

    lines.forEach((lineText, idx) => {
      for (const { rule, pattern } of GUARD_RULES) {
        if (pattern.test(lineText)) {
          violations.push({
            file: relPath,
            line: idx + 1,
            rule,
            excerpt: lineText.trim().slice(0, 140),
          });
        }
      }
    });
  }

  return { scannedFiles, centralChokepointHasGeminiHost, violations };
};

const formatViolations = (violations: TransportViolation[]): string =>
  violations
    .map((v) => `${v.file}:${v.line} [${v.rule}] -> ${v.excerpt}`)
    .join('\n');

const THIS_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(THIS_DIR, '..', '..');

describe('CR-2.4 Gemini Transport Chokepoint Static Drift Guard', () => {
  it('permits the central Gemini endpoint only in src/infrastructure/gemini-resilience.ts and finds zero bypasses across src/', () => {
    const result = scanTreeForGeminiTransportDrift({ repoRoot: REPO_ROOT });

    expect(result.scannedFiles.length).toBeGreaterThan(20);
    expect(result.scannedFiles).toContain(ALLOWED_CENTRAL_TRANSPORT_REL_PATH);
    expect(result.scannedFiles).toContain('src/infrastructure/distributed-rate-limiter.ts');
    expect(result.centralChokepointHasGeminiHost).toBe(true);
    expect(
      result.violations,
      `Unauthorized direct Gemini transport detected outside ${ALLOWED_CENTRAL_TRANSPORT_REL_PATH}:\n${formatViolations(result.violations)}`
    ).toEqual([]);
  });

  it('rejects a direct literal Gemini API endpoint or REST generateContent path outside the central module', () => {
    const tmpRoot = mkdtempSync(join(tmpdir(), 'aegis-gemini-guard-url-'));
    try {
      mkdirSync(join(tmpRoot, 'src', 'infrastructure'), { recursive: true });
      mkdirSync(join(tmpRoot, 'src', 'app', 'api', 'rogue'), { recursive: true });

      writeFileSync(
        join(tmpRoot, 'src', 'infrastructure', 'gemini-resilience.ts'),
        "export const GEMINI_BASE_URL = 'https://generativelanguage.googleapis.com/v1beta/models';\n",
        'utf8'
      );
      writeFileSync(
        join(tmpRoot, 'src', 'app', 'api', 'rogue', 'route.ts'),
        "const res = await fetch('https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash-lite:generateContent');\n",
        'utf8'
      );

      const result = scanTreeForGeminiTransportDrift({ repoRoot: tmpRoot });
      expect(result.centralChokepointHasGeminiHost).toBe(true);
      expect(result.violations.length).toBeGreaterThanOrEqual(1);
      expect(result.violations.some((v) => v.file === 'src/app/api/rogue/route.ts' && v.rule === 'GEMINI_API_HOST')).toBe(true);
      expect(formatViolations(result.violations)).toContain('src/app/api/rogue/route.ts:1');
    } finally {
      rmSync(tmpRoot, { recursive: true, force: true });
    }
  });

  it('rejects known Google Gemini SDK imports (@google/genai and @google/generative-ai) outside the central module', () => {
    const tmpRoot = mkdtempSync(join(tmpdir(), 'aegis-gemini-guard-sdk-'));
    try {
      mkdirSync(join(tmpRoot, 'src', 'infrastructure'), { recursive: true });
      mkdirSync(join(tmpRoot, 'src', 'application'), { recursive: true });
      mkdirSync(join(tmpRoot, 'src', 'domain'), { recursive: true });

      writeFileSync(
        join(tmpRoot, 'src', 'infrastructure', 'gemini-resilience.ts'),
        "export const GEMINI_BASE_URL = 'https://generativelanguage.googleapis.com/v1beta/models';\n",
        'utf8'
      );
      writeFileSync(
        join(tmpRoot, 'src', 'application', 'direct-genai.ts'),
        "import { GoogleGenAI } from '@google/genai';\nexport const c = GoogleGenAI;\n",
        'utf8'
      );
      writeFileSync(
        join(tmpRoot, 'src', 'domain', 'legacy-sdk.js'),
        "const sdk = require('@google/generative-ai');\nmodule.exports = sdk;\n",
        'utf8'
      );

      const result = scanTreeForGeminiTransportDrift({ repoRoot: tmpRoot });
      expect(result.violations).toHaveLength(2);
      expect(result.violations.map((v) => `${v.file}:${v.rule}`).sort()).toEqual([
        'src/application/direct-genai.ts:GEMINI_SDK_IMPORT',
        'src/domain/legacy-sdk.js:GEMINI_SDK_IMPORT',
      ]);
    } finally {
      rmSync(tmpRoot, { recursive: true, force: true });
    }
  });

  it('permits legitimate non-Gemini HTTP calls (Upstash Redis) and scans deeply nested .ts/.tsx/.js/.jsx trees while ignoring docs', () => {
    const tmpRoot = mkdtempSync(join(tmpdir(), 'aegis-gemini-guard-nested-'));
    try {
      mkdirSync(join(tmpRoot, 'src', 'infrastructure'), { recursive: true });
      mkdirSync(join(tmpRoot, 'src', 'presentation', 'deep', 'nested'), { recursive: true });

      writeFileSync(
        join(tmpRoot, 'src', 'infrastructure', 'gemini-resilience.ts'),
        "export const GEMINI_BASE_URL = 'https://generativelanguage.googleapis.com/v1beta/models';\n",
        'utf8'
      );
      writeFileSync(
        join(tmpRoot, 'src', 'infrastructure', 'upstash-client.ts'),
        "export const ping = (url: string) => fetch(`${url}/multi-exec`, { method: 'POST' });\n",
        'utf8'
      );
      writeFileSync(
        join(tmpRoot, 'src', 'presentation', 'deep', 'nested', 'notes.md'),
        'Documentation mention of generativelanguage.googleapis.com is ignored because .md is not source.\n',
        'utf8'
      );
      writeFileSync(
        join(tmpRoot, 'src', 'presentation', 'deep', 'nested', 'SneakyWidget.tsx'),
        "export const bad = () => fetch('/v1beta/models/gemini-2.5-flash:generateContent');\n",
        'utf8'
      );
      writeFileSync(
        join(tmpRoot, 'src', 'presentation', 'deep', 'nested', 'SafePanel.jsx'),
        "export const ok = () => fetch('/api/health');\n",
        'utf8'
      );

      const result = scanTreeForGeminiTransportDrift({ repoRoot: tmpRoot });
      expect(result.scannedFiles).toContain('src/infrastructure/upstash-client.ts');
      expect(result.scannedFiles).toContain('src/presentation/deep/nested/SneakyWidget.tsx');
      expect(result.scannedFiles).toContain('src/presentation/deep/nested/SafePanel.jsx');
      expect(result.scannedFiles).not.toContain('src/presentation/deep/nested/notes.md');
      expect(result.violations).toHaveLength(1);
      expect(result.violations[0]).toMatchObject({
        file: 'src/presentation/deep/nested/SneakyWidget.tsx',
        line: 1,
        rule: 'GEMINI_GENERATE_ENDPOINT',
      });
    } finally {
      rmSync(tmpRoot, { recursive: true, force: true });
    }
  });
});
