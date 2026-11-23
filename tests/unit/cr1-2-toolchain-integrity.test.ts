import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { DEFAULT_MAX_JSON_BODY_BYTES } from '@/domain/api-schemas';
import vitestConfig from '../../vitest.config';

const ROOT_DIR = path.resolve(__dirname, '../..');

describe('CR-1.2 — Upgraded Vitest 4.1.12 Runner & Toolchain Security Integrity', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('preserves vitest.config.ts invariants (node env, globals: false, e2e exclusion, @ alias)', () => {
    const testCfg = vitestConfig.test;
    expect(testCfg?.environment).toBe('node');
    expect(testCfg?.globals).toBe(false);
    expect(testCfg?.include).toContain('tests/**/*.test.ts');
    expect(testCfg?.exclude).toContain('tests/e2e/**');

    // Verify globals: false is actively enforced at runtime under Vitest 4
    expect('describe' in globalThis).toBe(false);
    expect('expect' in globalThis).toBe(false);

    // Verify '@' path alias resolves to src/
    const alias = vitestConfig.resolve?.alias as Record<string, string> | undefined;
    expect(alias?.['@']).toBe(path.resolve(ROOT_DIR, 'src'));
    expect(DEFAULT_MAX_JSON_BODY_BYTES).toBe(512 * 1024);
  });

  it('preserves strict vi.spyOn and vi.restoreAllMocks() isolation under Vitest 4', async () => {
    const target = {
      compute: (x: number) => x * 2,
    };
    const spy = vi.spyOn(target, 'compute').mockReturnValue(999);
    expect(target.compute(5)).toBe(999);
    expect(spy).toHaveBeenCalledTimes(1);

    vi.restoreAllMocks();
    expect(target.compute(5)).toBe(10);

    const originalFetch = globalThis.fetch;
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(new Response(JSON.stringify({ ok: true }), { status: 200 }));
    const res = await globalThis.fetch('http://localhost/cr12-check');
    expect(res.status).toBe(200);
    expect(fetchSpy).toHaveBeenCalledTimes(1);

    vi.restoreAllMocks();
    expect(globalThis.fetch).toBe(originalFetch);
  });

  it('confirms remediated Vitest 4.1.12 toolchain removes tinypool and aligns with Node 24 LTS across package.json and CI', () => {
    const rootPkgPath = path.join(ROOT_DIR, 'package.json');
    const ciWorkflowPath = path.join(ROOT_DIR, '.github', 'workflows', 'ci.yml');
    const vitestPkgPath = path.join(ROOT_DIR, 'node_modules', 'vitest', 'package.json');
    const mockerPkgPath = path.join(ROOT_DIR, 'node_modules', '@vitest', 'mocker', 'package.json');
    const tinypoolDir = path.join(ROOT_DIR, 'node_modules', 'tinypool');

    const rootPkg = JSON.parse(readFileSync(rootPkgPath, 'utf8')) as {
      engines?: { node?: string };
    };
    const ciYaml = readFileSync(ciWorkflowPath, 'utf8');
    const vitestPkg = JSON.parse(readFileSync(vitestPkgPath, 'utf8')) as {
      version: string;
      dependencies?: Record<string, string>;
      engines?: { node?: string };
    };
    const mockerPkg = JSON.parse(readFileSync(mockerPkgPath, 'utf8')) as {
      version: string;
    };

    const parseSemver = (v: string) => v.split('.').map((n) => Number.parseInt(n, 10));
    const [vMaj, vMin, vPatch] = parseSemver(vitestPkg.version);
    const [mMaj, mMin, mPatch] = parseSemver(mockerPkg.version);

    // Must be >= 4.1.12 to resolve GHSA-82fw-gwwq-j7x9 and GHSA-qxg6-89mg-rqv8
    expect(
      (vMaj ?? 0) > 4 ||
        ((vMaj ?? 0) === 4 && ((vMin ?? 0) > 1 || ((vMin ?? 0) === 1 && (vPatch ?? 0) >= 12)))
    ).toBe(true);
    expect(
      (mMaj ?? 0) > 4 ||
        ((mMaj ?? 0) === 4 && ((mMin ?? 0) > 1 || ((mMin ?? 0) === 1 && (mPatch ?? 0) >= 12)))
    ).toBe(true);

    // tinypool must no longer be depended on or installed
    expect(vitestPkg.dependencies?.tinypool).toBeUndefined();
    expect(existsSync(tinypoolDir)).toBe(false);

    // Node 24 LTS alignment across package.json, CI workflow, and Vitest engine declaration
    expect(rootPkg.engines?.node).toBe('>=24.0.0 <25.0.0');
    expect(ciYaml).toContain("node-version: '24'");
    expect(ciYaml).not.toContain("node-version: '20'");
    expect(vitestPkg.engines?.node ?? '').toContain('24');
  });
});
