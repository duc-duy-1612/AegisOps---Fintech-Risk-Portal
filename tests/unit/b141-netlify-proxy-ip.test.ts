import { afterEach, describe, expect, it } from 'vitest';
import { NextRequest } from 'next/server';
import { GET as healthGet } from '@/app/api/health/route';
import {
  isNetlifyRuntime,
  resetRateBucketsForTest,
  resolveTrustedClientIp,
} from '@/infrastructure/security-guard';

const ORIGINAL_ENV = { ...process.env };

const restoreEnv = () => {
  for (const key of Object.keys(process.env)) {
    if (!(key in ORIGINAL_ENV)) {
      delete process.env[key];
    }
  }
  for (const [key, val] of Object.entries(ORIGINAL_ENV)) {
    if (val === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = val;
    }
  }
};

const clearPlatformEnv = () => {
  delete process.env.VERCEL;
  delete process.env.NETLIFY;
  delete process.env.SITE_ID;
  delete process.env.SITE_NAME;
  delete process.env.URL;
  delete process.env.TRUST_PROXY_HEADERS;
};

const setNetlifyRuntimeEnv = () => {
  clearPlatformEnv();
  process.env.SITE_ID = '8f20b6ac-f135-4e31-9208-07b899a96dc8';
  process.env.SITE_NAME = 'aegisops-momo-contest-2026';
  process.env.URL = 'https://aegisops-momo-contest-2026.netlify.app';
};

afterEach(() => {
  restoreEnv();
  resetRateBucketsForTest();
});

describe('Wave B1.4.1 — B111-PROXY-01 Netlify Trusted Client IP Hardening', () => {
  describe('Netlify Functions runtime detection (SITE_ID + SITE_NAME + URL)', () => {
    it('detects Netlify runtime ONLY when all three documented runtime variables are present and non-empty', () => {
      clearPlatformEnv();
      expect(isNetlifyRuntime()).toBe(false);

      // Build-time NETLIFY=true alone does NOT establish Functions runtime identity
      process.env.NETLIFY = 'true';
      expect(isNetlifyRuntime()).toBe(false);

      // Incomplete combinations must return false
      clearPlatformEnv();
      process.env.SITE_ID = '8f20b6ac-f135-4e31-9208-07b899a96dc8';
      expect(isNetlifyRuntime()).toBe(false);

      process.env.URL = 'https://aegisops-momo-contest-2026.netlify.app';
      expect(isNetlifyRuntime()).toBe(false);

      delete process.env.URL;
      process.env.SITE_NAME = 'aegisops-momo-contest-2026';
      expect(isNetlifyRuntime()).toBe(false);

      delete process.env.SITE_ID;
      process.env.URL = 'https://aegisops-momo-contest-2026.netlify.app';
      expect(isNetlifyRuntime()).toBe(false);

      // Empty or whitespace-only values must return false
      process.env.SITE_ID = '   ';
      expect(isNetlifyRuntime()).toBe(false);

      process.env.SITE_ID = '8f20b6ac-f135-4e31-9208-07b899a96dc8';
      process.env.SITE_NAME = '';
      expect(isNetlifyRuntime()).toBe(false);

      process.env.SITE_NAME = 'aegisops-momo-contest-2026';
      process.env.URL = '   ';
      expect(isNetlifyRuntime()).toBe(false);

      // All three present and non-empty -> true
      setNetlifyRuntimeEnv();
      expect(isNetlifyRuntime()).toBe(true);
    });
  });

  describe('Strict node:net isIP validation and IPv6 lowercase normalization', () => {
    it('accepts valid IPv4 and normalizes mixed-case IPv6 addresses to identical lowercase keys', () => {
      setNetlifyRuntimeEnv();
      process.env.TRUST_PROXY_HEADERS = 'true';

      const ipv4Req = new NextRequest('https://aegisops-momo-contest-2026.netlify.app/api/health', {
        headers: {
          'x-nf-client-connection-ip': '  203.0.113.42  ',
          'x-real-ip': '198.51.100.77',
          'x-forwarded-for': '198.51.100.99, 203.0.113.42',
        },
      });
      expect(resolveTrustedClientIp(ipv4Req)).toBe('203.0.113.42');

      const upperIpv6Req = new NextRequest('https://aegisops-momo-contest-2026.netlify.app/api/health', {
        headers: {
          'x-nf-client-connection-ip': '2001:DB8::42',
          'x-real-ip': '198.51.100.77',
        },
      });
      const lowerIpv6Req = new NextRequest('https://aegisops-momo-contest-2026.netlify.app/api/health', {
        headers: {
          'x-nf-client-connection-ip': '2001:db8::42',
          'x-real-ip': '198.51.100.77',
        },
      });

      expect(resolveTrustedClientIp(upperIpv6Req)).toBe('2001:db8::42');
      expect(resolveTrustedClientIp(lowerIpv6Req)).toBe('2001:db8::42');
      expect(resolveTrustedClientIp(upperIpv6Req)).toBe(resolveTrustedClientIp(lowerIpv6Req));
    });

    it('rejects syntactically invalid IPs, hostnames, ports, and multi-IP values without throwing or falling back to x-real-ip', () => {
      setNetlifyRuntimeEnv();
      process.env.TRUST_PROXY_HEADERS = 'true';

      const invalidValues = [
        '999.999.999.999',
        ':::',
        'not-an-ip',
        '203.0.113.1, 198.51.100.77',
        'evil.example.com',
        '203.0.113.1:8080',
        '203.0.113.1 extra',
        '....',
        ':.:.:',
        '',
        '   ',
      ];

      for (const badValue of invalidValues) {
        const req = new NextRequest('https://aegisops-momo-contest-2026.netlify.app/api/health', {
          headers: {
            'x-nf-client-connection-ip': badValue,
            'x-real-ip': '198.51.100.77',
            'x-forwarded-for': '198.51.100.88',
          },
        });
        expect(resolveTrustedClientIp(req)).toBe('direct-unproxied-client');
      }
    });

    it('NEVER falls back to spoofable x-real-ip on Netlify when x-nf-client-connection-ip is absent', () => {
      setNetlifyRuntimeEnv();
      process.env.TRUST_PROXY_HEADERS = 'true';

      const missingHeaderReq = new NextRequest('https://aegisops-momo-contest-2026.netlify.app/api/health', {
        headers: {
          'x-real-ip': '198.51.100.77',
          'x-forwarded-for': '198.51.100.99',
        },
      });
      expect(resolveTrustedClientIp(missingHeaderReq)).toBe('direct-unproxied-client');
    });

    it('trusts x-nf-client-connection-ip on Netlify when TRUST_PROXY_HEADERS is unset', () => {
      setNetlifyRuntimeEnv();

      const req = new NextRequest('https://aegisops-momo-contest-2026.netlify.app/api/health', {
        headers: {
          'x-nf-client-connection-ip': '203.0.113.55',
          'x-real-ip': '198.51.100.77',
        },
      });
      expect(resolveTrustedClientIp(req)).toBe('203.0.113.55');
    });
  });

  describe('Explicit fail-closed override (TRUST_PROXY_HEADERS=false)', () => {
    it('ignores ALL proxy-supplied headers on Netlify when TRUST_PROXY_HEADERS is explicitly false (case/whitespace normalized)', () => {
      setNetlifyRuntimeEnv();

      for (const disabledValue of ['false', 'FALSE', '  False  ']) {
        process.env.TRUST_PROXY_HEADERS = disabledValue;
        const req = new NextRequest('https://aegisops-momo-contest-2026.netlify.app/api/health', {
          headers: {
            'x-nf-client-connection-ip': '203.0.113.42',
            'x-vercel-forwarded-for': '203.0.113.42',
            'x-real-ip': '198.51.100.77',
            'x-forwarded-for': '198.51.100.77',
          },
        });
        expect(resolveTrustedClientIp(req)).toBe('direct-unproxied-client');
      }
    });

    it('ignores ALL proxy-supplied headers on Vercel and generic proxies when TRUST_PROXY_HEADERS=false', () => {
      clearPlatformEnv();
      process.env.VERCEL = '1';
      process.env.TRUST_PROXY_HEADERS = 'false';

      const vercelReq = new NextRequest('https://example.vercel.app/api/health', {
        headers: {
          'x-vercel-forwarded-for': '203.0.113.42, 10.0.0.1',
          'x-real-ip': '198.51.100.77',
          'x-forwarded-for': '198.51.100.77',
        },
      });
      expect(resolveTrustedClientIp(vercelReq)).toBe('direct-unproxied-client');

      clearPlatformEnv();
      process.env.TRUST_PROXY_HEADERS = ' false ';
      const genericReq = new NextRequest('http://localhost:3000/api/health', {
        headers: {
          'x-nf-client-connection-ip': '203.0.113.42',
          'x-real-ip': '198.51.100.77',
          'x-forwarded-for': '198.51.100.77',
        },
      });
      expect(resolveTrustedClientIp(genericReq)).toBe('direct-unproxied-client');
    });
  });

  describe('Off-Netlify isolation, Vercel, and generic reverse-proxy regression checks', () => {
    it('ignores spoofed x-nf-client-connection-ip outside Netlify runtime and preserves Vercel / generic proxy behavior', () => {
      clearPlatformEnv();

      const directReq = new NextRequest('http://localhost:3000/api/health', {
        headers: {
          'x-nf-client-connection-ip': '203.0.113.99',
          'x-real-ip': '198.51.100.77',
          'x-forwarded-for': '198.51.100.88',
        },
      });
      expect(resolveTrustedClientIp(directReq)).toBe('direct-unproxied-client');

      // Build-time NETLIFY=true alone without runtime vars must also NOT trust x-nf-client-connection-ip
      process.env.NETLIFY = 'true';
      expect(resolveTrustedClientIp(directReq)).toBe('direct-unproxied-client');
      delete process.env.NETLIFY;

      // Generic trusted reverse proxy (non-Netlify) still honors valid x-real-ip
      process.env.TRUST_PROXY_HEADERS = 'true';
      expect(resolveTrustedClientIp(directReq)).toBe('198.51.100.77');

      // Generic trusted proxy rejects invalid x-real-ip syntax
      const badGenericReq = new NextRequest('http://localhost:3000/api/health', {
        headers: { 'x-real-ip': '999.999.999.999' },
      });
      expect(resolveTrustedClientIp(badGenericReq)).toBe('direct-unproxied-client');

      // Vercel platform still honors valid x-vercel-forwarded-for (and normalizes IPv6)
      delete process.env.TRUST_PROXY_HEADERS;
      process.env.VERCEL = '1';
      const vercelReq = new NextRequest('https://example.vercel.app/api/health', {
        headers: {
          'x-vercel-forwarded-for': '203.0.113.88, 10.0.0.1',
          'x-real-ip': '198.51.100.77',
        },
      });
      expect(resolveTrustedClientIp(vercelReq)).toBe('203.0.113.88');

      const vercelIpv6Req = new NextRequest('https://example.vercel.app/api/health', {
        headers: {
          'x-vercel-forwarded-for': '2001:DB8::88, 10.0.0.1',
          'x-real-ip': '198.51.100.77',
        },
      });
      expect(resolveTrustedClientIp(vercelIpv6Req)).toBe('2001:db8::88');
    });
  });

  describe('End-to-end 17-request anti-bypass rate-limit verification on Netlify runtime', () => {
    it('blocks 17th /api/health?diagnostics=internal request with 429 even when attacker injects spoofed x-real-ip or varies IPv6 case', async () => {
      setNetlifyRuntimeEnv();
      delete process.env.UPSTASH_REDIS_REST_URL;
      delete process.env.UPSTASH_REDIS_REST_TOKEN;
      delete process.env.AEGIS_REQUIRE_DISTRIBUTED_RATE_LIMIT;
      delete process.env.AEGIS_PRODUCTION_STRICT_READINESS;
      process.env.TRUST_PROXY_HEADERS = 'true';

      // Requests 1..15 hit 403 (unauthorized diagnostics) and consume the 15/min IP quota for 203.0.113.10
      for (let i = 1; i <= 15; i += 1) {
        const res = await healthGet(
          new NextRequest('https://aegisops-momo-contest-2026.netlify.app/api/health?diagnostics=internal', {
            headers: { 'x-nf-client-connection-ip': '203.0.113.10' },
          })
        );
        expect(res.status).toBe(403);
      }

      // Request 16 hits 429 DIAGNOSTICS_RATE_LIMIT_EXCEEDED
      const res16 = await healthGet(
        new NextRequest('https://aegisops-momo-contest-2026.netlify.app/api/health?diagnostics=internal', {
          headers: { 'x-nf-client-connection-ip': '203.0.113.10' },
        })
      );
      expect(res16.status).toBe(429);
      expect((await res16.json()).code).toBe('DIAGNOSTICS_RATE_LIMIT_EXCEEDED');

      // Request 17 injects spoofed x-real-ip while keeping the same Netlify edge IP -> MUST STILL return 429!
      const res17 = await healthGet(
        new NextRequest('https://aegisops-momo-contest-2026.netlify.app/api/health?diagnostics=internal', {
          headers: {
            'x-nf-client-connection-ip': '203.0.113.10',
            'x-real-ip': '198.51.100.77',
            'x-forwarded-for': '198.51.100.99',
          },
        })
      );
      expect(res17.status).toBe(429);
      expect((await res17.json()).code).toBe('DIAGNOSTICS_RATE_LIMIT_EXCEEDED');

      // IPv6 case-normalization consistency across rate-limit buckets (15 uppercase -> 16th lowercase hits 429)
      for (let i = 1; i <= 15; i += 1) {
        const res = await healthGet(
          new NextRequest('https://aegisops-momo-contest-2026.netlify.app/api/health?diagnostics=internal', {
            headers: { 'x-nf-client-connection-ip': '2001:DB8::42' },
          })
        );
        expect(res.status).toBe(403);
      }
      const ipv6Res16 = await healthGet(
        new NextRequest('https://aegisops-momo-contest-2026.netlify.app/api/health?diagnostics=internal', {
          headers: { 'x-nf-client-connection-ip': '2001:db8::42' },
        })
      );
      expect(ipv6Res16.status).toBe(429);
      expect((await ipv6Res16.json()).code).toBe('DIAGNOSTICS_RATE_LIMIT_EXCEEDED');
    });
  });
});
