import { Router, Request, Response } from "express";
import dns from "dns/promises";

const router = Router();

// ─── Constants ────────────────────────────────────────────────────────────────

const VALID_DOMAIN_RE = /^[a-zA-Z0-9][a-zA-Z0-9\-.]{1,251}[a-zA-Z0-9]$/;

// Private/internal IP ranges (IPv4 + IPv6) — block to prevent SSRF
const PRIVATE_IPV4_RE = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.0\.0\.0|169\.254\.)/;
const PRIVATE_IPV6_RE = /^(::1|fc00:|fd00:|fe80:)/i;

// Port allowlist — prevents using this API for port scanning of arbitrary services.
// "" (empty) means default port for scheme (80 for http, 443 for https).
const ALLOWED_PORTS = new Set(["", "80", "443", "8080", "8443"]);

const FETCH_TIMEOUT_MS = 8000;
const MAX_REDIRECTS    = 3;

// ─── Cache (4 hour TTL) ───────────────────────────────────────────────────────

interface CacheEntry {
  data:      Record<string, unknown>;
  expiresAt: number;
}
const cache = new Map<string, CacheEntry>();

function getCached(key: string): Record<string, unknown> | null {
  const entry = cache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) { cache.delete(key); return null; }
  return entry.data;
}

function setCached(key: string, data: Record<string, unknown>): void {
  cache.set(key, { data, expiresAt: Date.now() + 4 * 60 * 60 * 1000 });
  if (cache.size > 1000) {
    const firstKey = cache.keys().next().value;
    if (firstKey) cache.delete(firstKey);
  }
}

// ─── URL parsing & SSRF protection ────────────────────────────────────────────

interface ParsedUrl {
  url:      URL;
  hostname: string;
}

function parseAndValidateUrl(input: string): ParsedUrl | { error: string } {
  let url: URL;
  try {
    const withProto = input.match(/^https?:\/\//i) ? input : `https://${input}`;
    url = new URL(withProto);
  } catch {
    return { error: "Could not parse URL" };
  }

  // Only http/https — block file://, ftp://, javascript:, data:, gopher:, etc.
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { error: "Only http:// and https:// URLs are supported" };
  }

  // Port allowlist — block port scanning attempts
  if (!ALLOWED_PORTS.has(url.port)) {
    return { error: `Port ${url.port} not permitted (allowed: 80, 443, 8080, 8443)` };
  }

  const hostname = url.hostname.toLowerCase();

  if (!hostname) return { error: "Missing hostname" };
  if (hostname === "localhost") return { error: "Localhost not permitted" };

  // Block raw private/internal IPs at parse time (defense in depth — DNS check happens too)
  if (PRIVATE_IPV4_RE.test(hostname) || PRIVATE_IPV6_RE.test(hostname)) {
    return { error: "Private/internal addresses not permitted" };
  }

  // Hostname allowlist for domain names (IPs handled above)
  const isIp = /^[\d.]+$/.test(hostname) || hostname.includes(":");
  if (!isIp && !VALID_DOMAIN_RE.test(hostname)) {
    return { error: "Invalid hostname" };
  }

  return { url, hostname };
}

// Resolve hostname and ensure it doesn't point at private IPs.
// Catches DNS-rebinding-style hostnames that resolve to internal addresses.
//
// NOTE: This is a TOCTOU-vulnerable check — between this resolution and the
// fetch's own resolution, DNS records can change. Acceptable risk in Railway's
// network model where private IPs aren't reachable from app containers.
async function isHostnameSafe(hostname: string): Promise<boolean> {
  // Skip DNS check if already a public IP literal
  if (/^[\d.]+$/.test(hostname) || hostname.includes(":")) {
    return !PRIVATE_IPV4_RE.test(hostname) && !PRIVATE_IPV6_RE.test(hostname);
  }
  try {
    const addresses = await Promise.race([
      dns.resolve(hostname),
      new Promise<string[]>((_, reject) =>
        setTimeout(() => reject(new Error("DNS timeout")), 3000)
      ),
    ]);
    for (const addr of addresses) {
      if (PRIVATE_IPV4_RE.test(addr) || PRIVATE_IPV6_RE.test(addr)) return false;
    }
    return addresses.length > 0;
  } catch {
    return false;
  }
}

// ─── Fetch with redirect handling & SSRF re-check on each hop ─────────────────

interface FetchResult {
  finalUrl:  string;
  status:    number;
  headers:   Record<string, string>;
  redirects: number;
}

async function safeFetch(initialUrl: URL): Promise<FetchResult> {
  let currentUrl = initialUrl;
  let redirects  = 0;

  while (redirects <= MAX_REDIRECTS) {
    // Re-verify each redirect target — prevents redirect-to-internal attacks
    const safe = await isHostnameSafe(currentUrl.hostname);
    if (!safe) {
      throw new Error(`Refused: hostname ${currentUrl.hostname} resolves to a private address`);
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

    try {
      const response = await fetch(currentUrl.toString(), {
        method:   "GET",
        redirect: "manual",                            // we handle redirects ourselves
        signal:   controller.signal,
        headers: {
          "User-Agent":      "TrustSource-HeaderCheck/1.0 (+https://trustsource.cc)",
          "Accept":          "*/*",
          "Accept-Encoding": "identity",  // disable compression — prevents decompression-bomb DoS
        },
      });
      clearTimeout(timer);

      // Collect headers (lowercased keys for consistency)
      const headers: Record<string, string> = {};
      response.headers.forEach((value, key) => { headers[key.toLowerCase()] = value; });

      // Handle redirect
      if (response.status >= 300 && response.status < 400 && headers["location"]) {
        try {
          currentUrl = new URL(headers["location"], currentUrl);
        } catch {
          throw new Error("Invalid redirect Location header");
        }

        // Re-validate scheme + port on each redirect — Location header could be hostile
        if (currentUrl.protocol !== "http:" && currentUrl.protocol !== "https:") {
          throw new Error(`Refused redirect to ${currentUrl.protocol} scheme`);
        }
        if (!ALLOWED_PORTS.has(currentUrl.port)) {
          throw new Error(`Refused redirect to port ${currentUrl.port}`);
        }

        redirects++;

        // Discard response body to avoid memory accumulation
        try { await response.body?.cancel(); } catch { /* ignore */ }
        continue;
      }

      // Final response — discard body, we only care about headers
      try { await response.body?.cancel(); } catch { /* ignore */ }

      return {
        finalUrl: currentUrl.toString(),
        status:   response.status,
        headers,
        redirects,
      };
    } catch (err) {
      clearTimeout(timer);
      throw err;
    }
  }
  throw new Error(`Too many redirects (max ${MAX_REDIRECTS})`);
}

// ─── Header analysis ──────────────────────────────────────────────────────────

interface HeaderAnalysis {
  present:  boolean;
  value:    string | null;
  score:    number;
  maxScore: number;
  notes:    string[];
}

function analyzeHsts(value: string | undefined): HeaderAnalysis {
  if (!value) {
    return { present: false, value: null, score: 0, maxScore: 20, notes: ["missing"] };
  }
  const notes: string[] = [];
  let score = 8;  // base for presence

  const maxAgeMatch = value.match(/max-age=(\d+)/i);
  const maxAge      = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
  if (maxAge >= 31536000)      { score += 7; }                                // ≥ 1 year
  else if (maxAge >= 15768000) { score += 4; notes.push("max_age_short"); }   // ≥ 6 months
  else                         { notes.push("max_age_too_short"); }

  if (/includeSubDomains/i.test(value)) score += 3;
  else                                  notes.push("missing_includeSubDomains");

  if (/preload/i.test(value)) score += 2;

  return { present: true, value, score: Math.min(score, 20), maxScore: 20, notes };
}

function analyzeCsp(value: string | undefined): HeaderAnalysis {
  if (!value) {
    return { present: false, value: null, score: 0, maxScore: 20, notes: ["missing"] };
  }
  const notes: string[] = [];
  let score = 10; // base for presence

  // Penalize known weak directives
  if (/unsafe-inline/i.test(value)) { score -= 4; notes.push("uses_unsafe_inline"); }
  if (/unsafe-eval/i.test(value))   { score -= 4; notes.push("uses_unsafe_eval"); }
  if (/\*/.test(value) && !/strict-dynamic/i.test(value)) {
    notes.push("wildcard_source");
  } else {
    score += 5;
  }

  // Reward strong directives
  if (/default-src/i.test(value))                      score += 3;
  if (/frame-ancestors\s+(none|'self')/i.test(value))  score += 2;

  return {
    present:  true,
    value:    value.length > 200 ? value.slice(0, 200) + "…" : value,
    score:    Math.max(0, Math.min(score, 20)),
    maxScore: 20,
    notes,
  };
}

function analyzeXFrameOptions(value: string | undefined): HeaderAnalysis {
  if (!value) {
    return { present: false, value: null, score: 0, maxScore: 10, notes: ["missing"] };
  }
  const v = value.toUpperCase();
  if (v === "DENY")       return { present: true, value, score: 10, maxScore: 10, notes: [] };
  if (v === "SAMEORIGIN") return { present: true, value, score: 8,  maxScore: 10, notes: [] };
  return { present: true, value, score: 3, maxScore: 10, notes: ["weak_value"] };
}

function analyzeXContentTypeOptions(value: string | undefined): HeaderAnalysis {
  if (!value) {
    return { present: false, value: null, score: 0, maxScore: 10, notes: ["missing"] };
  }
  if (value.toLowerCase() === "nosniff") {
    return { present: true, value, score: 10, maxScore: 10, notes: [] };
  }
  return { present: true, value, score: 3, maxScore: 10, notes: ["weak_value"] };
}

function analyzeReferrerPolicy(value: string | undefined): HeaderAnalysis {
  if (!value) {
    return { present: false, value: null, score: 0, maxScore: 10, notes: ["missing"] };
  }
  const safe = ["no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"];
  const v = value.toLowerCase();
  if (safe.some(s => v.includes(s))) {
    return { present: true, value, score: 10, maxScore: 10, notes: [] };
  }
  if (v.includes("unsafe-url")) {
    return { present: true, value, score: 0, maxScore: 10, notes: ["unsafe_policy"] };
  }
  return { present: true, value, score: 5, maxScore: 10, notes: [] };
}

function analyzePermissionsPolicy(value: string | undefined): HeaderAnalysis {
  if (!value) {
    return { present: false, value: null, score: 0, maxScore: 10, notes: ["missing"] };
  }
  return {
    present:  true,
    value:    value.length > 150 ? value.slice(0, 150) + "…" : value,
    score:    10,
    maxScore: 10,
    notes:    [],
  };
}

function analyzeCoop(value: string | undefined): HeaderAnalysis {
  if (!value) {
    return { present: false, value: null, score: 0, maxScore: 10, notes: ["missing"] };
  }
  const v = value.toLowerCase();
  if (v === "same-origin")              return { present: true, value, score: 10, maxScore: 10, notes: [] };
  if (v === "same-origin-allow-popups") return { present: true, value, score: 7,  maxScore: 10, notes: [] };
  return { present: true, value, score: 3, maxScore: 10, notes: ["weak_value"] };
}

function analyzeServerDisclosure(headers: Record<string, string>): HeaderAnalysis {
  const server   = headers["server"];
  const xPowered = headers["x-powered-by"];
  const notes: string[] = [];
  let score = 10;

  // Version disclosure penalty — "nginx/1.18.0" leaks version, "nginx" alone is fine
  if (server && /\d+\.\d+/.test(server)) {
    score -= 5;
    notes.push("server_version_disclosed");
  } else if (server) {
    score -= 2;
    notes.push("server_disclosed");
  }

  if (xPowered) {
    score -= 5;
    notes.push("x_powered_by_disclosed");
  }

  return {
    present:  !!(server || xPowered),
    value:    server || xPowered || null,
    score:    Math.max(0, score),
    maxScore: 10,
    notes,
  };
}

// ─── Grade & tier ─────────────────────────────────────────────────────────────

function scoreToGrade(score: number): string {
  if (score >= 90) return "A+";
  if (score >= 80) return "A";
  if (score >= 70) return "B";
  if (score >= 50) return "C";
  if (score >= 30) return "D";
  return "F";
}

// ─── Main route ───────────────────────────────────────────────────────────────

router.get("/headers", async (req: Request, res: Response) => {
  const raw = (req.query.url as string) || (req.query.domain as string);

  if (!raw) {
    res.status(400).json({
      error:   "Missing parameter",
      message: "Provide ?url=https://example.com or ?domain=example.com",
    });
    return;
  }
  if (raw.length > 2048) {
    res.status(400).json({
      error:   "Invalid input",
      message: "URL must be 2048 characters or fewer",
    });
    return;
  }

  const parsed = parseAndValidateUrl(raw);
  if ("error" in parsed) {
    res.status(400).json({ error: "Invalid URL", message: parsed.error });
    return;
  }

  // Cache key uses normalized URL (origin + path)
  const cacheKey = parsed.url.origin + parsed.url.pathname;
  const cached   = getCached(cacheKey);
  if (cached) {
    res.json({ ...cached, meta: { ...(cached.meta as object), cached: true } });
    return;
  }

  try {
    const fetchResult = await safeFetch(parsed.url);
    const h = fetchResult.headers;

    const analysis = {
      hsts:                analyzeHsts(h["strict-transport-security"]),
      csp:                 analyzeCsp(h["content-security-policy"]),
      xFrameOptions:       analyzeXFrameOptions(h["x-frame-options"]),
      xContentTypeOptions: analyzeXContentTypeOptions(h["x-content-type-options"]),
      referrerPolicy:      analyzeReferrerPolicy(h["referrer-policy"]),
      permissionsPolicy:   analyzePermissionsPolicy(h["permissions-policy"]),
      coop:                analyzeCoop(h["cross-origin-opener-policy"]),
      serverDisclosure:    analyzeServerDisclosure(h),
    };

    const total    = Object.values(analysis).reduce((sum, a) => sum + a.score, 0);
    const maxTotal = Object.values(analysis).reduce((sum, a) => sum + a.maxScore, 0);
    const grade    = scoreToGrade(total);

    // Build warnings — flatten all "notes" arrays except plain "missing"
    const warnings: string[] = [];
    for (const [name, a] of Object.entries(analysis)) {
      if (!a.present) warnings.push(`missing_${name}`);
      else for (const n of a.notes) if (n !== "missing") warnings.push(`${name}:${n}`);
    }

    const response = {
      url:      fetchResult.finalUrl,
      hostname: parsed.hostname,
      grade,
      score:    total,
      maxScore: maxTotal,
      analysis,
      warnings,
      response: {
        status:    fetchResult.status,
        redirects: fetchResult.redirects,
      },
      meta: {
        checkedAt:  new Date().toISOString(),
        apiVersion: "1.0",
        paidWith:   "x402/USDC",
        cached:     false,
      },
    };

    setCached(cacheKey, response);
    res.json(response);

  } catch (err) {
    const msg = err instanceof Error ? err.message : "Unknown error";
    res.status(502).json({
      error:    "Header check failed",
      url:      parsed.url.toString(),
      message:  msg,
      meta: { checkedAt: new Date().toISOString(), apiVersion: "1.0" },
    });
  }
});

export default router;
