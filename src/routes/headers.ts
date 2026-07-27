import { Router, Request, Response } from "express";
import net from "net";
import {
  VALID_DOMAIN_RE,
  assertUrlSchemeAndPort,
  isPrivateIp,
  normalizeHostname,
  BlockedHostError,
} from "../lib/net-guard.js";
import { guardedFetch } from "../lib/fetch-guard.js";

const router = Router();

// ─── Constants ────────────────────────────────────────────────────────────────

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

  // Only http/https, on an allowed port — blocks file://, gopher://, port scans.
  try {
    assertUrlSchemeAndPort(url);
  } catch (e) {
    return { error: e instanceof Error ? e.message : "URL not permitted" };
  }

  // normalizeHostname strips surrounding IPv6 brackets so "[::1]" is classified
  // as "::1" — the old regex tested "[::1]" verbatim and never matched, letting
  // IPv6 loopback/ULA/link-local literals through (an SSRF hole).
  const hostname = normalizeHostname(url.hostname);

  if (!hostname) return { error: "Missing hostname" };
  if (hostname === "localhost") return { error: "Localhost not permitted" };

  // Block raw private/internal IP literals at parse time (defense in depth —
  // safeFetch also resolves the name and re-checks the resulting addresses).
  if (isPrivateIp(hostname)) {
    return { error: "Private/internal addresses not permitted" };
  }

  // Hostname allowlist for domain names (IP literals handled above)
  const isIp = net.isIP(hostname) !== 0;
  if (!isIp && !VALID_DOMAIN_RE.test(hostname)) {
    return { error: "Invalid hostname" };
  }

  return { url, hostname };
}

// ─── Fetch with redirect handling & SSRF re-check on each hop ─────────────────

interface FetchResult {
  finalUrl:  string;
  status:    number;
  headers:   Record<string, string>;
  redirects: number;
}

// Headers-only fetch. The SSRF-hardened redirect loop lives in lib/fetch-guard
// so /headers, /robots and /safefetch all share one implementation — the audit
// lesson was that duplicated guard logic drifts apart.
async function safeFetch(initialUrl: URL): Promise<FetchResult> {
  const r = await guardedFetch(initialUrl, {
    timeoutMs:    FETCH_TIMEOUT_MS,
    maxRedirects: MAX_REDIRECTS,
    maxBytes:     0,               // headers only — never buffer the body
    userAgent:    "TrustSource-HeaderCheck/1.0 (+https://trustsource.cc)",
    accept:       "*/*",
  });
  return {
    finalUrl:  r.finalUrl,
    status:    r.status,
    headers:   r.headers,
    redirects: r.redirects,
  };
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

export function analyzeCsp(value: string | undefined): HeaderAnalysis {
  if (!value) {
    return { present: false, value: null, score: 0, maxScore: 20, notes: ["missing"] };
  }
  const notes: string[] = [];
  let score = 10; // base for presence

  // Penalize known weak directives
  if (/unsafe-inline/i.test(value)) { score -= 4; notes.push("uses_unsafe_inline"); }
  if (/unsafe-eval/i.test(value))   { score -= 4; notes.push("uses_unsafe_eval"); }

  // A wildcard is only weak when it is a *source token* in a sensitive fetch
  // directive (e.g. "default-src *"). The old /\*/ test flagged any asterisk
  // anywhere — including a scoped "*.cdn.example.com" host or a report-uri —
  // and wrongly withheld the bonus from legitimate CSPs.
  const SENSITIVE_DIRECTIVES = new Set([
    "default-src", "script-src", "script-src-elem", "object-src", "base-uri",
  ]);
  let wildcardSource = false;
  for (const directive of value.split(";")) {
    const tokens = directive.trim().split(/\s+/);
    const name   = (tokens.shift() || "").toLowerCase();
    if (SENSITIVE_DIRECTIVES.has(name) &&
        tokens.some(t => t === "*" || t === "http:" || t === "https:")) {
      wildcardSource = true;
      break;
    }
  }
  if (wildcardSource && !/strict-dynamic/i.test(value)) {
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
    // Blocked-host detail (which internal IP a name resolved to) must not reach
    // the client — it would turn this endpoint into an internal-network oracle.
    const msg = err instanceof BlockedHostError
      ? "Target host not permitted"
      : (err instanceof Error ? err.message : "Unknown error");
    res.status(502).json({
      error:    "Header check failed",
      url:      parsed.url.toString(),
      message:  msg,
      meta: { checkedAt: new Date().toISOString(), apiVersion: "1.0" },
    });
  }
});

export default router;
