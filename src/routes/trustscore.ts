import { Router, Request, Response } from "express";
import dns from "dns/promises";
import whois from "whois-json";

const router = Router();

// ─── Constants ────────────────────────────────────────────────────────────────

const TRUSTED_TLDS = new Set([".com", ".org", ".net", ".io", ".dev", ".ai"]);
const RISKY_TLDS   = new Set([".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".click"]);

// Strict allowlist: letters, digits, hyphens, dots only (no shell chars)
const VALID_DOMAIN_RE = /^[a-zA-Z0-9][a-zA-Z0-9\-.]{1,251}[a-zA-Z0-9]$/;

// Block private/internal IP ranges — prevents SSRF via WHOIS subprocess
const PRIVATE_IP_RE = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.0\.0\.0)/;

// Established registrars — word-boundary safe substrings
const ESTABLISHED_REGISTRARS = [
  "godaddy", "namecheap", "cloudflare", "google", "amazon",
  "name.com", "network solutions", "markmonitor", "csc ",
  "tucows", "enom", "dynadot", "porkbun", "gandi",
];

// ─── Simple in-memory cache (1 hour TTL) ─────────────────────────────────────

interface CacheEntry {
  data: Record<string, unknown>;
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
  cache.set(key, { data, expiresAt: Date.now() + 60 * 60 * 1000 });
  // Prevent unbounded memory growth — evict oldest if over 1000 entries
  if (cache.size > 1000) {
    const firstKey = cache.keys().next().value;
    if (firstKey) cache.delete(firstKey);
  }
}

// ─── Scoring helpers ──────────────────────────────────────────────────────────

function extractDomain(input: string): string | null {
  try {
    const withProto = input.startsWith("http") ? input : `https://${input}`;
    const hostname  = new URL(withProto).hostname.replace(/^www\./, "").toLowerCase();
    if (!hostname) return null;

    // Block private IPs / localhost
    if (PRIVATE_IP_RE.test(hostname) || hostname === "localhost") return null;

    // Strict character allowlist — prevents command injection into whois subprocess
    if (!VALID_DOMAIN_RE.test(hostname)) return null;

    return hostname;
  } catch {
    return null;
  }
}

function getDomainAgeScore(whoisData: Record<string, string>): {
  agedays: number;
  score: number;
  label: string;
} {
  const raw =
    whoisData.creationDate    ||
    whoisData.created         ||
    whoisData.domainRegistered ||
    "";

  if (!raw) return { agedays: -1, score: 0, label: "unknown" };

  const created = new Date(raw);
  if (isNaN(created.getTime())) return { agedays: -1, score: 0, label: "unknown" };

  const agedays = Math.floor(
    (Date.now() - created.getTime()) / (1000 * 60 * 60 * 24)
  );

  let score = 0;
  let label = "";
  if      (agedays > 1825) { score = 30; label = "established (5+ years)"; }
  else if (agedays > 730)  { score = 25; label = "mature (2–5 years)";     }
  else if (agedays > 365)  { score = 18; label = "growing (1–2 years)";    }
  else if (agedays > 90)   { score = 10; label = "new (90d–1yr)";          }
  else                     { score = 2;  label = "very new (<90 days)";    }

  return { agedays, score, label };
}

function getTldScore(domain: string): { score: number; tld: string } {
  const tld = "." + domain.split(".").pop()!.toLowerCase();
  if (TRUSTED_TLDS.has(tld)) return { score: 20, tld };
  if (RISKY_TLDS.has(tld))   return { score: 0,  tld };
  return { score: 10, tld };
}

async function getDnsScore(domain: string): Promise<{
  score: number;
  hasMx: boolean;
  hasA: boolean;
  hasMxRecords: string[];
}> {
  let hasA = false;
  let hasMx = false;
  let hasMxRecords: string[] = [];

  // Timeout DNS lookups at 4s each — unresponsive servers don't hang the request
  const timeout = <T>(p: Promise<T>): Promise<T | null> =>
    Promise.race([p, new Promise<null>(r => setTimeout(() => r(null), 4000))]);

  try {
    const result = await timeout(dns.resolve4(domain));
    if (result) hasA = true;
  } catch {}

  try {
    const mx = await timeout(dns.resolveMx(domain));
    if (mx && mx.length > 0) {
      hasMx = true;
      hasMxRecords = mx.slice(0, 3).map((r) => r.exchange);
    }
  } catch {}

  return {
    score: (hasA ? 20 : 0) + (hasMx ? 10 : 0),
    hasA,
    hasMx,
    hasMxRecords,
  };
}

function getRegistrarScore(whoisData: Record<string, string>): {
  score: number;
  registrar: string;
} {
  const registrar = (
    whoisData.registrar     ||
    whoisData.registrarName ||
    ""
  ).toLowerCase();

  const match = ESTABLISHED_REGISTRARS.some((r) => registrar.includes(r));
  return {
    score:     match ? 20 : 10,
    registrar: registrar || "unknown",
  };
}

// ─── Main route ───────────────────────────────────────────────────────────────

router.get("/trustscore", async (req: Request, res: Response) => {
  const raw = (req.query.domain as string) || (req.query.url as string);

  // Input presence + length guard (DNS max = 253 chars)
  if (!raw) {
    res.status(400).json({
      error:   "Missing parameter",
      message: "Provide ?domain=example.com or ?url=https://example.com",
    });
    return;
  }

  if (raw.length > 253) {
    res.status(400).json({
      error:   "Invalid input",
      message: "Domain must be 253 characters or fewer",
    });
    return;
  }

  const domain = extractDomain(raw);

  if (!domain || domain.length < 4 || !domain.includes(".")) {
    res.status(400).json({
      error:   "Invalid domain",
      message: "Must be a valid public domain (e.g. example.com)",
    });
    return;
  }

  // Return cached result if available
  const cached = getCached(domain);
  if (cached) {
    res.json({ ...cached, meta: { ...(cached.meta as object), cached: true } });
    return;
  }

  try {
    // WHOIS with 5s timeout + DNS in parallel
    const [whoisData, dnsResult] = await Promise.all([
      Promise.race([
        whois(domain).catch(() => ({} as Record<string, string>)),
        new Promise<Record<string, string>>(r => setTimeout(() => r({}), 5000)),
      ]),
      getDnsScore(domain),
    ]);

    const ageResult       = getDomainAgeScore(whoisData as Record<string, string>);
    const tldResult       = getTldScore(domain);
    const registrarResult = getRegistrarScore(whoisData as Record<string, string>);

    const breakdown = {
      domainAge:   ageResult.score,
      tld:         tldResult.score,
      dnsPresence: dnsResult.score,
      registrar:   registrarResult.score,
    };

    const totalScore = Object.values(breakdown).reduce((a, b) => a + b, 0);

    let tier: string;
    if      (totalScore >= 75) tier = "TRUSTED";
    else if (totalScore >= 50) tier = "MODERATE";
    else if (totalScore >= 25) tier = "CAUTION";
    else                       tier = "HIGH_RISK";

    const result = {
      domain,
      score:    totalScore,
      maxScore: 100,
      tier,
      breakdown,
      details: {
        age: {
          days:    ageResult.agedays,
          label:   ageResult.label,
          created: (whoisData as Record<string, string>).creationDate    || null,
          expires: (whoisData as Record<string, string>).expirationDate  || null,
        },
        tld: tldResult.tld,
        dns: {
          hasARecord:  dnsResult.hasA,
          hasMxRecord: dnsResult.hasMx,
          mxRecords:   dnsResult.hasMxRecords,
        },
        registrar: registrarResult.registrar,
      },
      meta: {
        checkedAt:  new Date().toISOString(),
        apiVersion: "1.0",
        paidWith:   "x402/USDC",
        cached:     false,
      },
    };

    setCached(domain, result);
    res.json(result);

  } catch (err) {
    res.status(500).json({
      error:   "Lookup failed",
      domain,
      message: err instanceof Error ? err.message : "Unknown error",
    });
  }
});

export default router;