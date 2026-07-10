import dns from "dns/promises";
import whois from "whois-json";

// ─── Constants ────────────────────────────────────────────────────────────────

const TRUSTED_TLDS = new Set([".com", ".org", ".net", ".io", ".dev", ".ai"]);
const RISKY_TLDS   = new Set([".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".click"]);

// Established registrars, matched as whole tokens (see registrarMatches) so bare
// words like "google"/"amazon" don't false-positive on unrelated names, and
// "csc" matches without depending on a trailing space.
const ESTABLISHED_REGISTRARS = [
  "godaddy", "namecheap", "cloudflare", "google", "amazon",
  "name.com", "network solutions", "markmonitor", "csc",
  "tucows", "enom", "dynadot", "porkbun", "gandi",
];

// ─── Scoring helpers ──────────────────────────────────────────────────────────

export function getDomainAgeScore(whoisData: Record<string, string>): {
  agedays: number;
  score: number;
  label: string;
} {
  const raw =
    whoisData.creationDate     ||
    whoisData.created          ||
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

export function getTldScore(domain: string): { score: number; tld: string } {
  const tld = "." + domain.split(".").pop()!.toLowerCase();
  if (TRUSTED_TLDS.has(tld)) return { score: 20, tld };
  if (RISKY_TLDS.has(tld))   return { score: 0,  tld };
  return { score: 10, tld };
}

export async function getDnsScore(domain: string): Promise<{
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

// Match a known registrar name as a whole token, not a loose substring:
// "amazon registrar, inc." matches "amazon", but "amazonia domains" does not.
// Literal dots (e.g. "name.com") are escaped so they don't act as wildcards.
function registrarMatches(registrar: string, known: string): boolean {
  const escaped = known.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(^|[^a-z0-9])${escaped}([^a-z0-9]|$)`, "i").test(registrar);
}

export function getRegistrarScore(whoisData: Record<string, string>): {
  score: number;
  registrar: string;
} {
  const registrar = (
    whoisData.registrar     ||
    whoisData.registrarName ||
    ""
  ).toLowerCase();

  const match = ESTABLISHED_REGISTRARS.some((r) => registrarMatches(registrar, r));
  return {
    score:     match ? 20 : 10,
    registrar: registrar || "unknown",
  };
}

// ─── Composite trust score ─────────────────────────────────────────────────────

export interface DomainTrust {
  domain:    string;
  score:     number;
  maxScore:  number;
  tier:      "TRUSTED" | "MODERATE" | "CAUTION" | "HIGH_RISK";
  breakdown: { domainAge: number; tld: number; dnsPresence: number; registrar: number };
  details: {
    age:       { days: number; label: string; created: string | null; expires: string | null };
    tld:       string;
    dns:       { hasARecord: boolean; hasMxRecord: boolean; mxRecords: string[] };
    registrar: string;
  };
}

// Score a domain's trustworthiness (0–100) from WHOIS age, TLD risk, DNS
// presence, and registrar reputation. This is the single source of truth for
// domain trust — used by /trustscore directly and by /urlcheck as one signal.
export async function scoreDomainTrust(domain: string): Promise<DomainTrust> {
  const [whoisData, dnsResult] = await Promise.all([
    Promise.race([
      // follow:0 disables the whois lib's default referral-chasing (follow:2),
      // which parses a host:port out of the WHOIS response text and opens a raw
      // net.connect() to it with NO private-IP validation — a blind-SSRF vector
      // reachable via /trustscore and /urlcheck. The registry's own response
      // already carries creationDate + registrar, the only fields we read.
      // timeout:5000 bounds socket lifetime to the caller's own 5s race.
      whois(domain, { follow: 0, timeout: 5000 }).catch(() => ({} as Record<string, string>)),
      new Promise<Record<string, string>>(r => setTimeout(() => r({}), 5000)),
    ]),
    getDnsScore(domain),
  ]);

  const w               = whoisData as Record<string, string>;
  const ageResult       = getDomainAgeScore(w);
  const tldResult       = getTldScore(domain);
  const registrarResult = getRegistrarScore(w);

  const breakdown = {
    domainAge:   ageResult.score,
    tld:         tldResult.score,
    dnsPresence: dnsResult.score,
    registrar:   registrarResult.score,
  };

  const score = Object.values(breakdown).reduce((a, b) => a + b, 0);

  let tier: DomainTrust["tier"];
  if      (score >= 75) tier = "TRUSTED";
  else if (score >= 50) tier = "MODERATE";
  else if (score >= 25) tier = "CAUTION";
  else                  tier = "HIGH_RISK";

  return {
    domain,
    score,
    maxScore: 100,
    tier,
    breakdown,
    details: {
      age: {
        days:    ageResult.agedays,
        label:   ageResult.label,
        created: w.creationDate   || null,
        expires: w.expirationDate || null,
      },
      tld: tldResult.tld,
      dns: {
        hasARecord:  dnsResult.hasA,
        hasMxRecord: dnsResult.hasMx,
        mxRecords:   dnsResult.hasMxRecords,
      },
      registrar: registrarResult.registrar,
    },
  };
}
