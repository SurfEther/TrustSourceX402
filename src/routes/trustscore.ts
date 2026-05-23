import { Router, Request, Response } from "express";
import dns from "dns/promises";
import whois from "whois-json";

const router = Router();

// ─── Scoring helpers ──────────────────────────────────────────────────────────

const TRUSTED_TLDS = new Set([".com", ".org", ".net", ".io", ".dev", ".ai"]);
const RISKY_TLDS = new Set([".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".click"]);

function extractDomain(input: string): string {
  try {
    // Handle bare domains and full URLs
    const withProto = input.startsWith("http") ? input : `https://${input}`;
    return new URL(withProto).hostname.replace(/^www\./, "");
  } catch {
    return input.replace(/^www\./, "").split("/")[0];
  }
}

function getDomainAgeScore(whoisData: Record<string, string>): {
  agedays: number;
  score: number;
  label: string;
} {
  const raw =
    whoisData.creationDate ||
    whoisData.created ||
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
  if (agedays > 1825) { score = 30; label = "established (5+ years)"; }
  else if (agedays > 730) { score = 25; label = "mature (2–5 years)"; }
  else if (agedays > 365) { score = 18; label = "growing (1–2 years)"; }
  else if (agedays > 90)  { score = 10; label = "new (90d–1yr)"; }
  else                    { score = 2;  label = "very new (<90 days)"; }

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

  try {
    await dns.resolve4(domain);
    hasA = true;
  } catch {}

  try {
    const mx = await dns.resolveMx(domain);
    if (mx.length > 0) {
      hasMx = true;
      hasMxRecords = mx.slice(0, 3).map((r) => r.exchange);
    }
  } catch {}

  const score = (hasA ? 20 : 0) + (hasMx ? 10 : 0);
  return { score, hasA, hasMx, hasMxRecords };
}

function getRegistrarScore(whoisData: Record<string, string>): {
  score: number;
  registrar: string;
} {
  const registrar =
    whoisData.registrar ||
    whoisData.registrarName ||
    "";
  // Established registrars = higher trust signal
  const established = ["godaddy", "namecheap", "cloudflare", "google", "amazon", "name.com", "network solutions"];
  const match = established.some((r) => registrar.toLowerCase().includes(r));
  return { score: match ? 20 : 10, registrar: registrar || "unknown" };
}

// ─── Main route ───────────────────────────────────────────────────────────────

router.get("/trustscore", async (req: Request, res: Response) => {
  const input = (req.query.domain as string) || (req.query.url as string);

  if (!input) {
    res.status(400).json({
      error: "Missing parameter",
      message: "Provide ?domain=example.com or ?url=https://example.com",
    });
    return;
  }

  const domain = extractDomain(input);

  if (!domain || domain.length < 3 || !domain.includes(".")) {
    res.status(400).json({ error: "Invalid domain", input });
    return;
  }

  try {
    // Run WHOIS and DNS checks in parallel
    const [whoisData, dnsResult] = await Promise.all([
      whois(domain).catch(() => ({} as Record<string, string>)),
      getDnsScore(domain),
    ]);

    const ageResult       = getDomainAgeScore(whoisData as Record<string, string>);
    const tldResult       = getTldScore(domain);
    const registrarResult = getRegistrarScore(whoisData as Record<string, string>);

    // Score breakdown (max 100)
    const breakdown = {
      domainAge:   ageResult.score,    // 0–30
      tld:         tldResult.score,    // 0–20
      dnsPresence: dnsResult.score,    // 0–30
      registrar:   registrarResult.score, // 10–20
    };

    const totalScore = Object.values(breakdown).reduce((a, b) => a + b, 0);

    // Risk tier
    let tier: string;
    if (totalScore >= 75)      tier = "TRUSTED";
    else if (totalScore >= 50) tier = "MODERATE";
    else if (totalScore >= 25) tier = "CAUTION";
    else                       tier = "HIGH_RISK";

    res.json({
      domain,
      score: totalScore,
      maxScore: 100,
      tier,
      breakdown,
      details: {
        age: {
          days:  ageResult.agedays,
          label: ageResult.label,
          created: (whoisData as Record<string, string>).creationDate || null,
          expires: (whoisData as Record<string, string>).expirationDate || null,
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
        checkedAt:   new Date().toISOString(),
        apiVersion:  "1.0",
        paidWith:    "x402/USDC",
      },
    });
  } catch (err) {
    res.status(500).json({
      error: "Lookup failed",
      domain,
      message: err instanceof Error ? err.message : "Unknown error",
    });
  }
});

export default router;
