import { Router, Request, Response } from "express";
import { extractDomain, isUsableDomain } from "../lib/domain.js";
import { scoreDomainTrust, DomainTrust } from "../lib/domain-trust.js";
import { fetchCertChain, scoreCertificate } from "../lib/tls-check.js";
import { checkTyposquat, TyposquatResult } from "../lib/typosquat.js";
import { createTtlCache } from "../lib/cache.js";

const router = Router();

// 1 hour TTL — the underlying signals (WHOIS/DNS/TLS) change slowly.
const cache = createTtlCache(60 * 60 * 1000);

type Verdict = "CLEAR" | "REVIEW" | "BLOCK";
const RANK: Record<Verdict, number> = { CLEAR: 0, REVIEW: 1, BLOCK: 2 };

interface TlsSignal {
  reachable:     boolean;
  valid:         boolean;
  tier:          string | null;   // VALID | WEAK | EXPIRING | EXPIRED | UNTRUSTED | INVALID
  daysRemaining: number | null;
}

// Fuse the three signals into a single go/no-go verdict + a 0–100 score. The
// value of this endpoint is exactly this interpretation layer — an agent would
// otherwise run 3 lookups and have to decide what they mean together.
function decide(trust: DomainTrust, tls: TlsSignal, typo: TyposquatResult) {
  const reasons: string[] = [];
  let verdict: Verdict = "CLEAR";
  const escalate = (v: Verdict) => { if (RANK[v] > RANK[verdict]) verdict = v; };

  const ageDays          = trust.details.age.days;
  const newlyRegistered  = ageDays >= 0 && ageDays < 30;

  // ── Typosquat / lookalike (strongest danger signal) ────────────────────────
  if (typo.isLookalike) {
    reasons.push(
      `possible lookalike of ${typo.nearestBrand ?? "a known brand"} ` +
      `(${typo.technique}, confidence ${typo.confidence.toFixed(2)})`
    );
    escalate(typo.confidence >= 0.8 ? "BLOCK" : "REVIEW");
  }

  // ── Domain trust ───────────────────────────────────────────────────────────
  if (trust.tier === "HIGH_RISK") {
    escalate("BLOCK");
    reasons.push(`very low domain-trust score (${trust.score}/100)`);
  } else if (trust.tier === "CAUTION") {
    escalate("REVIEW");
    reasons.push(`low domain-trust score (${trust.score}/100)`);
  } else {
    reasons.push(`domain trust ${trust.tier.toLowerCase()} (${trust.score}/100)`);
  }

  if (newlyRegistered) {
    escalate("REVIEW");
    reasons.push(`domain registered very recently (${ageDays} days ago)`);
  }

  // ── TLS ────────────────────────────────────────────────────────────────────
  if (!tls.reachable) {
    escalate("REVIEW");
    reasons.push("no reachable HTTPS/TLS on port 443");
  } else if (tls.tier === "EXPIRED" || tls.tier === "INVALID") {
    escalate(trust.tier === "HIGH_RISK" ? "BLOCK" : "REVIEW");
    reasons.push(`TLS certificate ${tls.tier.toLowerCase()}`);
  } else if (tls.tier === "UNTRUSTED" || tls.tier === "EXPIRING" || tls.tier === "WEAK") {
    escalate("REVIEW");
    reasons.push(`TLS ${tls.tier.toLowerCase()}`);
  } else {
    reasons.push("valid, trusted TLS certificate");
  }

  // ── Composite 0–100 score (secondary to the verdict) ───────────────────────
  let score = trust.score;
  if (typo.isLookalike)                         score -= Math.round(typo.confidence * 50);
  if (!tls.reachable)                           score -= 15;
  else if (tls.tier === "EXPIRED" || tls.tier === "INVALID")     score -= 40;
  else if (tls.tier === "UNTRUSTED" || tls.tier === "EXPIRING" || tls.tier === "WEAK") score -= 20;
  if (newlyRegistered)                          score -= 15;
  score = Math.max(0, Math.min(100, score));

  return { verdict, score, reasons };
}

router.get("/urlcheck", async (req: Request, res: Response) => {
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

  const domain = extractDomain(raw);
  if (!isUsableDomain(domain)) {
    res.status(400).json({
      error:   "Invalid URL",
      message: "Must contain a valid public domain (e.g. https://example.com)",
    });
    return;
  }

  const cached = cache.get(domain);
  if (cached) {
    res.json({ ...cached, meta: { ...(cached.meta as object), cached: true } });
    return;
  }

  try {
    // Run all signals in parallel. TLS is allowed to fail without killing the
    // verdict — an unreachable/invalid HTTPS endpoint is itself a signal.
    const typo = checkTyposquat(domain);
    const [trust, tls] = await Promise.all([
      scoreDomainTrust(domain),
      fetchCertChain(domain, 8000)
        .then((r): TlsSignal => {
          const s = scoreCertificate(r);
          return { reachable: true, valid: r.chain.valid && r.chain.trusted, tier: s.tier, daysRemaining: r.cert.daysRemaining };
        })
        .catch((): TlsSignal => ({ reachable: false, valid: false, tier: null, daysRemaining: null })),
    ]);

    const { verdict, score, reasons } = decide(trust, tls, typo);

    const result = {
      domain,
      verdict,
      score,
      maxScore: 100,
      reasons,
      signals: {
        domainTrust: {
          score:           trust.score,
          tier:            trust.tier,
          ageDays:         trust.details.age.days,
          registrar:       trust.details.registrar,
          tld:             trust.details.tld,
          hasDns:          trust.details.dns.hasARecord,
          newlyRegistered: trust.details.age.days >= 0 && trust.details.age.days < 30,
        },
        tls: {
          reachable:     tls.reachable,
          valid:         tls.valid,
          tier:          tls.tier,
          daysRemaining: tls.daysRemaining,
        },
        typosquat: {
          isLookalike:  typo.isLookalike,
          nearestBrand: typo.nearestBrand,
          technique:    typo.technique,
          confidence:   typo.confidence,
        },
      },
      meta: {
        checkedAt:  new Date().toISOString(),
        apiVersion: "1.0",
        paidWith:   "x402/USDC",
        cached:     false,
      },
    };

    cache.set(domain, result);
    res.json(result);

  } catch (err) {
    res.status(500).json({
      error:   "URL check failed",
      domain,
      message: err instanceof Error ? err.message : "Unknown error",
      meta: { checkedAt: new Date().toISOString(), apiVersion: "1.0" },
    });
  }
});

export default router;
