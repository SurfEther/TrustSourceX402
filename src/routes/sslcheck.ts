import { Router, Request, Response } from "express";
import { extractDomain, isUsableDomain } from "../lib/domain.js";
import { fetchCertChain, scoreCertificate } from "../lib/tls-check.js";
import { createTtlCache } from "../lib/cache.js";
import { BlockedHostError } from "../lib/net-guard.js";

const router = Router();

// 6 hour TTL — certs change infrequently.
const cache = createTtlCache(6 * 60 * 60 * 1000);

router.get("/sslcheck", async (req: Request, res: Response) => {
  const raw = (req.query.domain as string) || (req.query.url as string);

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

  if (!isUsableDomain(domain)) {
    res.status(400).json({
      error:   "Invalid domain",
      message: "Must be a valid public domain (e.g. example.com)",
    });
    return;
  }

  // Cache hit
  const cached = cache.get(domain);
  if (cached) {
    res.json({ ...cached, meta: { ...(cached.meta as object), cached: true } });
    return;
  }

  try {
    const tlsResult = await fetchCertChain(domain, 8000);
    const score     = scoreCertificate(tlsResult);

    const response = {
      domain,
      score:    score.total,
      maxScore: 100,
      tier:     score.tier,
      breakdown: score.breakdown,
      warnings: score.warnings,
      certificate: {
        subject:        tlsResult.cert.subject,
        issuer:         tlsResult.cert.issuer,
        validFrom:      tlsResult.cert.validFrom,
        validTo:        tlsResult.cert.validTo,
        daysRemaining:  tlsResult.cert.daysRemaining,
        san:            tlsResult.cert.san,
        fingerprint256: tlsResult.cert.fingerprint256,
        serialNumber:   tlsResult.cert.serialNumber,
        isSelfSigned:   tlsResult.cert.isSelfSigned,
      },
      chain: tlsResult.chain,
      connection: {
        protocol:   tlsResult.protocol,
        cipher:     tlsResult.cipher,
        authorized: tlsResult.authorized,
        authError:  tlsResult.authError,
      },
      meta: {
        checkedAt:  new Date().toISOString(),
        apiVersion: "1.0",
        paidWith:   "x402/USDC",
        cached:     false,
      },
    };

    cache.set(domain, response);
    res.json(response);

  } catch (err) {
    // Don't echo which internal IP a name resolved to — keep the endpoint from
    // acting as an internal-network reachability oracle.
    const msg = err instanceof BlockedHostError
      ? "Target host not permitted"
      : (err instanceof Error ? err.message : "Unknown error");
    res.status(502).json({
      error:   "SSL check failed",
      domain,
      message: msg,
      meta: { checkedAt: new Date().toISOString(), apiVersion: "1.0" },
    });
  }
});

export default router;
