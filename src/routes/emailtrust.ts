import { Router, Request, Response } from "express";
import { extractDomain, isUsableDomain } from "../lib/domain.js";
import { checkMailAuth } from "../lib/mailauth.js";
import { createTtlCache } from "../lib/cache.js";

const router = Router();

// 6 hour TTL — mail-auth DNS records change infrequently.
const cache = createTtlCache(6 * 60 * 60 * 1000);

router.get("/emailtrust", async (req: Request, res: Response) => {
  const raw = (req.query.domain as string) || (req.query.url as string);

  if (!raw) {
    res.status(400).json({
      error:   "Missing parameter",
      message: "Provide ?domain=example.com (the sender's domain)",
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

  // Accept an email address (user@domain) or a domain/URL; extract the domain.
  const candidate = raw.includes("@") ? raw.split("@").pop()!.trim() : raw;
  const domain = extractDomain(candidate);
  if (!isUsableDomain(domain)) {
    res.status(400).json({
      error:   "Invalid domain",
      message: "Must be a valid public domain or email address (e.g. example.com or user@example.com)",
    });
    return;
  }

  const cached = cache.get(domain);
  if (cached) {
    res.json({ ...cached, meta: { ...(cached.meta as object), cached: true } });
    return;
  }

  try {
    const auth = await checkMailAuth(domain);

    const result = {
      domain,
      grade:     auth.grade,
      score:     auth.score,
      maxScore:  100,
      spoofable: auth.spoofable,
      spf:       auth.spf,
      dmarc:     auth.dmarc,
      dkim:      auth.dkim,
      bimi:      auth.bimi,
      mx:        auth.mx,
      issues:    auth.issues,
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
    res.status(502).json({
      error:   "Email-trust check failed",
      domain,
      message: err instanceof Error ? err.message : "Unknown error",
      meta: { checkedAt: new Date().toISOString(), apiVersion: "1.0" },
    });
  }
});

export default router;
