import { Router, Request, Response } from "express";
import dns from "dns/promises";

const router = Router();

// ─── Constants ────────────────────────────────────────────────────────────────

const VALID_DOMAIN_RE = /^[a-zA-Z0-9][a-zA-Z0-9\-.]{1,251}[a-zA-Z0-9]$/;
const PRIVATE_IPV4_RE = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.0\.0\.0|169\.254\.)/;
const PRIVATE_IPV6_RE = /^(::1|fc00:|fd00:|fe80:)/i;

const ALLOWED_PORTS  = new Set(["", "80", "443", "8080", "8443"]);
const FETCH_TIMEOUT  = 8000;
const MAX_BODY_BYTES = 100 * 1024;   // robots.txt cap — 100 KB (RFC-recommended limit is 500 KB, we're stricter)

// ─── Known AI/LLM training bots (Spring 2026 list) ────────────────────────────
// Tracking these gives agents a quick read on whether a site permits AI crawling.

const AI_BOTS = [
  // OpenAI / ChatGPT
  "GPTBot",          // OpenAI's training crawler
  "ChatGPT-User",    // Live ChatGPT browsing
  "OAI-SearchBot",   // OpenAI search index

  // Anthropic / Claude
  "ClaudeBot",       // Anthropic's general crawler
  "anthropic-ai",    // Legacy Anthropic bot
  "Claude-Web",      // Claude web access

  // Google
  "Google-Extended", // Google's AI training opt-out (separate from Googlebot)

  // Meta
  "FacebookBot",
  "Meta-ExternalAgent",

  // Other major AI crawlers
  "PerplexityBot",
  "YouBot",
  "cohere-ai",
  "Bytespider",      // ByteDance / TikTok
  "Diffbot",
  "Omgilibot",
  "Applebot-Extended",
  "ImagesiftBot",
  "Amazonbot",
  "Bingbot",         // Microsoft (also feeds Copilot)
  "CCBot",           // Common Crawl (training data for many models)

  // Aggregators / catch-all flags
  "AI2Bot",
  "Timpibot",
  "magpie-crawler",
  "SemrushBot-OCOB",
];

// ─── Cache (12 hour TTL — robots.txt changes infrequently) ────────────────────

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
  cache.set(key, { data, expiresAt: Date.now() + 12 * 60 * 60 * 1000 });
  if (cache.size > 1000) {
    const firstKey = cache.keys().next().value;
    if (firstKey) cache.delete(firstKey);
  }
}

// ─── Domain validation + SSRF protection (same pattern as headers.ts) ────────

function extractAndValidateDomain(input: string): { domain: string } | { error: string } {
  let url: URL;
  try {
    const withProto = input.match(/^https?:\/\//i) ? input : `https://${input}`;
    url = new URL(withProto);
  } catch {
    return { error: "Could not parse domain or URL" };
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { error: "Only http/https supported" };
  }
  if (!ALLOWED_PORTS.has(url.port)) {
    return { error: `Port ${url.port} not permitted` };
  }

  const hostname = url.hostname.toLowerCase().replace(/^www\./, "");
  if (!hostname) return { error: "Missing hostname" };
  if (hostname === "localhost") return { error: "Localhost not permitted" };
  if (PRIVATE_IPV4_RE.test(hostname) || PRIVATE_IPV6_RE.test(hostname)) {
    return { error: "Private addresses not permitted" };
  }

  const isIp = /^[\d.]+$/.test(hostname) || hostname.includes(":");
  if (!isIp && !VALID_DOMAIN_RE.test(hostname)) {
    return { error: "Invalid hostname" };
  }

  return { domain: hostname };
}

async function isHostnameSafe(hostname: string): Promise<boolean> {
  if (/^[\d.]+$/.test(hostname) || hostname.includes(":")) {
    return !PRIVATE_IPV4_RE.test(hostname) && !PRIVATE_IPV6_RE.test(hostname);
  }
  try {
    const addresses = await Promise.race([
      dns.resolve(hostname),
      new Promise<string[]>((_, reject) => setTimeout(() => reject(new Error("DNS timeout")), 3000)),
    ]);
    for (const addr of addresses) {
      if (PRIVATE_IPV4_RE.test(addr) || PRIVATE_IPV6_RE.test(addr)) return false;
    }
    return addresses.length > 0;
  } catch {
    return false;
  }
}

// ─── Fetch robots.txt with body size cap ─────────────────────────────────────

interface FetchResult {
  exists:    boolean;
  status:    number;
  body:      string;
  truncated: boolean;
}

async function fetchRobotsTxt(domain: string): Promise<FetchResult> {
  const safe = await isHostnameSafe(domain);
  if (!safe) throw new Error(`Refused: ${domain} resolves to a private address`);

  // Try HTTPS first, fall back to HTTP (some sites still don't redirect)
  const urls = [`https://${domain}/robots.txt`, `http://${domain}/robots.txt`];

  let lastErr: Error | null = null;
  for (const url of urls) {
    try {
      const controller = new AbortController();
      const timer      = setTimeout(() => controller.abort(), FETCH_TIMEOUT);

      const response = await fetch(url, {
        method:   "GET",
        redirect: "follow",   // robots.txt redirects are fine, browsers follow them
        signal:   controller.signal,
        headers: {
          "User-Agent":      "TrustSource-RobotsCheck/1.0 (+https://trustsource.cc)",
          "Accept":          "text/plain, */*",
          "Accept-Encoding": "identity",
        },
      });
      clearTimeout(timer);

      // No robots.txt → not an error, just record it
      if (response.status === 404) {
        try { await response.body?.cancel(); } catch { /* ignore */ }
        return { exists: false, status: 404, body: "", truncated: false };
      }

      // Stream the body up to MAX_BODY_BYTES, then abort
      let body       = "";
      let totalBytes = 0;
      let truncated  = false;

      const reader = response.body?.getReader();
      if (!reader) {
        return { exists: response.status === 200, status: response.status, body: "", truncated: false };
      }

      const decoder = new TextDecoder("utf-8");
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        totalBytes += value.length;
        if (totalBytes > MAX_BODY_BYTES) {
          truncated = true;
          try { await reader.cancel(); } catch { /* ignore */ }
          break;
        }
        body += decoder.decode(value, { stream: true });
      }
      body += decoder.decode();

      return { exists: response.status === 200, status: response.status, body, truncated };
    } catch (err) {
      lastErr = err instanceof Error ? err : new Error(String(err));
      continue;
    }
  }
  throw lastErr || new Error("Failed to fetch robots.txt");
}

// ─── robots.txt parser ────────────────────────────────────────────────────────

interface UserAgentRules {
  userAgent: string;
  allow:     string[];
  disallow:  string[];
  crawlDelay: number | null;
}

interface ParsedRobots {
  userAgents: UserAgentRules[];
  sitemaps:   string[];
  rawLines:   number;
  hasErrors:  boolean;
}

function parseRobotsTxt(body: string): ParsedRobots {
  const lines = body.split(/\r?\n/);
  const rawLines = lines.length;

  const userAgents: UserAgentRules[] = [];
  const sitemaps:   string[] = [];
  let currentGroup: UserAgentRules | null = null;
  let hasErrors = false;

  for (let line of lines) {
    // Strip comments and trim
    const hashIdx = line.indexOf("#");
    if (hashIdx >= 0) line = line.slice(0, hashIdx);
    line = line.trim();
    if (!line) continue;

    const colonIdx = line.indexOf(":");
    if (colonIdx < 0) { hasErrors = true; continue; }

    const directive = line.slice(0, colonIdx).trim().toLowerCase();
    const value     = line.slice(colonIdx + 1).trim();

    switch (directive) {
      case "user-agent": {
        // A new user-agent block — but consecutive user-agent lines share a group
        if (!currentGroup || currentGroup.allow.length || currentGroup.disallow.length || currentGroup.crawlDelay !== null) {
          currentGroup = { userAgent: value, allow: [], disallow: [], crawlDelay: null };
          userAgents.push(currentGroup);
        } else {
          // Empty group, add this UA as a peer (duplicate the rules later by reference)
          currentGroup = { userAgent: value, allow: [], disallow: [], crawlDelay: null };
          userAgents.push(currentGroup);
        }
        break;
      }
      case "allow":
        if (currentGroup) currentGroup.allow.push(value);
        break;
      case "disallow":
        if (currentGroup) currentGroup.disallow.push(value);
        break;
      case "crawl-delay":
        if (currentGroup) {
          const n = parseFloat(value);
          if (!isNaN(n)) currentGroup.crawlDelay = n;
        }
        break;
      case "sitemap":
        if (value) sitemaps.push(value);
        break;
      default:
        // Unknown directive — ignore (RFC says to skip unknowns gracefully)
        break;
    }
  }

  return { userAgents, sitemaps, rawLines, hasErrors };
}

// ─── AI bot policy analysis ───────────────────────────────────────────────────

interface AiBotPolicy {
  bot:      string;
  blocked:  boolean;
  partial:  boolean;   // disallow some paths but not all
  rules:    { allow: string[]; disallow: string[] };
}

function analyzeAiBotPolicies(parsed: ParsedRobots): {
  policies:    AiBotPolicy[];
  globalBlock: boolean;       // "User-agent: *" disallows "/"
  globalAllow: boolean;       // "User-agent: *" with no disallows or only "Disallow:"
} {
  const policies: AiBotPolicy[] = [];

  // Find global "*" group
  const globalGroup = parsed.userAgents.find(g => g.userAgent === "*");
  const globalBlock = !!globalGroup && globalGroup.disallow.some(d => d === "/" || d === "");
  const globalAllow = !globalGroup || globalGroup.disallow.length === 0 ||
                      globalGroup.disallow.every(d => d === "");

  // Check each known AI bot
  for (const bot of AI_BOTS) {
    const match = parsed.userAgents.find(
      g => g.userAgent.toLowerCase() === bot.toLowerCase()
    );

    if (!match) {
      // Not mentioned → governed by "*" rules
      policies.push({
        bot,
        blocked: globalBlock,
        partial: false,
        rules: { allow: [], disallow: [] },
      });
      continue;
    }

    const blockedRoot = match.disallow.some(d => d === "/" || d === "");
    const hasAllow    = match.allow.length > 0;
    const hasDisallow = match.disallow.length > 0 && match.disallow.some(d => d !== "");

    policies.push({
      bot,
      blocked: blockedRoot && !hasAllow,
      partial: !blockedRoot && hasDisallow,
      rules: { allow: match.allow, disallow: match.disallow },
    });
  }

  return { policies, globalBlock, globalAllow };
}

// ─── Overall tier classification ──────────────────────────────────────────────

function classifyTier(
  exists:      boolean,
  globalBlock: boolean,
  aiAnalysis:  ReturnType<typeof analyzeAiBotPolicies>
): { tier: string; aiFriendly: boolean } {
  if (!exists) return { tier: "NO_ROBOTS_TXT", aiFriendly: true };

  const blockedAiCount = aiAnalysis.policies.filter(p => p.blocked).length;
  const partialAiCount = aiAnalysis.policies.filter(p => p.partial).length;
  const totalAi        = aiAnalysis.policies.length;

  if (globalBlock && blockedAiCount === totalAi) {
    return { tier: "BLOCKED_ALL", aiFriendly: false };
  }
  if (blockedAiCount > totalAi / 2) {
    return { tier: "BLOCKED_AI", aiFriendly: false };
  }
  if (blockedAiCount > 0 || partialAiCount > totalAi / 3) {
    return { tier: "SELECTIVE", aiFriendly: true };
  }
  return { tier: "OPEN", aiFriendly: true };
}

// ─── Route ────────────────────────────────────────────────────────────────────

router.get("/robots", async (req: Request, res: Response) => {
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

  const validation = extractAndValidateDomain(raw);
  if ("error" in validation) {
    res.status(400).json({ error: "Invalid domain", message: validation.error });
    return;
  }

  const domain = validation.domain;

  // Cache check
  const cached = getCached(domain);
  if (cached) {
    res.json({ ...cached, meta: { ...(cached.meta as object), cached: true } });
    return;
  }

  try {
    const fetchResult = await fetchRobotsTxt(domain);
    const parsed      = fetchResult.exists ? parseRobotsTxt(fetchResult.body) : null;
    const aiAnalysis  = parsed ? analyzeAiBotPolicies(parsed) : null;
    const classify    = classifyTier(
      fetchResult.exists,
      aiAnalysis?.globalBlock ?? false,
      aiAnalysis ?? { policies: [], globalBlock: false, globalAllow: true }
    );

    const response = {
      domain,
      exists:    fetchResult.exists,
      tier:      classify.tier,
      aiFriendly: classify.aiFriendly,

      summary: parsed ? {
        userAgentGroups:  parsed.userAgents.length,
        sitemaps:         parsed.sitemaps.length,
        rawLines:         parsed.rawLines,
        truncated:        fetchResult.truncated,
        hasParseErrors:   parsed.hasErrors,
      } : null,

      ai: aiAnalysis ? {
        globalBlock:           aiAnalysis.globalBlock,
        globalAllow:           aiAnalysis.globalAllow,
        knownBotsChecked:      AI_BOTS.length,
        knownBotsBlocked:      aiAnalysis.policies.filter(p => p.blocked).length,
        knownBotsPartial:      aiAnalysis.policies.filter(p => p.partial).length,
        policies:              aiAnalysis.policies,
      } : null,

      sitemaps:   parsed?.sitemaps      ?? [],
      userAgents: parsed?.userAgents    ?? [],

      response: {
        status: fetchResult.status,
      },

      meta: {
        checkedAt:  new Date().toISOString(),
        apiVersion: "1.0",
        paidWith:   "x402/USDC",
        cached:     false,
      },
    };

    setCached(domain, response);
    res.json(response);

  } catch (err) {
    const msg = err instanceof Error ? err.message : "Unknown error";
    res.status(502).json({
      error:   "robots.txt fetch failed",
      domain,
      message: msg,
      meta: { checkedAt: new Date().toISOString(), apiVersion: "1.0" },
    });
  }
});

export default router;
