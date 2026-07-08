import { Router, Request, Response } from "express";
import net from "net";
import {
  VALID_DOMAIN_RE,
  ALLOWED_PORTS,
  assertHostAllowed,
  assertUrlSchemeAndPort,
  isPrivateIp,
  normalizeHostname,
  BlockedHostError,
} from "../lib/net-guard.js";

const router = Router();

// ─── Constants ────────────────────────────────────────────────────────────────

const FETCH_TIMEOUT  = 8000;
const MAX_BODY_BYTES = 100 * 1024;   // robots.txt cap — 100 KB (RFC-recommended limit is 500 KB, we're stricter)
const MAX_REDIRECTS  = 3;

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

  const hostname = normalizeHostname(url.hostname).replace(/^www\./, "");
  if (!hostname) return { error: "Missing hostname" };
  if (hostname === "localhost") return { error: "Localhost not permitted" };
  if (isPrivateIp(hostname)) {
    return { error: "Private addresses not permitted" };
  }

  const isIp = net.isIP(hostname) !== 0;
  if (!isIp && !VALID_DOMAIN_RE.test(hostname)) {
    return { error: "Invalid hostname" };
  }

  return { domain: hostname };
}

// ─── Fetch robots.txt with SSRF re-validation on every hop + body size cap ────

interface FetchResult {
  exists:    boolean;
  status:    number;
  body:      string;
  truncated: boolean;
}

async function fetchRobotsTxt(domain: string): Promise<FetchResult> {
  // Bracket bare IPv6 literals so they form a valid URL authority.
  const hostForUrl = net.isIPv6(domain) ? `[${domain}]` : domain;

  // Try HTTPS first, fall back to HTTP (some sites still don't redirect)
  const candidates = [
    `https://${hostForUrl}/robots.txt`,
    `http://${hostForUrl}/robots.txt`,
  ];

  let lastErr: Error | null = null;
  for (const candidate of candidates) {
    try {
      return await fetchGuarded(new URL(candidate));
    } catch (err) {
      if (err instanceof BlockedHostError) throw err; // don't retry a blocked target
      lastErr = err instanceof Error ? err : new Error(String(err));
      continue;
    }
  }
  throw lastErr || new Error("Failed to fetch robots.txt");
}

// Follow redirects manually, re-validating scheme/port and re-resolving the host
// against private ranges on EVERY hop. Native redirect:"follow" would let a
// public site 30x-bounce us to an internal address (or a disallowed port)
// without any re-check — the same SSRF surface /headers already closes.
async function fetchGuarded(startUrl: URL): Promise<FetchResult> {
  let currentUrl = startUrl;
  let redirects  = 0;

  while (redirects <= MAX_REDIRECTS) {
    assertUrlSchemeAndPort(currentUrl);
    await assertHostAllowed(currentUrl.hostname);

    const controller = new AbortController();
    const timer      = setTimeout(() => controller.abort(), FETCH_TIMEOUT);

    try {
      const response = await fetch(currentUrl.toString(), {
        method:   "GET",
        redirect: "manual",
        signal:   controller.signal,
        headers: {
          "User-Agent":      "TrustSource-RobotsCheck/1.0 (+https://trustsource.cc)",
          "Accept":          "text/plain, */*",
          "Accept-Encoding": "identity",
        },
      });
      clearTimeout(timer);

      // Redirect — re-validate the next hop on the following loop iteration.
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get("location");
        try { await response.body?.cancel(); } catch { /* ignore */ }
        if (!location) {
          return { exists: false, status: response.status, body: "", truncated: false };
        }
        try {
          currentUrl = new URL(location, currentUrl);
        } catch {
          throw new Error("Invalid redirect Location header");
        }
        redirects++;
        continue;
      }

      // No robots.txt → not an error, just record it
      if (response.status === 404) {
        try { await response.body?.cancel(); } catch { /* ignore */ }
        return { exists: false, status: 404, body: "", truncated: false };
      }

      // Stream the body up to MAX_BODY_BYTES, then abort
      const reader = response.body?.getReader();
      if (!reader) {
        return { exists: response.status === 200, status: response.status, body: "", truncated: false };
      }

      let body       = "";
      let totalBytes = 0;
      let truncated  = false;
      const decoder  = new TextDecoder("utf-8");
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
      clearTimeout(timer);
      throw err;
    }
  }
  throw new Error(`Too many redirects (max ${MAX_REDIRECTS})`);
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

export function parseRobotsTxt(body: string): ParsedRobots {
  const lines = body.split(/\r?\n/);
  const rawLines = lines.length;

  const userAgents: UserAgentRules[] = [];
  const sitemaps:   string[] = [];
  // Consecutive "User-agent:" lines share the rule block that follows them
  // (RFC 9309 §2.2.1). Accumulate the run of UAs, then apply each rule to all
  // of them — otherwise rules bind only to the last UA in the run and a site
  // that blocks several bots at once looks like it blocks only one.
  let activeGroup: UserAgentRules[] = [];
  let afterRule   = false;   // has a rule directive appeared since the last UA line?
  let hasErrors   = false;

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
        // A UA line after a rule starts a fresh group; a UA line directly after
        // another UA line joins the same (still ruleless) group.
        if (afterRule) { activeGroup = []; afterRule = false; }
        const ua: UserAgentRules = { userAgent: value, allow: [], disallow: [], crawlDelay: null };
        activeGroup.push(ua);
        userAgents.push(ua);
        break;
      }
      case "allow":
        for (const g of activeGroup) g.allow.push(value);
        afterRule = true;
        break;
      case "disallow":
        for (const g of activeGroup) g.disallow.push(value);
        afterRule = true;
        break;
      case "crawl-delay": {
        const n = parseFloat(value);
        if (!isNaN(n)) for (const g of activeGroup) g.crawlDelay = n;
        afterRule = true;
        break;
      }
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

export function analyzeAiBotPolicies(parsed: ParsedRobots): {
  policies:    AiBotPolicy[];
  globalBlock: boolean;       // "User-agent: *" disallows "/"
  globalAllow: boolean;       // "User-agent: *" with no disallows or only "Disallow:"
} {
  const policies: AiBotPolicy[] = [];

  // Find global "*" group. Note: an empty "Disallow:" value means ALLOW ALL
  // (RFC 9309 §2.2.2), so only a literal "/" counts as a root block.
  const globalGroup = parsed.userAgents.find(g => g.userAgent === "*");
  const globalBlock = !!globalGroup && globalGroup.disallow.some(d => d === "/");
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

    // Empty "Disallow:" means allow-all, so only a literal "/" blocks the root.
    const blockedRoot = match.disallow.some(d => d === "/");
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

export function classifyTier(
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
    // Don't leak internal-resolution detail (e.g. "resolves to 10.0.0.5") to
    // the client — that turns the endpoint into an internal-network oracle.
    const msg = err instanceof BlockedHostError
      ? "Target host not permitted"
      : (err instanceof Error ? err.message : "Unknown error");
    res.status(502).json({
      error:   "robots.txt fetch failed",
      domain,
      message: msg,
      meta: { checkedAt: new Date().toISOString(), apiVersion: "1.0" },
    });
  }
});

export default router;
