import { Router, Request, Response } from "express";
import { BlockedHostError, assertUrlSchemeAndPort, normalizeHostname, isPrivateIp, VALID_DOMAIN_RE } from "../lib/net-guard.js";
import { guardedFetch } from "../lib/fetch-guard.js";
import { extractContent, collapseWhitespace } from "../lib/html-text.js";
import { scanForInjection, stripInvisible, Finding } from "../lib/injection-scan.js";
import { scoreDomainTrust } from "../lib/domain-trust.js";
import { extractDomain, isUsableDomain } from "../lib/domain.js";
import { createTtlCache } from "../lib/cache.js";
import net from "net";

const router = Router();

// Short TTL — page content is expected to be fresh. Long enough to absorb an
// agent re-fetching the same page inside one task, short enough to stay honest.
const cache = createTtlCache(10 * 60 * 1000, 200);

const MAX_FETCH_BYTES = 2 * 1024 * 1024;   // 2 MB — plenty for a document
const MAX_TEXT_CHARS  = 100_000;
const MAX_CACHE_TEXT  = 25_000;   // don't retain large attacker-chosen bodies
const FETCH_TIMEOUT   = 10_000;
const TRUST_TIMEOUT   = 6_000;
const MAX_FINDINGS    = 25;

// Only these are worth extracting text from. Anything else is returned
// unanalyzed rather than guessed at.
const TEXTUAL_TYPES = [
  "text/html", "application/xhtml", "text/plain", "text/markdown",
  "application/json", "text/xml", "application/xml", "text/csv",
];

type Verdict = "SAFE" | "REVIEW" | "BLOCK";
const RANK: Record<Verdict, number> = { SAFE: 0, REVIEW: 1, BLOCK: 2 };

// Techniques that are effectively dispositive when found somewhere a human
// cannot see — there is no benign reason to hide these.
const CRITICAL_HIDDEN = new Set([
  "instruction_override", "system_prompt_exfil", "data_exfiltration",
  "unicode_tag_smuggling", "homoglyph_obfuscation", "delimiter_spoof",
]);
const UNSEEN = new Set(["hidden", "comment"]);

function parseTarget(raw: string): URL | { error: string } {
  let url: URL;
  try {
    url = new URL(raw.match(/^https?:\/\//i) ? raw : `https://${raw}`);
  } catch {
    return { error: "Could not parse URL" };
  }
  try {
    assertUrlSchemeAndPort(url);
  } catch (e) {
    return { error: e instanceof Error ? e.message : "URL not permitted" };
  }
  const host = normalizeHostname(url.hostname);
  if (!host) return { error: "Missing hostname" };
  if (host === "localhost") return { error: "Localhost not permitted" };
  if (isPrivateIp(host)) return { error: "Private/internal addresses not permitted" };
  if (net.isIP(host) === 0 && !VALID_DOMAIN_RE.test(host)) return { error: "Invalid hostname" };
  return url;
}

export function decide(
  risk: number,
  findings: Finding[],
  trustTier: string | null,
  analyzed: boolean,
) {
  const reasons: string[] = [];
  let verdict: Verdict = "SAFE";
  const escalate = (v: Verdict) => { if (RANK[v] > RANK[verdict]) verdict = v; };

  // A critical technique hidden from human view is a hard block regardless of
  // the aggregate score — one such finding is the whole attack.
  const critical = findings.filter(
    (f) => UNSEEN.has(f.placement) && CRITICAL_HIDDEN.has(f.technique),
  );
  if (critical.length) {
    escalate("BLOCK");
    for (const f of critical.slice(0, 4)) {
      reasons.push(`${f.technique.replace(/_/g, " ")} concealed in ${f.placement} content (${f.detail})`);
    }
  }

  if (risk >= 0.7)      { escalate("BLOCK");  reasons.push(`high injection risk score (${risk.toFixed(2)})`); }
  else if (risk >= 0.25){ escalate("REVIEW"); reasons.push(`possible injection patterns detected (risk ${risk.toFixed(2)})`); }

  // Visible-only hits are reported but deliberately weak — pages legitimately
  // discuss prompt injection.
  const visibleOnly = findings.filter((f) => f.placement === "visible");
  if (visibleOnly.length && verdict === "SAFE") {
    reasons.push(
      `injection-like phrasing appears in visible page text (${visibleOnly.length} match(es)) — ` +
      `common in security/documentation content, treated as low risk`,
    );
  }

  if (trustTier === "HIGH_RISK") { escalate("REVIEW"); reasons.push("content served from a very low-trust domain"); }
  else if (trustTier === "CAUTION") { reasons.push("content served from a low-trust domain"); }

  if (!analyzed) {
    escalate("REVIEW");
    reasons.push("content type was not text — body was NOT scanned; treat as untrusted");
  }

  if (!reasons.length) reasons.push("no injection patterns found in visible or hidden content");
  return { verdict, reasons };
}

router.get("/safefetch", async (req: Request, res: Response) => {
  const raw = (req.query.url as string) || (req.query.domain as string);

  if (!raw) {
    res.status(400).json({
      error: "Missing parameter",
      message: "Provide ?url=https://example.com",
    });
    return;
  }
  if (raw.length > 2048) {
    res.status(400).json({ error: "Invalid input", message: "URL must be 2048 characters or fewer" });
    return;
  }

  const parsed = parseTarget(raw);
  if ("error" in parsed) {
    res.status(400).json({ error: "Invalid URL", message: parsed.error });
    return;
  }
  const target = parsed;
  const domain = extractDomain(target.hostname);

  const cacheKey = target.origin + target.pathname + target.search;
  const cached = cache.get(cacheKey);
  if (cached) {
    res.json({ ...cached, meta: { ...(cached.meta as object), cached: true } });
    return;
  }

  try {
    // Fetch and score the domain in parallel. Domain trust must never block the
    // safety verdict — a slow WHOIS degrades, it does not fail the request.
    const [fetched, trust] = await Promise.all([
      guardedFetch(target, {
        timeoutMs: FETCH_TIMEOUT,
        maxBytes:  MAX_FETCH_BYTES,
        userAgent: "TrustSource-SafeFetch/1.0 (+https://trustsource.cc)",
        accept:    "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.5",
      }),
      (isUsableDomain(domain)
        ? Promise.race([
            scoreDomainTrust(domain!),
            new Promise<null>((r) => setTimeout(() => r(null), TRUST_TIMEOUT)),
          ]).catch(() => null)
        : Promise.resolve(null)),
    ]);

    const ct       = (fetched.contentType ?? "").toLowerCase();
    // A body with no Content-Type is only analyzed if it actually looks like
    // text — otherwise a binary blob gets mojibake-decoded and returned as "page
    // text". U+FFFD is what TextDecoder emits for undecodable bytes.
    const looksBinary = (() => {
      const sample = fetched.body.slice(0, 2000);
      if (!sample) return false;
      const bad = (sample.match(/[\uFFFD\u0000-\u0008\u000E-\u001F]/g) || []).length;
      return bad / sample.length > 0.05;
    })();
    const analyzed = TEXTUAL_TYPES.some((t) => ct.includes(t))
      ? !looksBinary
      : (!ct && fetched.body.length > 0 && !looksBinary);

    let visibleText = "";
    let title: string | null = null;
    let segments: ReturnType<typeof extractContent>["segments"] = [];
    let analysisTruncated = false;

    if (analyzed) {
      if (ct.includes("html") || ct.includes("xml") || !ct) {
        const extracted = extractContent(fetched.body);
        visibleText = extracted.visibleText;
        segments    = extracted.segments;
        title       = extracted.title;
        analysisTruncated = extracted.truncated || extracted.segmentsTruncated;
      } else {
        visibleText = collapseWhitespace(fetched.body);
      }
    }

    const scan = analyzed
      ? scanForInjection(visibleText, segments, fetched.body)
      : { detected: false, risk: 0, techniques: [] as string[], findings: [] as Finding[] };

    // The sanitized deliverable: what a human would see, with every invisible
    // smuggling character removed and hidden segments already excluded.
    const invisibleBefore = visibleText.length;
    const cleanFull  = stripInvisible(visibleText);
    const invisibleRemoved = invisibleBefore - cleanFull.length;
    const textTruncated = cleanFull.length > MAX_TEXT_CHARS;
    const text = textTruncated ? cleanFull.slice(0, MAX_TEXT_CHARS) : cleanFull;

    const { verdict, reasons } = decide(scan.risk, scan.findings, trust?.tier ?? null, analyzed);

    const result = {
      url:          fetched.finalUrl,
      requestedUrl: target.toString(),
      domain,
      verdict,
      risk:     scan.risk,
      reasons,
      injection: {
        detected:   scan.detected,
        risk:       scan.risk,
        techniques: scan.techniques,
        findings:   scan.findings.slice(0, MAX_FINDINGS).map((f) => ({
          technique: f.technique,
          placement: f.placement,
          severity:  f.severity,
          weight:    Math.round(f.weight * 100) / 100,
          detail:    f.detail,
          snippet:   f.snippet,
        })),
        findingsTruncated: scan.findings.length > MAX_FINDINGS,
      },
      content: {
        analyzed,
        contentType: fetched.contentType,
        title,
        text,
        chars:       text.length,
        truncated:   textTruncated || fetched.truncated || analysisTruncated,
        sanitized: {
          hiddenSegmentsRemoved: segments.filter((s) => s.kind !== "script").length,
          invisibleCharsRemoved: invisibleRemoved,
          note: "Hidden/off-screen elements and invisible control characters are excluded from `text`. This is the content a human would actually see.",
        },
      },
      domainTrust: trust
        ? {
            score:           trust.score,
            tier:            trust.tier,
            ageDays:         trust.details.age.days,
            newlyRegistered: trust.details.age.days >= 0 && trust.details.age.days < 30,
          }
        : null,
      response: {
        status:    fetched.status,
        redirects: fetched.redirects,
        bytes:     fetched.bytes,
      },
      meta: {
        checkedAt:  new Date().toISOString(),
        apiVersion: "1.0",
        paidWith:   "x402/USDC",
        cached:     false,
        degraded:   trust ? [] : ["domainTrust"],
      },
    };

    // Only cache modest responses — a 200-entry cache of 100 KB bodies would be
    // 20 MB of attacker-chosen content held for 10 minutes.
    if (text.length <= MAX_CACHE_TEXT) cache.set(cacheKey, result);
    res.json(result);

  } catch (err) {
    // Never echo which internal address a host resolved to.
    const msg = err instanceof BlockedHostError
      ? "Target host not permitted"
      : (err instanceof Error ? err.message : "Unknown error");
    res.status(502).json({
      error:   "Safe fetch failed",
      url:     target.toString(),
      message: msg,
      meta: { checkedAt: new Date().toISOString(), apiVersion: "1.0" },
    });
  }
});

export default router;
