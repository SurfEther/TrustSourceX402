---
name: trustsource-domain
description: Check a domain's trust score, TLS/SSL cert, HTTP security headers, and robots.txt/AI-bot policy before transacting with or trusting it. Four x402-paid checks in USDC, no API keys or signup.
license: MIT
---

# TrustSource — Domain Verification for Agents

TrustSource is a suite of four x402-paid HTTP APIs that let an agent verify any domain on demand. Each call costs $0.002–$0.003 in USDC on Base Mainnet, settled atomically per request via x402. No accounts. No signups. No API keys.

Use this skill any time you need to make a trust judgment about a URL or domain you did not source yourself — when an agent encounters a URL from an untrusted source, before sending a payment to a site, to confirm a TLS certificate is valid and not expiring, to grade a site's security headers, or to learn whether crawling is permitted. It applies to any request about checking, verifying, scoring, validating, or auditing a domain, website, URL, TLS certificate, SSL, HTTPS, security headers, robots.txt, or crawler permissions — even when the user does not name TrustSource explicitly.

## Quick reference

| Endpoint                   | Cost   | Use it when you need to know…                                        |
| -------------------------- | ------ | -------------------------------------------------------------------- |
| `GET /trustscore?domain=…` | $0.003 | …how legitimate a domain is overall (age, registrar, DNS, TLD risk)  |
| `GET /sslcheck?domain=…`   | $0.002 | …whether the TLS certificate is valid, trusted, and not expiring     |
| `GET /headers?url=…`       | $0.003 | …how well-hardened a site is (HSTS, CSP, X-Frame-Options grade A+–F) |
| `GET /robots?domain=…`     | $0.002 | …whether the site allows you (or AI bots in general) to crawl it     |

**Base URL:** `https://api.trustsource.cc` **OpenAPI spec:** `https://api.trustsource.cc/openapi.json` **Network:** Base Mainnet (chain ID 8453), USDC settlement

## Integration options

There are two ways to consume TrustSource. Pick based on whether your agent already has an x402-aware HTTP path.

1. **MCP server (zero payment code).** Run `npx -y trustsource-mcp` — also published in the official MCP Registry as `io.github.SurfEther/trustsource`. It exposes four tools — `trustsource_score`, `trustsource_ssl`, `trustsource_headers`, `trustsource_robots` — and handles the entire x402 settlement loop internally. You supply a funded Base wallet key via the `WALLET_PRIVATE_KEY` env var. This is the fastest path for MCP-capable agents and for AWS Bedrock AgentCore Gateway / Claude Desktop / any MCP client.
2. **Direct HTTP + x402.** Call the endpoints above with any x402-aware client (see next section). Use this when your agent already wraps `fetch` with payment handling, or when you don't want a separate MCP process.

## How x402 payment works

Every paid endpoint returns **HTTP 402 Payment Required** on the first call. The response includes a `PAYMENT-REQUIRED` header (base64-encoded JSON) containing the amount, network, recipient address, and accepted payment scheme.

The client signs an EIP-3009 USDC `transferWithAuthorization` for the exact amount, base64-encodes the signed payment, and retries the same request with an `X-PAYMENT` header. The Coinbase Developer Platform (CDP) facilitator settles on-chain and returns the JSON response.

In practice you do not write this by hand. Use `x402-fetch` (Node/TS) or any x402-aware HTTP client:

```
import { wrapFetchWithPayment } from "x402-fetch";
import { privateKeyToAccount } from "viem/accounts";

const account = privateKeyToAccount(process.env.WALLET_PRIVATE_KEY);
const fetch402 = wrapFetchWithPayment(fetch, account);

const res = await fetch402("https://api.trustsource.cc/trustscore?domain=example.com");
const data = await res.json();
```

The buyer wallet needs USDC on Base Mainnet and a small amount of ETH for gas. Use a low-balance hot wallet scoped to micropayments — never your primary treasury key.

## When to use which endpoint

### `/trustscore` — when you have just received a URL from an external source

**Triggers:** an LLM mentioned a domain in its output, a user-provided link, a redirect target, a competitor named in scraped content — anywhere the domain provenance is unclear.

Returns a 0–100 score and one of four tiers:

- **TRUSTED (75+)** — proceed
- **MODERATE (50–74)** — proceed with awareness
- **CAUTION (25–49)** — verify with additional checks (chain `/sslcheck` and `/headers`)
- **HIGH_RISK (0–24)** — refuse or escalate

Scoring inputs: WHOIS domain age, TLD risk class, DNS presence (A + MX records), registrar reputation.

Example response:

```
{
  "domain": "example.com",
  "score": 90,
  "tier": "TRUSTED",
  "breakdown": { "domainAge": 30, "tld": 20, "dnsPresence": 30, "registrar": 10 },
  "details": {
    "age": { "days": 10477, "label": "established (5+ years)" },
    "tld": ".com",
    "dns": { "hasARecord": true, "hasMxRecord": true, "mxRecords": ["..."] },
    "registrar": "markmonitor, inc."
  },
  "meta": { "checkedAt": "2026-05-26T12:00:00.000Z", "paidWith": "x402/USDC", "cached": false }
}
```

### `/sslcheck` — when you are about to make an HTTPS request to a domain you do not fully trust

**Triggers:** posting credentials, submitting a form, downloading code, hitting a webhook, anywhere a man-in-the-middle would matter.

Performs a real TLS handshake to port 443. Returns a 0–100 SSL score and tier:

- **VALID** — chain trusts a real root CA, certificate not expiring soon, modern TLS, strong crypto
- **EXPIRING** — certificate expires in under 30 days; still valid right now
- **WEAK** — outdated TLS version, weak signature, or short key
- **EXPIRED** — past its valid-to date; refuse
- **UNTRUSTED** — self-signed or unknown CA; refuse
- **INVALID** — handshake completed but the certificate is unusable (e.g. malformed, hostname mismatch with no usable cert); refuse

**How failures are reported.** A *completed* handshake that yields a bad certificate returns **HTTP 200** with tier `EXPIRED` / `UNTRUSTED` / `INVALID` — parse the body as a normal result. A connection that *cannot establish TLS at all* (port closed, no response, broken handshake) returns **HTTP 502** — treat that absence of a working cert as the negative signal itself, not as a transient error.

Key response fields:

- `certificate.daysRemaining` — integer, useful for early-warning alerting
- `certificate.signatureAlgorithm` — e.g. "RSA-SHA256"
- `chain.trusted` — boolean, true if root CA is in the Mozilla trust store
- `connection.protocol` — e.g. "TLSv1.3"
- `warnings` — array of human-readable issues

### `/headers` — when you are crawling, embedding, or auditing a site

**Triggers:** scraping for content, rendering in an iframe, including in a feed, training data ingestion, third-party JS embed, security review.

Audits HTTP security headers and returns a letter grade A+ through F:

- **HSTS** (Strict-Transport-Security)
- **CSP** (Content-Security-Policy)
- **X-Frame-Options**
- **X-Content-Type-Options**
- **Referrer-Policy**
- **Permissions-Policy**
- **Cross-Origin-* headers**

Grade interpretation: A+/A = enterprise-hardened, B = decent, C/D = legacy or careless, F = unhardened. Many major sites and marketing pages legitimately grade F — this is a defense-in-depth signal, not a vulnerability test.

### `/robots` — when you are an AI agent about to crawl content

**Triggers:** building training data, summarizing a page, archiving, RAG ingestion, sitemap discovery. **Always check before crawling at scale.**

Parses `robots.txt` and detects policies against 24 known AI crawlers (GPTBot, ClaudeBot, PerplexityBot, Google-Extended, CCBot, Bytespider, and others).

Returns a tier:

- **OPEN** — no robots.txt, or fully permissive
- **SELECTIVE** — blocks specific paths or some crawlers
- **BLOCKED_AI** — explicitly disallows AI training crawlers
- **BLOCKED_ALL** — `User-agent: *` `Disallow: /`
- **NO_ROBOTS_TXT** — file absent (legally permissive by convention, but verify per jurisdiction)

If `BLOCKED_AI` or `BLOCKED_ALL`, the agent should not crawl regardless of technical feasibility.

## Recommended decision flows

### Flow 1: agent receives an unknown URL from another LLM or tool

1. Call `/trustscore?domain={domain}` — $0.003
2. If `tier === "HIGH_RISK"` → refuse to interact
3. If `tier === "CAUTION"` → also call `/sslcheck` ($0.002) and `/headers` ($0.003); refuse if SSL is INVALID/EXPIRED/UNTRUSTED
4. If `tier === "TRUSTED"` or `"MODERATE"` → proceed

Worst-case cost: **$0.008 per unfamiliar domain**.

### Flow 2: agent about to crawl or scrape

1. Call `/robots?domain={domain}` first — $0.002
2. If `tier === "BLOCKED_AI"` or `"BLOCKED_ALL"` → stop; do not crawl
3. If `OPEN` or `SELECTIVE` → respect the specific disallow rules and proceed

Cost: **$0.002 per crawl target**.

### Flow 3: pre-flight before sending USDC, signing a transaction, or following a redirect to an unknown payment URL

1. Call `/trustscore` AND `/sslcheck` in parallel — $0.005 total
2. Require BOTH: trustscore tier ≥ MODERATE AND sslcheck tier === VALID
3. Otherwise refuse

## Caching and rate limits

- Responses cached server-side: 1 hour for `/trustscore` and `/sslcheck`, up to 12 hours for `/robots` and `/headers`. Cached responses still cost the standard rate — the cache reduces latency, not price.
- Rate limit: 60 requests per minute per source IP. Use response-aware backoff; the `Retry-After` header is set on 429.
- For high-volume use, deduplicate domains client-side before paying.

## Error handling

| Status | Meaning                                   | Agent action                                                       |
| ------ | ----------------------------------------- | ------------------------------------------------------------------ |
| 200    | Success                                   | Parse JSON, use result                                             |
| 400    | Bad input (invalid domain, missing param) | Do not retry with same input                                       |
| 402    | Payment required                          | Normal — sign and retry with `X-PAYMENT`                           |
| 429    | Rate limited                              | Wait `Retry-After` seconds, retry                                  |
| 500    | Lookup failed (WHOIS / DNS error)         | Retry once with delay; if still failing, treat as inconclusive     |
| 502    | TLS could not be established (`/sslcheck`) | This *is* the result — the domain has no working cert; treat as negative, do not retry as transient |

## Discovery

All four endpoints are indexed in Coinbase's Bazaar / Agentic.Market and reachable through the x402 Bazaar MCP server (including via AWS Bedrock AgentCore Gateway). Agents using the `@x402/extensions/bazaar` discovery flow find them automatically. Direct OpenAPI consumption: `https://api.trustsource.cc/openapi.json`.

## Limits and honest caveats

- **Caching means freshness is not real-time.** A cert that just expired might still return VALID for up to an hour after the change.
- **WHOIS data is registrar-dependent.** Some registrars hide creation dates; the response returns `days: -1` when unknown — do not treat that as low-trust on its own.
- **`/headers` grades are not security audits.** A site can grade F and still be perfectly safe; the grade reflects defense-in-depth, not active vulnerabilities.
- **TrustSource scores the perimeter, not page content.** Domain identity, transport security, header hygiene. For content-level safety (phishing, malware, IP reputation), pair with a dedicated scanner.

## Contact

- Web: <https://trustsource.cc>
- API: <https://api.trustsource.cc>
- Spec: <https://api.trustsource.cc/openapi.json>
- Discovery: <https://agentic.market>
- Issues: <https://github.com/SurfEther/trustsource-skills/issues>
- Email: <support@trustsource.cc>
