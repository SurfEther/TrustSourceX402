import "dotenv/config";
import express from "express";
import cors from "cors";
import rateLimit from "express-rate-limit";
import { paymentMiddleware, x402ResourceServer } from "@x402/express";
import { registerExactEvmScheme } from "@x402/evm/exact/server";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { createFacilitatorConfig } from "@coinbase/x402";
import { declareDiscoveryExtension } from "@x402/extensions/bazaar";
import trustscoreRouter from "./routes/trustscore.js";
import sslcheckRouter   from "./routes/sslcheck.js";
import headersRouter    from "./routes/headers.js";
import robotsRouter     from "./routes/robots.js";
import urlcheckRouter   from "./routes/urlcheck.js";
import emailtrustRouter from "./routes/emailtrust.js";
import openApiRouter    from "./openapi.js";
import path from "path";
import { fileURLToPath } from "url";

// ─── Path helpers ─────────────────────────────────────────────────────────────

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

// ─── Config ───────────────────────────────────────────────────────────────────

const PORT        = process.env.PORT || 3000;
const PAY_TO      = process.env.PAY_TO_ADDRESS as `0x${string}`;
const NETWORK     = (process.env.NETWORK || "eip155:84532") as `${string}:${string}`;
const FACILITATOR = process.env.FACILITATOR_URL || "https://x402.org/facilitator";
const IS_MAINNET  = NETWORK === "eip155:8453";

const PAID_PATHS = new Set(["/trustscore", "/sslcheck", "/headers", "/robots", "/urlcheck", "/emailtrust"]);

if (!PAY_TO || !PAY_TO.startsWith("0x")) {
  console.error("❌  PAY_TO_ADDRESS is missing or invalid in .env");
  process.exit(1);
}

// ─── x402 Setup ───────────────────────────────────────────────────────────────

// On mainnet, real USDC is at stake: require CDP facilitator credentials and
// fail fast. Otherwise the server would silently fall back to the public
// facilitator (which cannot settle mainnet payments) while advertising mainnet
// prices — clients would pay real USDC and every settlement would fail.
if (IS_MAINNET && (!process.env.CDP_API_KEY_ID || !process.env.CDP_API_KEY_SECRET)) {
  console.error(
    "❌  NETWORK is Base Mainnet but CDP_API_KEY_ID / CDP_API_KEY_SECRET are not set.\n" +
    "    Mainnet settlement requires CDP facilitator credentials — set both, or use a testnet NETWORK."
  );
  process.exit(1);
}

const usingCdp = IS_MAINNET; // guaranteed to have CDP creds past the guard above
const facilitatorClient = usingCdp
  ? new HTTPFacilitatorClient(
      createFacilitatorConfig(
        process.env.CDP_API_KEY_ID!,
        process.env.CDP_API_KEY_SECRET!
      )
    )
  : new HTTPFacilitatorClient({ url: FACILITATOR });

const resourceServer = new x402ResourceServer(facilitatorClient);
registerExactEvmScheme(resourceServer);

// ─── App ──────────────────────────────────────────────────────────────────────

const app = express();

// Don't advertise the framework. Our own /headers endpoint penalizes sites that
// expose X-Powered-By, so we shouldn't leak it ourselves.
app.disable("x-powered-by");

// Public agent-facing API with no cookies/credentials. Reflect any origin but
// forbid credentialed cross-origin requests and non-GET methods.
app.use(cors({
  origin:      true,
  methods:     ["GET", "OPTIONS"],
  credentials: false,
}));
app.use(express.json());

// Trust Railway's single proxy hop — needed for req.protocol to detect HTTPS,
// for x402 to build the resource URL correctly in 402 responses, and so that
// req.ip is the real client IP (used as the rate-limit key below).
app.set("trust proxy", 1);

// Rate limiter — 60 req/min per client IP. Keyed on req.ip (derived from the
// single trusted proxy hop), NOT a client-settable header like cf-connecting-ip:
// api.trustsource.cc is DNS-only (Cloudflare bypassed), so a direct caller could
// spoof cf-connecting-ip to mint a fresh bucket per request. Mounted BEFORE the
// paywall (see below) so it also throttles free routes and unpaid 402 floods.
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Safety net: ensure 402 responses always carry the PAYMENT-REQUIRED header.
// @x402/express in some configurations puts the v2 payload in the body only —
// this catches that case so Bazaar discovery validation passes.
app.use((_req, res, next) => {
  const originalJson = res.json.bind(res);
  res.json = (body: unknown) => {
    if (res.statusCode === 402 &&
        body && typeof body === "object" &&
        (body as { x402Version?: number }).x402Version === 2 &&
        !res.getHeader("PAYMENT-REQUIRED")) {
      const encoded = Buffer.from(JSON.stringify(body)).toString("base64");
      res.setHeader("PAYMENT-REQUIRED", encoded);
    }
    return originalJson(body);
  };
  next();
});

// ─── Settlement observability ────────────────────────────────────────────────
// Emits a structured JSON log on every request to a paid route, with the final
// status code so you can distinguish 402-issued from 200-settled. Greppable in
// Railway logs:
//   { "evt": "request" ... "status": 200 }  ← successful settlement
//   { "evt": "request" ... "status": 402 }  ← 402 issued, client never retried
//   { "evt": "request" ... "status": 429 }  ← rate-limited
// Filter your own test IPs with:  grep -v '"ip":"YOUR_TEST_IP"'
// Strip credentials and secret-bearing query values before logging. A caller
// can pass ?url=https://user:token@site/cb?apikey=SECRET — logging req.query
// verbatim would persist those secrets in Railway logs.
function sanitizeQueryForLog(query: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(query)) {
    if (typeof v !== "string") { out[k] = v; continue; }
    if (k === "url") {
      try {
        const u = new URL(v.match(/^https?:\/\//i) ? v : `https://${v}`);
        u.username = ""; u.password = ""; u.search = "";
        out[k] = u.origin + u.pathname;
      } catch { out[k] = "[unparseable]"; }
    } else {
      out[k] = v.slice(0, 253);
    }
  }
  return out;
}

app.use((req, res, next) => {
  if (!PAID_PATHS.has(req.path)) return next();
  const startedAt = Date.now();
  res.on("finish", () => {
    const ip = req.ip || "unknown";
    const log = {
      evt:       "request",
      path:      req.path,
      query:     sanitizeQueryForLog(req.query as Record<string, unknown>),
      status:    res.statusCode,
      settled:   res.statusCode === 200,
      ip,
      ua:        (req.headers["user-agent"] as string)?.slice(0, 120) ?? null,
      durationMs: Date.now() - startedAt,
      ts:        new Date().toISOString(),
    };
    console.log(JSON.stringify(log));
  });
  next();
});

// ─── Free routes ─────────────────────────────────────────────────────────────

app.get("/", (req, res) => {
  const wantHtml = req.headers.accept?.includes("text/html") ?? false;
  if (wantHtml) {
    res.sendFile(path.resolve("public/index.html"));
    return;
  }
  res.json({
    name:        "TrustSource API",
    description: "Domain trust, SSL, security, crawler-policy, URL-safety, and email-auth intelligence for AI agents — powered by x402",
    version:     "0.4.0",
    endpoints: {
      "GET /urlcheck": {
        description: "Composite URL safety verdict — CLEAR/REVIEW/BLOCK fusing trust + TLS + typosquat",
        price:       "$0.01 USDC",
        params:      { url: "string" },
        example:     "/urlcheck?url=https://example.com",
      },
      "GET /emailtrust": {
        description: "Email-auth posture grade — SPF/DKIM/DMARC/BIMI/MX, is this sender spoofable",
        price:       "$0.003 USDC",
        params:      { domain: "string" },
        example:     "/emailtrust?domain=example.com",
      },
      "GET /trustscore": {
        description: "Domain trust and safety scoring — WHOIS, DNS, TLD, registrar",
        price:       "$0.003 USDC",
        params:      { domain: "string" },
        example:     "/trustscore?domain=example.com",
      },
      "GET /sslcheck": {
        description: "SSL/TLS certificate intelligence — chain, expiry, crypto, TLS version",
        price:       "$0.002 USDC",
        params:      { domain: "string" },
        example:     "/sslcheck?domain=example.com",
      },
      "GET /headers": {
        description: "HTTP security header audit — HSTS, CSP, X-Frame-Options, A+/F grade",
        price:       "$0.003 USDC",
        params:      { url: "string" },
        example:     "/headers?url=https://example.com",
      },
      "GET /robots": {
        description: "robots.txt intelligence — crawl rules, AI bot policies, sitemap discovery",
        price:       "$0.002 USDC",
        params:      { domain: "string" },
        example:     "/robots?domain=example.com",
      },
    },
    payment: {
      protocol:    "x402",
      currency:    "USDC",
      network:     NETWORK,
      facilitator: FACILITATOR,
      payTo:       PAY_TO,
    },
    links: {
      docs:    "https://api.trustsource.cc/openapi.json",
      api:     "https://api.trustsource.cc",
      web:     "https://trustsource.cc",
      bazaar:  "https://agentic.market",
      contact: "mailto:hello@trustsource.cc",
    },
  });
});

app.get("/health", (_req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// ─── Discovery / crawl files (free, served for both trustsource.cc and the API
//     subdomain so LLM crawlers + agents can find the tools). Explicit routes
//     only — we never expose the rest of public/ or the repo. ─────────────────
const staticFile =
  (relPath: string, contentType: string) =>
  (_req: express.Request, res: express.Response) => {
    res.type(contentType).sendFile(path.resolve(relPath));
  };

app.get("/llms.txt",                 staticFile("public/llms.txt",                 "text/plain; charset=utf-8"));
app.get("/robots.txt",               staticFile("public/robots.txt",               "text/plain; charset=utf-8"));
app.get("/sitemap.xml",              staticFile("public/sitemap.xml",              "application/xml; charset=utf-8"));
app.get("/.well-known/security.txt", staticFile("public/.well-known/security.txt", "text/plain; charset=utf-8"));

app.use(openApiRouter);

// ─── x402 Paywall ─────────────────────────────────────────────────────────────

app.use(
  paymentMiddleware(
    {
      "GET /urlcheck": {
        accepts: [{ scheme: "exact", price: "$0.01", network: NETWORK, payTo: PAY_TO }],
        description: "Get a single CLEAR / REVIEW / BLOCK safety verdict on any URL before an agent clicks, fetches, submits data to, or transacts with it. Fuses domain trust (WHOIS age, TLD risk, DNS presence, registrar), a live TLS certificate check, and typosquat/lookalike-brand detection into one graded 0–100 answer with human-readable reasons — the go/no-go an agent can gate on instead of running and interpreting several separate checks itself.",
        mimeType: "application/json",
        extensions: {
          ...declareDiscoveryExtension({
            input: { url: "https://example.com" },
            inputSchema: {
              properties: { url: { type: "string", description: "URL or domain to vet (e.g. https://example.com or example.com)." } },
              required: ["url"],
            },
            output: {
              example: {
                domain: "example.com", verdict: "CLEAR", score: 90,
                signals: { domainTrust: { tier: "TRUSTED" }, tls: { tier: "VALID" }, typosquat: { isLookalike: false } },
              },
            },
          }),
        },
      },
      "GET /emailtrust": {
        accepts: [{ scheme: "exact", price: "$0.003", network: NETWORK, payTo: PAY_TO }],
        description: "Grade a domain's email-authentication posture (SPF, DKIM, DMARC, BIMI, MX) and tell an agent whether the sender can be spoofed. Returns an A–F grade, a `spoofable` flag, the parsed DMARC policy and SPF qualifier, and specific misconfiguration issues. Use to judge a sender domain before trusting an email, or to confirm your own outreach domain won't be silently rejected by Gmail/Yahoo/Microsoft's 2026 authentication rules.",
        mimeType: "application/json",
        extensions: {
          ...declareDiscoveryExtension({
            input: { domain: "example.com" },
            inputSchema: {
              properties: { domain: { type: "string", description: "Sender domain or email address to grade (e.g. example.com or user@example.com)." } },
              required: ["domain"],
            },
            output: {
              example: {
                domain: "example.com", grade: "C", spoofable: true,
                dmarc: { present: true, policy: "none" }, spf: { present: true, qualifier: "~all" },
              },
            },
          }),
        },
      },
      "GET /trustscore": {
        accepts: [{ scheme: "exact", price: "$0.003", network: NETWORK, payTo: PAY_TO }],
        description: "Verify whether a domain is legitimate and safe before transacting with it. Returns a 0–100 trust score and tier (TRUSTED/MODERATE/CAUTION/HIGH_RISK) derived from WHOIS domain age, TLD risk, DNS presence, and registrar reputation. Use to vet an unfamiliar URL, redirect target, or payment destination before sending USDC or trusting its content.",
        mimeType: "application/json",
        extensions: {
          ...declareDiscoveryExtension({
            input: { domain: "google.com" },
            inputSchema: {
              properties: { domain: { type: "string", description: "Domain name or full URL to score (e.g. example.com or https://example.com/path)." } },
              required: ["domain"],
            },
            output: {
              example: {
                domain: "google.com", score: 100, tier: "TRUSTED",
                breakdown: { domainAge: 30, tld: 20, dnsPresence: 30, registrar: 20 },
              },
            },
          }),
        },
      },
      "GET /sslcheck": {
        accepts: [{ scheme: "exact", price: "$0.002", network: NETWORK, payTo: PAY_TO }],
        description: "Check whether a domain's TLS/SSL certificate is valid, trusted, and not expiring before connecting to it. Performs a live handshake and returns a 0–100 score and tier (VALID/WEAK/EXPIRING/EXPIRED/UNTRUSTED/INVALID) with chain trust, days-to-expiry, signature algorithm, TLS version, and cipher quality. Use before submitting credentials, posting to a webhook, or following a payment link, to catch expired, self-signed, or MITM-risk certificates.",
        mimeType: "application/json",
        extensions: {
          ...declareDiscoveryExtension({
            input: { domain: "google.com" },
            inputSchema: {
              properties: { domain: { type: "string", description: "Domain to perform a live TLS handshake against (e.g. example.com); port 443 is assumed." } },
              required: ["domain"],
            },
            output: {
              example: {
                domain: "google.com", score: 100, tier: "VALID",
                breakdown: { chainValid: 30, trustedCa: 25, notExpired: 25, strongCrypto: 10, modernTls: 10 },
              },
            },
          }),
        },
      },
      "GET /headers": {
        accepts: [{ scheme: "exact", price: "$0.003", network: NETWORK, payTo: PAY_TO }],
        description: "Audit a site's HTTP security headers before embedding, scraping, or trusting it. Returns an A+ to F grade and 0–100 score with structured analysis of HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and Cross-Origin headers, plus server-header disclosure. A defense-in-depth signal for agents reviewing a site's security posture — not a vulnerability scan.",
        mimeType: "application/json",
        extensions: {
          ...declareDiscoveryExtension({
            input: { url: "https://example.com" },
            inputSchema: {
              properties: { url: { type: "string", description: "Full URL including scheme to audit (e.g. https://example.com). Follows up to 3 re-validated redirects." } },
              required: ["url"],
            },
            output: {
              example: {
                url: "https://example.com", grade: "A", score: 82, maxScore: 100,
              },
            },
          }),
        },
      },
      "GET /robots": {
        accepts: [{ scheme: "exact", price: "$0.002", network: NETWORK, payTo: PAY_TO }],
        description: "robots.txt and AI crawler policy check. Tells an agent whether a website permits crawling and whether it blocks AI bots such as GPTBot, ClaudeBot, Google-Extended, PerplexityBot and CCBot, before scraping, RAG ingestion, training data collection or archiving. Parses robots.txt and returns a crawl-policy tier with per-bot allow and disallow rules and sitemap URLs.",
        mimeType: "application/json",
        extensions: {
          ...declareDiscoveryExtension({
            input: { domain: "example.com" },
            inputSchema: {
              properties: { domain: { type: "string", description: "Domain whose robots.txt to fetch and parse (e.g. example.com); https is tried first, then http." } },
              required: ["domain"],
            },
            output: {
              example: {
                domain: "example.com", exists: true, tier: "SELECTIVE", aiFriendly: true,
                ai: { knownBotsChecked: 24, knownBotsBlocked: 5, knownBotsPartial: 2 },
              },
            },
          }),
        },
      },
    },
    resourceServer,
  )
);

// ─── Paid routes ──────────────────────────────────────────────────────────────

app.use(urlcheckRouter);
app.use(emailtrustRouter);
app.use(trustscoreRouter);
app.use(sslcheckRouter);
app.use(headersRouter);
app.use(robotsRouter);

// ─── 404 ─────────────────────────────────────────────────────────────────────

app.use((_req, res) => {
  res.status(404).json({ error: "Not found" });
});

// ─── Start ────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`
╔═════════════════════════════════════════════════════════════════════════╗
║          TrustSource API — Server Running                               ║
╠═════════════════════════════════════════════════════════════════════════╣
║  URL       : http://localhost:${PORT}                                   ║
║  Network   : ${NETWORK} ${IS_MAINNET ? "(MAINNET 🟢)" : "(TESTNET ✓) "} ║
║  Pay to    : ${PAY_TO.slice(0, 10)}...                                  ║
║  Facilitator: ${usingCdp ? "CDP (production) " : "x402.org (public) "}║
╠═════════════════════════════════════════════════════════════════════════╣
║  Endpoints:                                          ║
║    GET /              → Landing / API info (free)    ║
║    GET /health        → Health check     (free)      ║
║    GET /openapi.json  → OpenAPI spec     (free)      ║
║    GET /urlcheck      → URL safety verdict (0.010 USDC)║
║    GET /emailtrust    → Email-auth grade   (0.003 USDC)║
║    GET /trustscore    → Domain score     (0.003 USDC)║
║    GET /sslcheck      → SSL/TLS check    (0.002 USDC)║
║    GET /headers       → Header audit     (0.003 USDC)║
║    GET /robots        → robots.txt + AI  (0.002 USDC)║
╚══════════════════════════════════════════════════════╝
  `);
});
