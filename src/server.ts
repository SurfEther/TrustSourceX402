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

const PAID_PATHS = new Set(["/trustscore", "/sslcheck", "/headers", "/robots"]);

if (!PAY_TO || !PAY_TO.startsWith("0x")) {
  console.error("❌  PAY_TO_ADDRESS is missing or invalid in .env");
  process.exit(1);
}

// ─── x402 Setup ───────────────────────────────────────────────────────────────

const facilitatorClient = IS_MAINNET && process.env.CDP_API_KEY_ID
  ? new HTTPFacilitatorClient(
      createFacilitatorConfig(
        process.env.CDP_API_KEY_ID,
        process.env.CDP_API_KEY_SECRET!
      )
    )
  : new HTTPFacilitatorClient({ url: FACILITATOR });

const resourceServer = new x402ResourceServer(facilitatorClient);
registerExactEvmScheme(resourceServer);

// ─── App ──────────────────────────────────────────────────────────────────────

const app = express();
app.use(cors());
app.use(express.json());

// Trust Railway's single proxy hop — needed for req.protocol to detect HTTPS
// and for x402 to build the resource URL correctly in 402 responses.
app.set("trust proxy", 1);

// Rate limiter — uses a custom keyGenerator so we don't depend on trust proxy
// for IP detection (more secure than blanket trusting forwarded headers).
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return (req.headers["cf-connecting-ip"] as string) ||
           (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim() ||
           req.ip ||
           "unknown";
  },
  validate: {
    trustProxy:               false,   // we set it intentionally to 1
    keyGeneratorIpFallback:   false,   // we use our own IP detection
  },
});

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
app.use((req, res, next) => {
  if (!PAID_PATHS.has(req.path)) return next();
  const startedAt = Date.now();
  res.on("finish", () => {
    const ip =
      (req.headers["cf-connecting-ip"] as string) ||
      (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim() ||
      req.ip ||
      "unknown";
    const log = {
      evt:       "request",
      path:      req.path,
      query:     req.query,
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
    description: "Domain trust, SSL, security, and crawler-policy intelligence for AI agents — powered by x402",
    version:     "0.3.0",
    endpoints: {
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

app.use(openApiRouter);

// ─── x402 Paywall ─────────────────────────────────────────────────────────────

app.use(
  paymentMiddleware(
    {
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
                domain: "google.com", score: 90, tier: "TRUSTED",
                breakdown: { domainAge: 30, tld: 20, dnsPresence: 30, registrar: 10 },
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
        description: "robots.txt and AI-crawler policy check: tells an agent whether a website permits crawling and whether it blocks AI bots — GPTBot, ClaudeBot, Google-Extended, PerplexityBot, CCBot and 19 others — before scraping, RAG ingestion, training-data collection, or archiving. Returns a tier (OPEN/SELECTIVE/BLOCKED_AI/BLOCKED_ALL/NO_ROBOTS_TXT), per-bot allow/disallow rules, and sitemap URLs.",
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

app.use(limiter);
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
║  Facilitator: ${IS_MAINNET ? "CDP (production) " : "x402.org (public) "}║
╠═════════════════════════════════════════════════════════════════════════╣
║  Endpoints:                                          ║
║    GET /              → Landing / API info (free)    ║
║    GET /health        → Health check     (free)      ║
║    GET /openapi.json  → OpenAPI spec     (free)      ║
║    GET /trustscore    → Domain score     (0.003 USDC)║
║    GET /sslcheck      → SSL/TLS check    (0.002 USDC)║
║    GET /headers       → Header audit     (0.003 USDC)║
║    GET /robots        → robots.txt + AI  (0.002 USDC)║
╚══════════════════════════════════════════════════════╝
  `);
});
