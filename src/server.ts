import "dotenv/config";
import express from "express";
import cors from "cors";
import rateLimit from "express-rate-limit";
import { paymentMiddleware, x402ResourceServer } from "@x402/express";
import { ExactEvmScheme } from "@x402/evm/exact/server";
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

const resourceServer = new x402ResourceServer(facilitatorClient)
  .register(NETWORK, new ExactEvmScheme());

// ─── App ──────────────────────────────────────────────────────────────────────

const app = express();

app.set("trust proxy", true);
app.use(cors());
app.use(express.json());

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
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
      docs:   "https://trustsource.cc/openapi.json",
      bazaar: "https://agentic.market",
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
        description: "Domain trust and safety scoring — returns 0–100 score, tier (TRUSTED/MODERATE/CAUTION/HIGH_RISK), domain age, DNS records, registrar. For agents verifying URLs before transacting.",
        mimeType: "application/json",
        extensions: {
          ...declareDiscoveryExtension({
            input: { domain: "google.com" },
            inputSchema: {
              properties: { domain: { type: "string", description: "Domain or full URL" } },
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
        description: "SSL/TLS certificate intelligence — returns 0–100 score, tier (VALID/WEAK/EXPIRING/EXPIRED/UNTRUSTED/INVALID), chain details, expiry, signature, TLS protocol, cipher quality.",
        mimeType: "application/json",
        extensions: {
          ...declareDiscoveryExtension({
            input: { domain: "google.com" },
            inputSchema: {
              properties: { domain: { type: "string" } },
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
        description: "HTTP security headers analyzer — returns A+ to F grade with 0–100 score plus structured analysis of HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Cross-Origin-Opener-Policy, server header disclosure. For agents auditing site security posture.",
        mimeType: "application/json",
        extensions: {
          ...declareDiscoveryExtension({
            input: { url: "https://example.com" },
            inputSchema: {
              properties: { url: { type: "string" } },
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
        description: "robots.txt intelligence — parses crawl rules and detects AI bot policies (GPTBot, ClaudeBot, Google-Extended, PerplexityBot, etc.). Returns tier (OPEN/SELECTIVE/BLOCKED_AI/BLOCKED_ALL/NO_ROBOTS_TXT), per-bot allow/disallow analysis, sitemap URLs. For crawler agents that need to respect site policies.",
        mimeType: "application/json",
        extensions: {
          ...declareDiscoveryExtension({
            input: { domain: "example.com" },
            inputSchema: {
              properties: { domain: { type: "string" } },
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
╔══════════════════════════════════════════════════════╗
║          TrustSource API — Server Running           ║
╠══════════════════════════════════════════════════════╣
║  URL       : http://localhost:${PORT}                   ║
║  Network   : ${NETWORK} ${IS_MAINNET ? "(MAINNET 🟢)" : "(TESTNET ✓) "} ║
║  Pay to    : ${PAY_TO.slice(0, 10)}...                       ║
║  Facilitator: ${IS_MAINNET ? "CDP (production) " : "x402.org (public) "}         ║
╠══════════════════════════════════════════════════════╣
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
