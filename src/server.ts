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
import openApiRouter from "./openapi.js";

// ─── Config ───────────────────────────────────────────────────────────────────

const PORT        = process.env.PORT || 3000;
const PAY_TO      = process.env.PAY_TO_ADDRESS as `0x${string}`;
const NETWORK     = (process.env.NETWORK || "eip155:84532") as `${string}:${string}`;
const FACILITATOR = process.env.FACILITATOR_URL || "https://x402.org/facilitator";
const IS_MAINNET  = NETWORK === "eip155:8453";

if (!PAY_TO || !PAY_TO.startsWith("0x")) {
  console.error("❌  PAY_TO_ADDRESS is missing or invalid in .env");
  console.error("    Copy .env.example → .env and fill in your Base wallet address.");
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
app.use(cors());
app.use(express.json());

// Rate limiter — max 60 paid requests/min per IP
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
});

// ─── Free routes ─────────────────────────────────────────────────────────────

app.get("/", (_req, res) => {
  res.json({
    name:        "AgentBrain API",
    description: "x402-powered intelligence APIs for AI agents",
    version:     "0.1.0",
    endpoints: {
      "GET /trustscore": {
        description: "Domain trust and safety scoring — pay per lookup",
        price:       "$0.003 USDC",
        network:     NETWORK,
        params:      { domain: "string (e.g. example.com or https://example.com)" },
        example:     "/trustscore?domain=example.com",
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
      docs:   "https://trustsource.cc/docs",
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
        accepts: [
          {
            scheme:  "exact",
            price:   "$0.003",
            network: NETWORK,
            payTo:   PAY_TO,
          },
        ],
        description: "Domain trust and safety scoring — returns a 0–100 trust score, tier (TRUSTED/MODERATE/CAUTION/HIGH_RISK), domain age, DNS records, and registrar data as structured JSON. Designed for AI agents verifying URLs before transacting.",
        mimeType: "application/json",
        extensions: {
          ...declareDiscoveryExtension({
            input: { domain: "google.com" },
            inputSchema: {
              properties: {
                domain: {
                  type:        "string",
                  description: "Domain name or full URL to score (e.g. example.com or https://example.com/path)",
                },
              },
              required: ["domain"],
            },
            output: {
              example: {
                domain:    "google.com",
                score:     90,
                maxScore:  100,
                tier:      "TRUSTED",
                breakdown: { domainAge: 30, tld: 20, dnsPresence: 30, registrar: 10 },
                details: {
                  age:       { days: 10477, label: "established (5+ years)" },
                  tld:       ".com",
                  dns:       { hasARecord: true, hasMxRecord: true },
                  registrar: "MarkMonitor, Inc.",
                },
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

// ─── 404 ─────────────────────────────────────────────────────────────────────

app.use((_req, res) => {
  res.status(404).json({ error: "Not found" });
});

// ─── Start ────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════╗
║           AgentBrain API — Server Running            ║
╠══════════════════════════════════════════════════════╣
║  URL       : http://localhost:${PORT}                   ║
║  Network   : ${NETWORK} ${IS_MAINNET ? "(MAINNET 🟢)" : "(TESTNET ✓) "} ║
║  Pay to    : ${PAY_TO.slice(0, 10)}...                       ║
║  Facilitator: ${IS_MAINNET ? "CDP (production) " : "x402.org (public) "}         ║
╠══════════════════════════════════════════════════════╣
║  Endpoints:                                          ║
║    GET /              → API info (free)              ║
║    GET /health        → Health check (free)          ║
║    GET /trustscore    → Domain score (0.003 USDC)    ║
╚══════════════════════════════════════════════════════╝
  `);
});