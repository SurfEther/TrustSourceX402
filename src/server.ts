import "dotenv/config";
import express from "express";
import cors from "cors";
import { paymentMiddleware, x402ResourceServer } from "@x402/express";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { createFacilitatorConfig } from "@coinbase/x402";
import trustscoreRouter from "./routes/trustscore.js";

// ─── Config ───────────────────────────────────────────────────────────────────

const PORT          = process.env.PORT || 3000;
const PAY_TO        = process.env.PAY_TO_ADDRESS as `0x${string}`;
const NETWORK       = (process.env.NETWORK || "eip155:84532") as `${string}:${string}`;
const FACILITATOR   = process.env.FACILITATOR_URL || "https://facilitator.x402.org";

if (!PAY_TO || !PAY_TO.startsWith("0x")) {
  console.error("❌  PAY_TO_ADDRESS is missing or invalid in .env");
  console.error("    Copy .env.example → .env and fill in your Base wallet address.");
  process.exit(1);
}

// ─── x402 Setup ───────────────────────────────────────────────────────────────

const isMainnet = NETWORK === "eip155:8453";

const facilitatorClient = isMainnet && process.env.CDP_API_KEY_ID
  ? new HTTPFacilitatorClient(
      createFacilitatorConfig(
        process.env.CDP_API_KEY_ID,
        process.env.CDP_API_KEY_SECRET!
      )
    )
  : new HTTPFacilitatorClient({ url: FACILITATOR });

const resourceServer = new x402ResourceServer(facilitatorClient)
  .register("eip155:*", new ExactEvmScheme());

// ─── App ──────────────────────────────────────────────────────────────────────

const app = express();
app.use(cors());
app.use(express.json());

// ─── Free routes (no payment required) ───────────────────────────────────────

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
      docs:    "https://agentbrain.io/docs",
      status:  "https://agentbrain.io/status",
      bazaar:  "https://agentic.market",
    },
  });
});

app.get("/health", (_req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// ─── x402 Paywall middleware ───────────────────────────────────────────────────
// This intercepts requests to the routes below.
// If no payment header → returns HTTP 402 with price + wallet address.
// Agent pays USDC → retries request with proof → gets response.

app.use(
  paymentMiddleware(
    {
      "GET /trustscore": {
        accepts: {
          scheme:  "exact",
          price:   "$0.003",   // 0.003 USDC per lookup (~$0.003)
          network: NETWORK,
          payTo:   PAY_TO,
        },
        description: "Domain trust and safety score — returns score 0–100, tier, age, DNS, registrar data as JSON",
        mimeType:    "application/json",
      },
    },
    resourceServer,
  )
);

// ─── Paid routes ──────────────────────────────────────────────────────────────

app.use(trustscoreRouter);

// ─── 404 ──────────────────────────────────────────────────────────────────────

app.use((_req, res) => {
  res.status(404).json({ error: "Not found" });
});

// ─── Start ────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  const isTestnet = NETWORK.includes("84532");
  console.log(`
╔══════════════════════════════════════════════════════╗
║           AgentBrain API — Server Running            ║
╠══════════════════════════════════════════════════════╣
║  URL       : http://localhost:${PORT}                   ║
║  Network   : ${NETWORK} ${isTestnet ? "(TESTNET ✓)" : "(MAINNET)  "} ║
║  Pay to    : ${PAY_TO.slice(0, 10)}...                       ║
║  Facilitator: ${isTestnet ? "x402.org (public)" : "CDP (production)"}          ║
╠══════════════════════════════════════════════════════╣
║  Endpoints:                                          ║
║    GET /              → API info (free)              ║
║    GET /health        → Health check (free)          ║
║    GET /trustscore    → Domain score (0.003 USDC)    ║
╚══════════════════════════════════════════════════════╝
  `);

  if (isTestnet) {
    console.log("⚠️  TESTNET MODE — No real USDC required.");
    console.log("   Switch NETWORK=eip155:8453 and FACILITATOR_URL to CDP for production.\n");
  }
});
