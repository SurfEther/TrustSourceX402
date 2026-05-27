#!/usr/bin/env node
/**
 * TrustSource MCP Server
 *
 * Exposes the four TrustSource x402-paid HTTP APIs as MCP tools:
 *   - trustsource_score    — domain trust scoring ($0.003 USDC)
 *   - trustsource_ssl      — TLS/SSL certificate intelligence ($0.002 USDC)
 *   - trustsource_headers  — HTTP security header audit ($0.003 USDC)
 *   - trustsource_robots   — robots.txt + AI bot policy ($0.002 USDC)
 *
 * Payment is per-call in USDC on Base Mainnet via the x402 protocol.
 * The caller's wallet (set via WALLET_PRIVATE_KEY) must hold USDC and
 * a small amount of ETH for gas. No API keys.
 */

import "dotenv/config";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { x402Client, wrapFetchWithPayment } from "@x402/fetch";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";
import { z } from "zod";

// ─── Config ──────────────────────────────────────────────────────────────────

const BASE_URL =
  process.env.TRUSTSOURCE_API_URL?.replace(/\/$/, "") ??
  "https://api.trustsource.cc";

const PRIVATE_KEY = process.env.WALLET_PRIVATE_KEY;

if (!PRIVATE_KEY) {
  // Write to stderr so it does not interfere with the stdio transport.
  console.error(
    "[trustsource-mcp] FATAL: WALLET_PRIVATE_KEY environment variable is required.\n" +
      "Provide a Base Mainnet wallet private key that holds USDC and a small amount of ETH for gas.\n" +
      "See https://trustsource.cc for funding instructions.",
  );
  process.exit(1);
}

const signer   = privateKeyToAccount(PRIVATE_KEY as `0x${string}`);
const client   = new x402Client();
registerExactEvmScheme(client, { signer });
const fetch402 = wrapFetchWithPayment(fetch, client);

// ─── Helpers ─────────────────────────────────────────────────────────────────

type ToolResult = {
  content: { type: "text"; text: string }[];
  isError?: boolean;
};

async function callApi(path: string, params: Record<string, string>): Promise<ToolResult> {
  const qs = new URLSearchParams(params).toString();
  const url = `${BASE_URL}${path}?${qs}`;

  try {
    const res = await fetch402(url, { method: "GET" });
    const text = await res.text();

    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = { raw: text, status: res.status };
    }

    if (!res.ok) {
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: `HTTP ${res.status} from ${path}:\n${JSON.stringify(parsed, null, 2)}`,
          },
        ],
      };
    }

    return {
      content: [{ type: "text", text: JSON.stringify(parsed, null, 2) }],
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      isError: true,
      content: [
        {
          type: "text",
          text: `[trustsource-mcp] Request to ${path} failed: ${msg}`,
        },
      ],
    };
  }
}

// ─── Server ──────────────────────────────────────────────────────────────────

const server = new McpServer({
  name: "trustsource",
  version: "0.1.0",
});

// Tool 1: TrustScore — domain trust scoring
server.tool(
  "trustsource_score",
  "Score a domain's overall trustworthiness (0–100) using WHOIS age, TLD risk class, DNS presence (A + MX records), and registrar reputation. Returns tier TRUSTED (75+) / MODERATE (50–74) / CAUTION (25–49) / HIGH_RISK (0–24). Use before transacting with, recommending, or following links to an unfamiliar domain. Cost: $0.003 USDC per call. Cached 1 hour server-side.",
  {
    domain: z
      .string()
      .min(1)
      .max(253)
      .describe("Domain to score, e.g. 'example.com' (do not include scheme or path)"),
  },
  async ({ domain }) => callApi("/trustscore", { domain }),
);

// Tool 2: SslCheck — TLS certificate intelligence
server.tool(
  "trustsource_ssl",
  "Perform a live TLS handshake to a domain and return SSL/TLS certificate intelligence: chain validity, trusted root CA detection, expiry date and days remaining, signature algorithm, TLS protocol version, and cipher quality. Returns 0–100 score and tier VALID / EXPIRING / WEAK / EXPIRED / UNTRUSTED / INVALID. Use before sending credentials, posting forms, downloading code, or making any HTTPS request to a domain you do not fully trust. Cost: $0.002 USDC per call. Cached 1 hour server-side.",
  {
    domain: z
      .string()
      .min(1)
      .max(253)
      .describe("Domain to check, e.g. 'example.com'"),
  },
  async ({ domain }) => callApi("/sslcheck", { domain }),
);

// Tool 3: Headers — HTTP security header audit
server.tool(
  "trustsource_headers",
  "Audit a URL's HTTP security headers and return a defense-in-depth letter grade A+ through F. Checks HSTS (Strict-Transport-Security), Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and Cross-Origin-* headers. Use when crawling, embedding, building integrations against, or auditing a site. Note: many legitimate marketing sites grade F — this measures hardening, not active vulnerabilities. Cost: $0.003 USDC per call. Cached up to 12 hours server-side.",
  {
    url: z
      .string()
      .min(1)
      .max(2048)
      .describe("Full URL to audit, e.g. 'https://example.com'"),
  },
  async ({ url }) => callApi("/headers", { url }),
);

// Tool 4: Robots — robots.txt + AI bot policy
server.tool(
  "trustsource_robots",
  "Fetch and parse a domain's robots.txt, with policy detection across 24 known AI crawlers (GPTBot, ClaudeBot, PerplexityBot, Google-Extended, CCBot, Bytespider, etc.). Returns tier OPEN / SELECTIVE / BLOCKED_AI / BLOCKED_ALL / NO_ROBOTS_TXT. Use BEFORE any crawling, scraping, RAG ingestion, training-data collection, or page summarization. If tier is BLOCKED_AI or BLOCKED_ALL the agent should refuse to crawl. Cost: $0.002 USDC per call. Cached up to 12 hours server-side.",
  {
    domain: z
      .string()
      .min(1)
      .max(253)
      .describe("Domain to check, e.g. 'example.com'"),
  },
  async ({ domain }) => callApi("/robots", { domain }),
);

// ─── Boot ────────────────────────────────────────────────────────────────────

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`[trustsource-mcp] Connected. Buyer wallet: ${signer.address}`);
}

main().catch((err) => {
  console.error("[trustsource-mcp] FATAL:", err);
  process.exit(1);
});
