import { Router, Request, Response } from "express";

const router = Router();

const spec = {
  openapi: "3.1.0",
  info: {
    title:       "TrustSource API",
    version:     "1.0.0",
    description: "x402-powered domain trust and safety scoring API for AI agents. Returns structured trust intelligence on any domain — no API keys, no accounts. Pay per use with USDC via the x402 protocol.",
    contact: {
      url: "https://trustsource.cc",
    },
    license: {
      name: "Commercial",
      url:  "https://trustsource.cc/terms",
    },
  },
  servers: [
    {
      url:         "https://trustsource.cc",
      description: "Production (Base Mainnet)",
    },
  ],
  paths: {
    "/": {
      get: {
        operationId: "getApiInfo",
        summary:     "API discovery info",
        description: "Returns API metadata, available endpoints, pricing, and payment details. Free — no payment required.",
        tags:        ["Discovery"],
        responses: {
          "200": {
            description: "API info",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ApiInfo" },
              },
            },
          },
        },
      },
    },
    "/health": {
      get: {
        operationId: "getHealth",
        summary:     "Health check",
        description: "Returns server status. Free — no payment required.",
        tags:        ["Discovery"],
        responses: {
          "200": {
            description: "Server is healthy",
            content: {
              "application/json": {
                schema: {
                  type:       "object",
                  properties: {
                    status:    { type: "string", example: "ok" },
                    timestamp: { type: "string", format: "date-time" },
                  },
                },
              },
            },
          },
        },
      },
    },
    "/openapi.json": {
      get: {
        operationId: "getOpenApiSpec",
        summary:     "OpenAPI specification",
        description: "Returns this machine-readable OpenAPI 3.1 spec. Free — no payment required.",
        tags:        ["Discovery"],
        responses: {
          "200": {
            description: "OpenAPI spec",
            content: {
              "application/json": {
                schema: { type: "object" },
              },
            },
          },
        },
      },
    },
    "/trustscore": {
      get: {
        operationId: "getTrustScore",
        security:    [{ x402: [] }],
        summary:     "Domain trust and safety score",
        description: [
          "Returns a 0–100 trust score for any domain or URL.",
          "Analyzes domain age (WHOIS), TLD risk, DNS presence, and registrar reputation.",
          "Returns structured JSON including a tier (TRUSTED/MODERATE/CAUTION/HIGH_RISK),",
          "full scoring breakdown, and detailed signals.",
          "",
          "**Payment:** 0.003 USDC per call via x402 protocol (Base Mainnet).",
          "Clients must handle HTTP 402 responses by paying the specified amount",
          "and retrying with the payment proof header.",
          "",
          "**Caching:** Results are cached for 1 hour per domain.",
        ].join("\n"),
        tags: ["Trust"],
        parameters: [
          {
            name:        "domain",
            in:          "query",
            description: "Domain name to score (e.g. example.com)",
            required:    false,
            schema: {
              type:      "string",
              maxLength: 253,
              example:   "google.com",
            },
          },
          {
            name:        "url",
            in:          "query",
            description: "Full URL to score — domain is extracted automatically (e.g. https://example.com/path)",
            required:    false,
            schema: {
              type:    "string",
              example: "https://example.com/some/page",
            },
          },
        ],
        responses: {
          "200": {
            description: "Trust score returned successfully",
            content: {
              "application/json": {
                schema:  { $ref: "#/components/schemas/TrustScoreResponse" },
                example: {
                  domain:   "google.com",
                  score:    90,
                  maxScore: 100,
                  tier:     "TRUSTED",
                  breakdown: {
                    domainAge:   30,
                    tld:         20,
                    dnsPresence: 30,
                    registrar:   10,
                  },
                  details: {
                    age: {
                      days:    10477,
                      label:   "established (5+ years)",
                      created: "1997-09-15T07:00:00+0000",
                      expires: null,
                    },
                    tld: ".com",
                    dns: {
                      hasARecord:  true,
                      hasMxRecord: true,
                      mxRecords:   ["smtp.google.com"],
                    },
                    registrar: "markmonitor, inc.",
                  },
                  meta: {
                    checkedAt:  "2026-05-23T12:00:00.000Z",
                    apiVersion: "1.0",
                    paidWith:   "x402/USDC",
                    cached:     false,
                  },
                },
              },
            },
          },
          "400": {
            description: "Invalid or missing domain parameter",
            content: {
              "application/json": {
                schema:  { $ref: "#/components/schemas/ErrorResponse" },
                example: { error: "Missing parameter", message: "Provide ?domain=example.com or ?url=https://example.com" },
              },
            },
          },
          "402": {
            description: "Payment required — client must pay 0.003 USDC via x402 and retry",
            headers: {
              "PAYMENT-REQUIRED": {
                description: "Base64-encoded JSON payment requirements including price, network, and payTo address",
                schema: { type: "string" },
              },
            },
          },
          "429": {
            description: "Rate limit exceeded — max 60 requests per minute",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ErrorResponse" },
              },
            },
          },
          "500": {
            description: "Lookup failed — WHOIS or DNS error",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ErrorResponse" },
              },
            },
          },
        },
      },
    },
  },
  components: {
    schemas: {
      TrustScoreResponse: {
        type:     "object",
        required: ["domain", "score", "maxScore", "tier", "breakdown", "details", "meta"],
        properties: {
          domain:   { type: "string",  description: "The domain that was scored",     example: "google.com" },
          score:    { type: "integer", description: "Overall trust score (0–100)",     example: 90 },
          maxScore: { type: "integer", description: "Maximum possible score",          example: 100 },
          tier: {
            type:        "string",
            enum:        ["TRUSTED", "MODERATE", "CAUTION", "HIGH_RISK"],
            description: "Risk tier derived from score. TRUSTED=75+, MODERATE=50–74, CAUTION=25–49, HIGH_RISK=0–24",
            example:     "TRUSTED",
          },
          breakdown: {
            type:        "object",
            description: "Score contribution from each signal (all values sum to score)",
            properties: {
              domainAge:   { type: "integer", description: "Domain age score (0–30)",   example: 30 },
              tld:         { type: "integer", description: "TLD risk score (0–20)",     example: 20 },
              dnsPresence: { type: "integer", description: "DNS presence score (0–30)", example: 30 },
              registrar:   { type: "integer", description: "Registrar score (10–20)",   example: 10 },
            },
          },
          details: {
            type: "object",
            properties: {
              age: {
                type: "object",
                properties: {
                  days:    { type: "integer", description: "Domain age in days (-1 if unknown)", example: 10477 },
                  label:   { type: "string",  description: "Human-readable age label",           example: "established (5+ years)" },
                  created: { type: ["string", "null"], description: "Creation date from WHOIS",  example: "1997-09-15T07:00:00+0000" },
                  expires: { type: ["string", "null"], description: "Expiry date from WHOIS",    example: null },
                },
              },
              tld: { type: "string", description: "Top-level domain", example: ".com" },
              dns: {
                type: "object",
                properties: {
                  hasARecord:  { type: "boolean", description: "Domain resolves to an IP",    example: true },
                  hasMxRecord: { type: "boolean", description: "Domain has email (MX record)", example: true },
                  mxRecords:   { type: "array",   items: { type: "string" },                   example: ["smtp.google.com"] },
                },
              },
              registrar: { type: "string", description: "Domain registrar name from WHOIS", example: "markmonitor, inc." },
            },
          },
          meta: {
            type: "object",
            properties: {
              checkedAt:  { type: "string", format: "date-time", description: "ISO8601 timestamp of the check" },
              apiVersion: { type: "string", description: "API version", example: "1.0" },
              paidWith:   { type: "string", description: "Payment method", example: "x402/USDC" },
              cached:     { type: "boolean", description: "True if result was served from 1-hour cache", example: false },
            },
          },
        },
      },
      ErrorResponse: {
        type:       "object",
        properties: {
          error:   { type: "string", example: "Invalid domain" },
          message: { type: "string", example: "Must be a valid public domain (e.g. example.com)" },
        },
      },
      ApiInfo: {
        type: "object",
        properties: {
          name:        { type: "string", example: "AgentBrain API" },
          description: { type: "string" },
          version:     { type: "string", example: "0.1.0" },
          endpoints:   { type: "object" },
          payment:     { type: "object" },
          links:       { type: "object" },
        },
      },
    },
    securitySchemes: {
      x402: {
        type:        "http",
        scheme:      "x402",
        description: "Pay-per-use via x402 protocol. On a 402 response, read the PAYMENT-REQUIRED header, sign a USDC transfer on Base Mainnet, and retry with the X-PAYMENT header.",
      },
    },
  },
  "x-x402": {
    protocol:    "x402",
    version:     "2",
    currency:    "USDC",
    network:     "eip155:8453",
    facilitator: "https://api.cdp.coinbase.com/platform/v2/x402",
    discovery:   "https://agentic.market",
  },
};

router.get("/openapi.json", (_req: Request, res: Response) => {
  res.json(spec);
});

export default router;
