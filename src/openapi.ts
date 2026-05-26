import { Router, Request, Response } from "express";

const router = Router();

const spec = {
  openapi: "3.1.0",
  info: {
    title:       "TrustSource API",
    version:     "0.3.0",
    description: "x402-powered domain trust, SSL, security, and crawler-policy intelligence for AI agents. Returns structured JSON over four paid endpoints. No API keys — pay per use with USDC via x402 protocol.",
    contact: { url: "https://trustsource.cc" },
    license: { name: "Commercial", url:  "https://trustsource.cc/terms" },
  },
  servers: [
    { url: "https://trustsource.cc", description: "Production (Base Mainnet)" },
  ],
  tags: [
    { name: "Discovery", description: "Free endpoints — API info, health, this spec" },
    { name: "Trust",     description: "Paid endpoints — structured intelligence APIs" },
  ],
  paths: {
    // ─── Discovery (free) ─────────────────────────────────────────────────────

    "/": {
      get: {
        operationId: "getApiInfo",
        summary:     "API discovery info",
        description: "Returns API metadata, endpoint listing, pricing, and payment details. Browsers get the landing page HTML; agents/curl get JSON.",
        tags:        ["Discovery"],
        responses: {
          "200": {
            description: "API info",
            content: { "application/json": { schema: { $ref: "#/components/schemas/ApiInfo" } } },
          },
        },
      },
    },
    "/health": {
      get: {
        operationId: "getHealth",
        summary:     "Health check",
        description: "Server status. Free.",
        tags:        ["Discovery"],
        responses: {
          "200": {
            description: "Healthy",
            content: { "application/json": { schema: {
              type: "object",
              properties: {
                status:    { type: "string", example: "ok" },
                timestamp: { type: "string", format: "date-time" },
              },
            } } },
          },
        },
      },
    },
    "/openapi.json": {
      get: {
        operationId: "getOpenApiSpec",
        summary:     "OpenAPI specification",
        description: "Machine-readable OpenAPI 3.1 spec.",
        tags:        ["Discovery"],
        responses: { "200": { description: "OpenAPI spec" } },
      },
    },

    // ─── Trust APIs (paid) ────────────────────────────────────────────────────

    "/trustscore": {
      get: {
        operationId: "getTrustScore",
        security:    [{ x402: [] }],
        summary:     "Domain trust and safety score",
        description: [
          "Returns a 0–100 trust score for any domain or URL.",
          "Analyzes domain age (WHOIS), TLD risk, DNS presence, and registrar reputation.",
          "",
          "**Payment:** 0.003 USDC per call via x402 (Base Mainnet).",
          "**Caching:** 1 hour per domain.",
        ].join("\n"),
        tags: ["Trust"],
        parameters: [
          { name: "domain", in: "query", required: false,
            schema: { type: "string", maxLength: 253, example: "google.com" } },
          { name: "url", in: "query", required: false,
            schema: { type: "string", example: "https://example.com/page" } },
        ],
        responses: {
          "200": { description: "Trust score returned",
            content: { "application/json": {
              schema:  { $ref: "#/components/schemas/TrustScoreResponse" },
              example: {
                domain: "google.com", score: 90, maxScore: 100, tier: "TRUSTED",
                breakdown: { domainAge: 30, tld: 20, dnsPresence: 30, registrar: 10 },
                details: {
                  age: { days: 10477, label: "established (5+ years)" },
                  tld: ".com",
                  dns: { hasARecord: true, hasMxRecord: true, mxRecords: ["smtp.google.com"] },
                  registrar: "markmonitor, inc.",
                },
                meta: { checkedAt: "2026-05-25T12:00:00Z", paidWith: "x402/USDC", cached: false },
              },
            } },
          },
          "400": { description: "Invalid or missing domain" },
          "402": { description: "Payment required — pay 0.003 USDC via x402",
            headers: { "PAYMENT-REQUIRED": {
              description: "Base64-encoded payment requirements", schema: { type: "string" },
            } },
          },
          "429": { description: "Rate limit exceeded" },
          "500": { description: "Lookup failed" },
        },
      },
    },

    "/sslcheck": {
      get: {
        operationId: "getSslCheck",
        security:    [{ x402: [] }],
        summary:     "SSL/TLS certificate intelligence",
        description: [
          "Returns a 0–100 SSL/TLS score for any domain.",
          "Performs a live TLS handshake and analyzes the certificate chain,",
          "expiry, signature algorithm, trust anchor, and protocol version.",
          "",
          "**Payment:** 0.002 USDC per call via x402 (Base Mainnet).",
          "**Caching:** 6 hours per domain (certificates change rarely).",
        ].join("\n"),
        tags: ["Trust"],
        parameters: [
          { name: "domain", in: "query", required: false,
            schema: { type: "string", maxLength: 253, example: "google.com" } },
          { name: "url", in: "query", required: false,
            schema: { type: "string", example: "https://example.com/page" } },
        ],
        responses: {
          "200": { description: "SSL check completed",
            content: { "application/json": { schema: { $ref: "#/components/schemas/SslCheckResponse" } } },
          },
          "400": { description: "Invalid or missing domain" },
          "402": { description: "Payment required — pay 0.002 USDC via x402" },
          "429": { description: "Rate limit exceeded" },
          "502": { description: "TLS handshake failed (timeout, no cert, refused)" },
        },
      },
    },

    "/headers": {
      get: {
        operationId: "getHeaderAudit",
        security:    [{ x402: [] }],
        summary:     "HTTP security header audit",
        description: [
          "Analyzes HTTP response headers for security posture.",
          "Returns a letter grade (A+ to F) and 0–100 score across 8 dimensions:",
          "HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,",
          "Permissions-Policy, Cross-Origin-Opener-Policy, and server header disclosure.",
          "",
          "**Payment:** 0.003 USDC per call via x402 (Base Mainnet).",
          "**Caching:** 4 hours per URL.",
          "**Security:** Restricted to ports 80/443/8080/8443. Private IPs blocked.",
        ].join("\n"),
        tags: ["Trust"],
        parameters: [
          { name: "url", in: "query", required: false,
            schema: { type: "string", maxLength: 2048, example: "https://example.com" } },
          { name: "domain", in: "query", required: false,
            schema: { type: "string", maxLength: 253, example: "example.com" } },
        ],
        responses: {
          "200": { description: "Header audit completed",
            content: { "application/json": { schema: { $ref: "#/components/schemas/HeadersResponse" } } },
          },
          "400": { description: "Invalid URL or unsupported scheme/port" },
          "402": { description: "Payment required — pay 0.003 USDC via x402" },
          "429": { description: "Rate limit exceeded" },
          "502": { description: "Could not reach target URL" },
        },
      },
    },

    "/robots": {
      get: {
        operationId: "getRobotsCheck",
        security:    [{ x402: [] }],
        summary:     "robots.txt intelligence + AI bot policy",
        description: [
          "Fetches and parses robots.txt for any domain. Detects which AI training",
          "bots are blocked, partially restricted, or fully permitted. Tracks 24",
          "known AI bots (GPTBot, ClaudeBot, Google-Extended, PerplexityBot, Bytespider,",
          "CCBot, Applebot-Extended, and more). Extracts sitemap URLs.",
          "",
          "**Tiers:** OPEN / SELECTIVE / BLOCKED_AI / BLOCKED_ALL / NO_ROBOTS_TXT",
          "**Payment:** 0.002 USDC per call via x402 (Base Mainnet).",
          "**Caching:** 12 hours per domain.",
          "**Use case:** Crawler agents that need to respect site policies before fetching.",
        ].join("\n"),
        tags: ["Trust"],
        parameters: [
          { name: "domain", in: "query", required: false,
            schema: { type: "string", maxLength: 253, example: "example.com" } },
          { name: "url", in: "query", required: false,
            schema: { type: "string", example: "https://example.com" } },
        ],
        responses: {
          "200": { description: "robots.txt analyzed",
            content: { "application/json": { schema: { $ref: "#/components/schemas/RobotsResponse" } } },
          },
          "400": { description: "Invalid domain or unsupported scheme/port" },
          "402": { description: "Payment required — pay 0.002 USDC via x402" },
          "429": { description: "Rate limit exceeded" },
          "502": { description: "Could not fetch robots.txt" },
        },
      },
    },
  },

  // ─── Schemas ───────────────────────────────────────────────────────────────

  components: {
    schemas: {
      ApiInfo: {
        type: "object",
        properties: {
          name:        { type: "string", example: "TrustSource API" },
          description: { type: "string" },
          version:     { type: "string", example: "0.3.0" },
          endpoints:   { type: "object" },
          payment:     { type: "object" },
          links:       { type: "object" },
        },
      },

      TrustScoreResponse: {
        type:     "object",
        required: ["domain", "score", "maxScore", "tier", "breakdown", "details", "meta"],
        properties: {
          domain:   { type: "string" },
          score:    { type: "integer", description: "0–100" },
          maxScore: { type: "integer", example: 100 },
          tier: {
            type: "string",
            enum: ["TRUSTED", "MODERATE", "CAUTION", "HIGH_RISK"],
          },
          breakdown: {
            type: "object",
            properties: {
              domainAge:   { type: "integer", description: "0–30" },
              tld:         { type: "integer", description: "0–20" },
              dnsPresence: { type: "integer", description: "0–30" },
              registrar:   { type: "integer", description: "10–20" },
            },
          },
          details: {
            type: "object",
            properties: {
              age:       { type: "object" },
              tld:       { type: "string" },
              dns:       { type: "object" },
              registrar: { type: "string" },
            },
          },
          meta: { $ref: "#/components/schemas/Meta" },
        },
      },

      SslCheckResponse: {
        type:     "object",
        required: ["domain", "score", "maxScore", "tier", "breakdown", "certificate", "chain", "connection", "meta"],
        properties: {
          domain:    { type: "string" },
          score:     { type: "integer" },
          maxScore:  { type: "integer", example: 100 },
          tier: {
            type: "string",
            enum: ["VALID", "WEAK", "EXPIRING", "EXPIRED", "UNTRUSTED", "INVALID"],
          },
          breakdown: {
            type: "object",
            properties: {
              chainValid:   { type: "integer" },
              trustedCa:    { type: "integer" },
              notExpired:   { type: "integer" },
              strongCrypto: { type: "integer" },
              modernTls:    { type: "integer" },
            },
          },
          warnings:    { type: "array", items: { type: "string" } },
          certificate: {
            type: "object",
            properties: {
              subject:        { type: "string" },
              issuer:         { type: "string" },
              validFrom:      { type: ["string", "null"], format: "date-time" },
              validTo:        { type: ["string", "null"], format: "date-time" },
              daysRemaining:  { type: ["integer", "null"] },
              san:            { type: "array", items: { type: "string" } },
              fingerprint256: { type: "string" },
              serialNumber:   { type: "string" },
              isSelfSigned:   { type: "boolean" },
            },
          },
          chain: {
            type: "object",
            properties: {
              depth:   { type: "integer" },
              valid:   { type: "boolean" },
              trusted: { type: "boolean" },
              rootCa:  { type: ["string", "null"] },
            },
          },
          connection: {
            type: "object",
            properties: {
              protocol:   { type: ["string", "null"], example: "TLSv1.3" },
              cipher:     { type: ["object", "null"] },
              authorized: { type: "boolean" },
              authError:  { type: ["string", "null"] },
            },
          },
          meta: { $ref: "#/components/schemas/Meta" },
        },
      },

      HeadersResponse: {
        type:     "object",
        required: ["url", "grade", "score", "maxScore", "analysis", "warnings", "meta"],
        properties: {
          url:      { type: "string", format: "uri" },
          hostname: { type: "string" },
          grade: {
            type: "string",
            enum: ["A+", "A", "B", "C", "D", "F"],
          },
          score:    { type: "integer", description: "0–100" },
          maxScore: { type: "integer", example: 100 },
          analysis: {
            type: "object",
            properties: {
              hsts:                { $ref: "#/components/schemas/HeaderAnalysis" },
              csp:                 { $ref: "#/components/schemas/HeaderAnalysis" },
              xFrameOptions:       { $ref: "#/components/schemas/HeaderAnalysis" },
              xContentTypeOptions: { $ref: "#/components/schemas/HeaderAnalysis" },
              referrerPolicy:      { $ref: "#/components/schemas/HeaderAnalysis" },
              permissionsPolicy:   { $ref: "#/components/schemas/HeaderAnalysis" },
              coop:                { $ref: "#/components/schemas/HeaderAnalysis" },
              serverDisclosure:    { $ref: "#/components/schemas/HeaderAnalysis" },
            },
          },
          warnings: { type: "array", items: { type: "string" } },
          response: {
            type: "object",
            properties: {
              status:    { type: "integer" },
              redirects: { type: "integer" },
            },
          },
          meta: { $ref: "#/components/schemas/Meta" },
        },
      },

      HeaderAnalysis: {
        type: "object",
        properties: {
          present:  { type: "boolean" },
          value:    { type: ["string", "null"] },
          score:    { type: "integer" },
          maxScore: { type: "integer" },
          notes:    { type: "array", items: { type: "string" } },
        },
      },

      RobotsResponse: {
        type:     "object",
        required: ["domain", "exists", "tier", "aiFriendly", "meta"],
        properties: {
          domain: { type: "string" },
          exists: { type: "boolean", description: "Whether robots.txt was found" },
          tier: {
            type: "string",
            enum: ["OPEN", "SELECTIVE", "BLOCKED_AI", "BLOCKED_ALL", "NO_ROBOTS_TXT"],
            description: "Overall classification of crawl posture",
          },
          aiFriendly: { type: "boolean" },
          summary: {
            type: ["object", "null"],
            properties: {
              userAgentGroups: { type: "integer" },
              sitemaps:        { type: "integer" },
              rawLines:        { type: "integer" },
              truncated:       { type: "boolean", description: "True if robots.txt exceeded 100KB cap" },
              hasParseErrors:  { type: "boolean" },
            },
          },
          ai: {
            type: ["object", "null"],
            properties: {
              globalBlock:        { type: "boolean" },
              globalAllow:        { type: "boolean" },
              knownBotsChecked:   { type: "integer" },
              knownBotsBlocked:   { type: "integer" },
              knownBotsPartial:   { type: "integer" },
              policies: {
                type: "array",
                items: { $ref: "#/components/schemas/AiBotPolicy" },
              },
            },
          },
          sitemaps:   { type: "array", items: { type: "string", format: "uri" } },
          userAgents: {
            type: "array",
            items: {
              type: "object",
              properties: {
                userAgent:  { type: "string" },
                allow:      { type: "array", items: { type: "string" } },
                disallow:   { type: "array", items: { type: "string" } },
                crawlDelay: { type: ["number", "null"] },
              },
            },
          },
          response: {
            type: "object",
            properties: { status: { type: "integer" } },
          },
          meta: { $ref: "#/components/schemas/Meta" },
        },
      },

      AiBotPolicy: {
        type: "object",
        properties: {
          bot:     { type: "string", example: "GPTBot" },
          blocked: { type: "boolean" },
          partial: { type: "boolean" },
          rules: {
            type: "object",
            properties: {
              allow:    { type: "array", items: { type: "string" } },
              disallow: { type: "array", items: { type: "string" } },
            },
          },
        },
      },

      Meta: {
        type: "object",
        properties: {
          checkedAt:  { type: "string", format: "date-time" },
          apiVersion: { type: "string", example: "1.0" },
          paidWith:   { type: "string", example: "x402/USDC" },
          cached:     { type: "boolean" },
        },
      },

      ErrorResponse: {
        type: "object",
        properties: {
          error:   { type: "string" },
          message: { type: "string" },
        },
      },
    },

    securitySchemes: {
      x402: {
        type:        "http",
        scheme:      "x402",
        description: "Pay-per-use via x402 protocol. On 402, read PAYMENT-REQUIRED header, sign USDC transfer on Base Mainnet, retry with X-PAYMENT header.",
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
