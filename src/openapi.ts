import { Router, Request, Response } from "express";

const router = Router();

const spec = {
  openapi: "3.1.0",
  info: {
    title:       "TrustSource API",
    version:     "1.0.0",
    description: "x402-powered domain, SSL, security, and crawler-policy intelligence for AI agents. Four endpoints return structured trust intelligence on any domain — no API keys, no accounts. Pay per use with USDC via the x402 protocol on Base Mainnet.",
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
      url:         "https://api.trustsource.cc",
      description: "Production (Base Mainnet) — DNS-only, x402-aware",
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
    "/sslcheck": {
      get: {
        operationId: "getSslCheck",
        security:    [{ x402: [] }],
        summary:     "SSL/TLS certificate intelligence",
        description: [
          "Live TLS handshake to the target domain. Returns 0–100 SSL score, certificate",
          "chain details, expiry, trusted CA detection, TLS protocol version, cipher quality,",
          "and security warnings.",
          "",
          "**Payment:** 0.002 USDC per call via x402 protocol (Base Mainnet).",
          "**Caching:** Results are cached for 1 hour per domain.",
        ].join("\n"),
        tags: ["Trust"],
        parameters: [
          {
            name:        "domain",
            in:          "query",
            description: "Domain name to check (e.g. example.com)",
            required:    false,
            schema:      { type: "string", maxLength: 253, example: "google.com" },
          },
          {
            name:        "url",
            in:          "query",
            description: "Full URL — domain extracted automatically",
            required:    false,
            schema:      { type: "string", example: "https://example.com/page" },
          },
        ],
        responses: {
          "200": {
            description: "SSL check completed",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/SslCheckResponse" },
              },
            },
          },
          "400": { description: "Invalid or missing domain parameter" },
          "402": {
            description: "Payment required — 0.002 USDC via x402",
            headers: {
              "PAYMENT-REQUIRED": {
                description: "Base64-encoded JSON payment requirements",
                schema:      { type: "string" },
              },
            },
          },
          "429": { description: "Rate limit exceeded" },
          "502": { description: "TLS handshake failed (timeout, no cert, connection refused)" },
        },
      },
    },
    "/headers": {
      get: {
        operationId: "getSecurityHeaders",
        security:    [{ x402: [] }],
        summary:     "HTTP security header audit",
        description: [
          "Fetches the target URL and audits HTTP security headers (HSTS, CSP, X-Frame-Options,",
          "X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Cross-Origin-*). Returns",
          "a defense-in-depth letter grade A+ through F with per-header analysis and notes.",
          "",
          "**Note:** This is a hardening signal, not an active vulnerability scan. Many",
          "legitimate marketing sites grade F.",
          "",
          "**Payment:** 0.003 USDC per call via x402 protocol (Base Mainnet).",
          "**Caching:** Results cached up to 12 hours per URL.",
        ].join("\n"),
        tags: ["Trust"],
        parameters: [
          {
            name:        "url",
            in:          "query",
            description: "Full URL to audit (e.g. https://example.com)",
            required:    true,
            schema:      { type: "string", maxLength: 2048, example: "https://example.com" },
          },
        ],
        responses: {
          "200": {
            description: "Header audit completed",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/HeadersResponse" },
              },
            },
          },
          "400": { description: "Invalid or missing url parameter" },
          "402": {
            description: "Payment required — 0.003 USDC via x402",
            headers: {
              "PAYMENT-REQUIRED": {
                description: "Base64-encoded JSON payment requirements",
                schema:      { type: "string" },
              },
            },
          },
          "429": { description: "Rate limit exceeded" },
          "502": { description: "Fetch failed — target unreachable, blocked, or returned no usable response" },
        },
      },
    },
    "/robots": {
      get: {
        operationId: "getRobots",
        security:    [{ x402: [] }],
        summary:     "robots.txt + AI bot policy detection",
        description: [
          "Fetches and parses the target domain's robots.txt and detects policies across",
          "24 known AI crawlers (GPTBot, ClaudeBot, PerplexityBot, Google-Extended, CCBot,",
          "Bytespider, and more). Returns parsed rules, sitemap URLs, and an AI-friendliness",
          "tier (OPEN / SELECTIVE / BLOCKED_AI / BLOCKED_ALL / NO_ROBOTS_TXT).",
          "",
          "**Payment:** 0.002 USDC per call via x402 protocol (Base Mainnet).",
          "**Caching:** Results cached up to 12 hours per domain.",
        ].join("\n"),
        tags: ["Trust"],
        parameters: [
          {
            name:        "domain",
            in:          "query",
            description: "Domain name (e.g. example.com)",
            required:    true,
            schema:      { type: "string", maxLength: 253, example: "example.com" },
          },
        ],
        responses: {
          "200": {
            description: "robots.txt analysis completed",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/RobotsResponse" },
              },
            },
          },
          "400": { description: "Invalid or missing domain parameter" },
          "402": {
            description: "Payment required — 0.002 USDC via x402",
            headers: {
              "PAYMENT-REQUIRED": {
                description: "Base64-encoded JSON payment requirements",
                schema:      { type: "string" },
              },
            },
          },
          "429": { description: "Rate limit exceeded" },
          "502": { description: "robots.txt fetch failed" },
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
      SslCheckResponse: {
        type:     "object",
        required: ["domain", "score", "maxScore", "tier", "breakdown", "certificate", "chain", "connection", "meta"],
        properties: {
          domain:   { type: "string",  example: "google.com" },
          score:    { type: "integer", example: 100 },
          maxScore: { type: "integer", example: 100 },
          tier: {
            type: "string",
            enum: ["VALID", "WEAK", "EXPIRING", "EXPIRED", "UNTRUSTED", "INVALID"],
            description: "Risk tier based on certificate state and score",
          },
          breakdown: {
            type: "object",
            properties: {
              chainValid:   { type: "integer", description: "Certificate chain validity (0–30)" },
              trustedCa:    { type: "integer", description: "Trusted root CA (0–25)" },
              notExpired:   { type: "integer", description: "Expiry margin (0–25)" },
              strongCrypto: { type: "integer", description: "Signature strength (0–10)" },
              modernTls:    { type: "integer", description: "TLS protocol version (0–10)" },
            },
          },
          warnings: { type: "array", items: { type: "string" }, example: [] },
          certificate: {
            type: "object",
            properties: {
              subject:            { type: "string", example: "*.google.com" },
              issuer:             { type: "string", example: "Google Trust Services" },
              validFrom:          { type: "string", format: "date-time" },
              validTo:            { type: "string", format: "date-time" },
              daysRemaining:      { type: "integer", example: 67 },
              signatureAlgorithm: { type: "string", example: "RSA-SHA256" },
              san:                { type: "array", items: { type: "string" } },
              fingerprint256:     { type: "string" },
              serialNumber:       { type: "string" },
              isSelfSigned:       { type: "boolean" },
            },
          },
          chain: {
            type: "object",
            properties: {
              depth:   { type: "integer", example: 3 },
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
          meta: {
            type: "object",
            properties: {
              checkedAt:  { type: "string", format: "date-time" },
              apiVersion: { type: "string" },
              paidWith:   { type: "string", example: "x402/USDC" },
              cached:     { type: "boolean" },
            },
          },
        },
      },
      HeadersResponse: {
        type:     "object",
        required: ["url", "hostname", "grade", "score", "maxScore", "analysis", "warnings", "response", "meta"],
        properties: {
          url:      { type: "string", description: "The final URL after redirects", example: "https://example.com/" },
          hostname: { type: "string", description: "Hostname extracted from the URL", example: "example.com" },
          grade: {
            type:        "string",
            enum:        ["A+", "A", "B", "C", "D", "F"],
            description: "Defense-in-depth letter grade. A+/A = enterprise-hardened, B = decent, C/D = legacy, F = unhardened.",
            example:     "A",
          },
          score:    { type: "integer", description: "Numeric score backing the grade",   example: 82 },
          maxScore: { type: "integer", description: "Maximum possible score",             example: 100 },
          analysis: {
            type:        "object",
            description: "Per-header analysis. Each header is keyed by its lower-case name.",
            additionalProperties: { $ref: "#/components/schemas/HeaderAnalysis" },
            example: {
              "strict-transport-security": {
                present:  true,
                value:    "max-age=31536000; includeSubDomains",
                score:    20,
                maxScore: 20,
                notes:    ["HSTS enabled with 1-year max-age and subdomain coverage"],
              },
            },
          },
          warnings: {
            type:        "array",
            items:       { type: "string" },
            description: "Human-readable issues flagged during the audit",
            example:     ["Server header reveals nginx version"],
          },
          response: {
            type: "object",
            properties: {
              status:    { type: "integer", description: "Final HTTP status code", example: 200 },
              redirects: { type: "integer", description: "Number of redirects followed", example: 1 },
            },
          },
          meta: {
            type: "object",
            properties: {
              checkedAt:  { type: "string", format: "date-time" },
              apiVersion: { type: "string" },
              paidWith:   { type: "string", example: "x402/USDC" },
              cached:     { type: "boolean" },
            },
          },
        },
      },
      HeaderAnalysis: {
        type:     "object",
        required: ["present", "value", "score", "maxScore", "notes"],
        properties: {
          present:  { type: "boolean", description: "True if the header is present in the response" },
          value:    { type: ["string", "null"], description: "Raw header value or null if absent" },
          score:    { type: "integer", description: "Points awarded for this header's configuration" },
          maxScore: { type: "integer", description: "Maximum points this header could contribute" },
          notes:    { type: "array", items: { type: "string" }, description: "Human-readable observations" },
        },
      },
      RobotsResponse: {
        type:     "object",
        required: ["domain", "exists", "tier", "aiFriendly", "meta"],
        properties: {
          domain: { type: "string", example: "example.com" },
          exists: { type: "boolean", description: "True if a robots.txt file was found", example: true },
          tier: {
            type: "string",
            enum: ["OPEN", "SELECTIVE", "BLOCKED_AI", "BLOCKED_ALL", "NO_ROBOTS_TXT"],
            description: "Classification of overall crawler policy",
          },
          aiFriendly: {
            type:        "boolean",
            description: "True if AI training crawlers are not broadly blocked",
            example:     true,
          },
          summary: {
            type: ["object", "null"],
            properties: {
              userAgentGroups: { type: "integer", description: "Number of User-agent groups parsed", example: 3 },
              sitemaps:        { type: "integer", description: "Number of Sitemap declarations",      example: 1 },
              rawLines:        { type: "integer", description: "Total non-empty lines parsed",         example: 42 },
              truncated:       { type: "boolean", description: "True if response exceeded 100KB body cap" },
              hasParseErrors:  { type: "boolean", description: "True if any directive failed to parse" },
            },
          },
          ai: {
            type: ["object", "null"],
            description: "Per-AI-bot policy analysis across 24 known crawlers",
            properties: {
              globalBlock:      { type: "boolean", description: "True if User-agent: * Disallow: / is present" },
              globalAllow:      { type: "boolean", description: "True if User-agent: * Allow: / is present" },
              knownBotsChecked: { type: "integer", description: "Count of AI bots evaluated (currently 24)", example: 24 },
              knownBotsBlocked: { type: "integer", description: "Bots with full disallow rules",             example: 5 },
              knownBotsPartial: { type: "integer", description: "Bots with partial disallow rules",          example: 2 },
              policies: {
                type:        "array",
                description: "Per-bot policy details",
                items: {
                  type: "object",
                  properties: {
                    userAgent: { type: "string", example: "GPTBot" },
                    blocked:   { type: "boolean" },
                    partial:   { type: "boolean" },
                    disallow:  { type: "array", items: { type: "string" } },
                    allow:     { type: "array", items: { type: "string" } },
                  },
                },
              },
            },
          },
          sitemaps:   { type: "array", items: { type: "string" }, example: ["https://example.com/sitemap.xml"] },
          userAgents: { type: "array", items: { type: "string" }, example: ["*", "GPTBot", "Googlebot"] },
          response: {
            type: "object",
            properties: {
              status: { type: "integer", description: "HTTP status of the robots.txt fetch", example: 200 },
            },
          },
          meta: {
            type: "object",
            properties: {
              checkedAt:  { type: "string", format: "date-time" },
              apiVersion: { type: "string" },
              paidWith:   { type: "string", example: "x402/USDC" },
              cached:     { type: "boolean" },
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
          name:        { type: "string", example: "TrustSource API" },
          description: { type: "string" },
          version:     { type: "string", example: "0.3.0" },
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
