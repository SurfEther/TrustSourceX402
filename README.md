# TrustSource API

x402-powered verification APIs for AI agents — URL safety, email authentication, domain trust, SSL/TLS, security headers, robots.txt. Pay per use, no API keys, no accounts.

## Quick Start

### 1. Install dependencies
```bash
npm install
```

### 2. Configure environment
```bash
cp .env.example .env
```

Open `.env` and set **at minimum**:
```
PAY_TO_ADDRESS=0xYourBaseWalletAddress
```

Leave everything else as-is to run on **Base Sepolia testnet** (no real money).

### 3. Run the server
```bash
npm run dev
```

You should see the startup banner at `http://localhost:3000`.

---

## Testing the x402 Flow

### Free endpoints (no payment needed)
```bash
curl http://localhost:3000/
curl http://localhost:3000/health
```

### Paid endpoint — what an unpaid agent sees
```bash
curl http://localhost:3000/trustscore?domain=example.com
# Returns HTTP 402 with payment instructions in the PAYMENT-REQUIRED header
```

### Paid endpoint — bypass payment for local dev testing
The x402 testnet facilitator at `https://x402.org/facilitator` accepts test payments.
To fully test the payment flow, use an x402 client with a funded testnet wallet.

Get Base Sepolia testnet ETH: https://sepolia.base.org/faucet  
Get testnet USDC: https://faucet.circle.com (select Base Sepolia)

---

## Switching to Mainnet (Production)

1. In `.env`, change:
   ```
   NETWORK=eip155:8453
   FACILITATOR_URL=https://api.cdp.coinbase.com/platform/v2/x402
   CDP_API_KEY_ID=your-key-id
   CDP_API_KEY_SECRET=your-key-secret
   ```

2. Make sure your `PAY_TO_ADDRESS` Base wallet has some ETH for gas.

3. Your endpoints auto-list in the Bazaar/Agentic.Market after the first paid call clears.

---

## API Reference

### `GET /urlcheck`
One composite **CLEAR / REVIEW / BLOCK** safety verdict on any URL, fusing domain trust, a live TLS check, and typosquat/lookalike detection.

**Payment:** 0.01 USDC per call (via x402)

**Params:**
- `?url=https://example.com` — URL to vet
- `?domain=example.com` — bare domain (alternative)

**Response:**
```json
{
  "domain": "paypa1.com",
  "verdict": "BLOCK",
  "score": 12,
  "maxScore": 100,
  "reasons": ["possible lookalike of paypal.com (homoglyph_substitution, confidence 0.90)"],
  "signals": {
    "domainTrust": { "score": 12, "tier": "HIGH_RISK", "ageDays": 3, "newlyRegistered": true },
    "tls":         { "reachable": true, "valid": true, "tier": "VALID", "daysRemaining": 60 },
    "typosquat":   { "isLookalike": true, "nearestBrand": "paypal.com", "technique": "homoglyph_substitution", "confidence": 0.9 }
  },
  "meta": { "checkedAt": "...", "apiVersion": "1.0", "paidWith": "x402/USDC", "cached": false }
}
```

**Verdicts:** `CLEAR` (safe) · `REVIEW` (inspect before acting) · `BLOCK` (do not proceed)

---

### `GET /emailtrust`
Email-authentication posture grade (SPF/DKIM/DMARC/BIMI/MX) — is this sender domain spoofable?

**Payment:** 0.003 USDC per call (via x402)

**Params:**
- `?domain=example.com` — sender domain (or `user@example.com`)

**Response:**
```json
{
  "domain": "example.com",
  "grade": "C",
  "score": 45,
  "maxScore": 100,
  "spoofable": true,
  "spf":   { "present": true, "qualifier": "~all", "multiple": false },
  "dmarc": { "present": true, "policy": "none", "pct": 100, "rua": true },
  "dkim":  { "present": true, "selectorsFound": ["default"] },
  "bimi":  false,
  "mx":    ["mail.example.com"],
  "issues": ["dmarc_p_none_no_enforcement"],
  "meta": { "checkedAt": "...", "apiVersion": "1.0", "paidWith": "x402/USDC", "cached": false }
}
```

**Grades:** `A`/`B` = enforced, not spoofable · `C`/`D` = monitoring only, spoofable · `F` = no authentication

---

### `GET /trustscore`
Returns a 0–100 trust score for any domain.

**Payment:** 0.003 USDC per call (via x402)

**Params:**
- `?domain=example.com` — bare domain
- `?url=https://example.com/some/path` — full URL (domain extracted)

**Response:**
```json
{
  "domain": "example.com",
  "score": 80,
  "maxScore": 100,
  "tier": "TRUSTED",
  "breakdown": {
    "domainAge": 30,
    "tld": 20,
    "dnsPresence": 30,
    "registrar": 20
  },
  "details": {
    "age": { "days": 9720, "label": "established (5+ years)", "created": "...", "expires": "..." },
    "tld": ".com",
    "dns": { "hasARecord": true, "hasMxRecord": true, "mxRecords": ["mail.example.com"] },
    "registrar": "GoDaddy"
  },
  "meta": {
    "checkedAt": "2026-05-22T12:00:00.000Z",
    "apiVersion": "1.0",
    "paidWith": "x402/USDC"
  }
}
```

**Tiers:**
| Score | Tier |
|-------|------|
| 75–100 | `TRUSTED` |
| 50–74 | `MODERATE` |
| 25–49 | `CAUTION` |
| 0–24 | `HIGH_RISK` |

---

## Project Structure

```
trustsource/
├── src/
│   ├── server.ts          # Express app + x402 middleware, rate limiting, logging
│   ├── openapi.ts         # OpenAPI 3.1 spec served at /openapi.json
│   ├── lib/
│   │   ├── net-guard.ts   # Shared SSRF guard (private-IP checks, resolve + pin)
│   │   ├── domain.ts      # Shared domain extraction/validation
│   │   ├── cache.ts       # Shared in-memory TTL cache
│   │   ├── domain-trust.ts # Domain trust scoring (used by /trustscore + /urlcheck)
│   │   ├── tls-check.ts   # TLS handshake + cert scoring (used by /sslcheck + /urlcheck)
│   │   ├── typosquat.ts   # Lookalike/typosquat detection (used by /urlcheck)
│   │   └── mailauth.ts    # SPF/DKIM/DMARC/BIMI/MX analysis (used by /emailtrust)
│   └── routes/
│       ├── urlcheck.ts    # Composite CLEAR/REVIEW/BLOCK URL verdict
│       ├── emailtrust.ts  # Email-auth posture grade
│       ├── trustscore.ts  # WHOIS + DNS + TLD + registrar scoring
│       ├── sslcheck.ts    # Live TLS handshake + certificate scoring
│       ├── headers.ts     # HTTP security-header audit
│       └── robots.ts      # robots.txt + AI-bot policy detection
├── mcp-server/            # MCP server wrapping the six APIs as tools
├── public/                # Landing page
├── .env.example
├── .env                   # Your config (git-ignored)
├── package.json
└── tsconfig.json
```

---

## Roadmap

- [x] TrustScore API — domain trust scoring
- [x] SslCheck API — TLS/SSL certificate intelligence
- [x] Headers API — HTTP security-header audit
- [x] Robots API — robots.txt + AI-bot policy detection
- [x] **UrlCheck API — composite CLEAR/REVIEW/BLOCK URL safety verdict**
- [x] **EmailTrust API — SPF/DKIM/DMARC/BIMI/MX spoofability grade**
- [x] OpenAPI spec at `/openapi.json`
- [x] Bazaar / Agentic.Market discovery extension
- [x] MCP server (`trustsource-mcp`) wrapping all six APIs
- [ ] `/safefetch` — injection-safe content firewall (flagship)
- [ ] `/phishcheck` — typosquat + Certificate-Transparency detection
- [ ] `/kyb` — official-registry business-identity verification
- [ ] ResearchOracle (reshaped) — verification / source-trust oracle
