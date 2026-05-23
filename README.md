# AgentBrain API

x402-powered intelligence APIs for AI agents. Pay per use, no API keys, no accounts.

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
The x402 testnet facilitator at `https://facilitator.x402.org` accepts test payments.
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
agentbrain/
├── src/
│   ├── server.ts          # Express app + x402 middleware
│   └── routes/
│       └── trustscore.ts  # Domain analysis logic
├── .env.example
├── .env                   # Your config (git-ignored)
├── package.json
└── tsconfig.json
```

---

## Roadmap

- [x] Phase 1: TrustScore API
- [ ] Phase 2: ResearchOracle API
- [ ] Phase 3: SkillForge API
- [ ] Phase 4: Bazaar/Agentic.Market listing
- [ ] Phase 5: Cloudflare Workers deployment
