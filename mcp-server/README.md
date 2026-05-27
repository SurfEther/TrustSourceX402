# trustsource-mcp

MCP server exposing the [TrustSource](https://trustsource.cc) suite of x402-paid domain verification APIs to any MCP-compatible client (Claude Desktop, Claude Code, Cline, Continue, etc.).

Four tools, each settled per-call in USDC on Base Mainnet. No API keys, no signups, no accounts — just a wallet.

## Tools

| Tool | Cost | What it does |
|---|---|---|
| `trustsource_score` | $0.003 USDC | Domain trust score 0–100 (WHOIS age, TLD, DNS, registrar) |
| `trustsource_ssl` | $0.002 USDC | TLS certificate intelligence (chain, expiry, CA trust, TLS version) |
| `trustsource_headers` | $0.003 USDC | HTTP security header audit (A+ to F grade) |
| `trustsource_robots` | $0.002 USDC | robots.txt + AI bot policy across 24 known crawlers |

## Install

```bash
npm install -g trustsource-mcp
```

Or run without installing:

```bash
npx -y trustsource-mcp
```

## Configure

The server needs a Base Mainnet wallet private key. The wallet must hold:
- A few cents of USDC (for paying per-call fees)
- A small amount of ETH (for gas)

Set the private key in your MCP client's environment, **not** in any committed file.

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "trustsource": {
      "command": "npx",
      "args": ["-y", "trustsource-mcp"],
      "env": {
        "WALLET_PRIVATE_KEY": "0xYOUR_BASE_MAINNET_PRIVATE_KEY"
      }
    }
  }
}
```

Restart Claude Desktop. The four tools appear automatically.

### Cline / Continue / other MCP clients

Add to your client's MCP server configuration:

```json
{
  "trustsource": {
    "command": "npx",
    "args": ["-y", "trustsource-mcp"],
    "env": {
      "WALLET_PRIVATE_KEY": "0x..."
    }
  }
}
```

### Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `WALLET_PRIVATE_KEY` | yes | — | Base Mainnet wallet private key with USDC + ETH for gas |
| `TRUSTSOURCE_API_URL` | no | `https://api.trustsource.cc` | Override the API base URL (useful for testing) |

## How it works

1. The MCP client calls a tool (e.g. `trustsource_score`).
2. This server makes an HTTP request to the corresponding TrustSource endpoint.
3. The API returns HTTP 402 with a `PAYMENT-REQUIRED` header.
4. `x402-fetch` signs an EIP-3009 USDC `transferWithAuthorization` for the exact amount.
5. The request is retried with the signed payment in `X-PAYMENT`.
6. The Coinbase Developer Platform facilitator settles on-chain.
7. The API returns the JSON response. The MCP client receives the result.

Total latency per call: typically 1–3 seconds including settlement.

## Cost discipline

If your agent is making many calls, deduplicate by domain client-side before invoking tools. The API caches responses (1 hour for `/trustscore` and `/sslcheck`, up to 12 hours for `/robots` and `/headers`), but the cache reduces latency, not price — every call costs the same regardless of whether it hits cache.

Worst-case full domain audit: `trustsource_score` + `trustsource_ssl` + `trustsource_headers` + `trustsource_robots` = $0.010 USDC.

## Build from source

```bash
git clone https://github.com/SurfEther/TrustSourceX402.git
cd trustsource/mcp-server
npm install
npm run build
npm start
```

## Links

- TrustSource site: https://trustsource.cc
- OpenAPI spec: https://api.trustsource.cc/openapi.json
- Discoverable in Bazaar: https://agentic.market
- Contact: hello@trustsource.cc

## License

MIT
