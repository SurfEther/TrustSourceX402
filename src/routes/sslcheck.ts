import { Router, Request, Response } from "express";
import tls from "tls";

const router = Router();

// ─── Helpers ──────────────────────────────────────────────────────────────────

// Normalize string-or-array fields from getPeerCertificate.
// Node's TLS types return string | string[] for subject/issuer fields.
function asString(v: string | string[] | undefined | null): string {
  if (Array.isArray(v)) return v[0] || "";
  return v || "";
}

// Check if a Date is valid (not NaN, not Invalid Date)
function isValidDate(d: Date): boolean {
  return d instanceof Date && !isNaN(d.getTime());
}

// ─── Constants ────────────────────────────────────────────────────────────────

const VALID_DOMAIN_RE = /^[a-zA-Z0-9][a-zA-Z0-9\-.]{1,251}[a-zA-Z0-9]$/;
const PRIVATE_IP_RE   = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.0\.0\.0)/;

// Substrings that match established root certificate authority names.
// Match is case-insensitive and applied to both root and immediate issuer.
const TRUSTED_CAS = [
  "let's encrypt", "digicert", "globalsign", "sectigo", "comodo",
  "godaddy", "amazon", "google trust", "cloudflare", "entrust",
  "thawte", "geotrust", "rapidssl", "verisign", "buypass",
  "identrust", "actalis", "zerossl",
];

// Cipher name fragments indicating weak crypto.
// Modern HTTPS rarely uses these, but they exist on legacy servers.
const WEAK_CIPHER_FRAGMENTS = [
  "rc4", "des", "md5", "null", "export", "3des", "cbc-sha\b",
];

// ─── Cache (6 hour TTL — certs change infrequently) ───────────────────────────

interface CacheEntry {
  data:      Record<string, unknown>;
  expiresAt: number;
}
const cache = new Map<string, CacheEntry>();

function getCached(key: string): Record<string, unknown> | null {
  const entry = cache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) { cache.delete(key); return null; }
  return entry.data;
}

function setCached(key: string, data: Record<string, unknown>): void {
  cache.set(key, { data, expiresAt: Date.now() + 6 * 60 * 60 * 1000 });
  // Bound memory: evict oldest if over 1000 entries
  if (cache.size > 1000) {
    const firstKey = cache.keys().next().value;
    if (firstKey) cache.delete(firstKey);
  }
}

// ─── Domain extraction (matches trustscore.ts) ────────────────────────────────

function extractDomain(input: string): string | null {
  try {
    const withProto = input.startsWith("http") ? input : `https://${input}`;
    const hostname  = new URL(withProto).hostname.replace(/^www\./, "").toLowerCase();
    if (!hostname) return null;
    if (PRIVATE_IP_RE.test(hostname) || hostname === "localhost") return null;
    if (!VALID_DOMAIN_RE.test(hostname)) return null;
    return hostname;
  } catch {
    return null;
  }
}

// ─── TLS handshake ────────────────────────────────────────────────────────────

interface CertInfo {
  subject:        string;
  issuer:         string;
  validFrom:      string | null;
  validTo:        string | null;
  daysRemaining:  number | null;   // null if unparseable
  san:            string[];
  fingerprint256: string;
  serialNumber:   string;
  isSelfSigned:   boolean;
}

interface ChainInfo {
  depth:   number;
  valid:   boolean;
  trusted: boolean;
  rootCa:  string | null;
}

interface TlsResult {
  cert:       CertInfo;
  chain:      ChainInfo;
  protocol:   string | null;
  cipher:     { name: string; version: string } | null;
  authorized: boolean;
  authError:  string | null;
}

function fetchCertChain(domain: string, timeoutMs = 8000): Promise<TlsResult> {
  return new Promise((resolve, reject) => {
    // rejectUnauthorized: false → we WANT to see invalid certs, not throw on them.
    // The scoring logic uses authorized + authError to detect invalid chains.
    const socket = tls.connect({
      host:               domain,
      port:               443,
      servername:         domain,
      timeout:            timeoutMs,
      rejectUnauthorized: false,
      ALPNProtocols:      ["http/1.1"],
    }, () => {
      try {
        const peerCert = socket.getPeerCertificate(true);
        if (!peerCert || Object.keys(peerCert).length === 0) {
          socket.destroy();
          reject(new Error("No certificate presented"));
          return;
        }

        // Walk the chain. seen Set prevents infinite loops on self-referential certs.
        const chainCerts: typeof peerCert[] = [];
        const seen       = new Set<string>();
        let current      = peerCert;
        while (current && !seen.has(current.fingerprint256)) {
          seen.add(current.fingerprint256);
          chainCerts.push(current);
          if (current.issuerCertificate && current.issuerCertificate !== current) {
            current = current.issuerCertificate;
          } else {
            break;
          }
        }

        // Root CA identification (last cert in chain)
        const last     = chainCerts[chainCerts.length - 1];
        const rootO    = asString(last?.issuer?.O);
        const rootCN   = asString(last?.issuer?.CN);
        const rootCa: string | null = rootO || rootCN || null;

        // Trusted CA detection — check both root and immediate issuer
        const issuerOLower = asString(peerCert.issuer?.O).toLowerCase();
        const rootLower    = rootCa?.toLowerCase() ?? "";
        const trusted = TRUSTED_CAS.some(ca =>
          rootLower.includes(ca) || issuerOLower.includes(ca)
        );

        // Defensive date parsing — broken dates produce nulls, not NaN
        const validFromDate = new Date(peerCert.valid_from);
        const validToDate   = new Date(peerCert.valid_to);
        const validFrom     = isValidDate(validFromDate) ? validFromDate.toISOString() : null;
        const validTo       = isValidDate(validToDate)   ? validToDate.toISOString()   : null;
        const daysRemaining = isValidDate(validToDate)
          ? Math.floor((validToDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24))
          : null;

        // Self-signed detection — subject equals issuer
        const isSelfSigned =
          asString(peerCert.subject?.CN) === asString(peerCert.issuer?.CN) &&
          asString(peerCert.subject?.O)  === asString(peerCert.issuer?.O);

        // Parse SAN (Subject Alternative Names) — comma-separated "DNS:host" pairs
        const san = (peerCert.subjectaltname || "")
          .split(",")
          .map(s => s.trim().replace(/^DNS:/i, ""))
          .filter(Boolean)
          .slice(0, 20);

        const cipher  = socket.getCipher();
        const proto   = socket.getProtocol();
        const authErr = socket.authorizationError;

        const result: TlsResult = {
          cert: {
            subject:        asString(peerCert.subject?.CN) || asString(peerCert.subject?.O) || domain,
            issuer:         asString(peerCert.issuer?.O)   || asString(peerCert.issuer?.CN) || "unknown",
            validFrom,
            validTo,
            daysRemaining,
            san,
            fingerprint256: peerCert.fingerprint256 || "",
            serialNumber:   peerCert.serialNumber   || "",
            isSelfSigned,
          },
          chain: {
            depth:   chainCerts.length,
            valid:   !authErr,
            trusted: trusted && !isSelfSigned,
            rootCa,
          },
          protocol:   proto,
          cipher:     cipher ? { name: cipher.name, version: cipher.version } : null,
          authorized: socket.authorized,
          authError:  authErr ? String(authErr) : null,
        };

        socket.destroy();
        resolve(result);
      } catch (e) {
        socket.destroy();
        reject(e instanceof Error ? e : new Error(String(e)));
      }
    });

    socket.on("error",   err => { socket.destroy(); reject(err); });
    socket.on("timeout", ()  => { socket.destroy(); reject(new Error("TLS handshake timeout")); });
  });
}

// ─── Scoring ──────────────────────────────────────────────────────────────────

interface Score {
  total:     number;
  tier:      "VALID" | "WEAK" | "EXPIRING" | "EXPIRED" | "UNTRUSTED" | "INVALID";
  breakdown: Record<string, number>;
  warnings:  string[];
}

// Heuristic: detect weak cipher from name (e.g. "DES-CBC3-SHA")
function isCipherWeak(cipherName: string): boolean {
  const n = cipherName.toLowerCase();
  return WEAK_CIPHER_FRAGMENTS.some(f => n.includes(f.replace(/\\b/g, "")));
}

function scoreCertificate(result: TlsResult): Score {
  const breakdown: Record<string, number> = {
    chainValid:   0,   // 0–30
    trustedCa:    0,   // 0–25
    notExpired:   0,   // 0–25
    strongCrypto: 0,   // 0–10  (was signature algorithm; now cipher-based)
    modernTls:    0,   // 0–10
  };
  const warnings: string[] = [];

  // ── Chain validity (0–30) ─────────────────────────────────────────────────
  if (result.chain.valid && result.authorized) {
    breakdown.chainValid = 30;
  } else if (result.chain.valid) {
    breakdown.chainValid = 15;
    warnings.push("chain_warning");
  } else {
    warnings.push("invalid_chain");
    if (result.authError) warnings.push(`auth_error:${result.authError}`);
  }

  // ── Trusted CA (0–25) ──────────────────────────────────────────────────────
  if (result.cert.isSelfSigned) {
    warnings.push("self_signed");
  } else if (result.chain.trusted) {
    breakdown.trustedCa = 25;
  } else {
    breakdown.trustedCa = 5;
    warnings.push("untrusted_ca");
  }

  // ── Not expired (0–25) ─────────────────────────────────────────────────────
  // daysRemaining === null means cert dates are unparseable — score conservatively
  const days = result.cert.daysRemaining;
  if (days === null) {
    breakdown.notExpired = 0;
    warnings.push("unparseable_validity");
  } else if (days < 0) {
    warnings.push("expired");
  } else if (days < 7) {
    breakdown.notExpired = 5;
    warnings.push("expires_within_7_days");
  } else if (days < 30) {
    breakdown.notExpired = 15;
    warnings.push("expires_within_30_days");
  } else {
    breakdown.notExpired = 25;
  }

  // ── Strong crypto (0–10) — derived from cipher suite, not signature alg ────
  const cipherName = result.cipher?.name || "";
  if (!cipherName) {
    breakdown.strongCrypto = 0;
  } else if (isCipherWeak(cipherName)) {
    breakdown.strongCrypto = 0;
    warnings.push("weak_cipher");
  } else {
    breakdown.strongCrypto = 10;
  }

  // ── Modern TLS protocol (0–10) ─────────────────────────────────────────────
  const proto = result.protocol || "";
  if (proto === "TLSv1.3") {
    breakdown.modernTls = 10;
  } else if (proto === "TLSv1.2") {
    breakdown.modernTls = 7;
  } else if (proto) {
    breakdown.modernTls = 2;
    warnings.push("deprecated_tls");
  }

  const total = Object.values(breakdown).reduce((a, b) => a + b, 0);

  // ── Tier determination (priority order: expired > untrusted > invalid > exp soon) ──
  let tier: Score["tier"];
  if (days !== null && days < 0)         tier = "EXPIRED";
  else if (result.cert.isSelfSigned)     tier = "UNTRUSTED";
  else if (!result.chain.valid)          tier = "INVALID";
  else if (!result.chain.trusted)        tier = "UNTRUSTED";
  else if (days !== null && days < 7)    tier = "EXPIRING";
  else if (total < 70)                   tier = "WEAK";
  else                                   tier = "VALID";

  return { total, tier, breakdown, warnings };
}

// ─── Route ────────────────────────────────────────────────────────────────────

router.get("/sslcheck", async (req: Request, res: Response) => {
  const raw = (req.query.domain as string) || (req.query.url as string);

  if (!raw) {
    res.status(400).json({
      error:   "Missing parameter",
      message: "Provide ?domain=example.com or ?url=https://example.com",
    });
    return;
  }

  if (raw.length > 253) {
    res.status(400).json({
      error:   "Invalid input",
      message: "Domain must be 253 characters or fewer",
    });
    return;
  }

  const domain = extractDomain(raw);

  if (!domain || domain.length < 4 || !domain.includes(".")) {
    res.status(400).json({
      error:   "Invalid domain",
      message: "Must be a valid public domain (e.g. example.com)",
    });
    return;
  }

  // Cache hit
  const cached = getCached(domain);
  if (cached) {
    res.json({ ...cached, meta: { ...(cached.meta as object), cached: true } });
    return;
  }

  try {
    const tlsResult = await fetchCertChain(domain, 8000);
    const score     = scoreCertificate(tlsResult);

    const response = {
      domain,
      score:    score.total,
      maxScore: 100,
      tier:     score.tier,
      breakdown: score.breakdown,
      warnings: score.warnings,
      certificate: {
        subject:        tlsResult.cert.subject,
        issuer:         tlsResult.cert.issuer,
        validFrom:      tlsResult.cert.validFrom,
        validTo:        tlsResult.cert.validTo,
        daysRemaining:  tlsResult.cert.daysRemaining,
        san:            tlsResult.cert.san,
        fingerprint256: tlsResult.cert.fingerprint256,
        serialNumber:   tlsResult.cert.serialNumber,
        isSelfSigned:   tlsResult.cert.isSelfSigned,
      },
      chain: tlsResult.chain,
      connection: {
        protocol:   tlsResult.protocol,
        cipher:     tlsResult.cipher,
        authorized: tlsResult.authorized,
        authError:  tlsResult.authError,
      },
      meta: {
        checkedAt:  new Date().toISOString(),
        apiVersion: "1.0",
        paidWith:   "x402/USDC",
        cached:     false,
      },
    };

    setCached(domain, response);
    res.json(response);

  } catch (err) {
    const msg = err instanceof Error ? err.message : "Unknown error";
    res.status(502).json({
      error:   "SSL check failed",
      domain,
      message: msg,
      meta: { checkedAt: new Date().toISOString(), apiVersion: "1.0" },
    });
  }
});

export default router;
