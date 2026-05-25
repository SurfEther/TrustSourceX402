import { Router, Request, Response } from "express";
import tls from "tls";
import { X509Certificate } from "crypto";

const router = Router();

// ─── Constants ────────────────────────────────────────────────────────────────

const VALID_DOMAIN_RE = /^[a-zA-Z0-9][a-zA-Z0-9\-.]{1,251}[a-zA-Z0-9]$/;
const PRIVATE_IP_RE   = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.0\.0\.0)/;

// Trusted root CAs by issuer organization name fragment
const TRUSTED_CAS = [
  "let's encrypt", "digicert", "globalsign", "sectigo", "comodo",
  "godaddy", "amazon", "google trust", "cloudflare", "entrust",
  "thawte", "geotrust", "rapidssl", "verisign", "buypass",
  "identrust", "actalis", "zerossl",
];

// Weak / deprecated signature algorithms
const WEAK_SIGNATURES = ["md5", "sha1"];

// ─── Cache ────────────────────────────────────────────────────────────────────

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
  // 6 hour TTL — certs change rarely
  cache.set(key, { data, expiresAt: Date.now() + 6 * 60 * 60 * 1000 });
  if (cache.size > 1000) {
    const firstKey = cache.keys().next().value;
    if (firstKey) cache.delete(firstKey);
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

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

interface CertInfo {
  subject:             string;
  issuer:              string;
  validFrom:           string;
  validTo:             string;
  daysRemaining:       number;
  signatureAlgorithm:  string;
  san:                 string[];
  fingerprint256:      string;
  serialNumber:        string;
  isSelfSigned:        boolean;
}

interface ChainInfo {
  depth:    number;
  valid:    boolean;
  trusted:  boolean;
  rootCa:   string | null;
}

interface TlsResult {
  cert:        CertInfo;
  chain:       ChainInfo;
  protocol:    string | null;
  cipher:      { name: string; version: string } | null;
  authorized:  boolean;
  authError:   string | null;
}

function fetchCertChain(domain: string, timeoutMs = 8000): Promise<TlsResult> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host:               domain,
      port:               443,
      servername:         domain,
      timeout:            timeoutMs,
      rejectUnauthorized: false,        // we WANT to see invalid certs, not throw
      ALPNProtocols:      ["http/1.1"],
    }, () => {
      try {
        const peerCert = socket.getPeerCertificate(true);
        if (!peerCert || Object.keys(peerCert).length === 0) {
          socket.destroy();
          reject(new Error("No certificate presented"));
          return;
        }

        // Walk the chain
        const chainCerts: typeof peerCert[] = [];
        let current = peerCert;
        const seen  = new Set<string>();
        while (current && !seen.has(current.fingerprint256)) {
          seen.add(current.fingerprint256);
          chainCerts.push(current);
          if (current.issuerCertificate && current.issuerCertificate !== current) {
            current = current.issuerCertificate;
          } else {
            break;
          }
        }

        const last      = chainCerts[chainCerts.length - 1];
        const rootCa    = last?.issuer?.O || last?.issuer?.CN || null;
        const trusted   = TRUSTED_CAS.some(ca =>
          (rootCa?.toLowerCase().includes(ca) ?? false) ||
          (peerCert.issuer?.O?.toLowerCase().includes(ca) ?? false)
        );

        // Signature algorithm — extract from raw cert
        let signatureAlgorithm = "unknown";
        try {
          if (peerCert.raw) {
            const x509 = new X509Certificate(peerCert.raw);
            signatureAlgorithm = x509.sigalg || "unknown";
          }
        } catch { /* ignore */ }

        const validFrom = new Date(peerCert.valid_from).toISOString();
        const validTo   = new Date(peerCert.valid_to).toISOString();
        const days      = Math.floor(
          (new Date(peerCert.valid_to).getTime() - Date.now()) / (1000 * 60 * 60 * 24)
        );

        const isSelfSigned =
          peerCert.subject?.CN === peerCert.issuer?.CN &&
          peerCert.subject?.O  === peerCert.issuer?.O;

        const cipher  = socket.getCipher();
        const proto   = socket.getProtocol();
        const authErr = socket.authorizationError;

        const result: TlsResult = {
          cert: {
            subject:            peerCert.subject?.CN || peerCert.subject?.O || domain,
            issuer:             peerCert.issuer?.O   || peerCert.issuer?.CN || "unknown",
            validFrom,
            validTo,
            daysRemaining:      days,
            signatureAlgorithm,
            san:                (peerCert.subjectaltname || "")
              .split(",")
              .map(s => s.trim().replace(/^DNS:/, ""))
              .filter(Boolean)
              .slice(0, 20),
            fingerprint256:     peerCert.fingerprint256 || "",
            serialNumber:       peerCert.serialNumber || "",
            isSelfSigned,
          },
          chain: {
            depth:   chainCerts.length,
            valid:   !authErr,
            trusted: trusted && !isSelfSigned,
            rootCa,
          },
          protocol: proto,
          cipher:   cipher ? { name: cipher.name, version: cipher.version } : null,
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
  total:      number;
  tier:       "VALID" | "WEAK" | "EXPIRING" | "EXPIRED" | "UNTRUSTED" | "INVALID";
  breakdown:  Record<string, number>;
  warnings:   string[];
}

function scoreCertificate(result: TlsResult): Score {
  const breakdown: Record<string, number> = {
    chainValid:   0,   // 0–30
    trustedCa:    0,   // 0–25
    notExpired:   0,   // 0–25
    strongCrypto: 0,   // 0–10
    modernTls:    0,   // 0–10
  };
  const warnings: string[] = [];

  // Chain validity (0–30)
  if (result.chain.valid && result.authorized) {
    breakdown.chainValid = 30;
  } else if (result.chain.valid) {
    breakdown.chainValid = 15;
    warnings.push("chain_warning");
  } else {
    warnings.push("invalid_chain");
    if (result.authError) warnings.push(`auth_error:${result.authError}`);
  }

  // Trusted CA (0–25)
  if (result.cert.isSelfSigned) {
    warnings.push("self_signed");
  } else if (result.chain.trusted) {
    breakdown.trustedCa = 25;
  } else {
    breakdown.trustedCa = 5;
    warnings.push("untrusted_ca");
  }

  // Not expired (0–25)
  const days = result.cert.daysRemaining;
  if (days < 0) {
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

  // Strong crypto (0–10)
  const sigLower = result.cert.signatureAlgorithm.toLowerCase();
  const weak     = WEAK_SIGNATURES.some(w => sigLower.includes(w));
  if (weak) {
    warnings.push("weak_signature");
  } else if (sigLower !== "unknown") {
    breakdown.strongCrypto = 10;
  } else {
    breakdown.strongCrypto = 5;
  }

  // Modern TLS (0–10)
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

  let tier: Score["tier"];
  if (days < 0)                            tier = "EXPIRED";
  else if (result.cert.isSelfSigned)       tier = "UNTRUSTED";
  else if (!result.chain.valid)            tier = "INVALID";
  else if (!result.chain.trusted)          tier = "UNTRUSTED";
  else if (days < 7)                       tier = "EXPIRING";
  else if (total < 70)                     tier = "WEAK";
  else                                     tier = "VALID";

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
        subject:            tlsResult.cert.subject,
        issuer:             tlsResult.cert.issuer,
        validFrom:          tlsResult.cert.validFrom,
        validTo:            tlsResult.cert.validTo,
        daysRemaining:      tlsResult.cert.daysRemaining,
        signatureAlgorithm: tlsResult.cert.signatureAlgorithm,
        san:                tlsResult.cert.san,
        fingerprint256:     tlsResult.cert.fingerprint256,
        serialNumber:       tlsResult.cert.serialNumber,
        isSelfSigned:       tlsResult.cert.isSelfSigned,
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
