import tls from "tls";
import { assertHostAllowed } from "./net-guard.js";

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

// Substrings matching well-known root CA names. Used ONLY as a cosmetic
// "well-known CA" label — the real trust decision comes from Node's own
// validation against the full system root store (socket.authorized).
const TRUSTED_CAS = [
  "let's encrypt", "digicert", "globalsign", "sectigo", "comodo",
  "godaddy", "amazon", "google trust", "cloudflare", "entrust",
  "thawte", "geotrust", "rapidssl", "verisign", "buypass",
  "identrust", "actalis", "zerossl",
];

// Cipher-name fragments indicating outright-broken crypto (legacy servers only).
const WEAK_CIPHER_FRAGMENTS = ["rc4", "3des", "des", "md5", "null", "export"];

// Markers of an AEAD cipher (GCM / ChaCha20-Poly1305 / CCM). A modern suite has
// exactly one of these; a suite with none is a legacy CBC-mode suite.
const AEAD_MARKERS = ["gcm", "chacha20", "poly1305", "ccm"];

// ─── TLS handshake ────────────────────────────────────────────────────────────

export interface CertInfo {
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

export interface ChainInfo {
  depth:       number;
  valid:       boolean;
  trusted:     boolean;   // real trust: Node validated the chain to a system root
  wellKnownCa: boolean;   // cosmetic: root/issuer name matched our known-CA list
  rootCa:      string | null;
}

export interface TlsResult {
  cert:       CertInfo;
  chain:      ChainInfo;
  protocol:   string | null;
  cipher:     { name: string; version: string } | null;
  authorized: boolean;
  authError:  string | null;
}

export async function fetchCertChain(domain: string, timeoutMs = 8000): Promise<TlsResult> {
  // Resolve the name and reject private addresses, then pin the connection to
  // the vetted IP (SNI/validation still use `domain`). This closes the SSRF hole
  // (a public name whose A record points at 10.x / 169.254.x) and eliminates the
  // DNS-rebinding window — the address we checked is the address we dial.
  const [connectHost] = await assertHostAllowed(domain);

  return new Promise((resolve, reject) => {
    // rejectUnauthorized: false → we WANT to see invalid certs, not throw on them.
    // The scoring logic uses authorized + authError to detect invalid chains.
    const socket = tls.connect({
      host:               connectHost,
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

        // Cosmetic "well-known CA" label — check both root and immediate issuer
        // against our short name list. This must NOT decide trust: a valid cert
        // from a public CA not in the list (SSL.com, Certum, …) would otherwise
        // be mislabeled UNTRUSTED. Real trust = socket.authorized (below).
        const issuerOLower = asString(peerCert.issuer?.O).toLowerCase();
        const rootLower    = rootCa?.toLowerCase() ?? "";
        const wellKnownCa = TRUSTED_CAS.some(ca =>
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

        // Real trust decision: Node validated the presented chain against the
        // full system root store. A self-signed leaf is never "trusted".
        const trusted = socket.authorized && !isSelfSigned;

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
            depth:       chainCerts.length,
            valid:       !authErr,
            trusted,
            wellKnownCa,
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

export interface Score {
  total:     number;
  tier:      "VALID" | "WEAK" | "EXPIRING" | "EXPIRED" | "UNTRUSTED" | "INVALID";
  breakdown: Record<string, number>;
  warnings:  string[];
}

// Detect a weak cipher from its OpenSSL name. Two cases:
//   1. Outright-broken primitives (RC4, DES/3DES, MD5, NULL, EXPORT).
//   2. Legacy CBC-mode suites — an OpenSSL name with no AEAD marker (GCM /
//      ChaCha20-Poly1305 / CCM) is a CBC suite (e.g. "AES128-SHA").
function isCipherWeak(cipherName: string): boolean {
  const n = cipherName.toLowerCase();
  if (!n) return false;
  if (WEAK_CIPHER_FRAGMENTS.some(f => n.includes(f))) return true;
  if (!AEAD_MARKERS.some(m => n.includes(m))) return true;
  return false;
}

export function scoreCertificate(result: TlsResult): Score {
  const breakdown: Record<string, number> = {
    chainValid:   0,   // 0–30
    trustedCa:    0,   // 0–25
    notExpired:   0,   // 0–25
    strongCrypto: 0,   // 0–10  (cipher-based)
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

  // ── Strong crypto (0–10) — cipher-based ────────────────────────────────────
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

  // ── Tier (priority: expired > untrusted > invalid > expiring soon) ─────────
  let tier: Score["tier"];
  if      (days !== null && days < 0)    tier = "EXPIRED";
  else if (result.cert.isSelfSigned)     tier = "UNTRUSTED";
  else if (!result.chain.valid)          tier = "INVALID";
  else if (!result.chain.trusted)        tier = "UNTRUSTED";
  else if (days !== null && days < 7)    tier = "EXPIRING";
  else if (total < 70)                   tier = "WEAK";
  else                                   tier = "VALID";

  return { total, tier, breakdown, warnings };
}
