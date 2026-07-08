import dns from "dns/promises";
import net from "net";

// ─── Shared outbound-request / SSRF guard ─────────────────────────────────────
// Used by every route that opens a connection to a user-supplied host
// (/headers, /robots, /sslcheck) and by the domain-only routes for consistency.
// Centralizing this keeps the four routes from drifting apart (they previously
// had four different private-IP regexes with different coverage).

// Public-hostname allowlist: letters, digits, hyphens, dots only. Also permits
// bare IPv4 literals (digits + dots); IPv6 literals are validated separately.
export const VALID_DOMAIN_RE = /^[a-zA-Z0-9][a-zA-Z0-9\-.]{1,251}[a-zA-Z0-9]$/;

// Ports we are willing to dial. "" means the scheme default (80/443).
export const ALLOWED_PORTS = new Set(["", "80", "443", "8080", "8443"]);

// IPv4 ranges that must never be dialed: RFC1918, loopback, link-local
// (169.254/16 — includes the 169.254.169.254 cloud-metadata endpoint),
// and 0.0.0.0/8 ("this host"). Applied only to strings that net.isIPv4 accepts.
const PRIVATE_IPV4_RE =
  /^(0\.|10\.|127\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/;

// Strip an IPv6 zone id and surrounding brackets, then classify.
function isPrivateIpv6(addr: string): boolean {
  const a = addr.replace(/^\[|\]$/g, "").split("%")[0].toLowerCase();
  if (a === "::1" || a === "::") return true; // loopback / unspecified
  if (/^f[cd]/.test(a)) return true; // fc00::/7 unique-local
  if (/^fe[89ab]/.test(a)) return true; // fe80::/10 link-local
  // IPv4-mapped (::ffff:a.b.c.d) — classify by the embedded IPv4 address.
  const mapped = a.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (mapped) return PRIVATE_IPV4_RE.test(mapped[1]);
  return false;
}

// True if the given IP-literal string points at a private/internal address.
export function isPrivateIp(ip: string): boolean {
  const clean = normalizeHostname(ip);
  if (net.isIPv4(clean)) return PRIVATE_IPV4_RE.test(clean);
  if (net.isIPv6(clean)) return isPrivateIpv6(clean);
  return false; // not an IP literal — caller resolves it via assertHostAllowed
}

// Lower-case and remove surrounding IPv6 brackets so "[::1]" compares as "::1".
export function normalizeHostname(hostname: string): string {
  return hostname.replace(/^\[|\]$/g, "").toLowerCase();
}

export class BlockedHostError extends Error {}

// Resolve a hostname the same way the connection layer will (getaddrinfo, via
// dns.lookup) and reject if ANY resolved address is private. Returns the list of
// public IPs so callers can pin the connection to a vetted address (defeating
// DNS-rebinding TOCTOU where feasible, e.g. tls.connect).
//
// Also rejects non-standard numeric host encodings (decimal/octal/hex, e.g.
// "2852039166" or "0177.0.0.1") that regex checks miss but the OS would expand
// to an internal address at connect time.
export async function assertHostAllowed(
  hostname: string,
  timeoutMs = 3000,
): Promise<string[]> {
  const host = normalizeHostname(hostname);

  // Direct IP literal — classify without a DNS round-trip.
  if (net.isIP(host)) {
    if (isPrivateIp(host)) {
      throw new BlockedHostError(`blocked private address ${host}`);
    }
    return [host];
  }

  // Reject anything that looks like a numeric IP attempt but is not a clean
  // dotted-quad (blocks 2852039166, 0177.0.0.1, 0x7f.1, 10.0 shorthand, …).
  if (/^[0-9.]+$/.test(host) || /^0x/i.test(host)) {
    throw new BlockedHostError(`malformed numeric host ${host}`);
  }

  const addresses = await Promise.race([
    dns.lookup(host, { all: true }),
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new BlockedHostError("DNS timeout")), timeoutMs),
    ),
  ]);

  if (!addresses.length) throw new BlockedHostError(`no addresses for ${host}`);
  for (const { address } of addresses) {
    if (isPrivateIp(address)) {
      throw new BlockedHostError(`${host} resolves to private address ${address}`);
    }
  }
  return addresses.map((a) => a.address);
}

// Validate scheme + port for an initial URL or a redirect target. Throws
// BlockedHostError on anything outside the http/https + port allowlist.
export function assertUrlSchemeAndPort(url: URL): void {
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new BlockedHostError(`unsupported scheme ${url.protocol}`);
  }
  if (!ALLOWED_PORTS.has(url.port)) {
    throw new BlockedHostError(`port ${url.port} not permitted`);
  }
}
