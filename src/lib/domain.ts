import net from "net";
import { VALID_DOMAIN_RE, isPrivateIp, normalizeHostname } from "./net-guard.js";

// Extract a bare, safe, public hostname from a domain-or-URL string.
// Strips scheme and a leading "www.", rejects private/internal IPs, localhost,
// and anything that is neither a public IP literal nor a syntactically valid
// domain name. Shared by /trustscore, /sslcheck, /urlcheck, /emailtrust so the
// input-validation rules can't drift between endpoints.
export function extractDomain(input: string): string | null {
  try {
    const withProto = input.startsWith("http") ? input : `https://${input}`;
    const hostname  = normalizeHostname(new URL(withProto).hostname).replace(/^www\./, "");
    if (!hostname) return null;

    // Block private/internal IPs (incl. link-local/metadata and IPv6) + localhost.
    if (hostname === "localhost" || isPrivateIp(hostname)) return null;

    // Strict allowlist — also neutralizes injection into the WHOIS query string.
    // Accept a public IP literal or a syntactically valid domain name.
    if (net.isIP(hostname) === 0 && !VALID_DOMAIN_RE.test(hostname)) return null;

    return hostname;
  } catch {
    return null;
  }
}

// A registrable-ish domain (a public name with a dot), the shape every route
// requires before doing real work.
export function isUsableDomain(domain: string | null): domain is string {
  return !!domain && domain.length >= 4 && domain.includes(".");
}
