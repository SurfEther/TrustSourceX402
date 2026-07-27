import net from "net";
import { Agent } from "undici";
import {
  assertHostAllowed,
  assertUrlSchemeAndPort,
} from "./net-guard.js";

// Shared SSRF-safe outbound fetch. Every hop is re-validated (scheme, port, and
// the resolved IP) so a public host cannot 30x-redirect us into an internal
// address or a disallowed port. Used by /headers, /robots and /safefetch so the
// hardening lives in exactly one place.

export const DEFAULT_TIMEOUT_MS  = 8000;
export const DEFAULT_MAX_REDIRECTS = 3;

export interface GuardedFetchOptions {
  timeoutMs?:    number;
  maxRedirects?: number;
  /** Max body bytes to read. 0 = don't read the body at all (headers only). */
  maxBytes?:     number;
  userAgent?:    string;
  accept?:       string;
}

export interface GuardedFetchResult {
  finalUrl:    string;
  status:      number;
  headers:     Record<string, string>;
  redirects:   number;
  contentType: string | null;
  /** Decoded body text, or "" when maxBytes is 0 or the body was empty. */
  body:        string;
  bytes:       number;
  truncated:   boolean;
}

export async function guardedFetch(
  initialUrl: URL,
  opts: GuardedFetchOptions = {},
): Promise<GuardedFetchResult> {
  const timeoutMs    = opts.timeoutMs    ?? DEFAULT_TIMEOUT_MS;
  const maxRedirects = opts.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
  const maxBytes     = opts.maxBytes     ?? 0;

  let currentUrl = initialUrl;
  let redirects  = 0;

  while (redirects <= maxRedirects) {
    // Re-verify scheme, port, and that the host does not resolve to a private
    // address on EVERY hop — prevents redirect-to-internal / port-scan attacks.
    assertUrlSchemeAndPort(currentUrl);
    const vettedIps = await assertHostAllowed(currentUrl.hostname);

    // PIN the connection to the addresses we just validated. Without this,
    // fetch() performs its OWN resolution and a short-TTL DNS-rebinding record
    // can return a public IP to the guard and an internal IP to the connection
    // — the guard would pass and we would fetch (and return) internal content.
    // The hostname stays in the URL, so Host header, SNI and TLS verification
    // are unaffected. Re-pinned per hop, since each hop is re-validated.
    const dispatcher = new Agent({
      connect: {
        lookup: (
          _hostname: string,
          _options: unknown,
          cb: (err: Error | null, addresses: { address: string; family: number }[]) => void,
        ) => {
          cb(null, vettedIps.map((a) => ({ address: a, family: net.isIPv6(a) ? 6 : 4 })));
        },
      },
    });

    const controller = new AbortController();
    const timer      = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(currentUrl.toString(), {
        method:   "GET",
        redirect: "manual",              // we handle redirects ourselves
        signal:   controller.signal,
        dispatcher,
        headers: {
          "User-Agent":      opts.userAgent ?? "TrustSource/1.0 (+https://trustsource.cc)",
          "Accept":          opts.accept ?? "*/*",
          "Accept-Encoding": "identity", // no compression — blocks decompression bombs
        },
      } as RequestInit & { dispatcher: Agent });
      clearTimeout(timer);

      const headers: Record<string, string> = {};
      response.headers.forEach((value, key) => { headers[key.toLowerCase()] = value; });

      // Redirect — the next hop is re-validated at the top of the loop.
      if (response.status >= 300 && response.status < 400 && headers["location"]) {
        try {
          currentUrl = new URL(headers["location"], currentUrl);
        } catch {
          throw new Error("Invalid redirect Location header");
        }
        redirects++;
        try { await response.body?.cancel(); } catch { /* ignore */ }
        continue;
      }

      const contentType = headers["content-type"] ?? null;

      // Headers-only mode: discard the body without buffering it.
      if (maxBytes <= 0) {
        try { await response.body?.cancel(); } catch { /* ignore */ }
        return {
          finalUrl: currentUrl.toString(), status: response.status, headers,
          redirects, contentType, body: "", bytes: 0, truncated: false,
        };
      }

      // Stream the body up to maxBytes, then stop reading. Never buffer an
      // unbounded response into memory.
      const reader = response.body?.getReader();
      if (!reader) {
        return {
          finalUrl: currentUrl.toString(), status: response.status, headers,
          redirects, contentType, body: "", bytes: 0, truncated: false,
        };
      }

      let body       = "";
      let bytes      = 0;
      let truncated  = false;
      const decoder  = new TextDecoder("utf-8");
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        bytes += value.length;
        if (bytes > maxBytes) {
          truncated = true;
          try { await reader.cancel(); } catch { /* ignore */ }
          break;
        }
        body += decoder.decode(value, { stream: true });
      }
      body += decoder.decode();

      return {
        finalUrl: currentUrl.toString(), status: response.status, headers,
        redirects, contentType, body, bytes, truncated,
      };
    } catch (err) {
      clearTimeout(timer);
      throw err;
    } finally {
      // Runs after the return value is evaluated (body already read), and on the
      // redirect `continue` path — so each hop's pinned pool is released.
      dispatcher.close().catch(() => { /* ignore */ });
    }
  }
  throw new Error(`Too many redirects (max ${maxRedirects})`);
}
