// Deterministic typosquat / lookalike-domain detection. No network calls — pure
// string analysis against a corpus of high-value phishing targets (payment,
// crypto, big-tech, dev). Used by /urlcheck and (later) /phishcheck.
//
// It intentionally does NOT flag a brand's legitimate ccTLD/gTLD variants
// (e.g. paypal.de) on TLD alone — those are real. It flags the techniques that
// are actually malicious: homoglyph substitution, small edit-distance typos,
// combosquatting (brand token + extra words), and IDN/punycode lookalikes.

interface Brand {
  label: string;      // the distinctive second-level label, e.g. "paypal"
  legit: string[];    // known-legitimate full domains to never flag
  common?: boolean;   // label is also a common English word → combosquat is noisier
}

const BRANDS: Brand[] = [
  { label: "paypal",     legit: ["paypal.com", "paypal.me"] },
  { label: "stripe",     legit: ["stripe.com"] },
  { label: "coinbase",   legit: ["coinbase.com"] },
  { label: "binance",    legit: ["binance.com", "binance.us"] },
  { label: "kraken",     legit: ["kraken.com"] },
  { label: "metamask",   legit: ["metamask.io"] },
  { label: "ledger",     legit: ["ledger.com"] },
  { label: "trezor",     legit: ["trezor.io"] },
  { label: "uniswap",    legit: ["uniswap.org"] },
  { label: "opensea",    legit: ["opensea.io"] },
  { label: "circle",     legit: ["circle.com"], common: true },
  { label: "tether",     legit: ["tether.to"] },
  { label: "robinhood",  legit: ["robinhood.com"] },
  { label: "wise",       legit: ["wise.com"], common: true },
  { label: "revolut",    legit: ["revolut.com"] },
  { label: "chase",      legit: ["chase.com"], common: true },
  { label: "wellsfargo", legit: ["wellsfargo.com"] },
  { label: "google",     legit: ["google.com", "googleapis.com", "gmail.com"] },
  { label: "microsoft",  legit: ["microsoft.com", "microsoftonline.com", "live.com"] },
  { label: "apple",      legit: ["apple.com", "icloud.com"], common: true },
  { label: "amazon",     legit: ["amazon.com", "amazonaws.com", "aws.amazon.com"], common: true },
  { label: "cloudflare", legit: ["cloudflare.com"] },
  { label: "github",     legit: ["github.com", "githubusercontent.com"] },
  { label: "openai",     legit: ["openai.com"] },
  { label: "anthropic",  legit: ["anthropic.com", "claude.ai"] },
  { label: "netflix",    legit: ["netflix.com"] },
  { label: "facebook",   legit: ["facebook.com", "fb.com"] },
  { label: "instagram",  legit: ["instagram.com"] },
  { label: "whatsapp",   legit: ["whatsapp.com"] },
  { label: "linkedin",   legit: ["linkedin.com"] },
  { label: "dropbox",    legit: ["dropbox.com"] },
  { label: "docusign",   legit: ["docusign.com", "docusign.net"] },
];

// Multi-char confusables applied first, then single-char digit→letter maps.
const MULTI_HOMOGLYPHS: [RegExp, string][] = [
  [/rn/g, "m"],
  [/vv/g, "w"],
  [/cl/g, "d"],
];
const CHAR_HOMOGLYPHS: Record<string, string> = {
  "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "g", "7": "t", "8": "b", "9": "g",
};

function homoglyphNormalize(s: string): string {
  let out = s.toLowerCase();
  for (const [re, rep] of MULTI_HOMOGLYPHS) out = out.replace(re, rep);
  out = out.replace(/[0-9]/g, (c) => CHAR_HOMOGLYPHS[c] ?? c);
  return out;
}

// Common two-label public suffixes — strip BOTH labels so a legitimate ccTLD
// brand domain (amazon.co.uk) doesn't leave "co" as a spurious token beside the
// brand and get mis-flagged as combosquat.
const MULTI_LABEL_SUFFIXES = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk",
  "com.au", "net.au", "org.au", "edu.au", "gov.au",
  "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
  "co.nz", "com.br", "com.mx", "co.in", "co.za", "com.sg", "com.hk", "co.kr",
  "com.tr", "com.cn", "com.tw", "co.il",
]);

// The distinctive label of a hostname (everything but the public suffix): for
// "paypa1.com" → "paypa1"; "login-paypal.example.com" → "login-paypal.example";
// "amazon.co.uk" → "amazon" (two-label suffix stripped).
function coreOf(domain: string): string {
  const parts = domain.split(".");
  if (parts.length <= 1) return domain;
  const last2 = parts.slice(-2).join(".");
  const drop  = parts.length >= 3 && MULTI_LABEL_SUFFIXES.has(last2) ? 2 : 1;
  return parts.slice(0, -drop).join(".");
}

// True if `host` is one of a brand's own legitimate domains, or a subdomain of
// one (accounts.google.com, console.aws.amazon.com) — never a lookalike.
function isBrandOwned(host: string): boolean {
  return BRANDS.some((b) =>
    b.legit.some((legit) => host === legit || host.endsWith("." + legit)),
  );
}

// Levenshtein edit distance (iterative, O(a·b)).
function levenshtein(a: string, b: string): number {
  const m = a.length, n = b.length;
  if (!m) return n;
  if (!n) return m;
  let prev = Array.from({ length: n + 1 }, (_, i) => i);
  let curr = new Array(n + 1).fill(0);
  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
    }
    [prev, curr] = [curr, prev];
  }
  return prev[n];
}

export interface TyposquatResult {
  isLookalike:  boolean;
  nearestBrand: string | null;   // legitimate brand domain being impersonated
  technique:    string | null;   // homoglyph_substitution | typo_edit_distance | brand_in_name | idn_homoglyph
  confidence:   number;          // 0–1
  distance:     number | null;   // edit distance to the brand label, when relevant
}

const NONE: TyposquatResult = {
  isLookalike: false, nearestBrand: null, technique: null, confidence: 0, distance: null,
};

export function checkTyposquat(domain: string): TyposquatResult {
  const host = domain.toLowerCase();

  // A brand's own domain or subdomain → never a lookalike of itself.
  if (isBrandOwned(host)) return NONE;

  const core       = coreOf(host);
  const tokens     = core.split(/[-._]/).filter(Boolean);
  const normCore   = homoglyphNormalize(core);
  const isPunycode = host.split(".").some((lbl) => lbl.startsWith("xn--"));

  let best: TyposquatResult = NONE;
  const take = (r: TyposquatResult) => { if (r.confidence > best.confidence) best = r; };

  for (const brand of BRANDS) {
    const brandDomain = brand.legit[0];
    const L = brand.label;

    // 1. Homoglyph substitution — normalizes to the exact brand label.
    if (core !== L && normCore === L) {
      take({ isLookalike: true, nearestBrand: brandDomain, technique: "homoglyph_substitution", confidence: 0.9, distance: 0 });
      continue;
    }

    // 2. Small edit-distance typo on a distinctive (≥5-char) label.
    //    Common-word brands (apple/chase/wise/…) are capped BELOW the 0.8 BLOCK
    //    threshold — a legit unrelated word one edit away (apply.com→apple.com)
    //    should surface as REVIEW, not a hard BLOCK.
    if (L.length >= 5 && Math.abs(core.length - L.length) <= 2) {
      const d = levenshtein(normCore, L);
      if (d >= 1 && d <= 2) {
        const confidence = brand.common
          ? (d === 1 ? 0.6 : 0.45)   // REVIEW band
          : (d === 1 ? 0.85 : 0.7);  // BLOCK/REVIEW band
        take({ isLookalike: true, nearestBrand: brandDomain, technique: "typo_edit_distance", confidence, distance: d });
        continue;
      }
    }

    // 3. Combosquat — the brand appears as its own token among others
    //    ("paypal-secure", "login-paypal", "paypal.evil.com"). Noisier for
    //    common-word brands, so lower confidence there.
    if (tokens.length > 1 && (tokens.includes(L) || tokens.map(homoglyphNormalize).includes(L))) {
      take({ isLookalike: true, nearestBrand: brandDomain, technique: "brand_in_name", confidence: brand.common ? 0.45 : 0.6, distance: null });
    }
  }

  // 4. IDN/punycode label — a classic homoglyph vector. Informational on its own;
  //    upgrades a near-miss, and flags a REVIEW even without a brand match.
  if (isPunycode && !best.isLookalike) {
    best = { isLookalike: true, nearestBrand: best.nearestBrand, technique: "idn_homoglyph", confidence: 0.5, distance: null };
  }

  return best;
}
