import dns from "dns/promises";

// Grade a domain's email-authentication posture from DNS alone (SPF, DMARC,
// DKIM, BIMI, MX). Zero-COGS. The value is the *interpretation* — turning raw
// TXT records into "can this sender be spoofed, and will its mail be trusted".

const DNS_TIMEOUT_MS = 4000;

function timeout<T>(p: Promise<T>): Promise<T | null> {
  return Promise.race([p.catch(() => null), new Promise<null>((r) => setTimeout(() => r(null), DNS_TIMEOUT_MS))]);
}

async function txt(name: string): Promise<string[]> {
  const rows = await timeout(dns.resolveTxt(name));
  if (!rows) return [];
  // Each TXT record is an array of chunks to be concatenated.
  return rows.map((chunks) => chunks.join(""));
}

// Common DKIM selectors — DKIM keys live at <selector>._domainkey.<domain> and
// the selector isn't discoverable from DNS, so we probe well-known ones. A miss
// means "no key at a common selector", not a definitive absence.
const DKIM_SELECTORS = [
  "default", "google", "selector1", "selector2", "k1", "k2",
  "mail", "dkim", "s1", "s2", "mandrill", "mxvault", "sig1", "smtp",
];

export interface SpfInfo   { present: boolean; qualifier: string | null; multiple: boolean; record: string | null; }
export interface DmarcInfo { present: boolean; policy: "none" | "quarantine" | "reject" | null; pct: number; rua: boolean; }
export interface DkimInfo  { present: boolean; selectorsFound: string[]; note: string; }

export interface MailAuth {
  domain:    string;
  grade:     "A" | "B" | "C" | "D" | "F";
  score:     number;
  spoofable: boolean;
  spf:       SpfInfo;
  dmarc:     DmarcInfo;
  dkim:      DkimInfo;
  bimi:      boolean;
  mx:        string[];
  issues:    string[];
}

export function parseSpf(records: string[]): SpfInfo {
  const spfRecords = records.filter((r) => /^v=spf1\b/i.test(r.trim()));
  if (spfRecords.length === 0) return { present: false, qualifier: null, multiple: false, record: null };
  const record = spfRecords[0];
  // The `all` mechanism is a standalone whitespace-delimited term, NOT a
  // substring — matching `/[-~?+]all/` anywhere would mis-read a hostname like
  // `include:_spf-all.example.net` as a `-all` hardfail. Tokenize and take the
  // rightmost real `all` term (SPF evaluates left→right; `all` is terminal). A
  // bare `all` with no qualifier defaults to `+all` (pass) per RFC 7208.
  let qualifier: string | null = null;
  for (const term of record.trim().split(/\s+/)) {
    const m = /^([-~?+]?)all$/i.exec(term);
    if (m) qualifier = `${m[1] || "+"}all`;
  }
  return {
    present:   true,
    qualifier,                            // -all | ~all | ?all | +all
    multiple:  spfRecords.length > 1,     // >1 SPF record is a hard misconfig
    record,
  };
}

export function parseDmarc(records: string[]): DmarcInfo {
  const rec = records.find((r) => /^v=DMARC1\b/i.test(r.trim()));
  if (!rec) return { present: false, policy: null, pct: 0, rua: false };
  const pm = rec.match(/\bp\s*=\s*(none|quarantine|reject)\b/i);
  // A v=DMARC1 record with no required `p=` tag is invalid and MUST be ignored
  // (RFC 7489) — treat it as no DMARC rather than silently defaulting to p=none,
  // which would over-state the domain's posture (grade C instead of D/F).
  if (!pm) return { present: false, policy: null, pct: 0, rua: false };
  const pct = rec.match(/\bpct\s*=\s*(\d{1,3})\b/i);
  return {
    present: true,
    policy:  pm[1].toLowerCase() as DmarcInfo["policy"],
    pct:     pct ? Math.min(100, parseInt(pct[1], 10)) : 100,
    rua:     /\brua\s*=/i.test(rec),
  };
}

export async function checkMailAuth(domain: string): Promise<MailAuth> {
  const [spfTxt, dmarcTxt, bimiTxt, mxRecs, ...dkimTxts] = await Promise.all([
    txt(domain),
    txt(`_dmarc.${domain}`),
    txt(`default._bimi.${domain}`),
    timeout(dns.resolveMx(domain)),
    ...DKIM_SELECTORS.map((s) => txt(`${s}._domainkey.${domain}`)),
  ]);

  const spf   = parseSpf(spfTxt);
  const dmarc = parseDmarc(dmarcTxt);
  const bimi  = bimiTxt.some((r) => /^v=BIMI1\b/i.test(r.trim()));
  const mx    = (mxRecs || []).map((r) => r.exchange).filter(Boolean).slice(0, 5);

  const selectorsFound = DKIM_SELECTORS.filter((_, i) =>
    dkimTxts[i].some((r) => /(^|;)\s*(v=DKIM1|k=|p=)/i.test(r))
  );
  const dkim: DkimInfo = {
    present:        selectorsFound.length > 0,
    selectorsFound,
    note:           selectorsFound.length ? "" : "no key at common selectors (selector may be custom — treat as inconclusive)",
  };

  // ── Enforcement-driven grade + spoofability ────────────────────────────────
  const enforced = dmarc.policy === "reject" || dmarc.policy === "quarantine";
  const spoofable = !enforced || (dmarc.pct < 100);

  const issues: string[] = [];
  if (!spf.present)               issues.push("no_spf_record");
  if (spf.multiple)               issues.push("multiple_spf_records");   // SPF permerror
  if (spf.qualifier === "+all")   issues.push("spf_pass_all");           // allows anyone
  if (spf.qualifier === "?all")   issues.push("spf_neutral_only");
  if (!dmarc.present)             issues.push("no_dmarc_record");
  else if (dmarc.policy === "none")     issues.push("dmarc_p_none_no_enforcement");
  if (dmarc.present && dmarc.pct < 100) issues.push("dmarc_partial_pct");
  if (!dkim.present)              issues.push("no_dkim_at_common_selectors");
  if (mx.length === 0)            issues.push("no_mx_records");

  let grade: MailAuth["grade"];
  if      (dmarc.policy === "reject"     && spf.present && dkim.present) grade = "A";
  else if (dmarc.policy === "reject"     && spf.present)                 grade = "B";
  else if (dmarc.policy === "quarantine" && spf.present)                 grade = "B";
  else if (dmarc.policy === "quarantine")                               grade = "C";
  else if (dmarc.policy === "none")                                     grade = "C";
  else if (spf.present && spf.qualifier !== "+all")                     grade = "D";
  else                                                                  grade = "F";

  // Numeric score for thresholds (0–100).
  let score = 0;
  score += spf.qualifier === "-all" ? 25 : spf.qualifier === "~all" ? 18 : spf.present ? 8 : 0;
  score += dmarc.policy === "reject" ? 40 : dmarc.policy === "quarantine" ? 30 : dmarc.policy === "none" ? 10 : 0;
  if (dmarc.present && dmarc.pct < 100) score -= 10;
  score += dkim.present ? 20 : 0;
  score += bimi ? 10 : 0;
  score += mx.length ? 5 : 0;
  score = Math.max(0, Math.min(100, score));

  return { domain, grade, score, spoofable, spf, dmarc, dkim, bimi, mx, issues };
}
