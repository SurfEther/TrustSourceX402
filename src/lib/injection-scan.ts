// Deterministic indirect-prompt-injection detector.
//
// The central idea: a phrase like "ignore all previous instructions" is
// UNREMARKABLE in visible article text — security blogs, papers and docs quote
// it constantly — but is a strong attack signal when it is hidden in a comment,
// a display:none div, or an alt attribute. So every finding is scored as
//   technique severity × placement multiplier
// which is what keeps the false-positive rate survivable on real web content.
//
// No LLM, no network: this runs in microseconds and cannot itself be prompt-
// injected, which is the point — the agent gets a verdict WITHOUT ingesting the
// hostile content first.

import type { Segment, SegmentKind } from "./html-text.js";

export type Placement = SegmentKind | "visible";

export interface Finding {
  technique: string;
  placement: Placement;
  severity:  number;   // base severity of the technique (0–1)
  weight:    number;   // severity × placement multiplier — actual contribution
  detail:    string;   // where it was found
  snippet:   string;   // short, escaped excerpt
}

export interface InjectionScan {
  detected:   boolean;
  risk:       number;      // 0–1
  techniques: string[];    // unique, highest-weight first
  findings:   Finding[];
}

// How much to trust a hit based on WHERE it was found. Visible prose is heavily
// discounted; markup a human never sees is not.
const PLACEMENT_WEIGHT: Record<Placement, number> = {
  hidden:        1.0,
  comment:       0.95,
  metadata:      0.55,
  accessibility: 0.6,
  script:        0.5,
  visible:       0.2,
};

// Maximum aggregate risk that visible-text hits alone may contribute. Keeps a
// security article that quotes many injection phrases below the BLOCK threshold.
const VISIBLE_RISK_CAP = 0.35;

interface Rule { technique: string; severity: number; patterns: RegExp[]; }

// Patterns are deliberately bounded (no nested quantifiers, no unbounded `.*`)
// because they run against attacker-controlled input — a catastrophic-backtracking
// regex here would be a DoS vector.
const RULES: Rule[] = [
  {
    technique: "instruction_override",
    severity: 0.95,
    patterns: [
      /\bignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|preceding|above|earlier)\s+(?:instruction|prompt|direction|rule|command)/i,
      /\bdisregard\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|preceding|above|earlier|system)\b/i,
      /\bforget\s+(?:everything|all\s+(?:previous|prior))\b/i,
      /\bforget\s+(?:your|the)\s+(?:previous|prior|system|original)\b/i,
      /\bnew\s+instructions?\s*:/i,
      /\boverride\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instruction)/i,
      /\bdo\s+not\s+follow\s+(?:the\s+)?(?:previous|prior|above|system)\b/i,
      /\bstop\s+following\s+(?:your|the)\s+(?:previous|prior|original|system)\b/i,
    ],
  },
  {
    technique: "system_prompt_exfil",
    severity: 0.9,
    patterns: [
      /\b(?:reveal|print|show|output|repeat|disclose|display|dump)\s+(?:me\s+)?(?:your|the)\s+(?:full\s+|entire\s+|system\s+|initial\s+|original\s+)?(?:prompt|instruction|rule|directive)/i,
      /\bwhat\s+(?:are|were)\s+your\s+(?:initial|original|system|exact)\s+instruction/i,
      /\brepeat\s+(?:the\s+)?(?:text|words|everything)\s+above\b/i,
    ],
  },
  {
    technique: "data_exfiltration",
    severity: 0.9,
    patterns: [
      // Markdown image/link whose URL carries a data-bearing query param — the
      // classic zero-click exfil: the model "renders" it and leaks context.
      /!\[[^\]]{0,200}\]\(\s*https?:\/\/[^)\s]{0,300}[?&](?:q|d|s|data|text|content|prompt|msg|info|payload)=/i,
      /\bappend\s+(?:the\s+)?(?:conversation|chat|history|context|secret|api[\s_-]?key|token)\b/i,
      /\bsend\s+(?:it|them|the\s+(?:data|result|content|conversation|history|output))\s+to\s+https?:\/\//i,
      /\bexfiltrat(?:e|ing|ion)\b/i,
      /\binclude\s+(?:the\s+)?(?:api[\s_-]?key|password|secret|access[\s_-]?token)\b/i,
    ],
  },
  {
    technique: "delimiter_spoof",
    severity: 0.85,
    patterns: [
      /<\|(?:im_start|im_end|system|user|assistant|endoftext|eot_id|start_header_id)\|>/i,
      /\[\/?INST\]/,
      /<<\s*SYS\s*>>/i,
      /###\s*(?:instruction|system)\s*:/i,
    ],
  },
  {
    technique: "encoded_payload",
    severity: 0.85,
    patterns: [],   // handled specially in scanEncoded()
  },
  {
    technique: "tool_call_bait",
    severity: 0.55,
    patterns: [
      /\b(?:call|invoke|execute|run|use)\s+(?:the\s+)?(?:function|tool|command|api|endpoint|shell)\b/i,
      /\bsend\s+(?:an?\s+)?(?:email|message|dm)\s+to\b/i,
      /\b(?:curl|wget)\s+https?:\/\//i,
      /\btransfer\s+(?:\$|\d|all\b)/i,
      /\bexecute\s+the\s+following\s+(?:code|command|script)\b/i,
      /\bdelete\s+(?:all\s+)?(?:files|data|records)\b/i,
    ],
  },
  {
    technique: "role_hijack",
    severity: 0.5,
    patterns: [
      /\byou\s+are\s+now\s+(?:a|an|the)\b/i,
      /\bfrom\s+now\s+on[,\s]{1,3}you\b/i,
      /\byour\s+new\s+(?:role|task|goal|purpose|objective|instruction)\b/i,
      /\bpretend\s+(?:to\s+be|you\s+are)\b/i,
      /\byou\s+must\s+now\s+(?:obey|follow|comply)\b/i,
    ],
  },
];

// ── Invisible / control characters ────────────────────────────────────────────
// These are placement-independent: legitimate content essentially never carries
// instruction text in zero-width or Unicode-Tag characters.

// Zero-width space/joiner/non-joiner, LRM/RLM, word joiner, invisible operators, BOM.
const ZERO_WIDTH_RE = /[​-‏⁠-⁤﻿]/g;
// Unicode Tags block — the "invisible instructions" smuggling channel.
const UNICODE_TAG_RE = /[\u{E0000}-\u{E007F}]/gu;
// Bidirectional overrides — used to visually reorder text away from what parses.
const BIDI_RE = /[‪-‮⁦-⁩]/g;

/** Remove every invisible/control character used to smuggle instructions. */
export function stripInvisible(s: string): string {
  return s.replace(ZERO_WIDTH_RE, "").replace(UNICODE_TAG_RE, "").replace(BIDI_RE, "");
}

// ── Confusable (homoglyph) folding ────────────────────────────────────────────
// Separate from typosquat.ts's domain-oriented normalizer on purpose: touching
// that module would change /urlcheck's behaviour.
const CONFUSABLES: Record<string, string> = {
  "а":"a","е":"e","о":"o","р":"p","с":"c","х":"x","у":"y","і":"i","ѕ":"s","ԁ":"d","һ":"h","ј":"j","к":"k","м":"m","н":"h","т":"t","в":"b","г":"r",
  "Α":"A","Β":"B","Ε":"E","Ζ":"Z","Η":"H","Ι":"I","Κ":"K","Μ":"M","Ν":"N","Ο":"O","Ρ":"P","Τ":"T","Υ":"Y","Χ":"X","ο":"o","ρ":"p","ν":"v","ι":"i",
  "А":"A","В":"B","Е":"E","К":"K","М":"M","Н":"H","О":"O","Р":"P","С":"C","Т":"T","У":"Y","Х":"X",
};

/** Fold confusable scripts to ASCII so obfuscated instructions still match. */
export function foldConfusables(s: string): string {
  let out = s.normalize("NFKC");
  out = out.replace(/[^\x00-\x7F]/g, (c) => CONFUSABLES[c] ?? c);
  return out;
}

/** Defang an excerpt before returning it. We hand these to the calling model, so
 *  a live `<|im_start|>` or a zero-width payload in `snippet` would re-inject the
 *  very agent we are protecting. Neutralize delimiters and drop invisibles. */
export function defang(s: string): string {
  return stripInvisible(s)
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .replace(/\[\s*\/?\s*INST\s*\]/gi, "[INST-defanged]")
    .replace(/<<\s*SYS\s*>>/gi, "[SYS-defanged]")
    .replace(/</g, "\u2039").replace(/>/g, "\u203a");
}

function snippetAround(text: string, index: number, len: number): string {
  const start = Math.max(0, index - 30);
  const raw   = text.slice(start, Math.min(text.length, index + len + 50));
  return defang(raw.replace(/\s+/g, " ")).slice(0, 160).trim();
}

/** Look for base64 blobs that decode to instruction-like text. */
function scanEncoded(text: string, placement: Placement, push: (f: Finding) => void): void {
  const re = /[A-Za-z0-9+/]{40,}={0,2}/g;
  let m: RegExpExecArray | null;
  let checked = 0;
  while ((m = re.exec(text)) !== null && checked < 12) {
    checked++;
    let decoded = "";
    try { decoded = Buffer.from(m[0], "base64").toString("utf8"); } catch { continue; }
    // Ignore blobs that decode to binary noise.
    const printable = decoded.replace(/[^\x20-\x7E]/g, "").length;
    if (!decoded || printable / decoded.length < 0.85) continue;
    for (const rule of RULES) {
      if (rule.technique === "encoded_payload") continue;
      for (const p of rule.patterns) {
        if (p.test(decoded)) {
          push({
            technique: "encoded_payload",
            placement,
            severity:  0.85,
            weight:    0.85 * PLACEMENT_WEIGHT[placement],
            detail:    `base64 blob decodes to ${rule.technique}`,
            snippet:   defang(decoded.replace(/\s+/g, " ")).slice(0, 160),
          });
          return;
        }
      }
    }
  }
}

/** Remove short separators between letters so "i g n o r e" / "i-g-n-o-r-e"
 *  still matches. Only used as an ADDITIONAL pass, and only when it actually
 *  changes the text (i.e. separators were present) — so it can add matches on
 *  deliberately obfuscated text but never alters normal prose matching. */
function deSeparate(s: string): string {
  // Only collapse runs of alternating single letters + separators
  // ("i-g-n-o-r-e", "i g n o r e"). A plain space between real words is left
  // alone, otherwise word boundaries the patterns rely on are destroyed.
  // The trailing (?!\p{L}) stops the run greedily eating into the next word:
  // without it "i-g-n-o-r-e all" matched through "e a" and produced "ignoreall".
  // Repetition is bounded so backtracking stays linear on hostile input.
  return s.replace(/(?:\p{L}[\s\u00AD._\-*|]){2,40}\p{L}(?!\p{L})/gu,
                   (run) => run.replace(/[\s\u00AD._\-*|]/g, ""));
}

function scanText(text: string, placement: Placement, push: (f: Finding) => void): void {
  if (!text) return;
  // CRITICAL: strip invisible characters BEFORE matching. A single zero-width
  // space inside a keyword ("i\u200Bgnore all previous instructions") would
  // otherwise defeat every pattern below — the cheapest possible bypass.
  const clean  = stripInvisible(text);
  const folded = foldConfusables(clean);

  for (const rule of RULES) {
    for (const pattern of rule.patterns) {
      const direct = pattern.exec(clean);
      if (direct) {
        push({
          technique: rule.technique,
          placement,
          severity:  rule.severity,
          weight:    rule.severity * PLACEMENT_WEIGHT[placement],
          detail:    `matched in ${placement} content`,
          snippet:   snippetAround(clean, direct.index, direct[0].length),
        });
        break;   // one hit per technique per segment is enough
      }
      // Same pattern only matches after folding confusables → deliberate obfuscation.
      const obf = pattern.exec(folded);
      if (obf) {
        push({
          technique: "homoglyph_obfuscation",
          placement,
          severity:  0.9,
          weight:    0.9 * PLACEMENT_WEIGHT[placement],
          detail:    `${rule.technique} written with confusable characters in ${placement} content`,
          snippet:   snippetAround(folded, obf.index, obf[0].length),
        });
        break;
      }
      // Separator-obfuscated ("i g n o r e") — only when separators were present.
      const sep = deSeparate(folded);
      if (sep !== folded) {
        const sm = pattern.exec(sep);
        if (sm) {
          push({
            technique: "homoglyph_obfuscation",
            placement,
            severity:  0.9,
            weight:    0.9 * PLACEMENT_WEIGHT[placement],
            detail:    `${rule.technique} obfuscated with separator characters in ${placement} content`,
            snippet:   snippetAround(sep, sm.index, sm[0].length),
          });
          break;
        }
      }
    }
  }

  scanEncoded(clean, placement, push);
}

/**
 * Scan a page's visible text plus its hidden segments.
 * `rawSource` is the undecoded document, used only for invisible-character
 * detection (entity decoding would otherwise mask it).
 */
export function scanForInjection(
  visibleText: string,
  segments: Segment[],
  rawSource: string,
): InjectionScan {
  const findings: Finding[] = [];
  const push = (f: Finding) => findings.push(f);

  scanText(visibleText, "visible", push);
  for (const seg of segments) scanText(seg.text, seg.kind, push);

  // Splitting a payload across sibling hidden elements ("<div hidden>Ignore all
  // </div><div hidden>previous instructions</div>") defeats per-segment matching.
  // Scan the concatenation of the unseen segments as one document too.
  const unseen = segments.filter((s) => s.kind === "hidden" || s.kind === "comment");
  if (unseen.length > 1) {
    const joined = unseen.map((s) => s.text).join(" ").slice(0, 40_000);
    const before = findings.length;
    scanText(joined, "hidden", push);
    for (let i = before; i < findings.length; i++) {
      findings[i].detail = "reassembled across " + unseen.length + " hidden segments";
    }
  }

  // ── Invisible-character channels (placement-independent) ───────────────────
  const tagChars = rawSource.match(UNICODE_TAG_RE);
  if (tagChars && tagChars.length >= 3) {
    findings.push({
      technique: "unicode_tag_smuggling",
      placement: "hidden",
      severity:  1.0,
      weight:    1.0,
      detail:    `${tagChars.length} Unicode Tag characters (U+E0000 block) — an invisible instruction channel with no legitimate use in web content`,
      snippet:   `${tagChars.length} invisible tag characters`,
    });
  }

  const zw = rawSource.match(ZERO_WIDTH_RE);
  if (zw && zw.length >= 12) {
    // A handful of zero-width chars is normal (ligature control, emoji joiners);
    // a long run inside text is a smuggling channel.
    findings.push({
      technique: "invisible_unicode",
      placement: "hidden",
      severity:  0.65,
      weight:    0.65,
      detail:    `${zw.length} zero-width characters — possible hidden-text channel`,
      snippet:   `${zw.length} zero-width characters`,
    });
  }

  const bidi = rawSource.match(BIDI_RE);
  if (bidi && bidi.length >= 8) {
    findings.push({
      technique: "bidi_override",
      placement: "hidden",
      severity:  0.45,
      weight:    0.45,
      detail:    `${bidi.length} bidirectional override characters — text may render differently than it parses`,
      snippet:   `${bidi.length} bidi control characters`,
    });
  }

  // ── Aggregate ──────────────────────────────────────────────────────────────
  // Probabilistic OR: independent signals accumulate but can never exceed 1.
  // Visible-text hits are capped in aggregate: a page that merely DISCUSSES
  // prompt injection can legitimately match many patterns in prose, and without
  // a cap ~7 such hits would stack past the BLOCK threshold on their own.
  let survive = 1;
  for (const f of findings) {
    if (f.placement === "visible") continue;
    survive *= (1 - Math.min(0.99, f.weight));
  }
  let visibleSurvive = 1;
  for (const f of findings) {
    if (f.placement !== "visible") continue;
    visibleSurvive *= (1 - Math.min(0.99, f.weight));
  }
  const visibleRisk = Math.min(VISIBLE_RISK_CAP, 1 - visibleSurvive);
  const risk = Math.round((1 - survive * (1 - visibleRisk)) * 100) / 100;

  findings.sort((a, b) => b.weight - a.weight);
  const techniques = [...new Set(findings.map((f) => f.technique))];

  return { detected: findings.length > 0, risk, techniques, findings };
}
