// HTML → text extraction that SEPARATES what a human sees from what is only in
// the markup. That split is the whole point: an instruction like "ignore your
// previous instructions" is unremarkable in visible article text (security blogs
// discuss it constantly) but is a strong attack signal when it is hidden in a
// comment, a display:none div, or an alt attribute.
//
// Deliberately scanner based — no DOM parser dependency. We are not rendering a
// page, only classifying where text lives.
//
// PERFORMANCE IS A SECURITY PROPERTY HERE: this runs on up to megabytes of
// attacker-controlled markup on a single-threaded server, so every scan is
// forward-only/index-based or has a hard-bounded attribute window. Lazy regexes
// like /<!--([\s\S]*?)-->/ are O(n²) when the terminator never appears and a
// single crafted page can pin the event loop for minutes.

export type SegmentKind =
  | "hidden"         // CSS/attribute hidden from sighted users
  | "accessibility"  // sr-only / visually-hidden — legitimate pattern, but also a vector
  | "comment"        // HTML comment
  | "metadata"       // alt / title / aria-label / meta / other attribute values
  | "script";        // <script> / <style> / <template> / <noscript> body

export interface Segment {
  kind:   SegmentKind;
  text:   string;
  detail: string;
}

export interface ExtractedContent {
  visibleText:        string;
  segments:           Segment[];
  title:              string | null;
  truncated:          boolean;   // input exceeded the analysis budget
  segmentsTruncated:  boolean;   // segment cap hit
}

// Hard analysis budget. The fetch cap is larger (we still report byte size), but
// only this much is ever parsed — bounding worst-case CPU per request.
export const MAX_ANALYZE_CHARS = 256_000;
const MAX_SEGMENTS   = 2_000;
const MAX_ATTR_SCAN  = 2_000;     // longest attribute-list window we will scan
const MAX_ELEMENT_SCAN = 200_000;

const VOID_TAGS = new Set([
  "area","base","br","col","embed","hr","img","input","link","meta","param","source","track","wbr",
]);

// Inline elements are removed WITHOUT inserting a space, so `<b>ig</b>nore`
// yields "ignore" rather than "ig nore" — otherwise intra-word markup silently
// defeats every keyword pattern.
const INLINE_TAGS = new Set([
  "a","b","i","u","s","em","strong","span","small","mark","sub","sup","code","kbd",
  "var","samp","abbr","cite","q","time","font","bdi","bdo","wbr","tt","big","ins","del","label",
]);

// Content that is present but never rendered as page text.
const NON_RENDERED_TAGS = ["script","style","template","noscript"];

// Inline-style / attribute patterns that hide an element. Anchored to a CSS
// property boundary so `min-width:0` / `border-width:0` do not read as `width:0`.
const P = "(?:^|[;{\\s\"'])";
const HIDING_RULES: [RegExp, string][] = [
  [new RegExp(P + "display\\s*:\\s*none", "i"),                   "display:none"],
  [new RegExp(P + "visibility\\s*:\\s*hidden", "i"),              "visibility:hidden"],
  [new RegExp(P + "opacity\\s*:\\s*0(?![.\\d])", "i"),            "opacity:0"],
  [new RegExp(P + "font-size\\s*:\\s*0(?![.\\d])", "i"),          "font-size:0"],
  [new RegExp(P + "text-indent\\s*:\\s*-\\s*\\d{3,}", "i"),       "text-indent:-9999px"],
  [new RegExp(P + "(?:left|top)\\s*:\\s*-\\s*\\d{4,}", "i"),      "positioned off-screen"],
  [new RegExp(P + "clip\\s*:\\s*rect\\(\\s*0", "i"),              "clip:rect(0,0,0,0)"],
  [new RegExp(P + "clip-path\\s*:\\s*inset\\(\\s*(?:100%|50%)", "i"), "clip-path:inset(100%)"],
  [new RegExp(P + "(?:max-)?height\\s*:\\s*0(?![.\\d%a-z])", "i"), "height:0"],
  [new RegExp(P + "(?:max-)?width\\s*:\\s*0(?![.\\d%a-z])", "i"),  "width:0"],
  [/aria-hidden\s*=\s*["']?true/i,                                "aria-hidden=true"],
];

const A11Y_CLASS_RE  = /class\s*=\s*["'][^"']{0,500}\b(?:sr-only|visually-hidden|screen-reader(?:-only|-text)?|a11y-hidden)\b/i;
const HIDDEN_ATTR_RE = /(?:^|\s)hidden(?:\s*=\s*["']?(?:hidden|true|)["']?)?(?=[\s>]|$)/i;

export function decodeEntities(s: string): string {
  return s
    .replace(/&#x([0-9a-f]{1,6});/gi, (_, h) => cp(parseInt(h, 16)))
    .replace(/&#(\d{1,7});/g,         (_, d) => cp(parseInt(d, 10)))
    .replace(/&nbsp;/gi, " ").replace(/&quot;/gi, '"').replace(/&apos;/gi, "'")
    .replace(/&lt;/gi, "<").replace(/&gt;/gi, ">").replace(/&amp;/gi, "&");
}
function cp(n: number): string {
  if (!Number.isFinite(n) || n < 0 || n > 0x10ffff) return "";
  try { return String.fromCodePoint(n); } catch { return ""; }
}

// Strip real HTML tags. Must NOT eat model-control delimiters like `<|im_start|>`
// or `<<SYS>>` — those are payloads, and removing them would hide them from the
// scanner. Inline tags collapse to nothing; block tags become a space.
function stripTags(html: string): string {
  return html.replace(/<\/?([a-zA-Z][a-zA-Z0-9-]*)\b[^>]{0,2000}>|<!\[?[^>]{0,2000}>/g, (m, tag?: string) => {
    if (!tag) return " ";
    return INLINE_TAGS.has(tag.toLowerCase()) ? "" : " ";
  });
}

export function collapseWhitespace(s: string): string {
  return s.replace(/[^\S\n]+/g, " ").replace(/\s*\n\s*/g, "\n").replace(/\n{3,}/g, "\n\n").trim();
}
function textOf(html: string): string {
  return collapseWhitespace(decodeEntities(stripTags(html)));
}

/** Forward, index-based removal of `<tag …> … </tag>` regions. No backtracking. */
function cutRegions(src: string, open: string, closes: string[], onBody: (tag: string, body: string) => void): string {
  const out: string[] = [];
  let cur = 0;
  let i = src.indexOf(open, 0);
  while (i !== -1) {
    // identify which tag matched
    const rest = src.slice(i, i + 24).toLowerCase();
    const tag  = closes.find((t) => rest.startsWith("<" + t));
    if (!tag) { i = src.indexOf(open, i + 1); continue; }
    const gt = src.indexOf(">", i);
    if (gt === -1) break;
    const end = src.toLowerCase().indexOf("</" + tag, gt);
    const bodyEnd = end === -1 ? src.length : end;
    onBody(tag, src.slice(gt + 1, bodyEnd));
    out.push(src.slice(cur, i), " ");
    cur = end === -1 ? src.length : (src.indexOf(">", end) === -1 ? src.length : src.indexOf(">", end) + 1);
    i = src.indexOf(open, cur);
  }
  out.push(src.slice(cur));
  return out.join("");
}

/** Inner HTML of an element, tracking nesting depth. Bounded scan window. */
function innerHtmlOf(html: string, tag: string, openEnd: number): { inner: string; end: number } {
  if (VOID_TAGS.has(tag)) return { inner: "", end: openEnd };
  const limit   = Math.min(html.length, openEnd + MAX_ELEMENT_SCAN);
  const lower   = html.toLowerCase();
  const openTok = "<" + tag;
  const closeTok = "</" + tag;
  let depth = 1, pos = openEnd;
  while (pos < limit && depth > 0) {
    const o = lower.indexOf(openTok, pos);
    const c = lower.indexOf(closeTok, pos);
    if (c === -1 || c >= limit) break;
    if (o !== -1 && o < c && o < limit) { depth++; pos = o + openTok.length; }
    else {
      depth--;
      const gt = html.indexOf(">", c);
      pos = gt === -1 ? limit : gt + 1;
      if (depth === 0) return { inner: html.slice(openEnd, c), end: pos };
    }
  }
  return { inner: html.slice(openEnd, limit), end: limit };
}

/** Class/id selectors that a <style> block hides. Class-based hiding is the
 *  DOMINANT real-world technique; inspecting inline styles alone misses it. */
function hidingSelectorsFrom(css: string): Set<string> {
  const out = new Set<string>();
  // Bounded: selector list up to 200 chars, declaration block up to 400.
  const re = /([^{}]{1,200})\{([^{}]{0,400})\}/g;
  let m: RegExpExecArray | null;
  let seen = 0;
  while ((m = re.exec(css)) !== null && seen < 500) {
    seen++;
    const decl = m[2];
    if (!HIDING_RULES.some(([r]) => r.test(decl))) continue;
    for (const sel of m[1].split(",")) {
      const s = sel.trim().match(/[.#]([A-Za-z0-9_-]{1,64})/);
      if (s) out.add(s[1].toLowerCase());
    }
  }
  return out;
}

export function extractContent(html: string): ExtractedContent {
  const truncated = html.length > MAX_ANALYZE_CHARS;
  let work = truncated ? html.slice(0, MAX_ANALYZE_CHARS) : html;

  const segments: Segment[] = [];
  let segmentsTruncated = false;
  const add = (kind: SegmentKind, text: string, detail: string) => {
    if (!text) return;
    if (segments.length >= MAX_SEGMENTS) { segmentsTruncated = true; return; }
    segments.push({ kind, text: text.slice(0, 20_000), detail });
  };

  // ── 1. Comments — index scan, no lazy regex ────────────────────────────────
  {
    const out: string[] = [];
    let cur = 0, i = work.indexOf("<!--");
    while (i !== -1) {
      const end = work.indexOf("-->", i + 4);
      const bodyEnd = end === -1 ? work.length : end;
      add("comment", textOf(work.slice(i + 4, bodyEnd)), "HTML comment");
      out.push(work.slice(cur, i), " ");
      cur = end === -1 ? work.length : end + 3;
      i = end === -1 ? -1 : work.indexOf("<!--", cur);
    }
    out.push(work.slice(cur));
    work = out.join("");
  }

  // ── 2. Non-rendered bodies: script / style / template / noscript ───────────
  const cssBlocks: string[] = [];
  work = cutRegions(work, "<", NON_RENDERED_TAGS, (tag, body) => {
    if (tag === "style") cssBlocks.push(body);
    // template/noscript can carry rendered-looking payloads; treat as hidden.
    add(tag === "template" || tag === "noscript" ? "hidden" : "script",
        tag === "template" || tag === "noscript" ? textOf(body) : collapseWhitespace(body),
        `<${tag}> body`);
  });

  // ── 3. <title> ─────────────────────────────────────────────────────────────
  const tIdx = work.toLowerCase().indexOf("<title");
  let title: string | null = null;
  if (tIdx !== -1) {
    const gt = work.indexOf(">", tIdx);
    const end = gt === -1 ? -1 : work.toLowerCase().indexOf("</title", gt);
    if (gt !== -1 && end !== -1) title = textOf(work.slice(gt + 1, end)) || null;
  }

  // ── 4. Attribute values. alt/title/aria-label/meta-content are the classic
  //      carriers, but ANY attribute can hold a payload, so scan them all.
  const attrRe = /\b([a-zA-Z][a-zA-Z0-9:_-]{1,40})\s*=\s*"([^"]{13,2000})"|\b([a-zA-Z][a-zA-Z0-9:_-]{1,40})\s*=\s*'([^']{13,2000})'/g;
  const NOISY_ATTRS = new Set(["href","src","srcset","style","class","id","d","points","viewbox","integrity","nonce","transform","path"]);
  for (const m of work.matchAll(attrRe)) {
    const name = (m[1] ?? m[3] ?? "").toLowerCase();
    if (NOISY_ATTRS.has(name)) continue;
    const val = decodeEntities(m[2] ?? m[4] ?? "").trim();
    if (val.length > 12) add("metadata", val, `${name} attribute`);
  }

  // ── 5. Hidden elements (inline style, hidden attr, or a hiding CSS class) ──
  const hidingSelectors = new Set<string>();
  for (const css of cssBlocks) for (const s of hidingSelectorsFrom(css)) hidingSelectors.add(s);

  const tagRe = /<([a-zA-Z][a-zA-Z0-9-]*)\b([^>]{0,2000})>/g;
  const removals: [number, number][] = [];
  let tm: RegExpExecArray | null;

  while ((tm = tagRe.exec(work)) !== null) {
    const tag   = tm[1].toLowerCase();
    const attrs = tm[2] ?? "";
    if (tag === "html" || tag === "body" || tag === "head") continue;

    let kind: SegmentKind | null = null;
    let detail = "";

    for (const [re, label] of HIDING_RULES) {
      if (re.test(attrs)) { kind = "hidden"; detail = label; break; }
    }
    if (!kind && HIDDEN_ATTR_RE.test(attrs)) { kind = "hidden"; detail = "hidden attribute"; }
    if (!kind && hidingSelectors.size) {
      const cls = attrs.match(/(?:class|id)\s*=\s*["']([^"']{0,500})["']/i);
      if (cls) {
        const hit = cls[1].split(/\s+/).find((c) => hidingSelectors.has(c.toLowerCase()));
        if (hit) { kind = "hidden"; detail = `hidden via CSS class/id .${hit}`; }
      }
    }
    if (!kind && A11Y_CLASS_RE.test(attrs)) { kind = "accessibility"; detail = "screen-reader-only class"; }
    if (!kind) continue;

    const openEnd = tm.index + tm[0].length;
    const { inner, end } = innerHtmlOf(work, tag, openEnd);
    add(kind, textOf(inner), detail);
    removals.push([tm.index, end]);
    tagRe.lastIndex = end;
  }

  // ── 6. Visible text. Single forward pass over the (ascending, non-overlapping)
  //      removal ranges — rebuilding the string per removal is O(n²).
  let visible: string;
  if (removals.length) {
    const parts: string[] = [];
    let cur = 0;
    for (const [a, b] of removals) { if (a >= cur) { parts.push(work.slice(cur, a), " "); cur = b; } }
    parts.push(work.slice(cur));
    visible = parts.join("");
  } else {
    visible = work;
  }

  return { visibleText: textOf(visible), segments, title, truncated, segmentsTruncated };
}
