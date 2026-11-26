export interface SanitizeOptions {
  allowedTags?: readonly string[];
  allowedAttributes?: Record<string, readonly string[]>;
  allowMailto?: boolean;
}

const DEFAULT_ALLOWED_TAGS = new Set([
  "b",
  "i",
  "em",
  "strong",
  "p",
  "br",
  "ul",
  "ol",
  "li",
  "code",
  "pre",
  "blockquote",
  "a",
  "span",
]);

const VOID_TAGS = new Set(["br", "hr", "img", "wbr"]);

const EXECUTABLE_DROP_BLOCK_RE =
  /<\s*(script|style|iframe|object|embed|svg|math|template|noscript|textarea|xmp)\b[^>]*>[\s\S]*?<\s*\/\s*\1\s*>/gi;
const DANGLING_OPEN_BLOCK_RE =
  /<\s*(script|style|iframe|object|embed|svg|math|template|noscript|textarea|xmp)\b[\s\S]*$/gi;

const DEFAULT_ALLOWED_ATTRS: Record<string, Set<string>> = {
  "*": new Set(["class", "title", "dir", "lang"]),
  a: new Set(["href", "title", "target", "rel", "class"]),
  img: new Set(["src", "alt", "title", "width", "height", "class"]),
};

const NAMED_ENTITIES: Record<string, string> = {
  amp: "&",
  lt: "<",
  gt: ">",
  quot: '"',
  apos: "'",
  "#39": "'",
  colon: ":",
  tab: "\t",
  newline: "\n",
};

export function escapeHtml(input: string): string {
  return input
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;")
    .replace(/`/g, "&#96;");
}

function escapeTextNodeIdempotent(input: string): string {
  return input
    .replace(/&(?!amp;|lt;|gt;|quot;|#39;|#96;)/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;")
    .replace(/`/g, "&#96;");
}

export function decodeHtmlEntities(input: string): string {
  return input.replace(/&(#x[0-9a-f]+|#\d+|[a-z0-9]+);?/gi, (full, body: string) => {
    const low = body.toLowerCase();
    if (low in NAMED_ENTITIES) {
      return NAMED_ENTITIES[low] ?? full;
    }
    if (low.startsWith("#x")) {
      const cp = Number.parseInt(low.slice(2), 16);
      if (Number.isFinite(cp) && cp >= 1 && cp <= 0x10ffff) {
        return String.fromCodePoint(cp);
      }
      return "";
    }
    if (low.startsWith("#")) {
      const cp = Number.parseInt(low.slice(1), 10);
      if (Number.isFinite(cp) && cp >= 1 && cp <= 0x10ffff) {
        return String.fromCodePoint(cp);
      }
      return "";
    }
    return full;
  });
}

export function isSafeUrl(rawUrl: string, allowMailto = true): boolean {
  let decoded = rawUrl;
  for (let pass = 0; pass < 3; pass++) {
    const next = decodeHtmlEntities(decoded);
    if (next === decoded) {
      break;
    }
    decoded = next;
  }
  // Remove ASCII control chars and whitespace to defeat java\tscript: / \x01javascript: tricks.
  let normalized = "";
  for (let i = 0; i < decoded.length; i++) {
    const code = decoded.charCodeAt(i);
    if (code > 0x20 && code !== 0x7f) {
      normalized += decoded[i];
    }
  }
  if (normalized === "") {
    return false;
  }

  const lower = normalized.toLowerCase();
  if (lower.startsWith("#")) {
    return true;
  }
  if (lower.startsWith("/")) {
    return !lower.startsWith("//") && !lower.startsWith("/\\");
  }
  if (lower.startsWith("https://") || lower.startsWith("http://")) {
    return true;
  }
  if (allowMailto && lower.startsWith("mailto:")) {
    return true;
  }
  return false;
}

export function sanitizeHtml(input: string, options: SanitizeOptions = {}): string {
  if (!input) {
    return "";
  }

  const allowedTags = options.allowedTags
    ? new Set(options.allowedTags.map((t) => t.toLowerCase().trim()))
    : DEFAULT_ALLOWED_TAGS;

  const allowedAttrs = buildAttrMap(options.allowedAttributes);
  const allowMailto = options.allowMailto ?? true;

  // Iteratively strip executable tag blocks first so nested patterns collapse safely.
  let current = input.replace(/\0/g, "");
  for (let pass = 0; pass < 6; pass++) {
    const next = current
      .replace(EXECUTABLE_DROP_BLOCK_RE, "")
      .replace(DANGLING_OPEN_BLOCK_RE, "");
    if (next === current) {
      break;
    }
    current = next;
  }

  // Single-pass strict tokenizer/serializer; rerun once to guarantee fixpoint idempotency.
  let sanitized = tokenizeAndFilter(current, allowedTags, allowedAttrs, allowMailto);
  const second = tokenizeAndFilter(sanitized, allowedTags, allowedAttrs, allowMailto);
  if (second !== sanitized) {
    sanitized = second;
  }
  return sanitized;
}

function tokenizeAndFilter(
  input: string,
  allowedTags: Set<string>,
  allowedAttrs: Record<string, Set<string>>,
  allowMailto: boolean,
): string {
  let out = "";
  let i = 0;
  const len = input.length;
  const openStack: string[] = [];

  while (i < len) {
    const lt = input.indexOf("<", i);
    if (lt === -1) {
      out += escapeTextNodeIdempotent(input.slice(i));
      break;
    }
    if (lt > i) {
      out += escapeTextNodeIdempotent(input.slice(i, lt));
    }

    const gt = findTagEnd(input, lt + 1);
    if (gt === -1) {
      // Unclosed '<' gets escaped rather than executed.
      out += escapeTextNodeIdempotent(input.slice(lt));
      break;
    }

    const inner = input.slice(lt + 1, gt).trim();
    i = gt + 1;

    if (!inner || inner.startsWith("!") || inner.startsWith("?")) {
      continue;
    }

    const isClosing = inner.startsWith("/");
    const body = (isClosing ? inner.slice(1) : inner).trim();
    const match = /^([a-zA-Z][a-zA-Z0-9-]*)(?:[\s/]+([\s\S]*))?$/.exec(body);
    if (!match || !match[1]) {
      continue;
    }

    const tagName = match[1].toLowerCase();
    if (!allowedTags.has(tagName)) {
      continue;
    }

    if (isClosing) {
      if (VOID_TAGS.has(tagName)) {
        continue;
      }
      const matchIdx = openStack.lastIndexOf(tagName);
      if (matchIdx === -1) {
        continue;
      }
      while (openStack.length > matchIdx) {
        const closed = openStack.pop();
        if (closed) {
          out += `</${closed}>`;
        }
      }
      continue;
    }

    const rawAttrStr = (match[2] ?? "").replace(/\/\s*$/, "").trim();
    const safeAttrs = filterAttributes(tagName, rawAttrStr, allowedAttrs, allowMailto);
    out += `<${tagName}${safeAttrs}>`;
    if (!VOID_TAGS.has(tagName)) {
      openStack.push(tagName);
    }
  }

  while (openStack.length > 0) {
    const dangling = openStack.pop();
    if (dangling) {
      out += `</${dangling}>`;
    }
  }

  return out;
}

function findTagEnd(input: string, start: number): number {
  let quote: string | null = null;
  for (let i = start; i < input.length; i++) {
    const ch = input[i];
    if (quote) {
      if (ch === quote) {
        quote = null;
      }
    } else if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (ch === ">") {
      return i;
    } else if (ch === "<") {
      // Stray '<' before closing '>' truncates malformed tag candidate cleanly.
      return -1;
    }
  }
  return -1;
}

function filterAttributes(
  tagName: string,
  rawAttrs: string,
  allowedAttrs: Record<string, Set<string>>,
  allowMailto: boolean,
): string {
  if (!rawAttrs) {
    return "";
  }
  const tagSet = allowedAttrs[tagName];
  const globalSet = allowedAttrs["*"];
  const kept: string[] = [];
  let hasTargetBlank = false;
  let hasRel = false;

  const attrRe = /([a-zA-Z_:][a-zA-Z0-9_.:-]*)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  let m: RegExpExecArray | null;
  while ((m = attrRe.exec(rawAttrs)) !== null) {
    const attrName = (m[1] ?? "").toLowerCase();
    if (!attrName || attrName.startsWith("on") || attrName === "style") {
      continue;
    }
    const isPermitted = Boolean(tagSet?.has(attrName) || globalSet?.has(attrName));
    if (!isPermitted) {
      continue;
    }

    const rawVal = m[2] ?? m[3] ?? m[4] ?? "";
    const val = decodeHtmlEntities(rawVal).trim();

    if (attrName === "href" || attrName === "src") {
      if (!isSafeUrl(val, allowMailto)) {
        continue;
      }
    }
    if (attrName === "target" && val.toLowerCase() === "_blank") {
      hasTargetBlank = true;
    }
    if (attrName === "rel") {
      hasRel = true;
    }
    kept.push(`${attrName}="${escapeHtml(val)}"`);
  }

  if (tagName === "a" && hasTargetBlank && !hasRel) {
    kept.push('rel="noopener noreferrer"');
  }

  return kept.length > 0 ? " " + kept.join(" ") : "";
}

function buildAttrMap(
  custom?: Record<string, readonly string[]>,
): Record<string, Set<string>> {
  const map: Record<string, Set<string>> = {
    "*": new Set(DEFAULT_ALLOWED_ATTRS["*"]),
    a: new Set(DEFAULT_ALLOWED_ATTRS["a"]),
    img: new Set(DEFAULT_ALLOWED_ATTRS["img"]),
  };
  if (!custom) {
    return map;
  }
  for (const [tag, attrs] of Object.entries(custom)) {
    const clean = attrs
      .map((a) => a.toLowerCase().trim())
      .filter((a) => a !== "" && !a.startsWith("on") && a !== "style");
    map[tag.toLowerCase()] = new Set(clean);
  }
  return map;
}
