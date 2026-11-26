export interface SemanticSqlResult {
  matched: boolean;
  fingerprint?: string;
  sample?: string;
}

export interface SemanticXssResult {
  matched: boolean;
  vector?: string;
  sample?: string;
}

type SqlTokKind = "k" | "s" | "1" | "o" | "n" | "c" | "(" | ")" | "," | ";";

interface SqlToken {
  kind: SqlTokKind;
  raw: string;
}

const SQL_KEYWORDS = new Set([
  "union",
  "all",
  "select",
  "from",
  "where",
  "or",
  "and",
  "having",
  "order",
  "group",
  "by",
  "insert",
  "into",
  "values",
  "update",
  "set",
  "delete",
  "drop",
  "alter",
  "create",
  "exec",
  "execute",
  "sleep",
  "pg_sleep",
  "benchmark",
  "waitfor",
  "delay",
  "extractvalue",
  "updatexml",
  "concat",
  "cast",
  "convert",
  "case",
  "when",
  "then",
  "in",
  "not",
  "null",
  "xp_cmdshell",
]);

const SQL_EXPLOIT_FNS = new Set([
  "pg_sleep",
  "benchmark",
  "extractvalue",
  "updatexml",
  "sleep",
]);

const HTML_EXEC_TAGS = new Set([
  "script",
  "iframe",
  "object",
  "embed",
  "applet",
  "base",
  "svg",
  "math",
  "template",
  "xmp",
  "noscript",
]);

const HTML_URI_ATTRS = new Set([
  "href",
  "src",
  "action",
  "formaction",
  "data",
  "poster",
  "xlink:href",
  "codebase",
  "srcdoc",
]);

export function analyzeSqlSemantic(input: string): SemanticSqlResult {
  if (!hasSqlQuickTrigger(input)) {
    return { matched: false };
  }

  const direct = scanSqlFragment(input, false);
  if (direct.matched) {
    return direct;
  }

  let offsets = 0;
  for (let i = 0; i < input.length && offsets < 3; i++) {
    const ch = input[i];
    if (ch === "'" || ch === ")") {
      if (ch === "'") {
        offsets++;
      }
      const res = scanSqlFragment(input.slice(i + 1), true);
      if (res.matched) {
        return res;
      }
    }
  }

  return { matched: false };
}

function hasSqlQuickTrigger(s: string): boolean {
  if (s.length < 5) {
    return false;
  }
  let hasBreak = false;
  let hasAlpha = false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (
      c === 39 ||
      c === 59 ||
      c === 40 ||
      c === 41 ||
      c === 61 ||
      c === 60 ||
      c === 62 ||
      c === 45 ||
      c === 47
    ) {
      hasBreak = true;
    } else if ((c >= 97 && c <= 122) || (c >= 65 && c <= 90)) {
      hasAlpha = true;
    }
  }
  if (!hasBreak || !hasAlpha) {
    return false;
  }
  const low = s.toLowerCase();
  let i = 0;
  while (i < low.length) {
    const c = low.charCodeAt(i);
    if ((c >= 97 && c <= 122) || c === 95) {
      const start = i;
      i++;
      while (i < low.length) {
        const nc = low.charCodeAt(i);
        if ((nc >= 97 && nc <= 122) || (nc >= 48 && nc <= 57) || nc === 95) {
          i++;
        } else {
          break;
        }
      }
      const word = low.slice(start, i);
      if (
        SQL_KEYWORDS.has(word) &&
        word !== "all" &&
        word !== "from" &&
        word !== "in" &&
        word !== "set" &&
        word !== "not" &&
        word !== "null" &&
        word !== "by"
      ) {
        return true;
      }
    } else {
      i++;
    }
  }
  return false;
}

function scanSqlFragment(frag: string, afterContextBreak: boolean): SemanticSqlResult {
  if (frag.length < 4) {
    return { matched: false };
  }
  const tokens = tokenizeSql(frag);
  if (tokens.length === 0) {
    return { matched: false };
  }

  let hadComment = false;
  const compact: SqlToken[] = [];
  for (const t of tokens) {
    if (t.kind === "c") {
      hadComment = true;
      continue;
    }
    compact.push(t);
  }
  if (compact.length === 0) {
    return { matched: false };
  }

  // 1. Exploit function calls: pg_sleep(, benchmark(, extractvalue(, updatexml(, sleep(
  for (let i = 0; i + 1 < compact.length; i++) {
    const t0 = compact[i];
    const t1 = compact[i + 1];
    if (t0?.kind === "k" && SQL_EXPLOIT_FNS.has(t0.raw) && t1?.kind === "(") {
      return {
        matched: true,
        fingerprint: buildFp(compact, i, 4),
        sample: collectSamples(compact, i, 4),
      };
    }
  }

  // 2. UNION [ALL] SELECT
  for (let i = 0; i + 1 < compact.length; i++) {
    const t0 = compact[i];
    const t1 = compact[i + 1];
    const t2 = compact[i + 2];
    if (t0?.kind === "k" && t0.raw === "union") {
      if (
        t1?.kind === "k" &&
        (t1.raw === "select" ||
          (t1.raw === "all" && t2?.kind === "k" && t2.raw === "select"))
      ) {
        return {
          matched: true,
          fingerprint: buildFp(compact, i, 5),
          sample: collectSamples(compact, i, 5),
        };
      }
    }
  }

  // 3. Stacked statement: ; EXEC/EXECUTE/DROP/ALTER/CREATE
  for (let i = 0; i + 2 < compact.length; i++) {
    const t0 = compact[i];
    const t1 = compact[i + 1];
    if (
      t0?.kind === ";" &&
      t1?.kind === "k" &&
      (t1.raw === "exec" ||
        t1.raw === "execute" ||
        t1.raw === "drop" ||
        t1.raw === "alter" ||
        t1.raw === "create")
    ) {
      return {
        matched: true,
        fingerprint: buildFp(compact, i, 4),
        sample: collectSamples(compact, i, 4),
      };
    }
  }

  // 4. Context-break boolean tautology/subquery/fn
  const first = compact[0];
  if (afterContextBreak && first?.kind === "k" && (first.raw === "and" || first.raw === "or")) {
    const c1 = compact[1];
    const c2 = compact[2];
    const c3 = compact[3];
    if (c1 && c2?.kind === "o" && c3 && isScalar(c1.kind) && isScalar(c3.kind)) {
      return {
        matched: true,
        fingerprint: buildFp(compact, 0, 5),
        sample: collectSamples(compact, 0, 5),
      };
    }
    for (let i = 1; i + 3 < compact.length; i++) {
      if (
        compact[i]?.kind === "k" &&
        compact[i]?.raw === "in" &&
        compact[i + 1]?.kind === "(" &&
        compact[i + 2]?.kind === "k" &&
        compact[i + 2]?.raw === "select"
      ) {
        return {
          matched: true,
          fingerprint: buildFp(compact, 0, i + 4),
          sample: collectSamples(compact, 0, i + 4),
        };
      }
    }
    for (let i = 1; i + 1 < compact.length; i++) {
      const fn = compact[i];
      if (fn?.kind === "k" && SQL_EXPLOIT_FNS.has(fn.raw) && compact[i + 1]?.kind === "(") {
        return {
          matched: true,
          fingerprint: buildFp(compact, 0, i + 3),
          sample: collectSamples(compact, 0, i + 3),
        };
      }
    }
  }

  // 5. Context-break ORDER BY <number>
  if (
    afterContextBreak &&
    compact.length >= 3 &&
    compact[0]?.kind === "k" &&
    compact[0].raw === "order" &&
    compact[1]?.kind === "k" &&
    compact[1].raw === "by" &&
    compact[2]?.kind === "1" &&
    (hadComment ||
      compact.length === 3 ||
      compact[3]?.kind === ";" ||
      compact[3]?.kind === ",")
  ) {
    return {
      matched: true,
      fingerprint: buildFp(compact, 0, 4),
      sample: collectSamples(compact, 0, 4),
    };
  }

  return { matched: false };
}

function isScalar(k: SqlTokKind): boolean {
  return k === "1" || k === "s" || k === "n";
}

function tokenizeSql(s: string): SqlToken[] {
  const toks: SqlToken[] = [];
  let i = 0;
  const n = s.length;
  while (i < n && toks.length < 64) {
    const ch = s[i] ?? "";
    const code = s.charCodeAt(i);
    if (ch === " " || ch === "\t" || ch === "\r" || ch === "\n") {
      i++;
      continue;
    }
    if (ch === "-" && s[i + 1] === "-") {
      toks.push({ kind: "c", raw: "--" });
      break;
    }
    if (ch === "#") {
      toks.push({ kind: "c", raw: "#" });
      break;
    }
    if (ch === "/" && s[i + 1] === "*") {
      const end = s.indexOf("*/", i + 2);
      if (end >= 0) {
        toks.push({ kind: "c", raw: "/*" });
        i = end + 2;
        continue;
      }
      toks.push({ kind: "c", raw: "/*" });
      break;
    }
    if (ch === "'") {
      let j = i + 1;
      while (j < n && s[j] !== "'") {
        j++;
      }
      if (j < n) {
        toks.push({ kind: "s", raw: s.slice(i, j + 1) });
        i = j + 1;
      } else {
        toks.push({ kind: "s", raw: s.slice(i) });
        break;
      }
      continue;
    }
    if (ch === '"') {
      i++;
      continue;
    }
    if (code >= 48 && code <= 57) {
      let j = i + 1;
      while (j < n) {
        const nc = s.charCodeAt(j);
        if (
          (nc >= 48 && nc <= 57) ||
          (nc >= 97 && nc <= 102) ||
          (nc >= 65 && nc <= 70) ||
          s[j] === "x" ||
          s[j] === "."
        ) {
          j++;
        } else {
          break;
        }
      }
      toks.push({ kind: "1", raw: s.slice(i, j) });
      i = j;
      continue;
    }
    if ((code >= 97 && code <= 122) || (code >= 65 && code <= 90) || code === 95) {
      let j = i + 1;
      while (j < n) {
        const nc = s.charCodeAt(j);
        if (
          (nc >= 97 && nc <= 122) ||
          (nc >= 65 && nc <= 90) ||
          (nc >= 48 && nc <= 57) ||
          nc === 95
        ) {
          j++;
        } else {
          break;
        }
      }
      const low = s.slice(i, j).toLowerCase();
      toks.push({ kind: SQL_KEYWORDS.has(low) ? "k" : "n", raw: low });
      i = j;
      continue;
    }
    if (ch === "(" || ch === ")" || ch === "," || ch === ";") {
      toks.push({ kind: ch, raw: ch });
    } else if (ch === "=" || ch === "<" || ch === ">" || ch === "!") {
      const next = s[i + 1];
      if (next === "=" || next === ">") {
        toks.push({ kind: "o", raw: ch + next });
        i++;
      } else {
        toks.push({ kind: "o", raw: ch });
      }
    }
    i++;
  }
  return toks;
}

function buildFp(toks: SqlToken[], start: number, count: number): string {
  return toks
    .slice(start, start + count)
    .map((t) => t.kind)
    .join("");
}

function collectSamples(toks: SqlToken[], start: number, count: number): string {
  return toks
    .slice(start, start + count)
    .map((t) => t.raw)
    .join(" ");
}

export function analyzeXssSemantic(input: string): SemanticXssResult {
  if (!input.includes("<")) {
    return { matched: false };
  }

  const n = input.length;
  for (let i = 0; i < n; i++) {
    if (input[i] !== "<") {
      continue;
    }
    let j = i + 1;
    const c = input.charCodeAt(j);
    if (j >= n || !((c >= 65 && c <= 90) || (c >= 97 && c <= 122))) {
      continue;
    }
    const nameStart = j;
    while (j < n) {
      const tc = input.charCodeAt(j);
      if (
        (tc >= 65 && tc <= 90) ||
        (tc >= 97 && tc <= 122) ||
        (tc >= 48 && tc <= 57) ||
        tc === 45
      ) {
        j++;
      } else {
        break;
      }
    }
    const tagName = input.slice(nameStart, j).toLowerCase();
    const tagEnd = findTagClose(input, j);
    const rawTag = input.slice(i, tagEnd);

    if (HTML_EXEC_TAGS.has(tagName)) {
      const nextCh = input[j];
      if (j === n || nextCh === ">" || nextCh === "/" || (input.charCodeAt(j) <= 32)) {
        return { matched: true, vector: `executable-tag:${tagName}`, sample: rawTag };
      }
    }

    let attrSlice = input.slice(j, tagEnd);
    if (attrSlice.endsWith(">")) {
      attrSlice = attrSlice.slice(0, -1);
    }
    const attrHit = scanTagAttrsForXss(tagName, attrSlice);
    if (attrHit) {
      return { matched: true, vector: attrHit.vector, sample: attrHit.sample };
    }
  }

  return { matched: false };
}

function findTagClose(s: string, start: number): number {
  let quote: string | null = null;
  for (let i = start; i < s.length; i++) {
    const ch = s[i];
    if (quote) {
      if (ch === quote) {
        quote = null;
      }
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (ch === ">") {
      return i + 1;
    }
    if (ch === "<") {
      return i;
    }
  }
  return s.length;
}

function scanTagAttrsForXss(
  tagName: string,
  attrs: string,
): { vector: string; sample: string } | null {
  let i = 0;
  const n = attrs.length;
  const isMeta = tagName === "meta";

  while (i < n) {
    while (i < n && (attrs.charCodeAt(i) <= 32 || attrs[i] === "/")) {
      i++;
    }
    if (i >= n) break;
    const nameStart = i;
    while (
      i < n &&
      attrs[i] !== "=" &&
      attrs.charCodeAt(i) > 32 &&
      attrs[i] !== "/" &&
      attrs[i] !== ">"
    ) {
      i++;
    }
    const attrName = attrs.slice(nameStart, i).replace(/^["']+|["']+$/g, "").toLowerCase();
    while (i < n && attrs.charCodeAt(i) <= 32) {
      i++;
    }

    let attrVal = "";
    if (i < n && attrs[i] === "=") {
      i++;
      while (i < n && attrs.charCodeAt(i) <= 32) {
        i++;
      }
      const q = attrs[i];
      if (q === '"' || q === "'") {
        i++;
        const vStart = i;
        while (i < n && attrs[i] !== q) {
          i++;
        }
        attrVal = attrs.slice(vStart, i);
        if (i < n) i++;
      } else {
        const vStart = i;
        while (i < n && attrs.charCodeAt(i) > 32 && attrs[i] !== ">") {
          if (
            attrs[i] === "/" &&
            !attrs.slice(vStart, i).includes("://") &&
            looksLikeAttrAssign(attrs, i + 1)
          ) {
            break;
          }
          i++;
        }
        attrVal = attrs.slice(vStart, i);
      }
    }

    if (attrName.startsWith("on") && attrName.length >= 5 && /^[a-z]+$/.test(attrName) && attrVal !== "") {
      return { vector: `event-handler:${attrName}`, sample: `${attrName}=${attrVal}` };
    }

    if (HTML_URI_ATTRS.has(attrName)) {
      const norm = stripControlLower(attrVal);
      if (
        norm.startsWith("javascript:") ||
        norm.startsWith("vbscript:") ||
        norm.startsWith("data:text/html") ||
        norm.startsWith("data:application/xhtml")
      ) {
        return { vector: `dangerous-uri:${attrName}`, sample: `${attrName}=${attrVal}` };
      }
    }

    if (isMeta && attrName === "content") {
      const norm = stripControlLower(attrVal);
      if (norm.includes("url=javascript:") || norm.includes("url=data:text/html")) {
        return { vector: "meta-refresh-uri", sample: attrVal };
      }
    }
  }

  return null;
}

function looksLikeAttrAssign(s: string, start: number): boolean {
  let i = start;
  if (i >= s.length) return false;
  const first = s.charCodeAt(i);
  if (!((first >= 65 && first <= 90) || (first >= 97 && first <= 122))) {
    return false;
  }
  while (i < s.length) {
    const c = s.charCodeAt(i);
    if ((c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 45) {
      i++;
    } else {
      break;
    }
  }
  return s[i] === "=";
}

function stripControlLower(s: string): string {
  let out = "";
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code <= 32 || code === 127) {
      continue;
    }
    out += s[i]?.toLowerCase() ?? "";
  }
  return out;
}
