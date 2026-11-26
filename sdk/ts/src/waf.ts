import {
  buildSecurityHeaders,
  generateCspNonce,
  type SecurityHeadersOptions,
} from "./headers.js";
import {
  createMemoryRateLimiter,
  type RateLimiterOptions,
} from "./ratelimit.js";
import { analyzeSqlSemantic, analyzeXssSemantic } from "./semantic.js";

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface RaksaFinding {
  id: string;
  rule_id: string;
  module: string;
  layer: string;
  severity: Severity;
  title: string;
  description: string;
  target: string;
  evidence?: Record<string, unknown>;
  remediation: string;
  mitre_d3fend: string;
  timestamp: string;
}

export interface RaksaSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface RaksaPostureScore {
  score: number;
  grade: string;
}

export interface RaksaReport {
  schema_version: "1.0";
  tool: "raksa-webshield";
  layer: "web-defense";
  generated_at: string;
  posture: RaksaPostureScore;
  summary: RaksaSummary;
  findings: RaksaFinding[];
}

export interface CustomWafRule {
  id: string;
  title: string;
  severity?: Severity;
  weight?: number;
  matchType: "contains" | "regex" | "exact";
  pattern: string | RegExp;
  caseInsensitive?: boolean;
  action?: "block" | "monitor";
  remediation?: string;
}

export interface InspectOptions {
  paranoiaLevel?: number;
  anomalyThreshold?: number;
  customRules?: readonly CustomWafRule[];
}

export interface WebShieldRequestLike {
  url?: string;
  method?: string;
  ip?: string;
  headers?: Record<string, string | string[] | undefined>;
  query?: unknown;
  params?: unknown;
  body?: unknown;
}

export interface WebShieldResponseLike {
  statusCode: number;
  locals?: Record<string, unknown>;
  setHeader(name: string, value: string): void;
  removeHeader?(name: string): void;
  end(chunk?: string): void;
}

export type NextCallback = (err?: unknown) => void;

export interface MiddlewareOptions {
  mode?: "enforce" | "monitor";
  applyHeaders?: boolean;
  hidePoweredBy?: boolean;
  headerOptions?: SecurityHeadersOptions;
  cspNonce?: boolean;
  maxInspectBytes?: number;
  paranoiaLevel?: number;
  anomalyThreshold?: number;
  customRules?: readonly CustomWafRule[];
  excludePaths?: readonly (string | RegExp)[];
  exposeReportInResponse?: boolean;
  rateLimit?: RateLimiterOptions;
  getClientKey?: (req: WebShieldRequestLike) => string;
  onReport?: (report: RaksaReport, req: WebShieldRequestLike, incidentId: string) => void;
}

interface WafRule {
  ruleId: string;
  severity: Severity;
  weight: number;
  title: string;
  description: string;
  remediation: string;
  asvs: string;
  d3fend: string;
  pattern: RegExp;
  pl2Pattern?: RegExp;
  prefilter: (low: string) => boolean;
}

const SENSITIVE_HEADER_KEYS = ["user-agent", "referer", "x-forwarded-for", "cookie"];

const WAF_RULES: readonly WafRule[] = [
  {
    ruleId: "WEB-301",
    severity: "high",
    weight: 4,
    title: "Cross-Site Scripting (XSS) payload pattern detected",
    description:
      "Input contains executable HTML/script tags, inline event handlers, or dangerous URI schemes.",
    remediation:
      "Sanitize untrusted HTML with sanitizeHtml() and apply context-aware output encoding.",
    asvs: "5.3.3",
    d3fend: "D3-IV",
    pattern:
      /(<\s*script\b|(?:javascript|vbscript)\s*:|data\s*:\s*text\/html|\bon(?:error|load|click|mouseover|focus|blur|submit|animationstart)\s*=|<\s*svg\b[^>]*\bon\w+\s*=|<\s*iframe\b[^>]*\bsrcdoc\s*=)/i,
    pl2Pattern: /<\s*[a-z][a-z0-9-]*\b[^>]*\bon[a-z]+\s*=/i,
    prefilter: (low) =>
      low.includes("<") ||
      (low.includes("=") && low.includes("on")) ||
      low.includes("javascript") ||
      low.includes("vbscript") ||
      low.includes("text/html"),
  },
  {
    ruleId: "WEB-302",
    severity: "critical",
    weight: 5,
    title: "SQL Injection (SQLi) payload pattern detected",
    description:
      "Input matches SQL UNION, boolean tautology, stacked statement, or timing-delay injection patterns.",
    remediation:
      "Use parameterized prepared statements strictly and validate expected input schemas.",
    asvs: "5.3.4",
    d3fend: "D3-IV",
    pattern:
      /(\bunion\s+(?:all\s+)?select\b|(?:'\s*or\s+'?1'?\s*=\s*'?1|\bor\s+1\s*=\s*1\b|"\s*or\s+"?1"?\s*=\s*"?1)|;\s*(?:drop|delete|insert|update|alter)\s+\w+|\b(?:sleep\s*\(\s*\d+\s*\)|waitfor\s+delay)\b)/i,
    pl2Pattern: /(?:['"]\s*;\s*--|\bselect\b.+\bfrom\b.+\bwhere\b)/i,
    prefilter: (low) =>
      low.includes("union") ||
      (low.includes("=") &&
        (low.includes("or ") || low.includes("or\t") || low.includes("or\n"))) ||
      low.includes(";") ||
      low.includes("sleep") ||
      low.includes("waitfor") ||
      low.includes("select"),
  },
  {
    ruleId: "WEB-303",
    severity: "high",
    weight: 4,
    title: "Path Traversal / Local File Inclusion sequence detected",
    description:
      "Input contains directory traversal sequences, null bytes, or sensitive OS file targets.",
    remediation:
      "Normalize with path.basename or ensure resolved canonical path starts within the allowed directory.",
    asvs: "12.3.1",
    d3fend: "D3-IV",
    pattern: /(\.\.[/\\]|%00|\x00|\/etc\/passwd|\/etc\/shadow|windows[/\\]win\.ini)/i,
    prefilter: (low) =>
      low.includes("..") ||
      low.includes("\x00") ||
      low.includes("%00") ||
      low.includes("/etc/") ||
      low.includes("win.ini"),
  },
  {
    ruleId: "WEB-304",
    severity: "high",
    weight: 4,
    title: "Prototype Pollution key detected in request payload",
    description:
      "Input references JavaScript prototype chain mutation keys (__proto__ or constructor.prototype).",
    remediation:
      "Reject or strip __proto__, constructor, and prototype keys before object merging.",
    asvs: "5.1.3",
    d3fend: "D3-IV",
    pattern: /(__proto__|constructor\s*\.\s*prototype|\[\s*["']prototype["']\s*\]|["']prototype["']\s*:)/i,
    prefilter: (low) => low.includes("__proto__") || low.includes("prototype"),
  },
  {
    ruleId: "WEB-305",
    severity: "critical",
    weight: 5,
    title: "SSRF or cloud metadata URI target detected",
    description:
      "Input references cloud instance metadata endpoints or non-HTTP local schemes (file://, gopher://, dict://).",
    remediation:
      "Allowlist permitted outbound hosts and block loopback, private, and link-local IP ranges.",
    asvs: "12.6.1",
    d3fend: "D3-NI",
    pattern: /(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|(?:file|gopher|dict):\/\/)/i,
    prefilter: (low) =>
      low.includes("169.254.") ||
      low.includes("metadata.google") ||
      low.includes("100.100.") ||
      low.includes("file://") ||
      low.includes("gopher://") ||
      low.includes("dict://"),
  },
  {
    ruleId: "WEB-306",
    severity: "critical",
    weight: 5,
    title: "OS Command Injection / Remote Code Execution payload pattern detected",
    description:
      "Input contains shell metacharacter command chaining, command substitution, or subshell execution syntax.",
    remediation:
      "Avoid invoking a shell; execute binaries with explicit argv arrays and allowlisted arguments.",
    asvs: "5.3.8",
    d3fend: "D3-IV",
    pattern:
      /(?:[;&|`]\s*(?:cat|ls|id|whoami|uname|pwd|nc|ncat|curl|wget|bash|sh|zsh|powershell|cmd(?:\.exe)?|python[23]?|perl|ruby|php|chmod|chown|rm|kill)\b|\$\([^)]+\)|`[^`]+`)/i,
    prefilter: (low) =>
      low.includes(";") ||
      low.includes("|") ||
      low.includes("&") ||
      low.includes("$(") ||
      low.includes("`"),
  },
  {
    ruleId: "WEB-307",
    severity: "critical",
    weight: 5,
    title: "Server-Side Template Injection (SSTI) or JNDI lookup pattern detected",
    description:
      "Input contains template engine evaluation expressions or Java JNDI lookup payloads.",
    remediation:
      "Disable server-side evaluation of untrusted template expressions and block JNDI lookups.",
    asvs: "5.2.5",
    d3fend: "D3-IV",
    pattern:
      /(\$\{jndi:|{{\s*(?:\d+\s*[*+\-/]\s*\d+|[^}]*(?:__class__|__subclasses__|__globals__|__builtins__|config\.items))\s*}}|<%=\s*[^%]+%>)/i,
    prefilter: (low) =>
      low.includes("${jndi:") || low.includes("{{") || low.includes("<%="),
  },
  {
    ruleId: "WEB-308",
    severity: "high",
    weight: 4,
    title: "NoSQL operator injection pattern detected",
    description:
      "Input contains query operator keys ($ne, $gt, $where, $regex, $expr) indicative of NoSQL injection.",
    remediation:
      "Enforce strict scalar input schemas and strip keys prefixed with '$' prior to database queries.",
    asvs: "5.3.5",
    d3fend: "D3-IV",
    pattern:
      /(?:["']\$(?:ne|gt|gte|lt|lte|where|regex|expr|nin|in)\\?["']\s*:|\[\s*\$(?:ne|gt|gte|lt|lte|where|regex|nin|in)\s*\])/i,
    prefilter: (low) => low.includes("$"),
  },
  {
    ruleId: "WEB-309",
    severity: "critical",
    weight: 5,
    title: "XML External Entity (XXE) DOCTYPE/ENTITY injection pattern detected",
    description:
      "XML payload declares DOCTYPE internal subsets or external SYSTEM/PUBLIC ENTITY references.",
    remediation:
      "Disable DTD processing and external entity resolution in XML parsers.",
    asvs: "5.5.2",
    d3fend: "D3-IV",
    pattern: /(<!doctype\b[^>]*\[|<!entity\b[^>]*\b(?:system|public)\b)/i,
    prefilter: (low) => low.includes("<!doctype") || low.includes("<!entity"),
  },
  {
    ruleId: "WEB-310",
    severity: "high",
    weight: 4,
    title: "HTTP Response Splitting / CRLF header injection sequence detected",
    description:
      "Input contains CR/LF sequences followed by HTTP response headers such as Set-Cookie or Location.",
    remediation:
      "Strip or reject CR and LF characters before placing user input into HTTP response headers.",
    asvs: "5.3.10",
    d3fend: "D3-IV",
    pattern:
      /(?:\r\n|%0d%0a|\\r\\n)\s*(?:set-cookie|location|content-length|transfer-encoding|http\/1\.)/i,
    prefilter: (low) =>
      low.includes("\r\n") || low.includes("%0d%0a") || low.includes("\\r\\n"),
  },
];

export function inspectInput(
  input: string,
  target = "inline://request",
  options: InspectOptions = {},
): RaksaFinding[] {
  if (!input || input.trim() === "") {
    return [];
  }

  const paranoia = Math.max(1, Math.min(3, Math.floor(options.paranoiaLevel ?? 1)));
  const threshold = Math.max(0, Math.floor(options.anomalyThreshold ?? 0));

  const views = normalizePayloadViews(input);
  const lowViews = views.map((v) => v.toLowerCase());
  const now = new Date().toISOString();
  const findings: RaksaFinding[] = [];
  let totalScore = 0;

  for (const rule of WAF_RULES) {
    let matchedSample = "";
    let detector: "regex" | "semantic" = "regex";
    let semanticTag = "";

    for (let idx = 0; idx < views.length; idx++) {
      const low = lowViews[idx] ?? "";
      const view = views[idx] ?? "";
      if (!rule.prefilter(low)) {
        continue;
      }
      const m =
        rule.pattern.exec(view) ??
        (paranoia >= 2 && rule.pl2Pattern ? rule.pl2Pattern.exec(view) : null);
      if (m && m[0]) {
        matchedSample = m[0];
        break;
      }
    }

    if (matchedSample === "" && rule.ruleId === "WEB-301") {
      for (const view of views) {
        const sem = analyzeXssSemantic(view);
        if (sem.matched && sem.sample) {
          matchedSample = sem.sample;
          detector = "semantic";
          semanticTag = sem.vector ?? "";
          break;
        }
      }
    }
    if (matchedSample === "" && rule.ruleId === "WEB-302") {
      for (const view of views) {
        const sem = analyzeSqlSemantic(view);
        if (sem.matched && sem.sample) {
          matchedSample = sem.sample;
          detector = "semantic";
          semanticTag = sem.fingerprint ?? "";
          break;
        }
      }
    }

    if (matchedSample !== "") {
      totalScore += rule.weight;
      const evidence: Record<string, unknown> = {
        matched_sample: matchedSample.slice(0, 80),
        detector,
        anomaly_score: rule.weight,
        paranoia_level: paranoia,
        owasp_asvs: rule.asvs,
      };
      if (semanticTag !== "") {
        if (rule.ruleId === "WEB-302") {
          evidence.sql_fingerprint = semanticTag;
        } else {
          evidence.xss_vector = semanticTag;
        }
      }
      findings.push({
        id: `${rule.ruleId.toLowerCase()}-payload`,
        rule_id: rule.ruleId,
        module: "waf",
        layer: "web-defense",
        severity: rule.severity,
        title: rule.title,
        description: rule.description,
        target,
        evidence,
        remediation: rule.remediation,
        mitre_d3fend: rule.d3fend,
        timestamp: now,
      });
    }
  }

  if (options.customRules && options.customRules.length > 0) {
    const inputLow = lowViews[0] ?? input.toLowerCase();
    for (const cr of options.customRules) {
      const matched = matchCustomRule(input, inputLow, cr);
      if (!matched) continue;
      const sev = cr.severity ?? "high";
      const weight =
        cr.weight && cr.weight > 0 ? cr.weight : defaultWeightForSeverity(sev);
      const action = cr.action ?? "block";
      totalScore += weight;
      findings.push({
        id: `web-311-${cr.id.toLowerCase().replace(/[^a-z0-9-]+/g, "-")}`,
        rule_id: "WEB-311",
        module: "waf",
        layer: "web-defense",
        severity: sev,
        title: cr.title || `Custom enterprise WAF rule ${cr.id} matched`,
        description: `Payload matched custom WAF rule ${cr.id} (${cr.matchType}).`,
        target,
        evidence: {
          custom_rule_id: cr.id,
          action,
          matched_sample: matched.slice(0, 80),
          anomaly_score: weight,
          owasp_asvs: "5.1.3",
        },
        remediation:
          cr.remediation ??
          `Review traffic matching custom WAF rule ${cr.id} and apply targeted policy remediation.`,
        mitre_d3fend: "D3-IV",
        timestamp: now,
      });
    }
  }

  if (findings.length === 0) {
    return [];
  }
  if (threshold > 0 && totalScore < threshold) {
    return [];
  }
  for (const f of findings) {
    if (f.evidence) {
      f.evidence.total_anomaly_score = totalScore;
    }
  }
  return findings;
}

export function findingsRequireBlock(findings: readonly RaksaFinding[]): boolean {
  for (const f of findings) {
    if (f.evidence?.action !== "monitor") {
      return true;
    }
  }
  return false;
}

function matchCustomRule(
  raw: string,
  rawLow: string,
  rule: CustomWafRule,
): string {
  const ci = rule.caseInsensitive ?? false;
  if (rule.matchType === "regex") {
    const src =
      rule.pattern instanceof RegExp
        ? rule.pattern
        : new RegExp(rule.pattern, ci ? "i" : "");
    const safeFlags = src.flags.replace(/[gy]/g, "") + (ci && !src.flags.includes("i") ? "i" : "");
    const re = new RegExp(src.source, safeFlags);
    const m = re.exec(raw);
    return m?.[0] ?? "";
  }
  const pat = typeof rule.pattern === "string" ? rule.pattern : rule.pattern.source;
  if (rule.matchType === "exact") {
    if (ci) {
      return rawLow === pat.toLowerCase() ? raw : "";
    }
    return raw === pat ? raw : "";
  }
  if (ci) {
    return rawLow.includes(pat.toLowerCase()) ? pat : "";
  }
  return raw.includes(pat) ? pat : "";
}

function defaultWeightForSeverity(sev: Severity): number {
  switch (sev) {
    case "critical":
      return 5;
    case "high":
      return 4;
    case "medium":
      return 3;
    case "low":
      return 2;
    default:
      return 1;
  }
}

export function computePostureScore(findings: readonly RaksaFinding[]): RaksaPostureScore {
  let score = 100;
  for (const f of findings) {
    switch (f.severity) {
      case "critical":
        score -= 30;
        break;
      case "high":
        score -= 18;
        break;
      case "medium":
        score -= 8;
        break;
      case "low":
        score -= 3;
        break;
      case "info":
        break;
    }
  }
  if (score < 0) {
    score = 0;
  }

  let grade = "F";
  if (score >= 95) grade = "A+";
  else if (score >= 90) grade = "A";
  else if (score >= 80) grade = "B";
  else if (score >= 70) grade = "C";
  else if (score >= 55) grade = "D";

  return { score, grade };
}

export function buildRaksaReport(findings: RaksaFinding[]): RaksaReport {
  const summary: RaksaSummary = {
    total: findings.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const f of findings) {
    summary[f.severity]++;
  }
  return {
    schema_version: "1.0",
    tool: "raksa-webshield",
    layer: "web-defense",
    generated_at: new Date().toISOString(),
    posture: computePostureScore(findings),
    summary,
    findings,
  };
}

export function createIncidentId(): string {
  return `inc-${generateCspNonce(8)}`;
}

export function isExcludedPath(
  urlStr: string | undefined,
  excludePaths?: readonly (string | RegExp)[],
): boolean {
  if (!urlStr || !excludePaths || excludePaths.length === 0) {
    return false;
  }
  const qIdx = urlStr.indexOf("?");
  const pathname = qIdx >= 0 ? urlStr.slice(0, qIdx) : urlStr;
  for (const rule of excludePaths) {
    if (typeof rule === "string") {
      if (pathname === rule || pathname.startsWith(rule)) {
        return true;
      }
    } else if (rule.test(pathname)) {
      return true;
    }
  }
  return false;
}

export function extractSensitiveHeaderStrings(
  headers?: Record<string, string | string[] | undefined>,
): string[] {
  if (!headers) {
    return [];
  }
  const collected: string[] = [];
  for (const [k, v] of Object.entries(headers)) {
    if (!SENSITIVE_HEADER_KEYS.includes(k.toLowerCase()) || v === undefined) {
      continue;
    }
    if (Array.isArray(v)) {
      collected.push(v.join(" "));
    } else {
      collected.push(v);
    }
  }
  return collected;
}

export function extractDeepPayloadText(value: unknown, depth = 0, seen?: Set<object>): string {
  if (value === null || value === undefined) {
    return "";
  }
  if (typeof value === "string") {
    return value;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (typeof value !== "object") {
    return "";
  }
  if (depth >= 8) {
    return "";
  }
  const visited = seen ?? new Set<object>();
  if (visited.has(value)) {
    return "";
  }
  visited.add(value);

  try {
    const serialized = JSON.stringify(value);
    if (serialized !== undefined) {
      return serialized;
    }
  } catch {
    // Fall back to safe structural traversal for cyclic objects.
  }

  if (Array.isArray(value)) {
    return value.map((item) => extractDeepPayloadText(item, depth + 1, visited)).join(" ");
  }
  const rec = value as Record<string, unknown>;
  const parts: string[] = [];
  for (const k of Object.keys(rec)) {
    parts.push(`${k}:${extractDeepPayloadText(rec[k], depth + 1, visited)}`);
  }
  return parts.join(" ");
}

export function createWebShieldMiddleware(options: MiddlewareOptions = {}) {
  const mode = options.mode ?? "enforce";
  const applyHeaders = options.applyHeaders ?? true;
  const hidePoweredBy = options.hidePoweredBy ?? true;
  const maxInspectBytes = options.maxInspectBytes ?? 1024 * 1024;
  const paranoiaLevel = options.paranoiaLevel ?? 1;
  const anomalyThreshold = options.anomalyThreshold ?? 0;
  const cspNonce = options.cspNonce ?? false;
  const exposeReport = options.exposeReportInResponse ?? false;
  const limiter = options.rateLimit ? createMemoryRateLimiter(options.rateLimit) : null;
  const staticHeaders = cspNonce ? null : buildSecurityHeaders(options.headerOptions);

  return function webShieldMiddleware(
    req: WebShieldRequestLike,
    res: WebShieldResponseLike,
    next: NextCallback,
  ): void {
    if (hidePoweredBy && typeof res.removeHeader === "function") {
      res.removeHeader("X-Powered-By");
    }

    let reqNonce: string | undefined;
    const headersToApply = cspNonce
      ? (() => {
          reqNonce = generateCspNonce();
          return buildSecurityHeaders({ ...options.headerOptions, nonce: reqNonce });
        })()
      : staticHeaders!;

    if (applyHeaders) {
      for (const [name, value] of Object.entries(headersToApply)) {
        res.setHeader(name, value);
      }
    }
    if (reqNonce && res.locals && typeof res.locals === "object") {
      res.locals.cspNonce = reqNonce;
    }

    if (isExcludedPath(req.url, options.excludePaths)) {
      next();
      return;
    }

    if (limiter) {
      const clientKey = options.getClientKey
        ? options.getClientKey(req)
        : resolveNodeClientKey(req);
      const rl = limiter.check(clientKey);
      if (!rl.allowed && mode === "enforce") {
        res.statusCode = 429;
        res.setHeader("Retry-After", String(rl.retryAfterSeconds));
        res.setHeader("Content-Type", "application/json; charset=utf-8");
        res.end(
          JSON.stringify({
            error: "Rate limit exceeded by raksa-webshield",
            incident_id: createIncidentId(),
          }),
        );
        return;
      }
    }

    const parts: string[] = [];
    if (typeof req.url === "string") {
      parts.push(req.url);
    }
    for (const h of extractSensitiveHeaderStrings(req.headers)) {
      parts.push(h);
    }
    for (const part of [req.query, req.params, req.body]) {
      const txt = extractDeepPayloadText(part);
      if (txt !== "") {
        parts.push(txt);
      }
    }

    const combined = parts.join("\n");
    if (utf8ByteLength(combined) > maxInspectBytes) {
      if (mode === "enforce") {
        res.statusCode = 413;
        res.setHeader("Content-Type", "application/json; charset=utf-8");
        res.end(
          JSON.stringify({
            error: "Payload exceeds raksa-webshield inspection limit",
            incident_id: createIncidentId(),
          }),
        );
        return;
      }
      next();
      return;
    }

    const target = `http://${req.method ?? "REQ"}${req.url ? ` ${req.url}` : ""}`;
    const findings = inspectInput(combined, target, {
      paranoiaLevel,
      anomalyThreshold,
      customRules: options.customRules,
    });
    if (findings.length > 0) {
      const report = buildRaksaReport(findings);
      const incidentId = createIncidentId();
      options.onReport?.(report, req, incidentId);
      if (mode === "enforce" && findingsRequireBlock(findings)) {
        res.statusCode = 403;
        res.setHeader("Content-Type", "application/json; charset=utf-8");
        const body: Record<string, unknown> = {
          error: "Request blocked by raksa-webshield defensive policy",
          incident_id: incidentId,
        };
        if (exposeReport) {
          body.report = report;
        }
        res.end(JSON.stringify(body));
        return;
      }
    }

    next();
  };
}

function resolveNodeClientKey(req: WebShieldRequestLike): string {
  const xff = req.headers?.["x-forwarded-for"];
  if (typeof xff === "string" && xff.trim() !== "") {
    return xff.split(",")[0]?.trim() || "global";
  }
  return req.ip || "global";
}

function normalizePayloadViews(raw: string): string[] {
  const hasMarker =
    raw.includes("%") ||
    raw.includes("+") ||
    raw.includes("&") ||
    raw.includes("\\u") ||
    raw.includes("/*");
  if (!hasMarker) {
    return [raw];
  }

  const views = [raw];
  const pushUnique = (candidate: string) => {
    if (!views.includes(candidate)) {
      views.push(candidate);
    }
  };

  let cur = raw;
  for (let pass = 0; pass < 2; pass++) {
    if (!cur.includes("%") && !cur.includes("+")) {
      break;
    }
    let decoded = cur;
    try {
      decoded = decodeURIComponent(cur.replace(/\+/g, " "));
    } catch {
      decoded = cur.replace(/%([0-9a-fA-F]{2})/g, (_, hex: string) =>
        String.fromCharCode(Number.parseInt(hex, 16)),
      );
    }
    if (decoded === cur) {
      break;
    }
    pushUnique(decoded);
    cur = decoded;
  }

  const evaded = decodeEvasionLayers(cur);
  if (evaded !== cur) {
    pushUnique(evaded);
  }
  return views;
}

function decodeEvasionLayers(raw: string): string {
  let out = raw;
  if (out.includes("&")) {
    out = out
      .replace(/&#x([0-9a-f]{2});/gi, (_, hex: string) => {
        const cp = Number.parseInt(hex, 16);
        return cp > 0 ? String.fromCharCode(cp) : _;
      })
      .replace(/&#(\d{2,3});/g, (_, dec: string) => {
        const cp = Number.parseInt(dec, 10);
        return cp > 0 ? String.fromCharCode(cp) : _;
      })
      .replace(/&(lt|gt|quot|apos|colon);/gi, (full, name: string) => {
        switch (name.toLowerCase()) {
          case "lt":
            return "<";
          case "gt":
            return ">";
          case "quot":
            return '"';
          case "apos":
            return "'";
          case "colon":
            return ":";
          default:
            return full;
        }
      });
  }
  if (out.includes("\\u00") || out.includes("\\U00")) {
    out = out.replace(/\\u00([0-9a-f]{2})/gi, (_, hex: string) =>
      String.fromCharCode(Number.parseInt(hex, 16)),
    );
  }
  if (out.includes("/*")) {
    out = out.replace(/\/\*[\s\S]*?\*\//g, "");
  }
  return out;
}

function utf8ByteLength(input: string): number {
  let bytes = 0;
  for (let i = 0; i < input.length; i++) {
    const code = input.charCodeAt(i);
    if (code <= 0x7f) {
      bytes += 1;
    } else if (code <= 0x7ff) {
      bytes += 2;
    } else if (code >= 0xd800 && code <= 0xdbff) {
      bytes += 4;
      i++;
    } else {
      bytes += 3;
    }
  }
  return bytes;
}
