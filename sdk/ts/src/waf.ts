import { buildSecurityHeaders, type SecurityHeadersOptions } from "./headers.js";

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

export interface RaksaReport {
  schema_version: "1.0";
  tool: "raksa-webshield";
  layer: "web-defense";
  generated_at: string;
  summary: RaksaSummary;
  findings: RaksaFinding[];
}

export interface WebShieldRequestLike {
  url?: string;
  method?: string;
  headers?: Record<string, string | string[] | undefined>;
  query?: unknown;
  params?: unknown;
  body?: unknown;
}

export interface WebShieldResponseLike {
  statusCode: number;
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
  maxInspectBytes?: number;
  onReport?: (report: RaksaReport, req: WebShieldRequestLike) => void;
}

interface WafRule {
  ruleId: string;
  severity: Severity;
  title: string;
  description: string;
  remediation: string;
  asvs: string;
  d3fend: string;
  pattern: RegExp;
}

const WAF_RULES: readonly WafRule[] = [
  {
    ruleId: "WEB-301",
    severity: "high",
    title: "Cross-Site Scripting (XSS) payload pattern detected",
    description:
      "Input contains executable HTML/script tags, inline event handlers, or dangerous URI schemes.",
    remediation:
      "Sanitize untrusted HTML with sanitizeHtml() and apply context-aware output encoding.",
    asvs: "5.3.3",
    d3fend: "D3-IV",
    pattern:
      /(<\s*script\b|(?:javascript|vbscript)\s*:|data\s*:\s*text\/html|\bon(?:error|load|click|mouseover|focus|blur|submit|animationstart)\s*=|<\s*svg\b[^>]*\bon\w+\s*=|<\s*iframe\b[^>]*\bsrcdoc\s*=)/i,
  },
  {
    ruleId: "WEB-302",
    severity: "critical",
    title: "SQL Injection (SQLi) payload pattern detected",
    description:
      "Input matches SQL UNION, boolean tautology, stacked statement, or timing-delay injection patterns.",
    remediation:
      "Use parameterized prepared statements strictly and validate expected input schemas.",
    asvs: "5.3.4",
    d3fend: "D3-IV",
    pattern:
      /(\bunion\s+(?:all\s+)?select\b|(?:'\s*or\s+'?1'?\s*=\s*'?1|\bor\s+1\s*=\s*1\b|"\s*or\s+"?1"?\s*=\s*"?1)|;\s*(?:drop|delete|insert|update|alter)\s+\w+|\b(?:sleep\s*\(\s*\d+\s*\)|waitfor\s+delay)\b)/i,
  },
  {
    ruleId: "WEB-303",
    severity: "high",
    title: "Path Traversal / Local File Inclusion sequence detected",
    description:
      "Input contains directory traversal sequences, null bytes, or sensitive OS file targets.",
    remediation:
      "Normalize with path.basename or ensure resolved canonical path starts within the allowed directory.",
    asvs: "12.3.1",
    d3fend: "D3-IV",
    pattern: /(\.\.[/\\]|%00|\x00|\/etc\/passwd|\/etc\/shadow|windows[/\\]win\.ini)/i,
  },
  {
    ruleId: "WEB-304",
    severity: "high",
    title: "Prototype Pollution key detected in request payload",
    description:
      "Input references JavaScript prototype chain mutation keys (__proto__ or constructor.prototype).",
    remediation:
      "Reject or strip __proto__, constructor, and prototype keys before object merging.",
    asvs: "5.1.3",
    d3fend: "D3-IV",
    pattern: /(__proto__|constructor\s*\.\s*prototype|\[\s*["']prototype["']\s*\]|["']prototype["']\s*:)/i,
  },
  {
    ruleId: "WEB-305",
    severity: "critical",
    title: "SSRF or cloud metadata URI target detected",
    description:
      "Input references cloud instance metadata endpoints or non-HTTP local schemes (file://, gopher://, dict://).",
    remediation:
      "Allowlist permitted outbound hosts and block loopback, private, and link-local IP ranges.",
    asvs: "12.6.1",
    d3fend: "D3-NI",
    pattern: /(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|(?:file|gopher|dict):\/\/)/i,
  },
];

export function inspectInput(input: string, target = "inline://request"): RaksaFinding[] {
  if (!input || input.trim() === "") {
    return [];
  }

  const views = normalizePayloadViews(input);
  const now = new Date().toISOString();
  const findings: RaksaFinding[] = [];

  for (const rule of WAF_RULES) {
    let matchedSample = "";
    for (const view of views) {
      const m = rule.pattern.exec(view);
      if (m && m[0]) {
        matchedSample = m[0];
        break;
      }
    }
    if (matchedSample !== "") {
      findings.push({
        id: `${rule.ruleId.toLowerCase()}-payload`,
        rule_id: rule.ruleId,
        module: "waf",
        layer: "web-defense",
        severity: rule.severity,
        title: rule.title,
        description: rule.description,
        target,
        evidence: {
          matched_sample: matchedSample.slice(0, 80),
          owasp_asvs: rule.asvs,
        },
        remediation: rule.remediation,
        mitre_d3fend: rule.d3fend,
        timestamp: now,
      });
    }
  }

  return findings;
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
    summary,
    findings,
  };
}

export function createWebShieldMiddleware(options: MiddlewareOptions = {}) {
  const mode = options.mode ?? "enforce";
  const applyHeaders = options.applyHeaders ?? true;
  const hidePoweredBy = options.hidePoweredBy ?? true;
  const maxInspectBytes = options.maxInspectBytes ?? 1024 * 1024;
  const securityHeaders = buildSecurityHeaders(options.headerOptions);

  return function webShieldMiddleware(
    req: WebShieldRequestLike,
    res: WebShieldResponseLike,
    next: NextCallback,
  ): void {
    if (hidePoweredBy && typeof res.removeHeader === "function") {
      res.removeHeader("X-Powered-By");
    }
    if (applyHeaders) {
      for (const [name, value] of Object.entries(securityHeaders)) {
        res.setHeader(name, value);
      }
    }

    const parts: string[] = [];
    if (typeof req.url === "string") {
      parts.push(req.url);
    }
    for (const part of [req.query, req.params, req.body]) {
      if (part !== undefined && part !== null) {
        parts.push(typeof part === "string" ? part : safeStringify(part));
      }
    }

    const combined = parts.join("\n");
    if (utf8ByteLength(combined) > maxInspectBytes) {
      if (mode === "enforce") {
        res.statusCode = 413;
        res.setHeader("Content-Type", "application/json; charset=utf-8");
        res.end(JSON.stringify({ error: "Payload exceeds raksa-webshield inspection limit" }));
        return;
      }
      next();
      return;
    }

    const target = `http://${req.method ?? "REQ"}${req.url ? ` ${req.url}` : ""}`;
    const findings = inspectInput(combined, target);
    if (findings.length > 0) {
      const report = buildRaksaReport(findings);
      options.onReport?.(report, req);
      if (mode === "enforce") {
        res.statusCode = 403;
        res.setHeader("Content-Type", "application/json; charset=utf-8");
        res.end(
          JSON.stringify({
            error: "Request blocked by raksa-webshield defensive policy",
            report,
          }),
        );
        return;
      }
    }

    next();
  };
}

function normalizePayloadViews(raw: string): string[] {
  const views = [raw];
  let cur = raw;
  for (let pass = 0; pass < 2; pass++) {
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
    views.push(decoded);
    cur = decoded;
  }
  return views;
}

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value) ?? "";
  } catch {
    return String(value);
  }
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
