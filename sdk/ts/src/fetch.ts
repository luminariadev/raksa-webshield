import {
  buildSecurityHeaders,
  generateCspNonce,
  type SecurityHeadersOptions,
} from "./headers.js";
import {
  createMemoryRateLimiter,
  type RateLimiterOptions,
} from "./ratelimit.js";
import {
  buildRaksaReport,
  createIncidentId,
  findingsRequireBlock,
  inspectInput,
  isExcludedPath,
  type CustomWafRule,
  type RaksaReport,
} from "./waf.js";

export interface FetchShieldOptions {
  mode?: "enforce" | "monitor";
  applyHeaders?: boolean;
  headerOptions?: SecurityHeadersOptions;
  cspNonce?: boolean;
  maxInspectBytes?: number;
  paranoiaLevel?: number;
  anomalyThreshold?: number;
  customRules?: readonly CustomWafRule[];
  excludePaths?: readonly (string | RegExp)[];
  exposeReportInResponse?: boolean;
  rateLimit?: RateLimiterOptions;
  getClientKey?: (request: Request) => string;
  onReport?: (report: RaksaReport, request: Request, incidentId: string) => void;
}

export interface FetchShieldContext {
  nonce?: string;
  report?: RaksaReport;
  incidentId?: string;
}

export type FetchHandler = (
  request: Request,
  context: FetchShieldContext,
) => Response | Promise<Response>;

const SENSITIVE_FETCH_HEADERS = ["user-agent", "referer", "x-forwarded-for", "cookie"];

export function createFetchWebShield(options: FetchShieldOptions = {}) {
  const mode = options.mode ?? "enforce";
  const applyHeaders = options.applyHeaders ?? true;
  const maxInspectBytes = options.maxInspectBytes ?? 1024 * 1024;
  const paranoiaLevel = options.paranoiaLevel ?? 1;
  const anomalyThreshold = options.anomalyThreshold ?? 0;
  const cspNonce = options.cspNonce ?? false;
  const exposeReport = options.exposeReportInResponse ?? false;
  const limiter = options.rateLimit ? createMemoryRateLimiter(options.rateLimit) : null;
  const staticHeaders = cspNonce ? null : buildSecurityHeaders(options.headerOptions);

  return async function withWebShield(
    request: Request,
    handler: FetchHandler,
  ): Promise<Response> {
    const nonce = cspNonce ? generateCspNonce() : undefined;
    const secHeaders = cspNonce
      ? buildSecurityHeaders({ ...options.headerOptions, nonce })
      : staticHeaders!;

    const finalizeResponse = (resp: Response): Response => {
      if (!applyHeaders) {
        return resp;
      }
      const nextHeaders = new Headers(resp.headers);
      nextHeaders.delete("x-powered-by");
      for (const [k, v] of Object.entries(secHeaders)) {
        nextHeaders.set(k, v);
      }
      return new Response(resp.body, {
        status: resp.status,
        statusText: resp.statusText,
        headers: nextHeaders,
      });
    };

    const parsedPath = extractPathname(request.url);
    if (isExcludedPath(parsedPath, options.excludePaths)) {
      const upstream = await handler(request, { nonce });
      return finalizeResponse(upstream);
    }

    if (limiter) {
      const clientKey = options.getClientKey
        ? options.getClientKey(request)
        : resolveFetchClientKey(request);
      const rl = limiter.check(clientKey);
      if (!rl.allowed && mode === "enforce") {
        const resp = new Response(
          JSON.stringify({
            error: "Rate limit exceeded by raksa-webshield",
            incident_id: createIncidentId(),
          }),
          {
            status: 429,
            headers: {
              "Content-Type": "application/json; charset=utf-8",
              "Retry-After": String(rl.retryAfterSeconds),
            },
          },
        );
        return finalizeResponse(resp);
      }
    }

    const parts: string[] = [request.url];
    for (const hName of SENSITIVE_FETCH_HEADERS) {
      const hv = request.headers.get(hName);
      if (hv) {
        parts.push(hv);
      }
    }

    const method = request.method.toUpperCase();
    if (method !== "GET" && method !== "HEAD" && request.body !== null) {
      const bodyText = await request.clone().text();
      if (bodyText !== "") {
        parts.push(bodyText);
      }
    }

    const combined = parts.join("\n");
    if (new TextEncoder().encode(combined).length > maxInspectBytes) {
      if (mode === "enforce") {
        const resp = new Response(
          JSON.stringify({
            error: "Payload exceeds raksa-webshield inspection limit",
            incident_id: createIncidentId(),
          }),
          {
            status: 413,
            headers: { "Content-Type": "application/json; charset=utf-8" },
          },
        );
        return finalizeResponse(resp);
      }
      const upstream = await handler(request, { nonce });
      return finalizeResponse(upstream);
    }

    const findings = inspectInput(combined, `http://${method} ${request.url}`, {
      paranoiaLevel,
      anomalyThreshold,
      customRules: options.customRules,
    });

    let report: RaksaReport | undefined;
    let incidentId: string | undefined;
    if (findings.length > 0) {
      report = buildRaksaReport(findings);
      incidentId = createIncidentId();
      options.onReport?.(report, request, incidentId);
      if (mode === "enforce" && findingsRequireBlock(findings)) {
        const payload: Record<string, unknown> = {
          error: "Request blocked by raksa-webshield defensive policy",
          incident_id: incidentId,
        };
        if (exposeReport) {
          payload.report = report;
        }
        const resp = new Response(JSON.stringify(payload), {
          status: 403,
          headers: { "Content-Type": "application/json; charset=utf-8" },
        });
        return finalizeResponse(resp);
      }
    }

    const upstream = await handler(request, { nonce, report, incidentId });
    return finalizeResponse(upstream);
  };
}

function extractPathname(rawUrl: string): string {
  try {
    return new URL(rawUrl).pathname;
  } catch {
    return rawUrl;
  }
}

function resolveFetchClientKey(request: Request): string {
  const cf = request.headers.get("cf-connecting-ip");
  if (cf) return cf.trim();
  const xff = request.headers.get("x-forwarded-for");
  if (xff) return xff.split(",")[0]?.trim() || "global";
  return "global";
}
