export interface SecurityHeadersOptions {
  hstsMaxAge?: number;
  includeSubDomains?: boolean;
  csp?: string;
  frameOptions?: "DENY" | "SAMEORIGIN";
  referrerPolicy?: string;
  permissionsPolicy?: string;
  coop?: string;
  corp?: string;
}

const DEFAULT_CSP =
  "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'";

export function buildSecurityHeaders(
  options: SecurityHeadersOptions = {},
): Record<string, string> {
  const maxAge = Math.max(15768000, Math.floor(options.hstsMaxAge ?? 31536000));
  const sub = options.includeSubDomains !== false ? "; includeSubDomains" : "";

  return {
    "Strict-Transport-Security": `max-age=${maxAge}${sub}`,
    "Content-Security-Policy": options.csp ?? DEFAULT_CSP,
    "X-Frame-Options": options.frameOptions ?? "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": options.referrerPolicy ?? "strict-origin-when-cross-origin",
    "Permissions-Policy":
      options.permissionsPolicy ?? "geolocation=(), microphone=(), camera=()",
    "Cross-Origin-Opener-Policy": options.coop ?? "same-origin",
    "Cross-Origin-Resource-Policy": options.corp ?? "same-origin",
  };
}
