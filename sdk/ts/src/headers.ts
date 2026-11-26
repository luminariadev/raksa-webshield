export interface SecurityHeadersOptions {
  hstsMaxAge?: number;
  includeSubDomains?: boolean;
  csp?: string;
  nonce?: string;
  frameOptions?: "DENY" | "SAMEORIGIN";
  referrerPolicy?: string;
  permissionsPolicy?: string;
  coop?: string;
  corp?: string;
}

const DEFAULT_CSP =
  "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'";

export function generateCspNonce(byteLength = 16): string {
  const size = Math.max(8, Math.min(64, Math.floor(byteLength)));
  const bytes = new Uint8Array(size);
  globalThis.crypto.getRandomValues(bytes);

  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i] ?? 0);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function buildSecurityHeaders(
  options: SecurityHeadersOptions = {},
): Record<string, string> {
  const maxAge = Math.max(15768000, Math.floor(options.hstsMaxAge ?? 31536000));
  const sub = options.includeSubDomains !== false ? "; includeSubDomains" : "";
  const csp = applyNonceToCsp(options.csp ?? DEFAULT_CSP, options.nonce);

  return {
    "Strict-Transport-Security": `max-age=${maxAge}${sub}`,
    "Content-Security-Policy": csp,
    "X-Frame-Options": options.frameOptions ?? "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": options.referrerPolicy ?? "strict-origin-when-cross-origin",
    "Permissions-Policy":
      options.permissionsPolicy ?? "geolocation=(), microphone=(), camera=()",
    "Cross-Origin-Opener-Policy": options.coop ?? "same-origin",
    "Cross-Origin-Resource-Policy": options.corp ?? "same-origin",
  };
}

function applyNonceToCsp(csp: string, rawNonce?: string): string {
  if (!rawNonce) {
    return csp;
  }
  const safeNonce = rawNonce.replace(/[^A-Za-z0-9+/_=-]/g, "");
  if (!safeNonce || csp.includes(`'nonce-${safeNonce}'`)) {
    return csp;
  }
  const token = `'nonce-${safeNonce}' 'strict-dynamic'`;
  if (/(^|;\s*)script-src\s+/i.test(csp)) {
    return csp.replace(/((?:^|;\s*)script-src\s+)/i, `$1${token} `);
  }
  return `script-src 'self' ${token}; ${csp}`;
}
