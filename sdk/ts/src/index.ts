export const SDK_VERSION = "0.1.0";

export {
  decodeHtmlEntities,
  escapeHtml,
  isSafeUrl,
  sanitizeHtml,
  type SanitizeOptions,
} from "./sanitizer.js";

export {
  buildSecurityHeaders,
  type SecurityHeadersOptions,
} from "./headers.js";

export {
  buildRaksaReport,
  createWebShieldMiddleware,
  inspectInput,
  type MiddlewareOptions,
  type NextCallback,
  type RaksaFinding,
  type RaksaReport,
  type RaksaSummary,
  type Severity,
  type WebShieldRequestLike,
  type WebShieldResponseLike,
} from "./waf.js";
