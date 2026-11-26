export const SDK_VERSION = "0.2.0";

export {
  decodeHtmlEntities,
  escapeHtml,
  isSafeUrl,
  sanitizeHtml,
  type SanitizeOptions,
} from "./sanitizer.js";

export {
  buildSecurityHeaders,
  generateCspNonce,
  type SecurityHeadersOptions,
} from "./headers.js";

export {
  createMemoryRateLimiter,
  type MemoryRateLimiter,
  type RateLimiterOptions,
  type RateLimitResult,
} from "./ratelimit.js";

export {
  buildRaksaReport,
  computePostureScore,
  createWebShieldMiddleware,
  inspectInput,
  type InspectOptions,
  type MiddlewareOptions,
  type NextCallback,
  type RaksaFinding,
  type RaksaPostureScore,
  type RaksaReport,
  type RaksaSummary,
  type Severity,
  type WebShieldRequestLike,
  type WebShieldResponseLike,
} from "./waf.js";

export {
  createFetchWebShield,
  type FetchHandler,
  type FetchShieldContext,
  type FetchShieldOptions,
} from "./fetch.js";
