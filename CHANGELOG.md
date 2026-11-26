# Changelog

All notable changes to `raksa-webshield` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-11-26

### Added
- **Standalone Reverse-Proxy WAF Sidecar (`raksa-webshield proxy`, `internal/proxy/`)**:
  - Single-binary HTTP reverse proxy wrapping any upstream service with `strict`/`balanced` security header injection, `Server`/`X-Powered-By` stripping, sensitive request inspection, opaque `403` JSON responses, bounded-LRU per-IP rate limiting (`WEB-312`, HTTP `429` + `Retry-After`), Raksa Schema v1 NDJSON SIEM telemetry logs (`--log-file`), and Prometheus `/metrics` + `/healthz` (`--metrics-addr`).
- **Zero-CGO Semantic SQLi & XSS Tokenizers (Go + TypeScript)**:
  - Added deterministic SQL lexer (`AnalyzeSQLiSemantic` / `analyzeSqlSemantic`) catching syntactic SQL injections (`1' AND 2>1--`, `admin'/**/OR/**/'a'='a`, `1' AND PG_SLEEP(5)--`, `BENCHMARK`, `EXTRACTVALUE`, `1' ORDER BY 10--`, `1; EXEC xp_cmdshell`) with zero prose false positives.
  - Added stateful HTML5 attribute/tag scanner (`AnalyzeXSSSemantic` / `analyzeXssSemantic`) catching slash-split handlers (`<img/src=x/onerror=alert(1)>`), `<details open ontoggle=...>`, `<meta refresh>`, and tab-obfuscated URIs.
- **Custom Enterprise YAML WAF Rules Engine (`internal/rules/`, `WEB-311`)**:
  - Added `examples/custom-waf-rules.yml`, `--custom-rules` CLI support on `inspect-request` and `proxy`, `customRules` support in `@raksa/webshield` (`0.3.0`) Node and Web Fetch middlewares, and the 8th MCP tool `webshield_validate_custom_rules` for dry-run validation.
- **30-Rule Catalog**: Expanded built-in OWASP ASVS & MITRE D3FEND rule catalog from 28 to 30 rules (`WEB-311`, `WEB-312`).

## [0.2.0] - 2026-11-26

### Added
- **Security Posture Scoring (`WEB-*` Schema v1 Additive Extension)**: Added `posture` (`score` `0-100`, `grade` `A+`..`F`) to `Report` and rendered `score: X/100 (Grade)` directly in CLI table headers.
- **CSP Evaluator Pro & Modern Isolation Headers (`WEB-006`, `WEB-007`)**:
  - Added `script-src-elem` fallback chain, `blob:` / `filesystem:` detection, CSP Level 3 `'nonce-...'` / hash `'strict-dynamic'` awareness (zero false positive on backward-compatible `'unsafe-inline'`), JSONP/CDN bypass host database (`ajax.googleapis.com`, `cdnjs.cloudflare.com`, `cdn.jsdelivr.net`, `unpkg.com`, etc.), and missing `form-action` detection.
  - Added `Cross-Origin-Opener-Policy` (COOP), `Cross-Origin-Resource-Policy` (CORP), and authenticated `Set-Cookie` `Cache-Control: no-store` checks, plus smart classification of CSRF/preference cookies (`XSRF-TOKEN`, `csrf-token`) while keeping `Secure` mandatory.
  - Added live HTTPS TLS protocol and leaf certificate expiration (`<= 14d`) checks in `FetchAndAuditURL`.
- **Block-Aware Nginx AST, Caddyfile, and Modern Edge Config Auditors (`WEB-205`..`WEB-207`)**:
  - Upgraded `config.go` with Nginx scope stack tracking to detect `location` `add_header` parent security header cancellation (`WEB-205`), off-by-slash `alias` path traversal and dynamic `proxy_pass` / `$http_host` forwarding (`WEB-206`), and weak OpenSSL/Caddy `ssl_ciphers` ignoring `!`-prefixed exclusions (`WEB-207`).
  - Added real Caddyfile, `vercel.json`, `_headers`, and Kubernetes Ingress YAML auditing.
- **10-Class Anomaly-Scoring WAF Engine (`WEB-306`..`WEB-310`)**:
  - Added Command Injection / RCE (`WEB-306`), SSTI / JNDI (`WEB-307`), NoSQL operator injection (`WEB-308`), XXE (`WEB-309`), and CRLF header splitting (`WEB-310`), plus `--paranoia` (`1-3`) and `--anomaly-threshold`.
  - Added multi-layer URI + HTML entity + `\u00XX` + SQL `/**/` comment normalization and ASCII fast-path prefilters.
- **Auto-Remediation Generator & 7th MCP Tool**:
  - Added `raksa-webshield generate-policy --target nginx|caddy|nextjs|headers` and MCP tool `webshield_generate_remediation` emitting `100/100 A+` hardened snippets verified cleanly against `raksa-webshield` itself.
- **TypeScript SDK `@raksa/webshield` `0.2.0` (Zero Runtime Deps)**:
  - Added Web Standard Fetch API wrapper (`createFetchWebShield` for Next.js, Hono, Workers, Bun, Deno), per-request WebCrypto CSP nonce helper (`generateCspNonce`), bounded-LRU in-memory rate limiter (`createMemoryRateLimiter` emitting HTTP `429` + `Retry-After`), tag-stack balanced & idempotent `sanitizeHtml`, 3-pass `isSafeUrl`, deep JSON + request header inspection, and 10-class WAF parity.

### Security & Performance
- **Opaque HTTP 403 Responses by Default**: Middleware and Fetch wrapper now return `{ error, incident_id }` to clients by default so internal `rule_id` and `matched_sample` telemetry stay restricted to `onReport` callbacks (`exposeReportInResponse: true` overrides explicitly).
- **20x Go WAF Speedup**: Package-level rule compilation and ASCII prefilters cut `BenchmarkInspectPayload-12` from `51,969 ns/op` (~19.2k ops/s, 5 rules) in `v0.1.0` to `2,538 ns/op` (~394k ops/s, 10 rules) in `v0.2.0`.

## [0.1.0] - 2026-11-26

### Added
- **Go CLI & Web Security Auditors (`raksa-webshield`)**:
  - `audit-headers`: Offline header-dump and SSRF-safe live HTTP/HTTPS response auditing covering HSTS, CSP, Clickjacking, hardening headers/version banners, CORS credential exposures, and `Set-Cookie` flags/`__Host-`/`__Secure-` prefixes (`WEB-001` through `WEB-104`).
  - `audit-csp`: Deep Content-Security-Policy directive analyzer checking `script-src`/`default-src` unsafe tokens, wildcards, `object-src 'none'`, and `base-uri`.
  - `audit-config` & `audit-workspace`: Static Nginx/Caddyfile reverse-proxy auditor for legacy TLS, version banners, unsafe CORS/CSP `add_header`, and unbounded body size (`WEB-201` through `WEB-204`), plus recursive workspace aggregation.
  - `inspect-request`: Multi-pass URL-decoding defensive mini-WAF inspector catching XSS, SQLi, Path Traversal/LFI, Prototype Pollution, and metadata SSRF (`WEB-301` through `WEB-305`).
- **Suppression Policy Engine (`--policy`) & Raksa Contract**: Supports YAML/JSON suppression rules with mandatory audit reasons and fail-closed `expires_on` expiration dates, ANSI-sanitized `table` output, Raksa Schema v1 `json`, SARIF `2.1.0`, and CI exit codes `0 / 1 / 2`.
- **Native MCP Server (`raksa-webshield mcp`)**: Line-bounded `stdio` JSON-RPC 2.0 server exposing 6 defensive tools (`webshield_list_rules`, `webshield_audit_headers`, `webshield_audit_csp`, `webshield_audit_config`, `webshield_inspect_payload`, `webshield_audit_workspace`).
- **Zero-Dependency TypeScript SDK (`sdk/ts`, `@raksa/webshield`)**: Strict allowlist HTML/attribute/URI sanitizer (`sanitizeHtml`, `escapeHtml`, `isSafeUrl`), OWASP ASVS `buildSecurityHeaders`, `inspectInput`, and `createWebShieldMiddleware` with `enforce` and `monitor` modes.
- **Release Readiness**: Go `-race` tests, TypeScript regression tests, Go + TypeScript throughput benchmarks, `govulncheck` CI, `gcr.io/distroless/static-debian12:nonroot` container, and 3-OS release matrix workflows.
