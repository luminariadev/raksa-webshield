# Changelog

All notable changes to `raksa-webshield` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
