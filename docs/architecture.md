# raksa-webshield Architecture

`raksa-webshield` is the Layer 3 (`web-defense`) component of the Raksa security suite. It combines a static Go CLI, standalone reverse-proxy WAF sidecar, and stdio MCP server with a zero-dependency TypeScript runtime middleware SDK (`@raksa/webshield`) so engineering teams can enforce HTTP hardening, semantic injection defense, custom enterprise policies, and SIEM telemetry across both CI/CD pipelines and live production traffic.

## Component Flow

```text
  [ Go CLI, Reverse-Proxy Sidecar & MCP ]         [ TypeScript SDK (@raksa/webshield) ]
     |         |            |           |             |             |             |
     v         v            v           v             v             v             v
  +------+  +------+   +--------+  +--------+   +-----------+  +---------+  +-----------+
  |Headers| | CSP  |   |AST Proxy| |WAF +   |   | sanitize  |  | header  |  | Node/Fetch|
  |COOP/  | |Bypass|   |Nginx/   | |Semantic|   | Html/Href |  | & Nonce |  | Semantic  |
  |Cookies| |Eval  |   |Caddy/K8s| |+ Custom|   | Stack Bal |  | builder |  | + Custom  |
  +---+---+ +--+---+   +---+----+  +---+----+   +-----------+  +---------+  +-----+-----+
      |        |           |           |                                          |
      +--------+-----------+-----------+------------------------------------------+
                           |
                           v
               +------------------------+
               |   Policy / Sidecar     | (.webshield.yml / proxy /metrics & NDJSON)
               +-----------+------------+
                           |
                           v
               +------------------------+
               | Raksa Finding Schema v1| (Posture Score 0-100 / A+..F)
               +-----+-----+------+-----+
                     |     |      |
                     v     v      v
                  [Table] [JSON] [SARIF 2.1]
```

## Module Responsibilities

- `cmd/raksa-webshield/`: CLI entrypoint (`audit-headers`, `audit-csp`, `audit-config`, `inspect-request`, `audit-workspace`, `generate-policy`, `proxy`, `rules`, `mcp`, `version`) with CI exit codes (`0` clean, `1` CLI/runtime error, `2` findings >= `--fail-on`).
- `internal/schema/`: Canonical Raksa Finding Schema v1 (`Report`, `PostureScore`, `Finding`, `Severity`, `Summary`), posture grading (`0-100`, `A+`..`F`), and built-in `RuleCatalog()` covering 30 `WEB-*` rules mapped to OWASP ASVS and MITRE D3FEND.
- `internal/policy/`: YAML/JSON suppression policy engine requiring audit reasons and enforcing fail-closed `expires_on` (`YYYY-MM-DD`) expiration dates.
- `internal/rules/`: Enterprise custom YAML WAF rules engine (`LoadCustomRules`, `ParseCustomRules`, `Evaluate`) supporting `contains`, `regex`, and `exact` matching, target scoping, `block`/`monitor` actions, and emitting `WEB-311`.
- `internal/proxy/`: Standalone Go HTTP reverse-proxy sidecar wrapping `httputil.NewSingleHostReverseProxy` with hardened response header injection, banner stripping (`Server`/`X-Powered-By`), thread-safe bounded-LRU per-IP rate limiting (`WEB-312`, HTTP `429` + `Retry-After`), opaque `403` JSON responses, **Raksa Schema v1 NDJSON** telemetry logs, and Prometheus **`/metrics`** exposition.
- `internal/auditor/`:
  - `headers.go` / `csp.go` / `cors.go` / `cookies.go`: Raw HTTP header parser and analyzers (`WEB-001`..`WEB-104`).
  - `config.go`: Block-aware Nginx AST, Caddyfile, `vercel.json`, `_headers`, and Kubernetes Ingress YAML auditor (`WEB-201`..`WEB-207`) plus recursive `AuditWorkspace`.
  - `live.go`: Read-only live HTTP/HTTPS header and TLS protocol/certificate expiration inspector (`inspectTLSState`) with private/loopback/metadata SSRF blocking by default.
  - `waf.go` & `semantic.go`: High-speed 10-class WAF + zero-CGO deterministic SQLi token fingerprinter (`AnalyzeSQLiSemantic`) and stateful HTML5 XSS scanner (`AnalyzeXSSSemantic`) (`WEB-301`..`WEB-310`).
  - `remediate.go`: Self-auditing configuration generator for `nginx`, `caddy`, `nextjs`, and `headers`.
- `internal/report/`: ANSI-sanitized table (with score/grade), JSON Schema v1, and SARIF 2.1.0 serializers.
- `internal/mcp/`: Line-bounded `stdio` JSON-RPC 2.0 MCP server exposing 8 defensive `webshield_*` tools including `webshield_generate_remediation` and `webshield_validate_custom_rules`.
- `sdk/ts/`: Zero-dependency TypeScript package (`@raksa/webshield`) exporting `sanitizeHtml`, `escapeHtml`, `isSafeUrl`, `generateCspNonce`, `buildSecurityHeaders`, `createMemoryRateLimiter`, `analyzeSqlSemantic`, `analyzeXssSemantic`, `inspectInput`, `createWebShieldMiddleware`, and `createFetchWebShield`.

## Rule Catalog Overview (30 Rules)

| Rule ID | Module | Control | OWASP ASVS | MITRE D3FEND |
| :--- | :--- | :--- | :--- | :--- |
| `WEB-001` | `headers` | Missing or weak `Strict-Transport-Security` | 14.4.5 | `D3-HI` |
| `WEB-002` | `headers` | Missing `Content-Security-Policy` header | 14.4.3 | `D3-HI` |
| `WEB-003` | `csp` | Unsafe `Content-Security-Policy` directive | 14.4.3 | `D3-HI` |
| `WEB-004` | `headers` | Missing clickjacking protection | 14.4.4 | `D3-HI` |
| `WEB-005` | `headers` | Missing hardening header or version banner leak | 14.4.1 / 14.4.6 | `D3-HI` |
| `WEB-006` | `csp` | CSP permits JSONP/CDN bypass host or omits `form-action` | 14.4.3 | `D3-HI` |
| `WEB-007` | `headers` | Missing COOP/CORP or `Cache-Control: no-store` on `Set-Cookie` | 14.4.7 | `D3-HI` |
| `WEB-101` | `cors` | Dangerous CORS credential exposure | 14.5.3 | `D3-NI` |
| `WEB-102` | `cors` | Overly permissive CORS policy | 14.5.3 | `D3-NI` |
| `WEB-103` | `cookies` | Cookie missing `Secure` or `HttpOnly` attribute | 3.4.1 / 3.4.2 | `D3-HI` |
| `WEB-104` | `cookies` | Weak `SameSite` or cookie prefix violation | 3.4.3 / 3.4.4 | `D3-HI` |
| `WEB-201` | `config` | Deprecated TLS protocol enabled in config or live handshake | 9.1.2 | `D3-CH` |
| `WEB-202` | `config` | Server version banner, `file_server browse`, or `autoindex on` | 14.3.3 | `D3-CH` |
| `WEB-203` | `config` | Proxy/edge config emits unsafe CORS or CSP header | 14.4.3 | `D3-CH` |
| `WEB-204` | `config` | Unbounded request body size in config | 13.1.4 | `D3-IV` |
| `WEB-205` | `config` | Nginx `location` `add_header` drops parent security headers | 14.4.3 | `D3-CH` |
| `WEB-206` | `config` | Nginx `alias` off-by-slash traversal or dynamic `proxy_pass`/`$http_host` | 12.3.1 | `D3-CH` |
| `WEB-207` | `config` | Weak TLS cipher suite, expiring certificate, or insecure web config | 9.1.3 | `D3-CH` |
| `WEB-301` | `waf` | Cross-Site Scripting (XSS) payload or semantic vector | 5.3.3 | `D3-IV` |
| `WEB-302` | `waf` | SQL Injection (SQLi) payload or semantic AST pattern | 5.3.4 | `D3-IV` |
| `WEB-303` | `waf` | Path Traversal / LFI sequence | 12.3.1 | `D3-IV` |
| `WEB-304` | `waf` | Prototype Pollution key pattern | 5.1.3 | `D3-IV` |
| `WEB-305` | `waf` | SSRF or cloud metadata URI target | 12.6.1 | `D3-NI` |
| `WEB-306` | `waf` | OS Command Injection / RCE sequence | 5.3.8 | `D3-IV` |
| `WEB-307` | `waf` | SSTI or Java JNDI lookup pattern | 5.2.5 | `D3-IV` |
| `WEB-308` | `waf` | NoSQL operator injection pattern | 5.3.5 | `D3-IV` |
| `WEB-309` | `waf` | XML External Entity (XXE) DOCTYPE/ENTITY pattern | 5.5.2 | `D3-IV` |
| `WEB-310` | `waf` | HTTP Response Splitting / CRLF header injection | 5.3.10 | `D3-IV` |
| `WEB-311` | `waf` | Custom enterprise YAML WAF policy rule matched | 5.1.3 | `D3-IV` |
| `WEB-312` | `waf` | HTTP request rate limit exceeded in WebShield proxy | 13.1.4 | `D3-NI` |
