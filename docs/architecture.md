# raksa-webshield Architecture

`raksa-webshield` is the Layer 3 (`web-defense`) component of the Raksa security suite. It combines a single static Go CLI and MCP server with a zero-dependency TypeScript runtime middleware SDK (`@raksa/webshield`) so engineering teams can enforce HTTP hardening, reverse-proxy posture checks, and defensive input sanitization from CI/CD pipelines straight into production Node, Express, Next.js, Hono, Workers, Bun, and Deno services.

## Component Flow

```text
  [ Go CLI & stdio MCP (raksa-webshield) ]         [ TypeScript SDK (@raksa/webshield) ]
     |         |            |           |             |             |             |
     v         v            v           v             v             v             v
  +------+  +------+   +--------+  +--------+   +-----------+  +---------+  +-----------+
  |Headers| | CSP  |   |AST Proxy| |10-Class|   | sanitize  |  | header  |  | Node/Fetch|
  |COOP/  | |Bypass|   |Nginx/   | |WAF &   |   | Html/Href |  | & Nonce |  | WAF + LRU |
  |Cookies| |Eval  |   |Caddy/K8s| |Scoring |   | Stack Bal |  | builder |  | RateLimit |
  +---+---+ +--+---+   +---+----+  +---+----+   +-----------+  +---------+  +-----+-----+
      |        |           |           |                                          |
      +--------+-----------+-----------+------------------------------------------+
                           |
                           v
               +------------------------+
               |   Policy Filter        | (.webshield.yml + expires_on)
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

- `cmd/raksa-webshield/`: CLI entrypoint (`audit-headers`, `audit-csp`, `audit-config`, `inspect-request`, `audit-workspace`, `generate-policy`, `rules`, `mcp`, `version`) with CI exit codes (`0` clean, `1` CLI/runtime error, `2` findings >= `--fail-on`).
- `internal/schema/`: Canonical Raksa Finding Schema v1 (`Report`, `PostureScore`, `Finding`, `Severity`, `Summary`), posture grading (`0-100`, `A+`..`F`), and built-in `RuleCatalog()` covering 28 `WEB-*` rules mapped to OWASP ASVS and MITRE D3FEND.
- `internal/policy/`: YAML/JSON suppression policy engine requiring audit reasons and enforcing fail-closed `expires_on` (`YYYY-MM-DD`) expiration dates.
- `internal/auditor/`:
  - `headers.go` / `csp.go` / `cors.go` / `cookies.go`: Raw HTTP header parser and analyzers for HSTS, CSP directives + JSONP/CDN bypass host detection (`WEB-006`), `strict-dynamic`/nonce handling, COOP/CORP & cookie `Cache-Control: no-store` (`WEB-007`), clickjacking, CORS origin/credential leaks, and smart session vs CSRF cookie checks (`WEB-001`..`WEB-104`).
  - `config.go`: Block-aware Nginx AST scope parser (`WEB-205` `add_header` inheritance drop, `WEB-206` off-by-slash `alias` traversal / dynamic `proxy_pass` / `$http_host` forwarding, `WEB-207` weak `ssl_ciphers`), real Caddyfile rules, `vercel.json`, `_headers`, and Kubernetes Ingress YAML auditing (`WEB-201`..`WEB-207`) plus recursive `AuditWorkspace`.
  - `live.go`: Read-only live HTTP/HTTPS header + TLS protocol/certificate expiration inspector (`inspectTLSState`) with private/loopback/metadata SSRF blocking by default.
  - `waf.go`: High-speed 10-class anomaly-scoring payload inspector (`WEB-301`..`WEB-310`) with multi-layer URI, HTML entity, `\u00XX`, and SQL inline-comment normalization, paranoia levels `1-3`, and ASCII fast-path prefilters.
  - `remediate.go`: Self-auditing configuration generator producing hardened `nginx`, `caddy`, `nextjs`, and `headers` snippets (`strict` and `balanced` profiles).
- `internal/report/`: ANSI-sanitized table (showing score/grade), JSON Schema v1, and SARIF 2.1.0 serializers.
- `internal/mcp/`: Line-bounded `stdio` JSON-RPC 2.0 MCP server exposing 7 defensive `webshield_*` tools including `webshield_generate_remediation`.
- `sdk/ts/`: Zero-dependency TypeScript package (`@raksa/webshield`) exporting tag-stack balanced `sanitizeHtml`, `escapeHtml`, `isSafeUrl`, `generateCspNonce`, `buildSecurityHeaders`, `createMemoryRateLimiter`, `inspectInput`, `createWebShieldMiddleware` (opaque `incident_id` 403 by default), and Web Standard `createFetchWebShield`.

## Rule Catalog Overview (28 Rules)

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
| `WEB-301` | `waf` | Cross-Site Scripting (XSS) payload pattern | 5.3.3 | `D3-IV` |
| `WEB-302` | `waf` | SQL Injection (SQLi) payload pattern | 5.3.4 | `D3-IV` |
| `WEB-303` | `waf` | Path Traversal / LFI sequence | 12.3.1 | `D3-IV` |
| `WEB-304` | `waf` | Prototype Pollution key pattern | 5.1.3 | `D3-IV` |
| `WEB-305` | `waf` | SSRF or cloud metadata URI target | 12.6.1 | `D3-NI` |
| `WEB-306` | `waf` | OS Command Injection / RCE sequence | 5.3.8 | `D3-IV` |
| `WEB-307` | `waf` | SSTI or Java JNDI lookup pattern | 5.2.5 | `D3-IV` |
| `WEB-308` | `waf` | NoSQL operator injection pattern | 5.3.5 | `D3-IV` |
| `WEB-309` | `waf` | XML External Entity (XXE) DOCTYPE/ENTITY pattern | 5.5.2 | `D3-IV` |
| `WEB-310` | `waf` | HTTP Response Splitting / CRLF header injection | 5.3.10 | `D3-IV` |
