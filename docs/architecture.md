# raksa-webshield Architecture

`raksa-webshield` is the Layer 3 (`web-defense`) component of the Raksa security suite. It combines a single static Go CLI and MCP server with a zero-dependency TypeScript runtime middleware SDK (`@raksa/webshield`) so engineering teams can enforce HTTP hardening and defensive input sanitization from CI/CD pipelines straight into production Node/TypeScript services.

## Component Flow

```text
  [ Go CLI & stdio MCP (raksa-webshield) ]         [ TypeScript SDK (@raksa/webshield) ]
     |         |            |           |             |             |            |
     v         v            v           v             v             v            v
  +------+  +------+   +--------+  +--------+   +-----------+  +---------+  +--------+
  |Headers| | CSP  |   | Proxy  |  |Payload |   | sanitize  |  | header  |  |  WAF   |
  |CORS/  | |Audit |   | Config |  |Inspect |   | Html/Href |  | builder |  | mware  |
  |Cookies| |      |   | (Nginx)|  | (WAF)  |   | allowlist |  |         |  |        |
  +---+---+ +--+---+   +---+----+  +---+----+   +-----------+  +---------+  +---+----+
      |        |           |           |                                        |
      +--------+-----------+-----------+----------------------------------------+
                           |
                           v
               +------------------------+
               |   Policy Filter        | (.webshield.yml + expires_on)
               +-----------+------------+
                           |
                           v
               +------------------------+
               | Raksa Finding Schema v1| (Summary + --fail-on gate)
               +-----+-----+------+-----+
                     |     |      |
                     v     v      v
                  [Table] [JSON] [SARIF 2.1]
```

## Module Responsibilities

- `cmd/raksa-webshield/`: CLI entrypoint (`audit-headers`, `audit-csp`, `audit-config`, `inspect-request`, `audit-workspace`, `rules`, `mcp`, `version`) with CI exit codes (`0` clean, `1` CLI/runtime error, `2` findings >= `--fail-on`).
- `internal/schema/`: Canonical Raksa Finding Schema v1 (`Report`, `Finding`, `Severity`, `Summary`) and built-in `RuleCatalog()` covering 18 `WEB-*` rules mapped to OWASP ASVS v4.0 and MITRE D3FEND.
- `internal/policy/`: YAML/JSON suppression policy engine requiring audit reasons and enforcing fail-closed `expires_on` (`YYYY-MM-DD`) expiration dates.
- `internal/auditor/`:
  - `headers.go` / `csp.go` / `cors.go` / `cookies.go`: Raw HTTP header parser and analyzers for HSTS, CSP directives, clickjacking, CORS origin/credential leaks, and cookie flags/prefixes (`WEB-001`..`WEB-104`).
  - `config.go`: Static Nginx/Caddyfile reverse-proxy configuration auditor (`WEB-201`..`WEB-204`) plus recursive `AuditWorkspace`.
  - `live.go`: Read-only live HTTP header inspector with private/loopback/metadata SSRF blocking by default.
  - `waf.go`: URL-decoding-aware defensive payload inspector (`WEB-301`..`WEB-305`).
- `internal/report/`: ANSI-sanitized table, JSON Schema v1, and SARIF 2.1.0 serializers.
- `internal/mcp/`: Line-bounded `stdio` JSON-RPC 2.0 MCP server exposing 6 defensive `webshield_*` tools.
- `sdk/ts/`: Zero-dependency TypeScript package (`@raksa/webshield`) exporting `sanitizeHtml`, `escapeHtml`, `buildSecurityHeaders`, `inspectInput`, and `createWebShieldMiddleware`.

## Rule Catalog Overview (18 Rules)

| Rule ID | Module | Control | OWASP ASVS | MITRE D3FEND |
| :--- | :--- | :--- | :--- | :--- |
| `WEB-001` | `headers` | Missing or weak `Strict-Transport-Security` | 14.4.5 | `D3-HI` |
| `WEB-002` | `headers` | Missing `Content-Security-Policy` header | 14.4.3 | `D3-HI` |
| `WEB-003` | `csp` | Unsafe `Content-Security-Policy` directive | 14.4.3 | `D3-HI` |
| `WEB-004` | `headers` | Missing clickjacking protection | 14.4.4 | `D3-HI` |
| `WEB-005` | `headers` | Missing hardening header or version banner leak | 14.4.1 / 14.4.6 | `D3-HI` |
| `WEB-101` | `cors` | Dangerous CORS credential exposure | 14.5.3 | `D3-NI` |
| `WEB-102` | `cors` | Overly permissive CORS policy | 14.5.3 | `D3-NI` |
| `WEB-103` | `cookies` | Cookie missing `Secure` or `HttpOnly` attribute | 3.4.1 / 3.4.2 | `D3-HI` |
| `WEB-104` | `cookies` | Weak `SameSite` or cookie prefix violation | 3.4.3 / 3.4.4 | `D3-HI` |
| `WEB-201` | `config` | Deprecated TLS protocol enabled in server config | 9.1.2 | `D3-CH` |
| `WEB-202` | `config` | Server version banner or autoindex enabled | 14.3.3 | `D3-CH` |
| `WEB-203` | `config` | Proxy config emits unsafe CORS or CSP header | 14.4.3 | `D3-CH` |
| `WEB-204` | `config` | Unbounded request body size in config | 13.1.4 | `D3-IV` |
| `WEB-301` | `waf` | Cross-Site Scripting (XSS) payload pattern | 5.3.3 | `D3-IV` |
| `WEB-302` | `waf` | SQL Injection (SQLi) payload pattern | 5.3.4 | `D3-IV` |
| `WEB-303` | `waf` | Path Traversal / LFI sequence | 12.3.1 | `D3-IV` |
| `WEB-304` | `waf` | Prototype Pollution key pattern | 5.1.3 | `D3-IV` |
| `WEB-305` | `waf` | SSRF or cloud metadata URI target | 12.6.1 | `D3-NI` |
