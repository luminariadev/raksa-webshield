# raksa-webshield

[![CI](https://github.com/luminariadev/raksa-webshield/actions/workflows/ci.yml/badge.svg)](https://github.com/luminariadev/raksa-webshield/actions/workflows/ci.yml)
[![Release](https://github.com/luminariadev/raksa-webshield/actions/workflows/release.yml/badge.svg)](https://github.com/luminariadev/raksa-webshield/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.24%2B-00ADD8.svg)](https://go.dev/)
[![TypeScript](https://img.shields.io/badge/typescript-5.8%2B-3178C6.svg)](https://www.typescriptlang.org/)

Polyglot web security defense toolkit combining a static **Go CLI / stdio MCP server (`raksa-webshield`)** with a zero-dependency **TypeScript sanitization, CSP nonce, rate limiter, and 10-class WAF SDK (`@raksa/webshield`)**.

`raksa-webshield` is **Layer 3 (`web-defense`)** of the Raksa Blue Team and DevSecOps suite. It grades HTTP response headers (`0-100`, `A+`..`F`), catches CSP JSONP/CDN bypasses, audits Nginx AST/Caddyfile/Vercel/Kubernetes Ingress configs offline or via an SSRF-protected live TLS+header reader, screens incoming requests across 10 attack classes with anomaly scoring, generates `100/100 A+` hardened server snippets, outputs **Raksa Finding Schema v1** (`table`, `json`, `sarif` `2.1.0`), and runs natively in Node/TypeScript and Web Fetch Edge runtimes.

---

## Key Capabilities (`v0.2.0`)

- **HTTP Headers, CSP Bypass Evaluator, Isolation & Smart Cookies (`audit-headers` / `audit-csp`)**: Checks HSTS (`max-age >= 15768000`), CSP (`script-src-elem`, `'unsafe-inline'` ignored safely when paired with nonces/hashes, `'strict-dynamic'`, known JSONP/CDN bypass hosts `WEB-006`, `form-action`, `blob:`, `object-src 'none'`, `base-uri`), Clickjacking, `Cross-Origin-Opener-Policy` / `Cross-Origin-Resource-Policy`, cookie `Cache-Control: no-store` (`WEB-007`), CORS credential exposures (`WEB-101`..`102`), and smart `Set-Cookie` classification (`WEB-103`..`104`) with cookie values redacted.
- **SSRF-Safe Live Header & TLS Inspection (`--url`)**: Performs a single read-only `GET` with DNS/redirect validation blocking loopback, RFC 1918 private networks, link-local metadata endpoints (`169.254.169.254`), and `.internal` hosts by default (`--allow-private` overrides explicitly), plus live TLS version (`< 1.2`) and leaf certificate expiry checks (`<= 14d`).
- **Block-Aware Nginx AST, Caddyfile & Modern Edge Auditor (`audit-config` / `audit-workspace`)**: Parses Nginx block scopes for `location` `add_header` parent header drops (`WEB-205`), off-by-slash `alias` traversal, dynamic `proxy_pass`, and `$http_host` forwarding (`WEB-206`), weak OpenSSL/Caddy `ssl_ciphers` (`WEB-207`), legacy TLS (`WEB-201`), banners/`file_server browse` (`WEB-202`), unsafe CORS/CSP headers (`WEB-203`), and `vercel.json`, `_headers`, and Kubernetes Ingress YAML.
- **10-Class Anomaly-Scoring Payload Inspector (`inspect-request`)**: Normalizes multi-pass URL encoding, HTML entities, `\u00XX` escapes, and inline SQL `/**/` comments before scanning for XSS (`WEB-301`), SQLi (`WEB-302`), Path Traversal/LFI (`WEB-303`), Prototype Pollution (`WEB-304`), SSRF (`WEB-305`), Command Injection/RCE (`WEB-306`), SSTI/JNDI (`WEB-307`), NoSQL injection (`WEB-308`), XXE (`WEB-309`), and CRLF splitting (`WEB-310`) with `--paranoia` (`1-3`) and `--anomaly-threshold`.
- **Self-Auditing Hardened Config Generator (`generate-policy`)**: Emits `strict` or `balanced` hardening templates for `nginx`, `caddy`, `nextjs`, and raw `headers` verified to score `100/100 (A+)` cleanly.
- **Fail-Closed Policy Suppressions (`--policy`)**: Supports YAML/JSON exception files ([examples/webshield-policy.yml](examples/webshield-policy.yml)) requiring an audit reason and enforcing `expires_on` (`YYYY-MM-DD`).
- **Zero-Dependency TypeScript SDK (`sdk/ts`, `@raksa/webshield`)**: Stack-balanced idempotent `sanitizeHtml`, multi-pass `isSafeUrl`, `generateCspNonce`, `buildSecurityHeaders`, bounded-LRU `createMemoryRateLimiter`, `inspectInput`, Node middleware (`createWebShieldMiddleware`), and Web Standard Fetch API wrapper (`createFetchWebShield`) returning opaque `{ error, incident_id }` 403 responses by default.
- **Native MCP Server (`raksa-webshield mcp`)**: Exposes 7 defensive tools over newline-delimited `stdio` JSON-RPC 2.0 with 1 MiB inline payload caps.

---

## Defensive Scope & Boundaries

`raksa-webshield` prioritizes deterministic static audits, strict allowlist sanitization, and low-latency heuristic screening:

- **100% Read-Only & Non-Offensive**: Does not crawl applications, brute-force paths, inject active exploit payloads over the network, or fuzz targets.
- **Allowlist Sanitizer vs. Browser DOM**: `sanitizeHtml` strips disallowed elements and executable tag blocks (`script`, `style`, `iframe`, `svg`, `math`, `template`, `noscript`, `textarea`, `xmp`, `object`, `embed`), balances unclosed tags, and normalizes multi-encoded URIs deterministically without spinning up a headless browser DOM.
- **Defense-in-Depth Input Screening**: Heuristic WAF screening (`inspect-request` and TypeScript middleware/Fetch adapter) enforces anomaly thresholds as an edge defense layer alongside parameterized SQL queries and context-aware output escaping.

---

## Architecture

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

See [docs/architecture.md](docs/architecture.md) and [docs/threat-model.md](docs/threat-model.md) for component design and trust boundaries.

---

## Installation

### 1. Prebuilt Release Binaries

Download single-file static binaries (`linux/amd64`, `windows/amd64`, `darwin/arm64`) along with `SHA256SUMS.txt` from [GitHub Releases](https://github.com/luminariadev/raksa-webshield/releases).

### 2. Build CLI from Source (Go 1.24+)

```bash
git clone https://github.com/luminariadev/raksa-webshield.git
cd raksa-webshield
go build -trimpath -ldflags="-s -w" -o raksa-webshield ./cmd/raksa-webshield
```

### 3. Container Image (Distroless Non-Root)

```bash
docker build -t raksa-webshield:v0.2.0 .
docker run --rm raksa-webshield:v0.2.0 version
```

### 4. TypeScript SDK (`sdk/ts`)

```bash
cd sdk/ts
npm ci
npm run build
npm test
```

---

## Quickstart & Verified Examples

### CLI Version & Rule Catalog

```bash
raksa-webshield version
# raksa-webshield v0.2.0 (schema 1.0, layer web-defense)

raksa-webshield rules
```

### Audit HTTP Headers, CSP, Isolation, CORS & Cookies

```bash
raksa-webshield audit-headers --file testdata/headers_insecure.http --fail-on critical
```

Verified output (`exit 2`, posture score included, session cookie secret redacted):

```text
raksa-webshield v0.2.0 | layer: web-defense | score: 0/100 (F) | total: 20 (critical: 1, high: 4, medium: 7, low: 8, info: 0)
SEVERITY  RULE      MODULE     TARGET                                 TITLE
--------------------------------------------------------------------------------------------------------
HIGH      WEB-001   headers    file://testdata/headers_insecure.http  Missing or weak Strict-Transport-Security (HSTS)
          fix: Raise HSTS max-age to at least 31536000 (1 year) and include includeSubDomains.
HIGH      WEB-003   csp        file://testdata/headers_insecure.http  Unsafe Content-Security-Policy directive
          fix: Remove 'unsafe-inline', 'unsafe-eval', wildcard *, data:, blob:, and insecure http: origins from script-src; use nonces or SHA-256 hashes.
...
MEDIUM    WEB-006   csp        file://testdata/headers_insecure.http  CSP missing form-action restriction
          fix: Add form-action 'self' (or explicit trusted submission endpoints) to Content-Security-Policy.
LOW       WEB-007   headers    file://testdata/headers_insecure.http  Missing Cross-Origin-Opener-Policy header
          fix: Set Cross-Origin-Opener-Policy: same-origin on top-level document responses.
CRITICAL  WEB-101   cors       file://testdata/headers_insecure.http  Dangerous CORS credential exposure
          fix: Validate Origin against an exact allowlist before echoing Access-Control-Allow-Origin, never trust 'null' or '*', and omit Allow-Credentials unless strictly necessary.
HIGH      WEB-103   cookies    file://testdata/headers_insecure.http  Cookie missing Secure or HttpOnly attribute
          fix: Set Secure; HttpOnly on cookie 'sid' so it cannot traverse cleartext HTTP or be read by document.cookie.
```

### Audit Nginx AST, Caddyfile, Vercel & Kubernetes Ingress (`audit-config`)

```bash
raksa-webshield audit-config --path testdata/nginx_gixy_bugs.conf --fail-on high
```

Verified output (`exit 2`):

```text
raksa-webshield v0.2.0 | layer: web-defense | score: 20/100 (F) | total: 5 (critical: 0, high: 4, medium: 1, low: 0, info: 0)
SEVERITY  RULE      MODULE     TARGET                                 TITLE
--------------------------------------------------------------------------------------------------------
HIGH      WEB-207   config     file://testdata/nginx_gixy_bugs.conf   Weak TLS cipher suite enabled in web server config
          fix: Use modern AEAD cipher suites (ECDHE+AESGCM, CHACHA20) and exclude RC4, 3DES, DES, MD5, EXPORT, and NULL.
HIGH      WEB-206   config     file://testdata/nginx_gixy_bugs.conf   Nginx off-by-slash alias path traversal risk
          fix: Append a trailing '/' to location (/static/) or drop the trailing '/' from alias.
HIGH      WEB-205   config     file://testdata/nginx_gixy_bugs.conf   Nginx location add_header drops inherited parent security headers
          fix: Repeat required parent security headers inside this location block or move headers into a shared include snippet.
MEDIUM    WEB-206   config     file://testdata/nginx_gixy_bugs.conf   Proxy forwards raw $http_host instead of validated $host
          fix: Prefer proxy_set_header Host $host; or a fixed canonical upstream hostname.
HIGH      WEB-206   config     file://testdata/nginx_gixy_bugs.conf   Unsafe dynamic variable in proxy_pass target
          fix: Use static named upstream blocks instead of interpolating $http_host, $arg_*, or $uri as proxy_pass host.
```

### 10-Class WAF Payload Inspection (`inspect-request`)

```bash
raksa-webshield inspect-request --file testdata/payload_advanced.json --paranoia 1 --fail-on critical
```

Verified output (`exit 2`):

```text
raksa-webshield v0.2.0 | layer: web-defense | score: 0/100 (F) | total: 8 (critical: 5, high: 3, medium: 0, low: 0, info: 0)
SEVERITY  RULE      MODULE     TARGET                                 TITLE
--------------------------------------------------------------------------------------------------------
CRITICAL  WEB-302   waf        file://testdata/payload_advanced.json  SQL Injection (SQLi) payload pattern detected
HIGH      WEB-303   waf        file://testdata/payload_advanced.json  Path Traversal / Local File Inclusion sequence detected
CRITICAL  WEB-305   waf        file://testdata/payload_advanced.json  SSRF or cloud metadata URI target detected
CRITICAL  WEB-306   waf        file://testdata/payload_advanced.json  OS Command Injection / Remote Code Execution payload pattern detected
CRITICAL  WEB-307   waf        file://testdata/payload_advanced.json  Server-Side Template Injection (SSTI) or JNDI lookup pattern detected
HIGH      WEB-308   waf        file://testdata/payload_advanced.json  NoSQL operator injection pattern detected
CRITICAL  WEB-309   waf        file://testdata/payload_advanced.json  XML External Entity (XXE) DOCTYPE/ENTITY injection pattern detected
HIGH      WEB-310   waf        file://testdata/payload_advanced.json  HTTP Response Splitting / CRLF header injection sequence detected
```

### Generate Self-Audited Hardened Configs (`generate-policy`)

```bash
raksa-webshield generate-policy --target nginx --profile strict
raksa-webshield generate-policy --target caddy --profile balanced --origin https://app.example.com
raksa-webshield generate-policy --target nextjs --output next.config.mjs
```

### TypeScript SDK Middleware, CSP Nonce, Rate Limiter & Fetch API (`@raksa/webshield`)

See [examples/express-quickstart.ts](examples/express-quickstart.ts) for Node HTTP / Express usage, or use the Web Standard Fetch API wrapper across Next.js App Router, Hono, Cloudflare Workers, Bun, and Deno:

```ts
import {
  createFetchWebShield,
  sanitizeHtml,
} from "@raksa/webshield";

const clean = sanitizeHtml(`<p>Hello <a href="&amp;#x6a;avascript:alert(1)">bad</a>`);
// -> <p>Hello <a>bad</a></p>

const withWebShield = createFetchWebShield({
  mode: "enforce",
  cspNonce: true,
  anomalyThreshold: 4,
  rateLimit: { windowMs: 60_000, maxRequests: 120 },
  onReport(report, _req, incidentId) {
    console.warn("blocked:", incidentId, report.posture, report.summary);
  },
});

export async function handle(request: Request): Promise<Response> {
  return withWebShield(request, (_req, ctx) => {
    return new Response(`<script nonce="${ctx.nonce}">console.log("ok")</script>`, {
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  });
}
```

---

## CI/CD SARIF Integration

Export findings in **SARIF 2.1.0** for GitHub Code Scanning with `--policy` suppression rules and `--fail-on` severity gating:

```yaml
- name: Run raksa-webshield workspace audit
  run: |
    set +e
    raksa-webshield audit-workspace --path . --policy examples/webshield-policy.yml --format sarif --output webshield.sarif --fail-on high
    rc=$?
    set -e
    if [ "$rc" -eq 1 ]; then exit 1; fi

- name: Upload SARIF report
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: webshield.sarif
```

---

## MCP Integration

`raksa-webshield mcp` exposes 7 defensive web security tools over `stdio` JSON-RPC 2.0 for MCP-compatible clients and agents:

```json
{
  "mcpServers": {
    "raksa-webshield": {
      "command": "raksa-webshield",
      "args": ["mcp"]
    }
  }
}
```

Available MCP tools:
- `webshield_list_rules`: List all 28 `WEB-*` rules mapped to OWASP ASVS and MITRE D3FEND.
- `webshield_audit_headers`: Audit raw header text, file dumps, or SSRF-safe live URLs + TLS state (optional `allow_private`, `policy_path`).
- `webshield_audit_csp`: Evaluate a Content-Security-Policy header string cleanly (nonce/`strict-dynamic`, CDN bypasses, `form-action`).
- `webshield_audit_config`: Audit Nginx AST, Caddyfile, `vercel.json`, `_headers`, Kubernetes Ingress, or directories.
- `webshield_inspect_payload`: Screen request parameters or JSON text across 10 attack classes (`paranoia_level`, `anomaly_threshold`).
- `webshield_audit_workspace`: Recursively audit a full repository across web configs and header files with optional policy suppressions.
- `webshield_generate_remediation`: Generate `100/100 A+` hardened snippets for `nginx`, `caddy`, `nextjs`, or `headers`.

---

## Benchmarks (`v0.2.0`)

Measured on Windows `amd64` (`11th Gen Intel(R) Core(TM) i5-11400H @ 2.70GHz`, Go `go test -run '^$' -bench . -benchmem ./internal/auditor` and Node `npm run bench` across 20,000 iterations):

| Benchmark | Language | Workload / Allocations | Latency / Throughput |
| :--- | :--- | :--- | :--- |
| `BenchmarkAuditHeaders-12` | Go | Full header, CSP bypass, COOP/CORP, CORS & cookie pass (1,816 B/op, 40 allocs) | 4,121 ns/op (~242k ops/s) |
| `BenchmarkAuditCSP-12` | Go | Hardened CSP directive & bypass check (816 B/op, 15 allocs) | 1,555 ns/op (~643k ops/s) |
| `BenchmarkAuditConfig-12` | Go | Block-aware Nginx AST config check (1,032 B/op, 20 allocs) | 2,536 ns/op (~394k ops/s) |
| `BenchmarkInspectPayload-12` | Go | 10-class prefiltered WAF + URI/evasion pass (448 B/op, 6 allocs) | 2,538 ns/op (~394k ops/s) |
| `ts_sanitizeHtml` | TypeScript | Tag-balanced allowlist + XSS/mXSS strip (20,000 iters, 0.2852s) | 70,138.4 ops/s |
| `ts_inspectInput` | TypeScript | 10-class WAF inspection + fast prefilter (20,000 iters, 0.0621s) | 322,278.1 ops/s |

---

## Rule Catalog (28 OWASP ASVS & MITRE D3FEND Rules)

| Rule ID | Severity | Module | OWASP ASVS | MITRE D3FEND | Title |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `WEB-001` | High | `headers` | 14.4.5 | `D3-HI` | Missing or weak Strict-Transport-Security (HSTS) |
| `WEB-002` | High | `headers` | 14.4.3 | `D3-HI` | Missing Content-Security-Policy header |
| `WEB-003` | High | `csp` | 14.4.3 | `D3-HI` | Unsafe Content-Security-Policy directive |
| `WEB-004` | Medium | `headers` | 14.4.4 | `D3-HI` | Missing clickjacking protection |
| `WEB-005` | Low | `headers` | 14.4.1 / 14.4.6 | `D3-HI` | Missing hardening header or server version banner disclosure |
| `WEB-006` | Medium | `csp` | 14.4.3 | `D3-HI` | CSP permits known JSONP/CDN bypass host or omits form-action guard |
| `WEB-007` | Low | `headers` | 14.4.7 | `D3-HI` | Missing Cross-Origin Isolation header (COOP/CORP) or sensitive Cache-Control |
| `WEB-101` | Critical | `cors` | 14.5.3 | `D3-NI` | Dangerous CORS credential exposure |
| `WEB-102` | Medium | `cors` | 14.5.3 | `D3-NI` | Overly permissive CORS policy |
| `WEB-103` | High | `cookies` | 3.4.1 / 3.4.2 | `D3-HI` | Cookie missing Secure or HttpOnly attribute |
| `WEB-104` | Medium | `cookies` | 3.4.3 / 3.4.4 | `D3-HI` | Weak SameSite attribute or cookie prefix violation |
| `WEB-201` | High | `config` | 9.1.2 | `D3-CH` | Deprecated TLS protocol enabled in web server config |
| `WEB-202` | Medium | `config` | 14.3.3 | `D3-CH` | Web server version disclosure or directory listing enabled |
| `WEB-203` | High | `config` | 14.4.3 | `D3-CH` | Reverse-proxy config emits unsafe CORS or CSP header |
| `WEB-204` | Medium | `config` | 13.1.4 | `D3-IV` | Unbounded request body size in web server config |
| `WEB-205` | High | `config` | 14.4.3 | `D3-CH` | Nginx location add_header drops inherited parent security headers |
| `WEB-206` | High | `config` | 12.3.1 | `D3-CH` | Nginx alias off-by-slash traversal or unsafe proxy_pass/host-header variable |
| `WEB-207` | High | `config` | 9.1.3 | `D3-CH` | Weak TLS cipher suite, expiring certificate, or insecure modern web config |
| `WEB-301` | High | `waf` | 5.3.3 | `D3-IV` | Cross-Site Scripting (XSS) payload pattern detected |
| `WEB-302` | Critical | `waf` | 5.3.4 | `D3-IV` | SQL Injection (SQLi) payload pattern detected |
| `WEB-303` | High | `waf` | 12.3.1 | `D3-IV` | Path Traversal / Local File Inclusion sequence detected |
| `WEB-304` | High | `waf` | 5.1.3 | `D3-IV` | Prototype Pollution key detected in request payload |
| `WEB-305` | Critical | `waf` | 12.6.1 | `D3-NI` | SSRF or cloud metadata URI target detected |
| `WEB-306` | Critical | `waf` | 5.3.8 | `D3-IV` | OS Command Injection / Remote Code Execution payload pattern detected |
| `WEB-307` | Critical | `waf` | 5.2.5 | `D3-IV` | Server-Side Template Injection (SSTI) or JNDI lookup pattern detected |
| `WEB-308` | High | `waf` | 5.3.5 | `D3-IV` | NoSQL operator injection pattern detected |
| `WEB-309` | Critical | `waf` | 5.5.2 | `D3-IV` | XML External Entity (XXE) DOCTYPE/ENTITY injection pattern detected |
| `WEB-310` | High | `waf` | 5.3.10 | `D3-IV` | HTTP Response Splitting / CRLF header injection sequence detected |

---

## Raksa Security Suite

`raksa-webshield` shares **Raksa Finding Schema v1** (`schema_version = "1.0"`) across the modular Raksa ecosystem:

- **Layer 1 (`network-defense`)**: [raksa-netguard](https://github.com/luminariadev/raksa-netguard) (Go) - Exposed port audit and real-time firewall/log anomaly detection.
- **Layer 2 (`host-hardening`)**: [raksa-hostguard](https://github.com/luminariadev/raksa-hostguard) (Rust) - Signed parallel SHA-256 FIM, Linux/SSH/Docker CIS hardening, and MCP server.
- **Layer 3 (`web-defense`)**: `raksa-webshield` (TypeScript + Go) - This repository.
- **Layer 4 (`devsecops-ci`, planned)**: `raksa-pipeguard` (Go / Rust) - Secret scanning, SBOM audit, and IaC checks.
- **Layer 5 (`malware-ioc`, planned)**: `raksa-iocscan` (Python) - YARA, hash reputation, and entropy anomaly scanner.
- **Layer 6 (`observability-siem`, planned)**: `raksa-siem` (Python + Go) - Log normalizer, correlation engine, and alert router.

## License

Released under the [MIT License](LICENSE).
