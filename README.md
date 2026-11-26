# raksa-webshield

[![CI](https://github.com/luminariadev/raksa-webshield/actions/workflows/ci.yml/badge.svg)](https://github.com/luminariadev/raksa-webshield/actions/workflows/ci.yml)
[![Release](https://github.com/luminariadev/raksa-webshield/actions/workflows/release.yml/badge.svg)](https://github.com/luminariadev/raksa-webshield/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.24%2B-00ADD8.svg)](https://go.dev/)
[![TypeScript](https://img.shields.io/badge/typescript-5.8%2B-3178C6.svg)](https://www.typescriptlang.org/)

Polyglot enterprise web security defense toolkit combining a static **Go CLI, reverse-proxy WAF sidecar, and stdio MCP server (`raksa-webshield`)** with a zero-dependency **TypeScript sanitization, semantic SQLi/XSS analyzer, CSP nonce, rate limiter, and WAF middleware SDK (`@raksa/webshield`)**.

`raksa-webshield` is **Layer 3 (`web-defense`)** of the Raksa Blue Team and DevSecOps suite. It grades HTTP response headers (`0-100`, `A+`..`F`), detects CSP JSONP/CDN bypasses, audits Nginx AST / Caddyfile / Vercel / Kubernetes Ingress configs offline or via an SSRF-protected live TLS+header reader, inspects requests with regex + zero-CGO semantic SQLi/XSS tokenizers and custom enterprise YAML rules, deploys as an inline reverse-proxy sidecar with Prometheus `/metrics` and SIEM NDJSON telemetry, outputs **Raksa Finding Schema v1** (`table`, `json`, `sarif` `2.1.0`), and runs natively in Node, TypeScript, and Web Fetch Edge runtimes.

---

## Key Capabilities (`v0.3.0`)

- **Standalone Reverse-Proxy WAF Sidecar (`raksa-webshield proxy`)**: Runs in front of any HTTP backend (Go, Python, PHP, Java, Rust, Node), strips `Server`/`X-Powered-By`, injects hardened `strict`/`balanced` security headers, screens traffic via 10-class WAF + semantic SQLi/XSS + custom YAML rules, enforces bounded-LRU per-IP rate limiting (`429` + `Retry-After`), emits opaque `403` JSON `{ error, incident_id }`, streams **Raksa Schema v1 NDJSON** logs to `--log-file`/`stderr`, and serves Prometheus **`/metrics`** and `/healthz` on `--metrics-addr`.
- **Zero-CGO Semantic SQLi & XSS Tokenizers (Go + TypeScript)**: Syntactic SQL lexer (`AnalyzeSQLiSemantic`) and stateful HTML5 attribute/tag scanner (`AnalyzeXSSSemantic`) catch obfuscated attacks missed by pure regexes (`1' AND PG_SLEEP(5)--`, `admin'/**/OR/**/'a'='a`, `1' ORDER BY 10--`, `1; EXEC xp_cmdshell`, `<img/src=x/onerror=alert(1)>`, `<details open ontoggle=alert(1)>`, `<meta http-equiv="refresh" content="0;url=javascript:...">`) with zero false positives on normal prose.
- **Custom Enterprise YAML WAF Rules (`WEB-311`, `--custom-rules`)**: Define organization-specific virtual patches in YAML ([examples/custom-waf-rules.yml](examples/custom-waf-rules.yml)) supporting `contains`, `regex`, and `exact` matching, scoped targets (`path`, `query`, `headers`, `body`, `all`), `block` vs `monitor` actions, and anomaly weights.
- **HTTP Headers, CSP Bypass Evaluator, Isolation & Smart Cookies (`audit-headers` / `audit-csp`)**: Checks HSTS (`max-age >= 15768000`), CSP (`script-src-elem`, `'nonce-...'`/hash + `'strict-dynamic'` awareness, known JSONP/CDN bypass hosts `WEB-006`, `form-action`, `blob:`, `object-src 'none'`, `base-uri`), Clickjacking, `Cross-Origin-Opener-Policy` / `Cross-Origin-Resource-Policy`, cookie `Cache-Control: no-store` (`WEB-007`), CORS credential exposures (`WEB-101`..`102`), and smart `Set-Cookie` classification (`WEB-103`..`104`) with secret values redacted.
- **SSRF-Safe Live Header & TLS Inspection (`--url`)**: Single read-only `GET` with DNS/redirect validation blocking loopback, RFC 1918 private networks, link-local metadata endpoints (`169.254.169.254`), and `.internal` hosts by default (`--allow-private` overrides explicitly), plus live TLS version (`< 1.2`) and leaf certificate expiry checks (`<= 14d`).
- **Block-Aware Nginx AST, Caddyfile & Modern Edge Auditor (`audit-config` / `audit-workspace`)**: Parses Nginx block scopes for `location` `add_header` parent header drops (`WEB-205`), off-by-slash `alias` traversal, dynamic `proxy_pass`, and `$http_host` forwarding (`WEB-206`), weak OpenSSL/Caddy `ssl_ciphers` (`WEB-207`), legacy TLS (`WEB-201`), banners/`file_server browse` (`WEB-202`), unsafe CORS/CSP (`WEB-203`), and `vercel.json`, `_headers`, and Kubernetes Ingress YAML.
- **Self-Auditing Hardened Config Generator (`generate-policy`)**: Emits `strict` or `balanced` hardening templates for `nginx`, `caddy`, `nextjs`, and raw `headers` verified to score `100/100 (A+)` cleanly.
- **Fail-Closed Policy Suppressions (`--policy`)**: YAML/JSON exception files ([examples/webshield-policy.yml](examples/webshield-policy.yml)) requiring an audit reason and enforcing `expires_on` (`YYYY-MM-DD`).
- **Zero-Dependency TypeScript SDK (`sdk/ts`, `@raksa/webshield`)**: Stack-balanced idempotent `sanitizeHtml`, 3-pass `isSafeUrl`, `generateCspNonce`, `buildSecurityHeaders`, bounded-LRU `createMemoryRateLimiter`, semantic SQLi/XSS tokenizers, custom rules, Node middleware (`createWebShieldMiddleware`), and Web Standard Fetch API wrapper (`createFetchWebShield`).
- **Native MCP Server (`raksa-webshield mcp`)**: Exposes 8 defensive tools over newline-delimited `stdio` JSON-RPC 2.0 including `webshield_validate_custom_rules`.

---

## Architecture

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

See [docs/architecture.md](docs/architecture.md) and [docs/threat-model.md](docs/threat-model.md) for component design and trust boundaries.

---

## Installation

### 1. Prebuilt Release Binaries

Download single-file static binaries (`linux/amd64`, `windows/amd64`, `darwin/arm64`) along with `SHA256SUMS.txt` from [GitHub Releases](https://github.com/luminariadev/raksa-webshield/releases).

### 2. Build CLI & Sidecar from Source (Go 1.24+)

```bash
git clone https://github.com/luminariadev/raksa-webshield.git
cd raksa-webshield
go build -trimpath -ldflags="-s -w" -o raksa-webshield ./cmd/raksa-webshield
```

### 3. Container Image (Distroless Non-Root)

```bash
docker build -t raksa-webshield:v0.3.0 .
docker run --rm raksa-webshield:v0.3.0 version
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

### Reverse-Proxy WAF Sidecar (`proxy`)

Run `raksa-webshield` directly in front of any web service on `:8443` with rate limiting, custom virtual patches, SIEM NDJSON telemetry, and Prometheus metrics on `:9090`:

```bash
raksa-webshield proxy \
  --listen :8443 \
  --upstream http://127.0.0.1:8080 \
  --mode enforce \
  --profile strict \
  --rate-limit 120 \
  --rate-window 60s \
  --custom-rules examples/custom-waf-rules.yml \
  --exclude-paths /healthz,/metrics \
  --log-file /var/log/raksa-webshield.ndjson \
  --metrics-addr 127.0.0.1:9090
```

Sidecar features:
- **Prometheus `/metrics` endpoint**: Exports `raksa_webshield_requests_total`, `raksa_webshield_requests_blocked_total`, `raksa_webshield_requests_monitored_total`, `raksa_webshield_rate_limited_total`, `raksa_webshield_upstream_errors_total`, and `raksa_webshield_findings_by_rule_total{rule_id="..."}`.
- **Raksa SIEM NDJSON logs**: Streams one JSON line per security event `{ timestamp, incident_id, action, client_ip, method, path, report }` ready for ingestion into `raksa-siem`.
- **Zero-leak HTTP responses**: Blocked requests receive opaque HTTP `403` / `429` JSON `{ "error": "...", "incident_id": "inc-..." }` while backend responses have `Server`/`X-Powered-By` stripped and security headers enforced.

### Semantic SQLi / XSS & Custom Enterprise YAML Rules (`inspect-request`)

```bash
raksa-webshield inspect-request --input "1' AND PG_SLEEP(5)--" --fail-on high
```

Verified output (`exit 2`, detected by zero-CGO semantic SQLi tokenizer):

```text
raksa-webshield v0.3.0 | layer: web-defense | score: 70/100 (C) | total: 1 (critical: 1, high: 0, medium: 0, low: 0, info: 0)
SEVERITY  RULE      MODULE     TARGET                                 TITLE
--------------------------------------------------------------------------------------------------------
CRITICAL  WEB-302   waf        inline://request                       SQL Injection (SQLi) payload pattern detected
          fix: Use parameterized prepared statements strictly and reject malformed query strings.
```

Evaluate custom enterprise virtual-patch YAML rules ([examples/custom-waf-rules.yml](examples/custom-waf-rules.yml)):

```bash
raksa-webshield inspect-request --input "{ __schema { types { name } } }" --custom-rules examples/custom-waf-rules.yml --fail-on medium
```

Verified output (`exit 2`):

```text
raksa-webshield v0.3.0 | layer: web-defense | score: 92/100 (A) | total: 1 (critical: 0, high: 0, medium: 1, low: 0, info: 0)
SEVERITY  RULE      MODULE     TARGET                                 TITLE
--------------------------------------------------------------------------------------------------------
MEDIUM    WEB-311   waf        inline://request                       Block unauthenticated GraphQL schema introspection query
          fix: Disable GraphQL schema introspection in production gateways.
```

### Audit HTTP Headers, Nginx AST, & Generate Hardened Configs

```bash
raksa-webshield audit-headers --file testdata/headers_insecure.http --fail-on critical
raksa-webshield audit-config --path testdata/nginx_gixy_bugs.conf --fail-on high
raksa-webshield generate-policy --target nginx --profile strict
raksa-webshield generate-policy --target caddy --profile balanced --origin https://app.example.com
```

### TypeScript SDK Middleware, Semantic Tokenizers, Custom Rules & Fetch API (`@raksa/webshield`)

See [examples/express-quickstart.ts](examples/express-quickstart.ts) for Node HTTP usage, or protect Next.js, Hono, Cloudflare Workers, Bun, and Deno endpoints:

```ts
import {
  analyzeSqlSemantic,
  createFetchWebShield,
  sanitizeHtml,
} from "@raksa/webshield";

const clean = sanitizeHtml(`<p>Hello <a href="&amp;#x6a;avascript:alert(1)">bad</a>`);
// -> <p>Hello <a>bad</a></p>

const sqli = analyzeSqlSemantic(`admin'/**/OR/**/'a'='a`);
// -> { matched: true, fingerprint: "ksos", ... }

const withWebShield = createFetchWebShield({
  mode: "enforce",
  cspNonce: true,
  anomalyThreshold: 4,
  rateLimit: { windowMs: 60_000, maxRequests: 120 },
  customRules: [
    {
      id: "BLOCK-GQL-INTROSPECT",
      title: "Block GraphQL introspection",
      matchType: "regex",
      pattern: "__schema\\b",
      caseInsensitive: true,
      action: "block",
    },
  ],
  onReport(report, _req, incidentId) {
    console.warn("blocked:", incidentId, report.posture, report.summary);
  },
});
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

`raksa-webshield mcp` exposes 8 defensive web security tools over `stdio` JSON-RPC 2.0 for MCP-compatible clients and agents:

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
- `webshield_list_rules`: List all 30 `WEB-*` rules mapped to OWASP ASVS and MITRE D3FEND.
- `webshield_audit_headers`: Audit raw header text, file dumps, or SSRF-safe live URLs + TLS state (optional `allow_private`, `policy_path`).
- `webshield_audit_csp`: Evaluate a Content-Security-Policy header string cleanly (nonce/`strict-dynamic`, CDN bypasses, `form-action`).
- `webshield_audit_config`: Audit Nginx AST, Caddyfile, `vercel.json`, `_headers`, Kubernetes Ingress, or directories.
- `webshield_inspect_payload`: Screen request parameters or JSON text across 10 attack classes, semantic SQLi/XSS tokenizers, and optional `custom_rules_path`.
- `webshield_audit_workspace`: Recursively audit a full repository across web configs and header files with optional policy suppressions.
- `webshield_generate_remediation`: Generate `100/100 A+` hardened snippets for `nginx`, `caddy`, `nextjs`, or `headers`.
- `webshield_validate_custom_rules`: Validate enterprise custom YAML WAF rules syntax and dry-run test payloads without launching the proxy.

---

## Benchmarks (`v0.3.0`)

Measured on Windows `amd64` (`11th Gen Intel(R) Core(TM) i5-11400H @ 2.70GHz`, Go `go test -run '^$' -bench . -benchmem ./internal/auditor` and Node `npm run bench` across 20,000 iterations):

| Benchmark | Language | Workload / Allocations | Latency / Throughput |
| :--- | :--- | :--- | :--- |
| `BenchmarkAuditHeaders-12` | Go | Full header, CSP bypass, COOP/CORP, CORS & cookie pass (1,816 B/op, 40 allocs) | 3,799 ns/op (~263k ops/s) |
| `BenchmarkAuditCSP-12` | Go | Hardened CSP directive & bypass check (816 B/op, 15 allocs) | 1,384 ns/op (~722k ops/s) |
| `BenchmarkAuditConfig-12` | Go | Block-aware Nginx AST config check (1,032 B/op, 20 allocs) | 2,417 ns/op (~414k ops/s) |
| `BenchmarkInspectPayload-12` | Go | 10-class WAF + semantic SQLi/XSS tokenizers + prefilter (608 B/op, 8 allocs) | 3,314 ns/op (~301k ops/s) |
| `ts_sanitizeHtml` | TypeScript | Tag-balanced allowlist + XSS/mXSS strip (20,000 iters, 0.2647s) | 75,565.2 ops/s |
| `ts_inspectInput` | TypeScript | 10-class WAF + semantic SQLi/XSS + prefilter (20,000 iters, 0.0774s) | 258,563.0 ops/s |

---

## Rule Catalog (30 OWASP ASVS & MITRE D3FEND Rules)

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
| `WEB-311` | High | `waf` | 5.1.3 | `D3-IV` | Custom enterprise WAF policy rule matched |
| `WEB-312` | Medium | `waf` | 13.1.4 | `D3-NI` | HTTP request rate limit exceeded in WebShield proxy |

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
