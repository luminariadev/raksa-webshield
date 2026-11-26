# raksa-webshield

[![CI](https://github.com/luminariadev/raksa-webshield/actions/workflows/ci.yml/badge.svg)](https://github.com/luminariadev/raksa-webshield/actions/workflows/ci.yml)
[![Release](https://github.com/luminariadev/raksa-webshield/actions/workflows/release.yml/badge.svg)](https://github.com/luminariadev/raksa-webshield/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.24%2B-00ADD8.svg)](https://go.dev/)
[![TypeScript](https://img.shields.io/badge/typescript-5.8%2B-3178C6.svg)](https://www.typescriptlang.org/)

Polyglot web security defense toolkit combining a static **Go CLI / stdio MCP server (`raksa-webshield`)** with a zero-dependency **TypeScript sanitization and mini-WAF SDK (`@raksa/webshield`)**.

`raksa-webshield` is **Layer 3 (`web-defense`)** of the Raksa Blue Team and DevSecOps suite. It audits HTTP response headers, Content-Security-Policy (CSP), CORS policies, cookie security flags, and Nginx/Caddy configs offline or via an SSRF-protected live reader, inspects incoming request payloads against common web attack classes, outputs **Raksa Finding Schema v1** (`table`, `json`, `sarif` `2.1.0`), and integrates into Node/TypeScript web services.

---

## Key Capabilities

- **HTTP Headers, CSP, CORS & Cookie Auditor (`audit-headers` / `audit-csp`)**: Checks HSTS (`max-age >= 15768000`), Content-Security-Policy (`unsafe-inline`, `unsafe-eval`, wildcards, `data:`, `object-src 'none'`, `base-uri`), Clickjacking defenses, `nosniff`/`Referrer-Policy`/`Permissions-Policy`, server/framework banner leakage, CORS credential exposures (`WEB-101`..`102`), and `Set-Cookie` flags + `__Host-` / `__Secure-` invariants (`WEB-103`..`104`) with cookie secret values redacted from all outputs.
- **SSRF-Safe Live Header Inspection (`--url`)**: Performs a single read-only `GET` with DNS/redirect validation blocking loopback, RFC 1918 private networks, link-local metadata endpoints (`169.254.169.254`), and `.internal` hosts by default (`--allow-private` overrides explicitly when scanning local staging targets).
- **Proxy Config & Workspace Auditor (`audit-config` / `audit-workspace`)**: Parses Nginx and Caddy configs statically for legacy TLS (`SSLv2`/`SSLv3`/`TLSv1`/`TLSv1.1` without false positives on `TLSv1.2`/`TLSv1.3`), `server_tokens on`, `autoindex on`, dangerous `add_header` CORS/CSP directives, and unbounded `client_max_body_size 0`.
- **Defensive Payload Inspector (`inspect-request`)**: Normalizes multi-pass URL encoding and inspects payloads for XSS (`WEB-301`), SQL injection (`WEB-302`), Path Traversal/LFI (`WEB-303`), Prototype Pollution (`WEB-304`), and metadata SSRF (`WEB-305`).
- **Fail-Closed Policy Suppressions (`--policy`)**: Supports YAML/JSON exception files ([examples/webshield-policy.yml](examples/webshield-policy.yml)) requiring an audit reason and enforcing `expires_on` (`YYYY-MM-DD`) so expired waivers stop suppressing automatically.
- **Zero-Dependency TypeScript SDK (`sdk/ts`, `@raksa/webshield`)**: Strict allowlist `sanitizeHtml`, entity/control-char normalized `isSafeUrl`, `buildSecurityHeaders`, `inspectInput`, and `createWebShieldMiddleware` (`enforce` or `monitor` mode) emitting Raksa Schema v1 reports.
- **Native MCP Server (`raksa-webshield mcp`)**: Exposes 6 defensive tools over newline-delimited `stdio` JSON-RPC 2.0 with 1 MiB inline payload caps.

---

## Defensive Scope & Boundaries

`raksa-webshield` prioritizes deterministic static audits, strict allowlist sanitization, and low-latency heuristic screening:

- **100% Read-Only & Non-Offensive**: Does not crawl applications, brute-force paths, inject active exploit payloads over the network, or fuzz targets.
- **Allowlist Sanitizer vs. Browser DOM**: `sanitizeHtml` strips disallowed elements and executable tag blocks (`script`, `style`, `iframe`, `svg`, `math`, `object`, `embed`) using a deterministic tokenizer and URL normalizer without spinning up a headless browser DOM.
- **Defense-in-Depth Input Screening**: Heuristic mini-WAF inspection (`inspect-request` and TypeScript middleware) catches high-confidence injection vectors as an extra edge layer alongside parameterized SQL queries and context-aware escaping, not as a replacement for them.

---

## Architecture

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
               | Raksa Finding Schema v1| (Table | JSON | SARIF 2.1.0)
               +------------------------+
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

### 3. Container Image (Distroless Non-Root, 9 MB)

```bash
docker build -t raksa-webshield:v0.1.0 .
docker run --rm raksa-webshield:v0.1.0 version
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
# raksa-webshield v0.1.0 (schema 1.0, layer web-defense)

raksa-webshield rules
```

### Audit HTTP Headers, CSP, CORS & Cookies

```bash
raksa-webshield audit-headers --file testdata/headers_insecure.http --fail-on critical
```

Verified output (`exit 2`, session cookie secret redacted):

```text
raksa-webshield v0.1.0 | layer: web-defense | total: 16 (critical: 1, high: 4, medium: 6, low: 5, info: 0)
SEVERITY  RULE      MODULE     TARGET                                 TITLE
--------------------------------------------------------------------------------------------------------
HIGH      WEB-001   headers    file://testdata/headers_insecure.http  Missing or weak Strict-Transport-Security (HSTS)
          fix: Raise HSTS max-age to at least 31536000 (1 year) and include includeSubDomains.
HIGH      WEB-003   csp        file://testdata/headers_insecure.http  Unsafe Content-Security-Policy directive
          fix: Remove 'unsafe-inline', 'unsafe-eval', wildcard *, data:, and insecure http: origins from script-src; use nonces or SHA-256 hashes.
...
CRITICAL  WEB-101   cors       file://testdata/headers_insecure.http  Dangerous CORS credential exposure
          fix: Validate Origin against an exact allowlist before echoing Access-Control-Allow-Origin, never trust 'null' or '*', and omit Allow-Credentials unless strictly necessary.
HIGH      WEB-103   cookies    file://testdata/headers_insecure.http  Cookie missing Secure or HttpOnly attribute
          fix: Set Secure; HttpOnly on cookie 'sid' so it cannot traverse cleartext HTTP or be read by document.cookie.
```

### Audit Reverse-Proxy Configs (`audit-config`)

```bash
raksa-webshield audit-config --path testdata/nginx_insecure.conf --fail-on high
```

Verified output (`exit 2`):

```text
raksa-webshield v0.1.0 | layer: web-defense | total: 6 (critical: 0, high: 3, medium: 3, low: 0, info: 0)
SEVERITY  RULE      MODULE     TARGET                                 TITLE
--------------------------------------------------------------------------------------------------------
MEDIUM    WEB-202   config     file://testdata/nginx_insecure.conf    Web server version disclosure or directory listing enabled
          fix: Set 'server_tokens off;' in server configuration.
HIGH      WEB-201   config     file://testdata/nginx_insecure.conf    Deprecated TLS protocol enabled in web server config
          fix: Restrict ssl_protocols strictly to TLSv1.2 TLSv1.3.
MEDIUM    WEB-204   config     file://testdata/nginx_insecure.conf    Unbounded request body size in web server config
          fix: Set a concrete bounded size (e.g., client_max_body_size 10m;) aligned with application upload needs.
HIGH      WEB-203   config     file://testdata/nginx_insecure.conf    Reverse-proxy config emits unsafe CSP header
          fix: Remove 'unsafe-inline' and 'unsafe-eval' from static Content-Security-Policy directives.
```

### Defensive Request Payload Inspection (`inspect-request`)

```bash
raksa-webshield inspect-request --file testdata/payload_malicious.json --fail-on critical
```

Verified output (`exit 2`):

```text
raksa-webshield v0.1.0 | layer: web-defense | total: 5 (critical: 2, high: 3, medium: 0, low: 0, info: 0)
SEVERITY  RULE      MODULE     TARGET                                 TITLE
--------------------------------------------------------------------------------------------------------
HIGH      WEB-301   waf        file://testdata/payload_malicious.json Cross-Site Scripting (XSS) payload pattern detected
CRITICAL  WEB-302   waf        file://testdata/payload_malicious.json SQL Injection (SQLi) payload pattern detected
HIGH      WEB-303   waf        file://testdata/payload_malicious.json Path Traversal / Local File Inclusion sequence detected
HIGH      WEB-304   waf        file://testdata/payload_malicious.json Prototype Pollution key detected in request payload
CRITICAL  WEB-305   waf        file://testdata/payload_malicious.json SSRF or cloud metadata URI target detected
```

### TypeScript SDK Middleware & HTML Sanitizer (`@raksa/webshield`)

See [examples/express-quickstart.ts](examples/express-quickstart.ts):

```ts
import {
  buildSecurityHeaders,
  createWebShieldMiddleware,
  sanitizeHtml,
} from "@raksa/webshield";

const clean = sanitizeHtml(`<p>Hello <a href="&#x6a;avascript:alert(1)">bad</a></p>`);
// -> <p>Hello <a>bad</a></p>

const middleware = createWebShieldMiddleware({
  mode: "enforce", // or "monitor" for non-blocking telemetry
  headerOptions: { frameOptions: "DENY" },
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

`raksa-webshield mcp` exposes 6 defensive web security tools over `stdio` JSON-RPC 2.0 for MCP-compatible clients and agents:

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
- `webshield_list_rules`: List all 18 `WEB-*` rules mapped to OWASP ASVS and MITRE D3FEND.
- `webshield_audit_headers`: Audit raw header text, file dumps, or SSRF-safe live URLs (optional `allow_private`, `policy_path`).
- `webshield_audit_csp`: Evaluate a Content-Security-Policy header string cleanly.
- `webshield_audit_config`: Audit Nginx/Caddyfile reverse-proxy configurations or directories.
- `webshield_inspect_payload`: Screen request parameters or JSON text for XSS, SQLi, LFI, Prototype Pollution, and SSRF.
- `webshield_audit_workspace`: Recursively audit a full repository across web configs and header files with optional policy suppressions.

---

## Benchmarks

Measured on Windows `amd64` (`11th Gen Intel(R) Core(TM) i5-11400H @ 2.70GHz`, Go 1.26.2 `go test -bench=. -benchmem` and Node v24.18.0 `npm run bench` across 20,000 iterations):

| Benchmark | Language | Workload / Allocations | Latency / Throughput |
| :--- | :--- | :--- | :--- |
| `BenchmarkAuditHeaders-12` | Go | Full header, CSP, CORS & cookie pass (1,656 B/op, 34 allocs) | 2,992 ns/op (~334k ops/s) |
| `BenchmarkAuditCSP-12` | Go | Hardened CSP directive check (752 B/op, 13 allocs) | 910.6 ns/op (~1.10M ops/s) |
| `BenchmarkAuditConfig-12` | Go | Nginx config hardening check (736 B/op, 16 allocs) | 1,460 ns/op (~685k ops/s) |
| `BenchmarkInspectPayload-12` | Go | Multi-pass decode + 5-class WAF scan (129 B/op, 3 allocs) | 51,969 ns/op (~19.2k ops/s) |
| `ts_sanitizeHtml` | TypeScript | Strict allowlist + XSS/mXSS strip (20,000 iters, 0.2448s) | 81,694.6 ops/s |
| `ts_inspectInput` | TypeScript | JSON + multi-pass WAF inspection (20,000 iters, 0.0487s) | 410,414.7 ops/s |

---

## Rule Catalog (18 OWASP ASVS & MITRE D3FEND Rules)

| Rule ID | Severity | Module | OWASP ASVS | MITRE D3FEND | Title |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `WEB-001` | High | `headers` | 14.4.5 | `D3-HI` | Missing or weak Strict-Transport-Security (HSTS) |
| `WEB-002` | High | `headers` | 14.4.3 | `D3-HI` | Missing Content-Security-Policy header |
| `WEB-003` | High | `csp` | 14.4.3 | `D3-HI` | Unsafe Content-Security-Policy directive |
| `WEB-004` | Medium | `headers` | 14.4.4 | `D3-HI` | Missing clickjacking protection |
| `WEB-005` | Low | `headers` | 14.4.1 / 14.4.6 | `D3-HI` | Missing hardening header or server version banner disclosure |
| `WEB-101` | Critical | `cors` | 14.5.3 | `D3-NI` | Dangerous CORS credential exposure |
| `WEB-102` | Medium | `cors` | 14.5.3 | `D3-NI` | Overly permissive CORS policy |
| `WEB-103` | High | `cookies` | 3.4.1 / 3.4.2 | `D3-HI` | Cookie missing Secure or HttpOnly attribute |
| `WEB-104` | Medium | `cookies` | 3.4.3 / 3.4.4 | `D3-HI` | Weak SameSite attribute or cookie prefix violation |
| `WEB-201` | High | `config` | 9.1.2 | `D3-CH` | Deprecated TLS protocol enabled in web server config |
| `WEB-202` | Medium | `config` | 14.3.3 | `D3-CH` | Web server version disclosure or directory listing enabled |
| `WEB-203` | High | `config` | 14.4.3 | `D3-CH` | Reverse-proxy config emits unsafe CORS or CSP header |
| `WEB-204` | Medium | `config` | 13.1.4 | `D3-IV` | Unbounded request body size in web server config |
| `WEB-301` | High | `waf` | 5.3.3 | `D3-IV` | Cross-Site Scripting (XSS) payload pattern detected |
| `WEB-302` | Critical | `waf` | 5.3.4 | `D3-IV` | SQL Injection (SQLi) payload pattern detected |
| `WEB-303` | High | `waf` | 12.3.1 | `D3-IV` | Path Traversal / Local File Inclusion sequence detected |
| `WEB-304` | High | `waf` | 5.1.3 | `D3-IV` | Prototype Pollution key detected in request payload |
| `WEB-305` | Critical | `waf` | 12.6.1 | `D3-NI` | SSRF or cloud metadata URI target detected |

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
