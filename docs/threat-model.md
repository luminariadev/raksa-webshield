# raksa-webshield Threat Model

## Defensive Scope

`raksa-webshield` helps web engineers, DevSecOps pipelines, and security agents harden HTTP edges, validate CSP/CORS/cookie postures, sanitize untrusted HTML fragments, and inspect suspicious request payloads defensively.

### In Scope
- Offline and single-request read-only auditing of HTTP response headers (`HSTS`, `CSP`, `X-Frame-Options`, CORS, `Set-Cookie`).
- Static auditing of Nginx and reverse-proxy configuration files.
- Defensive payload inspection and runtime Node/TypeScript middleware protection against XSS, SQLi, path traversal, prototype pollution, and metadata SSRF.
- Strict allowlist HTML sanitization in `@raksa/webshield` to neutralize DOM XSS and attribute/protocol smuggling vectors.

### Out of Scope (Non-Goals)
- **Active Exploitation or Fuzzing**: `raksa-webshield` does not crawl sites, inject payloads over the network, brute-force endpoints, or run offensive vulnerability scanning.
- **Full Browser DOM Execution**: `sanitizeHtml` uses a strict static tokenizer and allowlist rather than spawning headless browsers or executing scripts. Complex browser-specific parser quirks outside allowed safe tags are rejected rather than repaired heuristically.
- **Signature WAF Completeness**: Heuristic inspection catches common high-risk injection patterns as an application defense-in-depth layer alongside parameterized queries and context-aware output encoding, not as a substitute for them.

## Security Guarantees & Trust Boundaries

1. **SSRF Protection on Live Audits (`ValidateLiveURL`)**:
   - `audit-headers --url` (and MCP `webshield_audit_headers`) rejects non-HTTP(S) schemes and blocks loopback (`127.0.0.0/8`, `::1`), RFC 1918 private networks, link-local (`169.254.0.0/16`), and unique-local IPv6 targets via DNS resolution before opening connections, unless an operator explicitly passes `--allow-private` / `allow_private: true`.
   - Redirect chains are re-validated per hop (max 3 hops), response bodies are bounded and discarded (`io.LimitReader(4096)`), and request timeouts are strictly enforced (10s).
2. **Bounded Input Sizes**:
   - Config files, header dumps, payloads, policy manifests, and MCP inline arguments enforce a 1 MiB (`1048576` byte) ceiling; JSON-RPC `stdio` lines cap at 2 MiB; runtime middleware `maxBodyBytes` defaults safely.
3. **Fail-Closed Policy Suppressions**:
   - Policy entries require a non-empty `reason`. Expired `expires_on` dates (`< today`) automatically stop suppressing findings.
4. **Sanitizer Normalization Before Checks**:
   - `sanitizeHtml` strips disallowed tags along with inner content of executable elements (`script`, `style`, `iframe`, `svg`, `math`, `object`, `embed`, `template`, `noscript`), strips `on*` event attributes, decodes HTML character entities, and strips control/whitespace characters before validating URL schemes (`https:`, `http:`, `mailto:`, `/`, `#`).
5. **Terminal Safety**:
   - `table` rendering sanitizes ANSI CSI/OSC escape sequences and control characters before printing untrusted HTTP header values or targets.
