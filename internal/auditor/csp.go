package auditor

import (
	"fmt"
	"strings"
	"time"

	"github.com/luminariadev/raksa-webshield/internal/schema"
)

func ParseCSP(policyStr string) map[string][]string {
	directives := make(map[string][]string)
	for _, seg := range strings.Split(policyStr, ";") {
		fields := strings.Fields(strings.TrimSpace(seg))
		if len(fields) == 0 {
			continue
		}
		name := strings.ToLower(fields[0])
		if _, exists := directives[name]; exists {
			// Browsers ignore duplicate CSP directives after the first occurrence.
			continue
		}
		vals := make([]string, 0, len(fields)-1)
		for _, tok := range fields[1:] {
			vals = append(vals, strings.ToLower(tok))
		}
		directives[name] = vals
	}
	return directives
}

func AuditCSPFile(path string) ([]schema.Finding, error) {
	raw, err := readBoundedText(path)
	if err != nil {
		return nil, err
	}
	return AuditCSP(raw, "file://"+normalizePath(path)), nil
}

func AuditCSP(policyStr string, target string) []schema.Finding {
	now := time.Now().UTC()
	directives := ParseCSP(policyStr)
	var findings []schema.Finding

	scriptDir := "script-src-elem"
	scriptVals, hasScript := directives["script-src-elem"]
	if !hasScript {
		scriptDir = "script-src"
		scriptVals, hasScript = directives["script-src"]
	}
	if !hasScript {
		scriptDir = "default-src"
		scriptVals = directives["default-src"]
	}

	unsafeTokens := findUnsafeCSPSources(scriptVals)
	if scriptDir == "script-src-elem" {
		if fallbackScript, ok := directives["script-src"]; ok {
			for _, tok := range findUnsafeCSPSources(fallbackScript) {
				if (tok == "'unsafe-eval'" || tok == "'wasm-unsafe-eval'") && !containsToken(unsafeTokens, tok) {
					unsafeTokens = append(unsafeTokens, tok)
				}
			}
		}
	}
	if len(unsafeTokens) > 0 {
		findings = append(findings, newFinding(
			"WEB-003", "csp", schema.SeverityHigh,
			"Unsafe Content-Security-Policy directive",
			fmt.Sprintf("CSP %s permits risky execution sources (%s).", scriptDir, strings.Join(unsafeTokens, ", ")),
			target,
			map[string]any{
				"directive":      scriptDir,
				"unsafe_sources": unsafeTokens,
				"owasp_asvs":     "14.4.3",
			},
			"Remove 'unsafe-inline', 'unsafe-eval', wildcard *, data:, blob:, and insecure http: origins from script-src; use nonces or SHA-256 hashes.",
			"D3-HI", "unsafe-"+scriptDir, now,
		))
	}

	if !containsToken(scriptVals, "'strict-dynamic'") {
		bypassHosts := findCSPBypassHosts(scriptVals)
		if len(bypassHosts) > 0 {
			findings = append(findings, newFinding(
				"WEB-006", "csp", schema.SeverityMedium,
				"CSP permits known JSONP/CDN bypass hosts",
				fmt.Sprintf("CSP %s allows hosts known to host JSONP/gadget bypasses without 'strict-dynamic' (%s).", scriptDir, strings.Join(bypassHosts, ", ")),
				target,
				map[string]any{
					"directive":    scriptDir,
					"bypass_hosts": bypassHosts,
					"owasp_asvs":   "14.4.3",
				},
				"Adopt nonces or SHA-256 hashes paired with 'strict-dynamic', or replace broad public CDN hosts with vetted self-hosted bundles.",
				"D3-HI", "csp-bypass-hosts", now,
			))
		}
	}

	if hasScript {
		if defVals, hasDef := directives["default-src"]; hasDef {
			for _, tok := range defVals {
				if tok == "*" {
					findings = append(findings, newFinding(
						"WEB-003", "csp", schema.SeverityMedium,
						"Wildcard default-src in Content-Security-Policy",
						"CSP default-src uses wildcard '*' fallback for styles, fonts, images, and fetch origins.",
						target,
						map[string]any{"directive": "default-src", "token": "*", "owasp_asvs": "14.4.3"},
						"Restrict default-src to 'self' or 'none' and explicitly allowlist required origins per directive.",
						"D3-HI", "wildcard-default-src", now,
					))
					break
				}
			}
		}
	}

	defaultNone := containsToken(directives["default-src"], "'none'")
	if objVals, hasObj := directives["object-src"]; hasObj {
		if !containsToken(objVals, "'none'") {
			findings = append(findings, newFinding(
				"WEB-003", "csp", schema.SeverityMedium,
				"CSP object-src not restricted to 'none'",
				"CSP object-src allows legacy plugin/object embedding instead of 'none'.",
				target,
				map[string]any{"directive": "object-src", "values": objVals, "owasp_asvs": "14.4.3"},
				"Set object-src 'none' in Content-Security-Policy.",
				"D3-HI", "object-src", now,
			))
		}
	} else if !defaultNone {
		findings = append(findings, newFinding(
			"WEB-003", "csp", schema.SeverityMedium,
			"CSP missing object-src 'none'",
			"CSP omits object-src 'none', allowing fallback plugin/object loads unless default-src is 'none'.",
			target,
			map[string]any{"directive": "object-src", "owasp_asvs": "14.4.3"},
			"Explicitly set object-src 'none' in Content-Security-Policy.",
			"D3-HI", "missing-object-src", now,
		))
	}

	if _, hasBase := directives["base-uri"]; !hasBase {
		findings = append(findings, newFinding(
			"WEB-003", "csp", schema.SeverityMedium,
			"CSP missing base-uri restriction",
			"CSP omits base-uri, allowing injected <base href> tags to hijack relative script or link paths.",
			target,
			map[string]any{"directive": "base-uri", "owasp_asvs": "14.4.3"},
			"Add base-uri 'self' (or 'none') to Content-Security-Policy.",
			"D3-HI", "missing-base-uri", now,
		))
	}

	if _, hasForm := directives["form-action"]; !hasForm {
		findings = append(findings, newFinding(
			"WEB-006", "csp", schema.SeverityMedium,
			"CSP missing form-action restriction",
			"CSP omits form-action, allowing injected or dangling HTML forms to exfiltrate credentials to external origins.",
			target,
			map[string]any{"directive": "form-action", "owasp_asvs": "14.4.3"},
			"Add form-action 'self' (or explicit trusted submission endpoints) to Content-Security-Policy.",
			"D3-HI", "missing-form-action", now,
		))
	}

	return findings
}

var knownBypassHosts = []string{
	"ajax.googleapis.com",
	"googleapis.com",
	"cdnjs.cloudflare.com",
	"cdn.jsdelivr.net",
	"unpkg.com",
	"raw.githubusercontent.com",
	"accounts.google.com",
	"gstatic.com",
	"cloudfront.net",
}

func hasNonceOrHash(tokens []string) bool {
	for _, tok := range tokens {
		if strings.HasSuffix(tok, "'") && (strings.HasPrefix(tok, "'nonce-") ||
			strings.HasPrefix(tok, "'sha256-") ||
			strings.HasPrefix(tok, "'sha384-") ||
			strings.HasPrefix(tok, "'sha512-")) {
			return true
		}
	}
	return false
}

func extractCSPHost(token string) string {
	t := strings.TrimSpace(strings.ToLower(token))
	if t == "" || strings.HasPrefix(t, "'") {
		return ""
	}
	if strings.HasPrefix(t, "https://") {
		t = strings.TrimPrefix(t, "https://")
	} else if strings.HasPrefix(t, "http://") {
		t = strings.TrimPrefix(t, "http://")
	} else if strings.HasPrefix(t, "//") {
		t = strings.TrimPrefix(t, "//")
	} else if strings.Contains(t, ":") && !strings.Contains(t, "/") {
		// Ignore schemes like data:, blob:, filesystem:
		if strings.HasSuffix(t, ":") {
			return ""
		}
	}
	if slash := strings.IndexByte(t, '/'); slash >= 0 {
		t = t[:slash]
	}
	if colon := strings.IndexByte(t, ':'); colon >= 0 {
		t = t[:colon]
	}
	t = strings.TrimPrefix(t, "*.")
	return strings.TrimSuffix(t, ".")
}

func findCSPBypassHosts(tokens []string) []string {
	var hits []string
	seen := make(map[string]struct{})
	for _, tok := range tokens {
		host := extractCSPHost(tok)
		if host == "" {
			continue
		}
		for _, bad := range knownBypassHosts {
			if host == bad || strings.HasSuffix(host, "."+bad) {
				if _, ok := seen[host]; !ok {
					seen[host] = struct{}{}
					hits = append(hits, host)
				}
				break
			}
		}
	}
	return hits
}

func findUnsafeCSPSources(tokens []string) []string {
	var unsafe []string
	seen := make(map[string]struct{})
	ignoreUnsafeInline := hasNonceOrHash(tokens)
	for _, tok := range tokens {
		if tok == "'unsafe-inline'" && ignoreUnsafeInline {
			continue
		}
		isRisky := tok == "'unsafe-inline'" ||
			tok == "'unsafe-eval'" ||
			tok == "'wasm-unsafe-eval'" ||
			tok == "*" ||
			tok == "data:" ||
			tok == "blob:" ||
			tok == "filesystem:" ||
			strings.HasPrefix(tok, "http:") ||
			strings.HasPrefix(tok, "*.")
		if isRisky {
			if _, ok := seen[tok]; !ok {
				seen[tok] = struct{}{}
				unsafe = append(unsafe, tok)
			}
		}
	}
	return unsafe
}

func containsToken(tokens []string, needle string) bool {
	for _, t := range tokens {
		if t == needle {
			return true
		}
	}
	return false
}
