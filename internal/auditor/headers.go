package auditor

import (
	"bufio"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/luminariadev/raksa-webshield/internal/schema"
)

const minHSTSMaxAgeSeconds = 15768000 // 180 days (OWASP ASVS 14.4.5 guidance)

var versionBannerRegex = regexp.MustCompile(`/\d+(\.\d+)+`)

func ParseRawHeaders(raw string) (http.Header, error) {
	if len(raw) > MaxConfigBytes {
		return nil, fmt.Errorf("header input exceeds %d byte limit", MaxConfigBytes)
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("header input is empty")
	}

	hdr := make(http.Header)
	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 16*1024), 256*1024)

	seenHeaders := false
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			if seenHeaders {
				break
			}
			continue
		}
		if !seenHeaders && strings.HasPrefix(strings.ToUpper(strings.TrimSpace(line)), "HTTP/") {
			continue
		}
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			return nil, fmt.Errorf("invalid header line %q: expected 'Name: Value'", line)
		}
		name := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		hdr.Add(name, val)
		seenHeaders = true
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan headers: %w", err)
	}
	if !seenHeaders {
		return nil, fmt.Errorf("no valid HTTP headers found")
	}
	return hdr, nil
}

func AuditHeadersFile(path string) ([]schema.Finding, error) {
	raw, err := readBoundedText(path)
	if err != nil {
		return nil, err
	}
	hdr, err := ParseRawHeaders(raw)
	if err != nil {
		return nil, fmt.Errorf("parse headers in %q: %w", path, err)
	}
	return AuditHeaders(hdr, "file://"+normalizePath(path)), nil
}

func AuditHeaders(hdr http.Header, target string) []schema.Finding {
	return AuditHeadersWithProbe(hdr, target, "")
}

func AuditHeadersWithProbe(hdr http.Header, target string, probeOrigin string) []schema.Finding {
	now := time.Now().UTC()
	var findings []schema.Finding

	// WEB-001: Strict-Transport-Security
	hsts := strings.TrimSpace(hdr.Get("Strict-Transport-Security"))
	if hsts == "" {
		findings = append(findings, newFinding(
			"WEB-001", "headers", schema.SeverityHigh,
			"Missing or weak Strict-Transport-Security (HSTS)",
			"Response omits Strict-Transport-Security header, leaving clients exposed to downgrade/SSL-stripping.",
			target,
			map[string]any{"header": "Strict-Transport-Security", "observed": "<missing>", "owasp_asvs": "14.4.5"},
			"Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload on all HTTPS responses.",
			"D3-HI", "missing-hsts", now,
		))
	} else {
		age, ok := parseHSTSMaxAge(hsts)
		if !ok || age < minHSTSMaxAgeSeconds {
			findings = append(findings, newFinding(
				"WEB-001", "headers", schema.SeverityHigh,
				"Missing or weak Strict-Transport-Security (HSTS)",
				fmt.Sprintf("Strict-Transport-Security max-age (%d) is missing or below minimum 15768000 seconds.", age),
				target,
				map[string]any{"header": "Strict-Transport-Security", "observed": hsts, "max_age": age, "owasp_asvs": "14.4.5"},
				"Raise HSTS max-age to at least 31536000 (1 year) and include includeSubDomains.",
				"D3-HI", "weak-hsts", now,
			))
		}
	}

	// WEB-002 + WEB-003: Content-Security-Policy
	csps := hdr.Values("Content-Security-Policy")
	hasFrameAncestors := false
	if len(csps) == 0 {
		findings = append(findings, newFinding(
			"WEB-002", "headers", schema.SeverityHigh,
			"Missing Content-Security-Policy header",
			"Response does not declare Content-Security-Policy to constrain script, style, and frame origins.",
			target,
			map[string]any{"header": "Content-Security-Policy", "owasp_asvs": "14.4.3"},
			"Set a strict Content-Security-Policy (e.g., default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none').",
			"D3-HI", "missing-csp", now,
		))
	} else {
		for _, p := range csps {
			directives := ParseCSP(p)
			if _, ok := directives["frame-ancestors"]; ok {
				hasFrameAncestors = true
			}
			findings = append(findings, AuditCSP(p, target)...)
		}
	}

	// WEB-004: Clickjacking defense
	xfo := strings.ToUpper(strings.TrimSpace(hdr.Get("X-Frame-Options")))
	validXFO := xfo == "DENY" || xfo == "SAMEORIGIN"
	if !hasFrameAncestors && !validXFO {
		findings = append(findings, newFinding(
			"WEB-004", "headers", schema.SeverityMedium,
			"Missing clickjacking protection",
			"Neither CSP frame-ancestors nor X-Frame-Options (DENY/SAMEORIGIN) is configured.",
			target,
			map[string]any{"x_frame_options": hdr.Get("X-Frame-Options"), "owasp_asvs": "14.4.4"},
			"Add frame-ancestors 'none' (or 'self') to Content-Security-Policy and set X-Frame-Options: DENY.",
			"D3-HI", "missing-clickjacking-guard", now,
		))
	}

	// WEB-005: Hardening headers & version banners
	if !strings.EqualFold(strings.TrimSpace(hdr.Get("X-Content-Type-Options")), "nosniff") {
		findings = append(findings, newFinding(
			"WEB-005", "headers", schema.SeverityLow,
			"Missing X-Content-Type-Options: nosniff",
			"Response omits X-Content-Type-Options: nosniff, allowing MIME type sniffing on legacy clients.",
			target,
			map[string]any{"header": "X-Content-Type-Options", "observed": hdr.Get("X-Content-Type-Options")},
			"Set X-Content-Type-Options: nosniff on all HTTP responses.",
			"D3-HI", "missing-nosniff", now,
		))
	}
	if strings.TrimSpace(hdr.Get("Referrer-Policy")) == "" {
		findings = append(findings, newFinding(
			"WEB-005", "headers", schema.SeverityLow,
			"Missing Referrer-Policy header",
			"Response does not specify Referrer-Policy, risking leakage of URL path/query parameters to external origins.",
			target,
			map[string]any{"header": "Referrer-Policy"},
			"Set Referrer-Policy: strict-origin-when-cross-origin or no-referrer.",
			"D3-HI", "missing-referrer-policy", now,
		))
	}
	if strings.TrimSpace(hdr.Get("Permissions-Policy")) == "" {
		findings = append(findings, newFinding(
			"WEB-005", "headers", schema.SeverityLow,
			"Missing Permissions-Policy header",
			"Response does not restrict powerful browser features via Permissions-Policy.",
			target,
			map[string]any{"header": "Permissions-Policy"},
			"Set Permissions-Policy (e.g., geolocation=(), microphone=(), camera=()).",
			"D3-HI", "missing-permissions-policy", now,
		))
	}
	if srv := strings.TrimSpace(hdr.Get("Server")); srv != "" && versionBannerRegex.MatchString(srv) {
		findings = append(findings, newFinding(
			"WEB-005", "headers", schema.SeverityLow,
			"Server header discloses exact software version",
			fmt.Sprintf("Server header reveals version metadata (%q), aiding targeted fingerprinting.", srv),
			target,
			map[string]any{"header": "Server", "observed": srv},
			"Strip detailed version numbers from Server headers (e.g., server_tokens off in Nginx).",
			"D3-HI", "banner-server", now,
		))
	}
	if powered := strings.TrimSpace(hdr.Get("X-Powered-By")); powered != "" {
		findings = append(findings, newFinding(
			"WEB-005", "headers", schema.SeverityLow,
			"X-Powered-By header discloses framework metadata",
			fmt.Sprintf("X-Powered-By header reveals runtime stack (%q).", powered),
			target,
			map[string]any{"header": "X-Powered-By", "observed": powered},
			"Disable X-Powered-By header emission (e.g., app.disable('x-powered-by') in Express).",
			"D3-HI", "banner-powered-by", now,
		))
	}

	// WEB-007: Modern Cross-Origin Isolation headers and authenticated Cache-Control
	coop := strings.ToLower(strings.TrimSpace(hdr.Get("Cross-Origin-Opener-Policy")))
	if coop != "same-origin" && coop != "same-origin-allow-popups" {
		findings = append(findings, newFinding(
			"WEB-007", "headers", schema.SeverityLow,
			"Missing Cross-Origin-Opener-Policy header",
			"Response omits Cross-Origin-Opener-Policy: same-origin, leaving browsing context windows exposed to XS-Leaks.",
			target,
			map[string]any{"header": "Cross-Origin-Opener-Policy", "observed": hdr.Get("Cross-Origin-Opener-Policy"), "owasp_asvs": "14.4.7"},
			"Set Cross-Origin-Opener-Policy: same-origin on top-level document responses.",
			"D3-HI", "missing-coop", now,
		))
	}

	corp := strings.ToLower(strings.TrimSpace(hdr.Get("Cross-Origin-Resource-Policy")))
	if corp != "same-origin" && corp != "same-site" && corp != "cross-origin" {
		findings = append(findings, newFinding(
			"WEB-007", "headers", schema.SeverityLow,
			"Missing Cross-Origin-Resource-Policy header",
			"Response omits Cross-Origin-Resource-Policy to protect resources from unintended cross-origin reads.",
			target,
			map[string]any{"header": "Cross-Origin-Resource-Policy", "observed": hdr.Get("Cross-Origin-Resource-Policy"), "owasp_asvs": "14.4.7"},
			"Set Cross-Origin-Resource-Policy: same-origin (or same-site) on application responses.",
			"D3-HI", "missing-corp", now,
		))
	}

	if len(hdr.Values("Set-Cookie")) > 0 {
		cc := hdr.Get("Cache-Control")
		if !hasCacheControlGuard(cc) {
			findings = append(findings, newFinding(
				"WEB-007", "headers", schema.SeverityLow,
				"Authenticated Set-Cookie response lacks Cache-Control: no-store",
				"Response issues cookies without Cache-Control: no-store or private, risking shared proxy/browser caching.",
				target,
				map[string]any{"header": "Cache-Control", "observed": cc, "owasp_asvs": "8.2.1"},
				"Set Cache-Control: no-store on responses issuing or mutating session cookies.",
				"D3-HI", "missing-cache-control-no-store", now,
			))
		}
	}

	findings = append(findings, AuditCORS(hdr, target, probeOrigin)...)
	findings = append(findings, AuditCookies(hdr, target)...)
	return findings
}

func hasCacheControlGuard(raw string) bool {
	if strings.TrimSpace(raw) == "" {
		return false
	}
	for _, tok := range strings.Split(raw, ",") {
		t := strings.ToLower(strings.TrimSpace(tok))
		if t == "no-store" || t == "private" {
			return true
		}
	}
	return false
}

func parseHSTSMaxAge(val string) (int, bool) {
	for _, part := range strings.Split(val, ";") {
		tok := strings.TrimSpace(part)
		low := strings.ToLower(tok)
		if strings.HasPrefix(low, "max-age=") {
			numStr := strings.Trim(strings.TrimPrefix(low, "max-age="), `"' `)
			n, err := strconv.Atoi(numStr)
			if err != nil || n < 0 {
				return 0, false
			}
			return n, true
		}
	}
	return 0, false
}

func newFinding(
	ruleID string,
	module string,
	severity schema.Severity,
	title string,
	description string,
	target string,
	evidence map[string]any,
	remediation string,
	d3fend string,
	idSuffix string,
	ts time.Time,
) schema.Finding {
	return schema.Finding{
		ID:          fmt.Sprintf("%s-%s", strings.ToLower(ruleID), schema.SanitizeIDPart(idSuffix)),
		RuleID:      ruleID,
		Module:      module,
		Layer:       schema.LayerWeb,
		Severity:    severity,
		Title:       title,
		Description: description,
		Target:      target,
		Evidence:    evidence,
		Remediation: remediation,
		MitreD3FEND: d3fend,
		Timestamp:   ts,
	}
}
