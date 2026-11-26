package auditor

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/luminariadev/raksa-webshield/internal/schema"
)

var (
	wafXSSRegex = regexp.MustCompile(
		`(?i)(<\s*script\b|(?:javascript|vbscript)\s*:|data\s*:\s*text/html|\bon(?:error|load|click|mouseover|focus|blur|submit|animationstart)\s*=|<\s*svg\b[^>]*\bon\w+\s*=|<\s*iframe\b[^>]*\bsrcdoc\s*=)`,
	)
	wafSQLiRegex = regexp.MustCompile(
		`(?i)(\bunion\s+(?:all\s+)?select\b|(?:'\s*or\s+'?1'?\s*=\s*'?1|\bor\s+1\s*=\s*1\b|"\s*or\s+"?1"?\s*=\s*"?1)|;\s*(?:drop|delete|insert|update|alter)\s+\w+|\b(?:sleep\s*\(\s*\d+\s*\)|waitfor\s+delay)\b)`,
	)
	wafTraversalRegex = regexp.MustCompile(
		`(?i)(\.\.[/\\]|%00|\x00|/etc/passwd|/etc/shadow|windows[/\\]win\.ini)`,
	)
	wafProtoRegex = regexp.MustCompile(
		`(?i)(__proto__|constructor\s*\.\s*prototype|\[\s*["']prototype["']\s*\]|["']prototype["']\s*:)`,
	)
	wafSSRFRegex = regexp.MustCompile(
		`(?i)(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|(?:file|gopher|dict)://)`,
	)
)

func InspectPayloadFile(path string) ([]schema.Finding, error) {
	raw, err := readBoundedText(path)
	if err != nil {
		return nil, err
	}
	return InspectPayload(raw, "file://"+normalizePath(path))
}

func InspectPayload(input string, target string) ([]schema.Finding, error) {
	if len(input) > MaxConfigBytes {
		return nil, fmt.Errorf("payload exceeds %d byte limit", MaxConfigBytes)
	}
	if strings.TrimSpace(input) == "" {
		return nil, nil
	}

	views := normalizePayloadViews(input)
	now := time.Now().UTC()
	var findings []schema.Finding

	type wafCheck struct {
		ruleID      string
		severity    schema.Severity
		title       string
		description string
		remediation string
		asvs        string
		d3fend      string
		regex       *regexp.Regexp
	}

	checks := []wafCheck{
		{
			ruleID:      "WEB-301",
			severity:    schema.SeverityHigh,
			title:       "Cross-Site Scripting (XSS) payload pattern detected",
			description: "Payload contains executable script tags, inline event handlers, or dangerous URI schemes.",
			remediation: "Sanitize untrusted HTML via a strict allowlist (e.g., sanitizeHtml) and apply context-aware output encoding.",
			asvs:        "5.3.3",
			d3fend:      "D3-IV",
			regex:       wafXSSRegex,
		},
		{
			ruleID:      "WEB-302",
			severity:    schema.SeverityCritical,
			title:       "SQL Injection (SQLi) payload pattern detected",
			description: "Payload contains SQL UNION, boolean tautology, stacked statement, or timing-delay injection syntax.",
			remediation: "Use parameterized prepared statements strictly and reject malformed query strings.",
			asvs:        "5.3.4",
			d3fend:      "D3-IV",
			regex:       wafSQLiRegex,
		},
		{
			ruleID:      "WEB-303",
			severity:    schema.SeverityHigh,
			title:       "Path Traversal / Local File Inclusion sequence detected",
			description: "Payload contains parent-directory traversal, null-byte truncation, or sensitive OS file targets.",
			remediation: "Resolve filesystem paths with filepath.Base or verify canonical paths remain strictly inside the permitted base directory.",
			asvs:        "12.3.1",
			d3fend:      "D3-IV",
			regex:       wafTraversalRegex,
		},
		{
			ruleID:      "WEB-304",
			severity:    schema.SeverityHigh,
			title:       "Prototype Pollution key detected in request payload",
			description: "Payload attempts to mutate JavaScript object prototypes via __proto__ or constructor.prototype.",
			remediation: "Strip __proto__, constructor, and prototype keys when merging JSON objects or use Object.create(null).",
			asvs:        "5.1.3",
			d3fend:      "D3-IV",
			regex:       wafProtoRegex,
		},
		{
			ruleID:      "WEB-305",
			severity:    schema.SeverityCritical,
			title:       "SSRF or cloud metadata URI target detected",
			description: "Payload references cloud metadata IPs or dangerous non-HTTP schemes (file://, gopher://, dict://).",
			remediation: "Allowlist outbound target hosts and block link-local, loopback, and RFC 1918 IP ranges before dialing.",
			asvs:        "12.6.1",
			d3fend:      "D3-NI",
			regex:       wafSSRFRegex,
		},
	}

	for _, chk := range checks {
		if matched := matchAnyView(views, chk.regex); matched != "" {
			findings = append(findings, newFinding(
				chk.ruleID, "waf", chk.severity,
				chk.title,
				chk.description,
				target,
				map[string]any{
					"matched_sample": truncateSample(matched, 80),
					"owasp_asvs":     chk.asvs,
				},
				chk.remediation,
				chk.d3fend,
				strings.ToLower(chk.ruleID)+"-payload",
				now,
			))
		}
	}

	return findings, nil
}

func normalizePayloadViews(raw string) []string {
	views := []string{raw}
	cur := raw
	for pass := 0; pass < 2; pass++ {
		decoded, err := url.QueryUnescape(cur)
		if err != nil {
			// Also decode raw %XX sequences even when lone '%' exists elsewhere.
			decoded = pathUnescapeFallback(cur)
		}
		if decoded == cur {
			break
		}
		views = append(views, decoded)
		cur = decoded
	}
	return views
}

func pathUnescapeFallback(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if hi, ok1 := hexVal(s[i+1]); ok1 {
				if lo, ok2 := hexVal(s[i+2]); ok2 {
					b.WriteByte((hi << 4) | lo)
					i += 2
					continue
				}
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

func matchAnyView(views []string, re *regexp.Regexp) string {
	for _, v := range views {
		if loc := re.FindString(v); loc != "" {
			return loc
		}
	}
	return ""
}

func truncateSample(s string, maxLen int) string {
	clean := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(clean) <= maxLen {
		return clean
	}
	return clean[:maxLen] + "..."
}
