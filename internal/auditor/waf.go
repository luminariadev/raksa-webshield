package auditor

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/luminariadev/raksa-webshield/internal/schema"
)

type InspectOptions struct {
	ParanoiaLevel    int
	AnomalyThreshold int
}

type wafCheck struct {
	ruleID      string
	severity    schema.Severity
	weight      int
	title       string
	description string
	remediation string
	asvs        string
	d3fend      string
	idSuffix    string
	regex       *regexp.Regexp
	pl2Regex    *regexp.Regexp
	prefilter   func(low string) bool
}

var (
	wafXSSRegex = regexp.MustCompile(
		`(?i)(<\s*script\b|(?:javascript|vbscript)\s*:|data\s*:\s*text/html|\bon(?:error|load|click|mouseover|focus|blur|submit|animationstart)\s*=|<\s*svg\b[^>]*\bon\w+\s*=|<\s*iframe\b[^>]*\bsrcdoc\s*=)`,
	)
	wafXSSPL2Regex = regexp.MustCompile(
		`(?i)<\s*[a-z][a-z0-9-]*\b[^>]*\bon[a-z]+\s*=`,
	)
	wafSQLiRegex = regexp.MustCompile(
		`(?i)(\bunion\s+(?:all\s+)?select\b|(?:'\s*or\s+'?1'?\s*=\s*'?1|\bor\s+1\s*=\s*1\b|"\s*or\s+"?1"?\s*=\s*"?1)|;\s*(?:drop|delete|insert|update|alter)\s+\w+|\b(?:sleep\s*\(\s*\d+\s*\)|waitfor\s+delay)\b)`,
	)
	wafSQLiPL2Regex = regexp.MustCompile(
		`(?i)(?:['"]\s*;\s*--|\bselect\b.+\bfrom\b.+\bwhere\b)`,
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
	wafCmdIRegex = regexp.MustCompile(
		"(?i)(?:[;&|`]\\s*(?:cat|ls|id|whoami|uname|pwd|nc|ncat|curl|wget|bash|sh|zsh|powershell|cmd(?:\\.exe)?|python[23]?|perl|ruby|php|chmod|chown|rm|kill)\\b|\\$\\([^)]+\\)|`[^`]+`)",
	)
	wafSSTIRegex = regexp.MustCompile(
		`(?i)(\$\{jndi:|{{\s*(?:\d+\s*[*+\-/]\s*\d+|[^}]*(?:__class__|__subclasses__|__globals__|__builtins__|config\.items))\s*}}|<%=\s*[^%]+%>)`,
	)
	wafNoSQLRegex = regexp.MustCompile(
		`(?i)(?:["']\$(?:ne|gt|gte|lt|lte|where|regex|expr|nin|in)\\?["']\s*:|\[\s*\$(?:ne|gt|gte|lt|lte|where|regex|nin|in)\s*\])`,
	)
	wafXXERegex = regexp.MustCompile(
		`(?i)(<!doctype\b[^>]*\[|<!entity\b[^>]*\b(?:system|public)\b)`,
	)
	wafCRLFRegex = regexp.MustCompile(
		`(?i)(?:\r\n|%0d%0a|\\r\\n)\s*(?:set-cookie|location|content-length|transfer-encoding|http/1\.)`,
	)
	wafSQLCommentRe  = regexp.MustCompile(`/\*[^*]*\*+(?:[^/*][^*]*\*+)*/`)
	wafUnicodeHexRe  = regexp.MustCompile(`\\u00([0-9a-fA-F]{2})`)
	wafHTMLEntityDec = regexp.MustCompile(`&#(\d{2,3});`)
	wafHTMLEntityHex = regexp.MustCompile(`(?i)&#x([0-9a-f]{2});`)
)

var wafChecks = []wafCheck{
	{
		ruleID:      "WEB-301",
		severity:    schema.SeverityHigh,
		weight:      4,
		title:       "Cross-Site Scripting (XSS) payload pattern detected",
		description: "Payload contains executable script tags, inline event handlers, or dangerous URI schemes.",
		remediation: "Sanitize untrusted HTML via a strict allowlist (e.g., sanitizeHtml) and apply context-aware output encoding.",
		asvs:        "5.3.3",
		d3fend:      "D3-IV",
		idSuffix:    "web-301-payload",
		regex:       wafXSSRegex,
		pl2Regex:    wafXSSPL2Regex,
		prefilter: func(low string) bool {
			return strings.IndexByte(low, '<') >= 0 ||
				(strings.IndexByte(low, '=') >= 0 && strings.Contains(low, "on")) ||
				strings.Contains(low, "javascript") ||
				strings.Contains(low, "vbscript") ||
				strings.Contains(low, "text/html")
		},
	},
	{
		ruleID:      "WEB-302",
		severity:    schema.SeverityCritical,
		weight:      5,
		title:       "SQL Injection (SQLi) payload pattern detected",
		description: "Payload contains SQL UNION, boolean tautology, stacked statement, or timing-delay injection syntax.",
		remediation: "Use parameterized prepared statements strictly and reject malformed query strings.",
		asvs:        "5.3.4",
		d3fend:      "D3-IV",
		idSuffix:    "web-302-payload",
		regex:       wafSQLiRegex,
		pl2Regex:    wafSQLiPL2Regex,
		prefilter: func(low string) bool {
			return strings.Contains(low, "union") ||
				(strings.IndexByte(low, '=') >= 0 && (strings.Contains(low, "or ") || strings.Contains(low, "or\t") || strings.Contains(low, "or\n") || strings.Contains(low, "or\r"))) ||
				strings.IndexByte(low, ';') >= 0 ||
				strings.Contains(low, "sleep") ||
				strings.Contains(low, "waitfor") ||
				strings.Contains(low, "select")
		},
	},
	{
		ruleID:      "WEB-303",
		severity:    schema.SeverityHigh,
		weight:      4,
		title:       "Path Traversal / Local File Inclusion sequence detected",
		description: "Payload contains parent-directory traversal, null-byte truncation, or sensitive OS file targets.",
		remediation: "Resolve filesystem paths with filepath.Base or verify canonical paths remain strictly inside the permitted base directory.",
		asvs:        "12.3.1",
		d3fend:      "D3-IV",
		idSuffix:    "web-303-payload",
		regex:       wafTraversalRegex,
		prefilter: func(low string) bool {
			return strings.Contains(low, "..") ||
				strings.IndexByte(low, 0) >= 0 ||
				strings.Contains(low, "%00") ||
				strings.Contains(low, "/etc/") ||
				strings.Contains(low, "win.ini")
		},
	},
	{
		ruleID:      "WEB-304",
		severity:    schema.SeverityHigh,
		weight:      4,
		title:       "Prototype Pollution key detected in request payload",
		description: "Payload attempts to mutate JavaScript object prototypes via __proto__ or constructor.prototype.",
		remediation: "Strip __proto__, constructor, and prototype keys when merging JSON objects or use Object.create(null).",
		asvs:        "5.1.3",
		d3fend:      "D3-IV",
		idSuffix:    "web-304-payload",
		regex:       wafProtoRegex,
		prefilter: func(low string) bool {
			return strings.Contains(low, "__proto__") || strings.Contains(low, "prototype")
		},
	},
	{
		ruleID:      "WEB-305",
		severity:    schema.SeverityCritical,
		weight:      5,
		title:       "SSRF or cloud metadata URI target detected",
		description: "Payload references cloud metadata IPs or dangerous non-HTTP schemes (file://, gopher://, dict://).",
		remediation: "Allowlist outbound target hosts and block link-local, loopback, and RFC 1918 IP ranges before dialing.",
		asvs:        "12.6.1",
		d3fend:      "D3-NI",
		idSuffix:    "web-305-payload",
		regex:       wafSSRFRegex,
		prefilter: func(low string) bool {
			return strings.Contains(low, "169.254.") ||
				strings.Contains(low, "metadata.google") ||
				strings.Contains(low, "100.100.") ||
				strings.Contains(low, "file://") ||
				strings.Contains(low, "gopher://") ||
				strings.Contains(low, "dict://")
		},
	},
	{
		ruleID:      "WEB-306",
		severity:    schema.SeverityCritical,
		weight:      5,
		title:       "OS Command Injection / Remote Code Execution payload pattern detected",
		description: "Payload contains shell command separators, subshells, or backtick execution syntax.",
		remediation: "Pass arguments to exec.Command directly without a shell interpreter and strictly allowlist command arguments.",
		asvs:        "5.3.8",
		d3fend:      "D3-IV",
		idSuffix:    "web-306-payload",
		regex:       wafCmdIRegex,
		prefilter: func(low string) bool {
			return strings.IndexAny(low, ";|&$`") >= 0
		},
	},
	{
		ruleID:      "WEB-307",
		severity:    schema.SeverityCritical,
		weight:      5,
		title:       "Server-Side Template Injection (SSTI) or JNDI lookup pattern detected",
		description: "Payload contains template engine evaluation expressions or JNDI remote class-loading lookups.",
		remediation: "Disable server-side evaluation of user strings in templates and block JNDI lookups.",
		asvs:        "5.2.5",
		d3fend:      "D3-IV",
		idSuffix:    "web-307-payload",
		regex:       wafSSTIRegex,
		prefilter: func(low string) bool {
			return strings.Contains(low, "${jndi:") ||
				strings.Contains(low, "{{") ||
				strings.Contains(low, "<%=")
		},
	},
	{
		ruleID:      "WEB-308",
		severity:    schema.SeverityHigh,
		weight:      4,
		title:       "NoSQL operator injection pattern detected",
		description: "Payload contains MongoDB/NoSQL operator keys such as $ne, $gt, $where, or $regex.",
		remediation: "Validate scalar field types explicitly and reject object keys starting with '$'.",
		asvs:        "5.3.5",
		d3fend:      "D3-IV",
		idSuffix:    "web-308-payload",
		regex:       wafNoSQLRegex,
		prefilter: func(low string) bool {
			return strings.IndexByte(low, '$') >= 0
		},
	},
	{
		ruleID:      "WEB-309",
		severity:    schema.SeverityCritical,
		weight:      5,
		title:       "XML External Entity (XXE) DOCTYPE/ENTITY injection pattern detected",
		description: "Payload contains XML DOCTYPE subsets or external SYSTEM/PUBLIC ENTITY declarations.",
		remediation: "Disable DTD processing and external entities in XML parsers by default.",
		asvs:        "5.5.2",
		d3fend:      "D3-IV",
		idSuffix:    "web-309-payload",
		regex:       wafXXERegex,
		prefilter: func(low string) bool {
			return strings.Contains(low, "<!doctype") || strings.Contains(low, "<!entity")
		},
	},
	{
		ruleID:      "WEB-310",
		severity:    schema.SeverityHigh,
		weight:      4,
		title:       "HTTP Response Splitting / CRLF header injection sequence detected",
		description: "Payload embeds CR/LF line breaks followed by HTTP response headers.",
		remediation: "Reject CR and LF characters before writing untrusted strings into HTTP header fields.",
		asvs:        "5.3.10",
		d3fend:      "D3-IV",
		idSuffix:    "web-310-payload",
		regex:       wafCRLFRegex,
		prefilter: func(low string) bool {
			return strings.Contains(low, "\r\n") ||
				strings.Contains(low, "%0d%0a") ||
				strings.Contains(low, `\r\n`)
		},
	},
}

func InspectPayloadFile(path string) ([]schema.Finding, error) {
	return InspectPayloadFileWithOptions(path, InspectOptions{ParanoiaLevel: 1})
}

func InspectPayloadFileWithOptions(path string, opts InspectOptions) ([]schema.Finding, error) {
	raw, err := readBoundedText(path)
	if err != nil {
		return nil, err
	}
	return InspectPayloadWithOptions(raw, "file://"+normalizePath(path), opts)
}

func InspectPayload(input string, target string) ([]schema.Finding, error) {
	return InspectPayloadWithOptions(input, target, InspectOptions{ParanoiaLevel: 1})
}

func InspectPayloadWithOptions(input string, target string, opts InspectOptions) ([]schema.Finding, error) {
	if len(input) > MaxConfigBytes {
		return nil, fmt.Errorf("payload exceeds %d byte limit", MaxConfigBytes)
	}
	if strings.TrimSpace(input) == "" {
		return nil, nil
	}

	paranoia := opts.ParanoiaLevel
	if paranoia <= 0 {
		paranoia = 1
	} else if paranoia > 3 {
		paranoia = 3
	}

	views, lowViews := normalizePayloadViewsFast(input)
	now := time.Now().UTC()
	var findings []schema.Finding
	totalScore := 0

	for i := range wafChecks {
		chk := &wafChecks[i]
		matched := matchAnyViewPrefiltered(views, lowViews, chk, paranoia)
		if matched != "" {
			totalScore += chk.weight
			findings = append(findings, newFinding(
				chk.ruleID, "waf", chk.severity,
				chk.title,
				chk.description,
				target,
				map[string]any{
					"matched_sample": truncateSample(matched, 80),
					"anomaly_score":  chk.weight,
					"paranoia_level": paranoia,
					"owasp_asvs":     chk.asvs,
				},
				chk.remediation,
				chk.d3fend,
				chk.idSuffix,
				now,
			))
		}
	}

	if len(findings) == 0 {
		return nil, nil
	}
	if opts.AnomalyThreshold > 0 && totalScore < opts.AnomalyThreshold {
		return nil, nil
	}
	for idx := range findings {
		if findings[idx].Evidence != nil {
			findings[idx].Evidence["total_anomaly_score"] = totalScore
		}
	}
	return findings, nil
}

func normalizePayloadViewsFast(raw string) (views []string, lowViews []string) {
	rawLow := strings.ToLower(raw)
	needsExtra := strings.IndexAny(raw, "%+&\\") >= 0 || strings.Contains(raw, "/*")
	if !needsExtra {
		return []string{raw}, []string{rawLow}
	}

	views = make([]string, 0, 4)
	lowViews = make([]string, 0, 4)
	addView := func(v string) {
		for _, existing := range views {
			if existing == v {
				return
			}
		}
		views = append(views, v)
		lowViews = append(lowViews, strings.ToLower(v))
	}

	addView(raw)

	cur := raw
	for pass := 0; pass < 2; pass++ {
		if strings.IndexByte(cur, '%') < 0 && strings.IndexByte(cur, '+') < 0 {
			break
		}
		decoded, err := url.QueryUnescape(cur)
		if err != nil {
			decoded = pathUnescapeFallback(cur)
		}
		if decoded == cur {
			break
		}
		addView(decoded)
		cur = decoded
	}

	evaded := decodeEvasionLayers(cur)
	if evaded != cur {
		addView(evaded)
	}
	return views, lowViews
}

func decodeEvasionLayers(s string) string {
	out := s
	if strings.Contains(out, "&") {
		out = decodeBasicEntities(out)
	}
	if strings.Contains(out, `\u00`) || strings.Contains(out, `\U00`) {
		out = wafUnicodeHexRe.ReplaceAllStringFunc(out, func(m string) string {
			v, err := strconv.ParseUint(m[4:], 16, 8)
			if err != nil {
				return m
			}
			return string([]byte{byte(v)})
		})
	}
	if strings.Contains(out, "/*") {
		out = wafSQLCommentRe.ReplaceAllString(out, "")
	}
	return out
}

func decodeBasicEntities(s string) string {
	out := wafHTMLEntityHex.ReplaceAllStringFunc(s, func(m string) string {
		v, err := strconv.ParseUint(m[3:len(m)-1], 16, 8)
		if err != nil || v == 0 {
			return m
		}
		return string([]byte{byte(v)})
	})
	out = wafHTMLEntityDec.ReplaceAllStringFunc(out, func(m string) string {
		v, err := strconv.ParseUint(m[2:len(m)-1], 10, 8)
		if err != nil || v == 0 {
			return m
		}
		return string([]byte{byte(v)})
	})
	repl := strings.NewReplacer(
		"&lt;", "<", "&LT;", "<",
		"&gt;", ">", "&GT;", ">",
		"&quot;", `"`, "&QUOT;", `"`,
		"&#39;", "'", "&apos;", "'",
		"&colon;", ":", "&COLON;", ":",
	)
	return repl.Replace(out)
}

func matchAnyViewPrefiltered(views, lowViews []string, chk *wafCheck, paranoia int) string {
	for idx, v := range views {
		if !chk.prefilter(lowViews[idx]) {
			continue
		}
		if loc := chk.regex.FindString(v); loc != "" {
			return loc
		}
		if paranoia >= 2 && chk.pl2Regex != nil {
			if loc := chk.pl2Regex.FindString(v); loc != "" {
				return loc
			}
		}
	}
	return ""
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
