package auditor

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/luminariadev/raksa-webshield/internal/schema"
)

type proxyConfigKind int

const (
	kindNginx proxyConfigKind = iota
	kindCaddy
	kindVercel
	kindHeadersFile
	kindK8sIngress
)

var inheritedSecurityHeaders = map[string]string{
	"strict-transport-security": "Strict-Transport-Security",
	"content-security-policy":   "Content-Security-Policy",
	"x-frame-options":           "X-Frame-Options",
	"x-content-type-options":    "X-Content-Type-Options",
}

func AuditConfigPath(path string) ([]schema.Finding, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat config path %q: %w", path, err)
	}
	if !info.IsDir() {
		raw, err := readBoundedText(path)
		if err != nil {
			return nil, err
		}
		return AuditConfigContent(raw, "file://"+normalizePath(path)), nil
	}

	var files []string
	err = filepath.WalkDir(path, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if isIgnoredWorkspaceDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if isProxyConfigName(strings.ToLower(d.Name())) {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk config dir %q: %w", path, err)
	}
	sort.Strings(files)

	var all []schema.Finding
	for _, f := range files {
		raw, err := readBoundedText(f)
		if err != nil {
			return nil, err
		}
		all = append(all, AuditConfigContent(raw, "file://"+normalizePath(f))...)
	}
	return all, nil
}

func AuditConfigContent(content string, target string) []schema.Finding {
	now := time.Now().UTC()
	switch detectConfigKind(content, target) {
	case kindVercel:
		return auditVercelJSON(content, target, now)
	case kindHeadersFile:
		return auditNetlifyHeaders(content, target, now)
	case kindK8sIngress:
		return auditK8sIngressYAML(content, target, now)
	case kindCaddy:
		return auditCaddyConfig(content, target, now)
	default:
		return auditNginxConfig(content, target, now)
	}
}

func detectConfigKind(content string, target string) proxyConfigKind {
	cleanTarget := strings.TrimPrefix(strings.ToLower(target), "file://")
	base := strings.ToLower(filepath.Base(cleanTarget))
	switch {
	case base == "vercel.json":
		return kindVercel
	case base == "_headers":
		return kindHeadersFile
	case base == "caddyfile" || strings.HasSuffix(base, ".caddy"):
		return kindCaddy
	case (strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml")) && looksLikeK8sIngress(content):
		return kindK8sIngress
	case strings.HasSuffix(base, ".conf") || strings.HasSuffix(base, ".nginx"):
		return kindNginx
	}

	trimmed := strings.TrimSpace(content)
	if strings.HasPrefix(trimmed, "{") && strings.Contains(trimmed, `"headers"`) {
		return kindVercel
	}
	if looksLikeK8sIngress(content) {
		return kindK8sIngress
	}
	low := strings.ToLower(content)
	if (strings.Contains(low, "file_server") || strings.Contains(low, "auto_https") || strings.Contains(low, "reverse_proxy")) &&
		!strings.Contains(low, "add_header") {
		return kindCaddy
	}
	return kindNginx
}

func looksLikeK8sIngress(content string) bool {
	hasKindIngress := false
	for _, line := range strings.Split(content, "\n") {
		t := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(t, "kind:") && strings.Contains(t, "ingress") {
			hasKindIngress = true
			break
		}
	}
	return hasKindIngress
}

type nginxScope struct {
	kind         string
	locationPath string
	isExactLoc   bool
	isRegexLoc   bool
	openLine     int
	secHeaders   map[string]bool
	localAddHdrs int
}

func newNginxScope(kind string, lineNo int) *nginxScope {
	return &nginxScope{
		kind:       kind,
		openLine:   lineNo,
		secHeaders: make(map[string]bool),
	}
}

func auditNginxConfig(content string, target string, now time.Time) []schema.Finding {
	var findings []schema.Finding
	stack := []*nginxScope{newNginxScope("root", 1)}

	lines := strings.Split(content, "\n")
	for idx, rawLine := range lines {
		lineNo := idx + 1
		cleaned := strings.TrimSpace(stripHashComment(rawLine))
		if cleaned == "" {
			continue
		}

		// Handle lines that open scopes, execute statements, or close braces cleanly.
		findings = append(findings, processNginxLine(cleaned, lineNo, target, now, &stack)...)
	}

	return findings
}

func processNginxLine(
	line string,
	lineNo int,
	target string,
	now time.Time,
	stack *[]*nginxScope,
) []schema.Finding {
	var findings []schema.Finding
	cur := 0
	for cur < len(line) {
		openIdx, closeIdx, semiIdx := nextNginxDelimiter(line, cur)

		// Process braces or semicolons in textual order.
		nextPos := len(line)
		delim := byte(0)
		for _, cand := range []struct {
			pos int
			ch  byte
		}{
			{openIdx, '{'},
			{closeIdx, '}'},
			{semiIdx, ';'},
		} {
			if cand.pos >= 0 && cand.pos < nextPos {
				nextPos = cand.pos
				delim = cand.ch
			}
		}

		segment := strings.TrimSpace(line[cur:nextPos])
		switch delim {
		case '{':
			scope := parseNginxBlockHeader(segment, lineNo)
			*stack = append(*stack, scope)
		case '}':
			if segment != "" {
				findings = append(findings, evalNginxStatement(segment, lineNo, target, now, *stack)...)
			}
			if len(*stack) > 1 {
				popped := (*stack)[len(*stack)-1]
				*stack = (*stack)[:len(*stack)-1]
				if dropped := checkInheritedHeaderDrop(popped, *stack, target, now); dropped != nil {
					findings = append(findings, *dropped)
				}
			}
		case ';':
			if segment != "" {
				findings = append(findings, evalNginxStatement(segment, lineNo, target, now, *stack)...)
			}
		default:
			if segment != "" {
				findings = append(findings, evalNginxStatement(segment, lineNo, target, now, *stack)...)
			}
		}
		if nextPos >= len(line) {
			break
		}
		cur = nextPos + 1
	}
	return findings
}

func nextNginxDelimiter(line string, start int) (openIdx, closeIdx, semiIdx int) {
	openIdx, closeIdx, semiIdx = -1, -1, -1
	var quote byte
	for i := start; i < len(line); i++ {
		c := line[i]
		if quote != 0 {
			if c == quote && (i == 0 || line[i-1] != '\\') {
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			continue
		}
		switch c {
		case '{':
			if openIdx == -1 {
				openIdx = i
			}
		case '}':
			if closeIdx == -1 {
				closeIdx = i
			}
		case ';':
			if semiIdx == -1 {
				semiIdx = i
			}
		}
		if openIdx != -1 || closeIdx != -1 || semiIdx != -1 {
			break
		}
	}
	return openIdx, closeIdx, semiIdx
}

func parseNginxBlockHeader(header string, lineNo int) *nginxScope {
	fields := strings.Fields(strings.TrimSpace(header))
	if len(fields) == 0 {
		return newNginxScope("other", lineNo)
	}
	head := strings.ToLower(fields[0])
	switch head {
	case "http":
		return newNginxScope("http", lineNo)
	case "server":
		return newNginxScope("server", lineNo)
	case "location":
		sc := newNginxScope("location", lineNo)
		if len(fields) == 2 {
			sc.locationPath = fields[1]
		} else if len(fields) >= 3 {
			mod := fields[1]
			switch mod {
			case "~", "~*":
				sc.isRegexLoc = true
				sc.locationPath = fields[2]
			case "=":
				sc.isExactLoc = true
				sc.locationPath = fields[2]
			default:
				sc.locationPath = fields[len(fields)-1]
			}
		}
		return sc
	default:
		return newNginxScope(head, lineNo)
	}
}

func checkInheritedHeaderDrop(popped *nginxScope, ancestors []*nginxScope, target string, now time.Time) *schema.Finding {
	if popped.kind != "location" || popped.localAddHdrs == 0 {
		return nil
	}
	parentHeaders := make(map[string]string)
	for _, anc := range ancestors {
		if anc.kind != "http" && anc.kind != "server" && anc.kind != "root" {
			continue
		}
		for lowName := range anc.secHeaders {
			if canonical, ok := inheritedSecurityHeaders[lowName]; ok {
				parentHeaders[lowName] = canonical
			}
		}
	}
	if len(parentHeaders) == 0 {
		return nil
	}

	var dropped []string
	for lowName, canonical := range parentHeaders {
		if !popped.secHeaders[lowName] {
			dropped = append(dropped, canonical)
		}
	}
	if len(dropped) == 0 {
		return nil
	}
	sort.Strings(dropped)

	f := newFinding(
		"WEB-205", "config", schema.SeverityHigh,
		"Nginx location add_header drops inherited parent security headers",
		fmt.Sprintf("Location block %q (line %d) defines add_header and silently cancels parent headers (%s).", popped.locationPath, popped.openLine, strings.Join(dropped, ", ")),
		target,
		map[string]any{
			"line":            popped.openLine,
			"location":        popped.locationPath,
			"dropped_headers": dropped,
			"owasp_asvs":      "14.4.3",
		},
		"Repeat required parent security headers inside this location block or move headers into a shared include snippet.",
		"D3-CH", fmt.Sprintf("cfg-l%d-hdr-inherit", popped.openLine), now,
	)
	return &f
}

func evalNginxStatement(stmt string, lineNo int, target string, now time.Time, stack []*nginxScope) []schema.Finding {
	fields := strings.Fields(strings.TrimSpace(stmt))
	if len(fields) == 0 {
		return nil
	}
	dir := strings.ToLower(fields[0])
	curScope := stack[len(stack)-1]
	var findings []schema.Finding

	// WEB-201: Deprecated TLS protocols (exact token check so TLSv1.2/TLSv1.3 stay clean).
	if (dir == "ssl_protocols" || dir == "protocols") && len(fields) > 1 {
		var deprecated []string
		for _, tok := range fields[1:] {
			t := strings.ToLower(strings.Trim(tok, `"'`))
			if t == "sslv2" || t == "sslv3" || t == "tlsv1" || t == "tlsv1.0" || t == "tlsv1.1" {
				deprecated = append(deprecated, tok)
			}
		}
		if len(deprecated) > 0 {
			findings = append(findings, newFinding(
				"WEB-201", "config", schema.SeverityHigh,
				"Deprecated TLS protocol enabled in web server config",
				fmt.Sprintf("Directive %s on line %d permits legacy protocols (%s).", fields[0], lineNo, strings.Join(deprecated, ", ")),
				target,
				map[string]any{"line": lineNo, "deprecated_protocols": deprecated, "owasp_asvs": "9.1.2"},
				"Restrict ssl_protocols strictly to TLSv1.2 TLSv1.3.",
				"D3-CH", fmt.Sprintf("cfg-l%d-tls", lineNo), now,
			))
		}
	}

	// WEB-202: server_tokens on / autoindex on
	if (dir == "server_tokens" || dir == "autoindex") && len(fields) >= 2 && strings.EqualFold(strings.Trim(fields[1], `"'`), "on") {
		findings = append(findings, newFinding(
			"WEB-202", "config", schema.SeverityMedium,
			"Web server version disclosure or directory listing enabled",
			fmt.Sprintf("Directive '%s on' on line %d exposes server version info or directory indexes.", dir, lineNo),
			target,
			map[string]any{"line": lineNo, "directive": dir, "value": "on", "owasp_asvs": "14.3.3"},
			fmt.Sprintf("Set '%s off;' in server configuration.", dir),
			"D3-CH", fmt.Sprintf("cfg-l%d-%s", lineNo, dir), now,
		))
	}

	// WEB-203 & inheritance tracking: add_header
	if dir == "add_header" && len(fields) >= 3 {
		hdrName := strings.ToLower(strings.Trim(fields[1], `"'`))
		curScope.localAddHdrs++
		if _, tracked := inheritedSecurityHeaders[hdrName]; tracked {
			curScope.secHeaders[hdrName] = true
		}

		valTokens := fields[2:]
		if len(valTokens) > 1 && strings.EqualFold(strings.Trim(valTokens[len(valTokens)-1], `"'`), "always") {
			valTokens = valTokens[:len(valTokens)-1]
		}
		hdrVal := strings.TrimSpace(strings.Join(valTokens, " "))
		if f := checkStaticHeaderValue(hdrName, hdrVal, lineNo, target, now); f != nil {
			findings = append(findings, *f)
		}
	}

	// WEB-204: Unbounded client_max_body_size 0
	if dir == "client_max_body_size" && len(fields) >= 2 {
		val := strings.ToLower(strings.Trim(fields[1], `"'`))
		if val == "0" || val == "0m" || val == "0k" {
			findings = append(findings, newFinding(
				"WEB-204", "config", schema.SeverityMedium,
				"Unbounded request body size in web server config",
				fmt.Sprintf("client_max_body_size %s on line %d disables request payload size enforcement.", val, lineNo),
				target,
				map[string]any{"line": lineNo, "directive": "client_max_body_size", "value": val, "owasp_asvs": "13.1.4"},
				"Set a concrete bounded size (e.g., client_max_body_size 10m;) aligned with application upload needs.",
				"D3-IV", fmt.Sprintf("cfg-l%d-body-size", lineNo), now,
			))
		}
	}

	// WEB-206: Nginx off-by-slash alias path traversal
	if dir == "alias" && len(fields) >= 2 && curScope.kind == "location" && !curScope.isRegexLoc && !curScope.isExactLoc {
		locPath := curScope.locationPath
		aliasVal := strings.Trim(fields[1], `"'`)
		if locPath != "" && !strings.HasSuffix(locPath, "/") && strings.HasSuffix(aliasVal, "/") {
			findings = append(findings, newFinding(
				"WEB-206", "config", schema.SeverityHigh,
				"Nginx off-by-slash alias path traversal risk",
				fmt.Sprintf("Location %q (no trailing '/') uses alias %q (trailing '/') on line %d, permitting sibling directory traversal.", locPath, aliasVal, lineNo),
				target,
				map[string]any{"line": lineNo, "location": locPath, "alias": aliasVal, "owasp_asvs": "12.3.1"},
				fmt.Sprintf("Append a trailing '/' to location (%s/) or drop the trailing '/' from alias.", locPath),
				"D3-CH", fmt.Sprintf("cfg-l%d-alias", lineNo), now,
			))
		}
	}

	// WEB-206: Dynamic proxy_pass or spoofable $http_host forwarding
	if dir == "proxy_pass" && len(fields) >= 2 {
		upstream := strings.ToLower(strings.Trim(fields[1], `"'`))
		if strings.Contains(upstream, "$http_host") ||
			strings.Contains(upstream, "$arg_") ||
			strings.Contains(upstream, "://$uri") ||
			strings.Contains(upstream, "://${uri") {
			findings = append(findings, newFinding(
				"WEB-206", "config", schema.SeverityHigh,
				"Unsafe dynamic variable in proxy_pass target",
				fmt.Sprintf("proxy_pass on line %d interpolates user-controlled input (%s), risking SSRF or open proxy routing.", lineNo, fields[1]),
				target,
				map[string]any{"line": lineNo, "proxy_pass": fields[1], "owasp_asvs": "12.6.1"},
				"Use static named upstream blocks instead of interpolating $http_host, $arg_*, or $uri as proxy_pass host.",
				"D3-CH", fmt.Sprintf("cfg-l%d-proxypass", lineNo), now,
			))
		}
	}
	if dir == "proxy_set_header" && len(fields) >= 3 && strings.EqualFold(strings.Trim(fields[1], `"'`), "Host") {
		hostExpr := strings.ToLower(strings.Trim(fields[2], `"'`))
		if strings.Contains(hostExpr, "$http_host") {
			findings = append(findings, newFinding(
				"WEB-206", "config", schema.SeverityMedium,
				"Proxy forwards raw $http_host instead of validated $host",
				fmt.Sprintf("proxy_set_header Host %s on line %d trusts arbitrary client Host header values.", fields[2], lineNo),
				target,
				map[string]any{"line": lineNo, "directive": "proxy_set_header", "value": fields[2], "owasp_asvs": "14.4.1"},
				"Prefer proxy_set_header Host $host; or a fixed canonical upstream hostname.",
				"D3-CH", fmt.Sprintf("cfg-l%d-hosthdr", lineNo), now,
			))
		}
	}

	// WEB-207: Weak TLS ciphers in ssl_ciphers
	if dir == "ssl_ciphers" && len(fields) >= 2 {
		if weak := findWeakCiphers(strings.Join(fields[1:], " ")); len(weak) > 0 {
			findings = append(findings, newFinding(
				"WEB-207", "config", schema.SeverityHigh,
				"Weak TLS cipher suite enabled in web server config",
				fmt.Sprintf("ssl_ciphers on line %d permits weak or broken ciphers (%s).", lineNo, strings.Join(weak, ", ")),
				target,
				map[string]any{"line": lineNo, "weak_ciphers": weak, "owasp_asvs": "9.1.3"},
				"Use modern AEAD cipher suites (ECDHE+AESGCM, CHACHA20) and exclude RC4, 3DES, DES, MD5, EXPORT, and NULL.",
				"D3-CH", fmt.Sprintf("cfg-l%d-ciphers", lineNo), now,
			))
		}
	}

	return findings
}

func auditCaddyConfig(content string, target string, now time.Time) []schema.Finding {
	var findings []schema.Finding
	for idx, rawLine := range strings.Split(content, "\n") {
		lineNo := idx + 1
		line := strings.TrimSpace(stripHashComment(rawLine))
		if line == "" || line == "{" || line == "}" {
			continue
		}
		fields := strings.Fields(strings.TrimSuffix(line, "{"))
		if len(fields) == 0 {
			continue
		}
		dir := strings.ToLower(fields[0])

		switch dir {
		case "protocols":
			var deprecated []string
			for _, tok := range fields[1:] {
				t := strings.ToLower(strings.Trim(tok, `"'`))
				if t == "ssl" || t == "sslv2" || t == "sslv3" || t == "tls1.0" || t == "tlsv1" || t == "tlsv1.1" || t == "tls1.1" {
					deprecated = append(deprecated, tok)
				}
			}
			if len(deprecated) > 0 {
				findings = append(findings, newFinding(
					"WEB-201", "config", schema.SeverityHigh,
					"Deprecated TLS protocol enabled in Caddyfile",
					fmt.Sprintf("Caddy tls protocols on line %d permits legacy versions (%s).", lineNo, strings.Join(deprecated, ", ")),
					target,
					map[string]any{"line": lineNo, "deprecated_protocols": deprecated, "owasp_asvs": "9.1.2"},
					"Restrict Caddy tls protocols to tls1.2 tls1.3.",
					"D3-CH", fmt.Sprintf("cfg-l%d-caddy-tls", lineNo), now,
				))
			}
		case "file_server":
			for _, tok := range fields[1:] {
				if strings.EqualFold(tok, "browse") {
					findings = append(findings, newFinding(
						"WEB-202", "config", schema.SeverityMedium,
						"Caddy directory browsing enabled",
						fmt.Sprintf("Directive 'file_server browse' on line %d exposes directory listings.", lineNo),
						target,
						map[string]any{"line": lineNo, "directive": "file_server", "owasp_asvs": "14.3.3"},
						"Remove 'browse' from file_server in production Caddyfile blocks.",
						"D3-CH", fmt.Sprintf("cfg-l%d-caddy-browse", lineNo), now,
					))
					break
				}
			}
		case "header":
			if len(fields) >= 3 {
				hdrName := strings.ToLower(strings.Trim(fields[1], `"'`))
				hdrVal := strings.TrimSpace(strings.Join(fields[2:], " "))
				if f := checkStaticHeaderValue(hdrName, hdrVal, lineNo, target, now); f != nil {
					findings = append(findings, *f)
				}
			}
		case "auto_https":
			if len(fields) >= 2 && strings.EqualFold(strings.Trim(fields[1], `"'`), "off") {
				findings = append(findings, newFinding(
					"WEB-207", "config", schema.SeverityHigh,
					"Automatic HTTPS disabled in Caddyfile",
					fmt.Sprintf("Directive 'auto_https off' on line %d disables automated TLS provisioning and HTTPS redirects.", lineNo),
					target,
					map[string]any{"line": lineNo, "directive": "auto_https", "value": "off", "owasp_asvs": "9.1.1"},
					"Keep auto_https enabled (or enforce explicit HTTPS listeners with TLSv1.2+).",
					"D3-CH", fmt.Sprintf("cfg-l%d-caddy-https", lineNo), now,
				))
			}
		case "ciphers":
			if weak := findWeakCiphers(strings.Join(fields[1:], " ")); len(weak) > 0 {
				findings = append(findings, newFinding(
					"WEB-207", "config", schema.SeverityHigh,
					"Weak TLS cipher suite enabled in Caddyfile",
					fmt.Sprintf("Caddy ciphers on line %d permits weak cipher suites (%s).", lineNo, strings.Join(weak, ", ")),
					target,
					map[string]any{"line": lineNo, "weak_ciphers": weak, "owasp_asvs": "9.1.3"},
					"Remove RC4/3DES/DES/EXPORT/NULL/MD5 cipher suites and use Caddy default TLS 1.2/1.3 ciphers.",
					"D3-CH", fmt.Sprintf("cfg-l%d-caddy-ciphers", lineNo), now,
				))
			}
		}
	}
	return findings
}

func auditVercelJSON(content string, target string, now time.Time) []schema.Finding {
	var parsed struct {
		Headers []struct {
			Source  string `json:"source"`
			Headers []struct {
				Key   string `json:"key"`
				Value string `json:"value"`
			} `json:"headers"`
		} `json:"headers"`
	}
	if err := json.Unmarshal([]byte(content), &parsed); err != nil {
		return nil
	}

	var findings []schema.Finding
	for ruleIdx, rule := range parsed.Headers {
		for hdrIdx, h := range rule.Headers {
			if f := checkStaticHeaderValue(strings.ToLower(strings.TrimSpace(h.Key)), h.Value, ruleIdx+hdrIdx+1, target, now); f != nil {
				findings = append(findings, *f)
			}
		}
	}
	return findings
}

func auditNetlifyHeaders(content string, target string, now time.Time) []schema.Finding {
	var findings []schema.Finding
	for idx, rawLine := range strings.Split(content, "\n") {
		lineNo := idx + 1
		line := strings.TrimSpace(stripHashComment(rawLine))
		if line == "" || strings.HasPrefix(line, "/") {
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(line[:colon]))
		val := strings.TrimSpace(line[colon+1:])
		if f := checkStaticHeaderValue(name, val, lineNo, target, now); f != nil {
			findings = append(findings, *f)
		}
	}
	return findings
}

func auditK8sIngressYAML(content string, target string, now time.Time) []schema.Finding {
	var findings []schema.Finding
	for idx, rawLine := range strings.Split(content, "\n") {
		lineNo := idx + 1
		line := strings.TrimSpace(stripHashComment(rawLine))
		if line == "" {
			continue
		}
		low := strings.ToLower(line)

		if strings.Contains(low, "ssl-redirect:") &&
			(strings.Contains(low, `"false"`) || strings.Contains(low, `'false'`) || strings.HasSuffix(low, " false")) {
			findings = append(findings, newFinding(
				"WEB-207", "config", schema.SeverityHigh,
				"Kubernetes Ingress disables mandatory SSL redirect",
				fmt.Sprintf("Ingress annotation ssl-redirect is disabled on line %d, permitting plaintext HTTP traffic.", lineNo),
				target,
				map[string]any{"line": lineNo, "annotation": "ssl-redirect", "value": "false", "owasp_asvs": "9.1.1"},
				"Remove ssl-redirect: \"false\" or set nginx.ingress.kubernetes.io/force-ssl-redirect: \"true\".",
				"D3-CH", fmt.Sprintf("cfg-l%d-k8s-ssl", lineNo), now,
			))
		}

		if strings.Contains(low, "cors-allow-origin:") &&
			(strings.Contains(low, `"*"`) || strings.Contains(low, `'*'`) || strings.HasSuffix(low, " *") || strings.Contains(low, "null")) {
			findings = append(findings, newFinding(
				"WEB-203", "config", schema.SeverityHigh,
				"Kubernetes Ingress exposes wildcard CORS origin",
				fmt.Sprintf("Ingress annotation cors-allow-origin on line %d permits wildcard or null origin.", lineNo),
				target,
				map[string]any{"line": lineNo, "annotation": "cors-allow-origin", "owasp_asvs": "14.5.3"},
				"Restrict nginx.ingress.kubernetes.io/cors-allow-origin to explicit trusted domain origins.",
				"D3-CH", fmt.Sprintf("cfg-l%d-k8s-cors", lineNo), now,
			))
		}

		if strings.Contains(low, "server_tokens on") {
			findings = append(findings, newFinding(
				"WEB-202", "config", schema.SeverityMedium,
				"Kubernetes Ingress snippet enables server_tokens",
				fmt.Sprintf("Ingress configuration-snippet on line %d sets server_tokens on.", lineNo),
				target,
				map[string]any{"line": lineNo, "directive": "server_tokens", "owasp_asvs": "14.3.3"},
				"Set server_tokens off; in Ingress configuration.",
				"D3-CH", fmt.Sprintf("cfg-l%d-k8s-tokens", lineNo), now,
			))
		}

		if strings.Contains(low, "content-security-policy") && (strings.Contains(low, "unsafe-inline") || strings.Contains(low, "unsafe-eval")) {
			findings = append(findings, newFinding(
				"WEB-203", "config", schema.SeverityHigh,
				"Kubernetes Ingress emits unsafe CSP header",
				fmt.Sprintf("Ingress snippet on line %d sets CSP containing unsafe-inline or unsafe-eval.", lineNo),
				target,
				map[string]any{"line": lineNo, "header": "Content-Security-Policy", "owasp_asvs": "14.4.3"},
				"Remove unsafe-inline and unsafe-eval from Ingress Content-Security-Policy annotations.",
				"D3-CH", fmt.Sprintf("cfg-l%d-k8s-csp", lineNo), now,
			))
		}
	}
	return findings
}

func checkStaticHeaderValue(hdrName, hdrVal string, lineNo int, target string, now time.Time) *schema.Finding {
	hdrValLow := strings.ToLower(hdrVal)
	switch hdrName {
	case "access-control-allow-origin":
		cleanedVal := strings.Trim(hdrValLow, `"' `)
		if cleanedVal == "*" || cleanedVal == "null" {
			f := newFinding(
				"WEB-203", "config", schema.SeverityHigh,
				"Reverse-proxy config emits unsafe CORS header",
				fmt.Sprintf("Config header on line %d emits Access-Control-Allow-Origin %s.", lineNo, cleanedVal),
				target,
				map[string]any{"line": lineNo, "header": "Access-Control-Allow-Origin", "value": cleanedVal, "owasp_asvs": "14.4.3"},
				"Allow only explicit trusted Origin domains rather than '*' or 'null'.",
				"D3-CH", fmt.Sprintf("cfg-l%d-cors", lineNo), now,
			)
			return &f
		}
	case "content-security-policy":
		if strings.Contains(hdrValLow, "unsafe-inline") || strings.Contains(hdrValLow, "unsafe-eval") {
			f := newFinding(
				"WEB-203", "config", schema.SeverityHigh,
				"Reverse-proxy config emits unsafe CSP header",
				fmt.Sprintf("Content-Security-Policy on line %d includes unsafe-inline or unsafe-eval.", lineNo),
				target,
				map[string]any{"line": lineNo, "header": "Content-Security-Policy", "owasp_asvs": "14.4.3"},
				"Remove 'unsafe-inline' and 'unsafe-eval' from static Content-Security-Policy directives.",
				"D3-CH", fmt.Sprintf("cfg-l%d-csp", lineNo), now,
			)
			return &f
		}
	}
	return nil
}

func findWeakCiphers(spec string) []string {
	cleaned := strings.Trim(spec, `"' `)
	tokens := strings.FieldsFunc(cleaned, func(r rune) bool {
		return r == ':' || r == ',' || r == ' ' || r == '\t'
	})
	weakSet := map[string]struct{}{
		"RC4": {}, "3DES": {}, "DES": {}, "MD5": {},
		"EXPORT": {}, "EXP": {}, "NULL": {}, "ANULL": {}, "ENULL": {},
	}
	var found []string
	seen := make(map[string]struct{})
	for _, raw := range tokens {
		tok := strings.TrimSpace(raw)
		if tok == "" || strings.HasPrefix(tok, "!") || strings.HasPrefix(tok, "-!") {
			continue
		}
		parts := strings.FieldsFunc(strings.ToUpper(tok), func(r rune) bool {
			return r == '-' || r == '_'
		})
		for _, p := range parts {
			if _, isWeak := weakSet[p]; isWeak {
				if _, ok := seen[tok]; !ok {
					seen[tok] = struct{}{}
					found = append(found, tok)
				}
				break
			}
		}
	}
	return found
}

func stripHashComment(line string) string {
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		if quote != 0 {
			if c == quote && (i == 0 || line[i-1] != '\\') {
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			continue
		}
		if c == '#' {
			return line[:i]
		}
	}
	return line
}

func AuditWorkspace(root string) ([]schema.Finding, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("stat workspace %q: %w", root, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("workspace path %q is not a directory", root)
	}

	var files []string
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if isIgnoredWorkspaceDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		files = append(files, p)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk workspace %q: %w", root, err)
	}
	sort.Strings(files)

	var findings []schema.Finding
	for _, f := range files {
		low := strings.ToLower(filepath.Base(f))
		switch {
		case isProxyConfigName(low):
			res, err := AuditConfigPath(f)
			if err != nil {
				return nil, err
			}
			findings = append(findings, res...)
		case isHeaderDumpName(low):
			res, err := AuditHeadersFile(f)
			if err != nil {
				return nil, err
			}
			findings = append(findings, res...)
		}
	}

	return findings, nil
}

func isIgnoredWorkspaceDir(name string) bool {
	return name == ".git" || name == "node_modules" || name == "dist" || name == "target" || name == "vendor"
}

func isProxyConfigName(lowerName string) bool {
	return (strings.Contains(lowerName, "nginx") && strings.HasSuffix(lowerName, ".conf")) ||
		strings.HasSuffix(lowerName, ".nginx") ||
		lowerName == "caddyfile" ||
		strings.HasSuffix(lowerName, ".caddy") ||
		lowerName == "vercel.json" ||
		lowerName == "_headers" ||
		(strings.Contains(lowerName, "ingress") && (strings.HasSuffix(lowerName, ".yml") || strings.HasSuffix(lowerName, ".yaml")))
}

func isHeaderDumpName(lowerName string) bool {
	return strings.Contains(lowerName, "header") &&
		(strings.HasSuffix(lowerName, ".http") || strings.HasSuffix(lowerName, ".txt"))
}
