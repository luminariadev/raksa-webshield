package auditor

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/luminariadev/raksa-webshield/internal/schema"
)

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
	var findings []schema.Finding

	lines := strings.Split(content, "\n")
	for idx, rawLine := range lines {
		lineNo := idx + 1
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if commentIdx := strings.IndexByte(line, '#'); commentIdx >= 0 {
			line = strings.TrimSpace(line[:commentIdx])
		}
		stmt := strings.TrimSpace(strings.TrimSuffix(line, ";"))
		if stmt == "" {
			continue
		}
		low := strings.ToLower(stmt)
		fields := strings.Fields(stmt)
		if len(fields) == 0 {
			continue
		}
		dir := strings.ToLower(fields[0])

		// WEB-201: Deprecated TLS protocols (exact token check so TLSv1.2/TLSv1.3 stay clean).
		if (dir == "ssl_protocols" || dir == "protocols") && len(fields) > 1 {
			var deprecated []string
			for _, tok := range fields[1:] {
				t := strings.ToLower(strings.Trim(tok, ";"))
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
		if (dir == "server_tokens" || dir == "autoindex") && len(fields) >= 2 && strings.EqualFold(fields[1], "on") {
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

		// WEB-203: add_header emitting wildcard CORS or unsafe CSP
		if dir == "add_header" && len(fields) >= 3 {
			hdrName := strings.ToLower(strings.Trim(fields[1], `"'`))
			hdrVal := strings.TrimSpace(strings.Join(fields[2:], " "))
			hdrValLow := strings.ToLower(hdrVal)

			if hdrName == "access-control-allow-origin" {
				cleanedVal := strings.Trim(hdrValLow, `"' `)
				if cleanedVal == "*" || cleanedVal == "null" {
					findings = append(findings, newFinding(
						"WEB-203", "config", schema.SeverityHigh,
						"Reverse-proxy config emits unsafe CORS header",
						fmt.Sprintf("add_header on line %d emits Access-Control-Allow-Origin %s.", lineNo, cleanedVal),
						target,
						map[string]any{"line": lineNo, "header": "Access-Control-Allow-Origin", "value": cleanedVal, "owasp_asvs": "14.4.3"},
						"Allow only explicit trusted Origin domains rather than '*' or 'null'.",
						"D3-CH", fmt.Sprintf("cfg-l%d-cors", lineNo), now,
					))
				}
			}
			if hdrName == "content-security-policy" && (strings.Contains(hdrValLow, "unsafe-inline") || strings.Contains(hdrValLow, "unsafe-eval")) {
				findings = append(findings, newFinding(
					"WEB-203", "config", schema.SeverityHigh,
					"Reverse-proxy config emits unsafe CSP header",
					fmt.Sprintf("add_header Content-Security-Policy on line %d includes unsafe-inline or unsafe-eval.", lineNo),
					target,
					map[string]any{"line": lineNo, "header": "Content-Security-Policy", "owasp_asvs": "14.4.3"},
					"Remove 'unsafe-inline' and 'unsafe-eval' from static Content-Security-Policy directives.",
					"D3-CH", fmt.Sprintf("cfg-l%d-csp", lineNo), now,
				))
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
		_ = low
	}

	return findings
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
		lowerName == "caddyfile"
}

func isHeaderDumpName(lowerName string) bool {
	return strings.Contains(lowerName, "header") &&
		(strings.HasSuffix(lowerName, ".http") || strings.HasSuffix(lowerName, ".txt"))
}
