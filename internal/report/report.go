package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/luminariadev/raksa-webshield/internal/schema"
)

const (
	sarifSchemaURI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	repoURI        = "https://github.com/luminariadev/raksa-webshield"
)

type OutputFormat string

const (
	FormatTable OutputFormat = "table"
	FormatJSON  OutputFormat = "json"
	FormatSARIF OutputFormat = "sarif"
)

func ParseFormat(raw string) (OutputFormat, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "table":
		return FormatTable, nil
	case "json":
		return FormatJSON, nil
	case "sarif":
		return FormatSARIF, nil
	default:
		return "", fmt.Errorf("invalid output format %q: expected table, json, or sarif", raw)
	}
}

func WriteReport(w io.Writer, rep schema.Report, format OutputFormat) error {
	var rendered string
	var err error
	switch format {
	case FormatTable:
		rendered = FormatTableRender(rep)
	case FormatJSON:
		rendered, err = FormatJSONRender(rep)
	case FormatSARIF:
		rendered, err = FormatSARIFRender(rep)
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, rendered)
	return err
}

func SanitizeTerminalText(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	for i := 0; i < len(raw); {
		if raw[i] == 0x1b {
			if i+1 < len(raw) && raw[i+1] == '[' {
				i += 2
				for i < len(raw) {
					c := raw[i]
					i++
					if c >= '@' && c <= '~' {
						break
					}
				}
				continue
			}
			if i+1 < len(raw) && raw[i+1] == ']' {
				i += 2
				for i < len(raw) {
					if raw[i] == 0x07 {
						i++
						break
					}
					if raw[i] == 0x1b && i+1 < len(raw) && raw[i+1] == '\\' {
						i += 2
						break
					}
					i++
				}
				continue
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(raw[i:])
		i += size
		if r == '\t' || r == '\n' || r == '\r' {
			b.WriteByte(' ')
		} else if r >= 0x20 && r != 0x7f {
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

func FormatTableRender(rep schema.Report) string {
	var b strings.Builder
	scoreSuffix := ""
	if rep.Posture != nil {
		scoreSuffix = fmt.Sprintf(" | score: %d/100 (%s)", rep.Posture.Score, SanitizeTerminalText(rep.Posture.Grade))
	}
	fmt.Fprintf(
		&b,
		"%s v%s | layer: %s%s | total: %d (critical: %d, high: %d, medium: %d, low: %d, info: %d)\n",
		SanitizeTerminalText(rep.Tool),
		schema.Version,
		SanitizeTerminalText(rep.Layer),
		scoreSuffix,
		rep.Summary.Total,
		rep.Summary.Critical,
		rep.Summary.High,
		rep.Summary.Medium,
		rep.Summary.Low,
		rep.Summary.Info,
	)

	if len(rep.Findings) == 0 {
		b.WriteString("No security findings detected.\n")
		return b.String()
	}

	fmt.Fprintf(&b, "%-9s %-9s %-10s %-38s %s\n", "SEVERITY", "RULE", "MODULE", "TARGET", "TITLE")
	b.WriteString(strings.Repeat("-", 104))
	b.WriteByte('\n')

	for _, f := range rep.Findings {
		sev := strings.ToUpper(string(f.Severity))
		rule := SanitizeTerminalText(f.RuleID)
		mod := truncateRunes(SanitizeTerminalText(f.Module), 10)
		target := truncateRunes(SanitizeTerminalText(f.Target), 38)
		title := SanitizeTerminalText(f.Title)
		rem := SanitizeTerminalText(f.Remediation)

		fmt.Fprintf(&b, "%-9s %-9s %-10s %-38s %s\n", sev, rule, mod, target, title)
		fmt.Fprintf(&b, "          fix: %s\n", rem)
	}
	return b.String()
}

func FormatJSONRender(rep schema.Report) (string, error) {
	raw, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return "", err
	}
	return string(raw) + "\n", nil
}

func FormatSARIFRender(rep schema.Report) (string, error) {
	catalog := make(map[string]schema.RuleInfo)
	for _, r := range schema.RuleCatalog() {
		catalog[r.RuleID] = r
	}

	rulesByID := make(map[string]map[string]any)
	results := make([]map[string]any, 0, len(rep.Findings))

	for _, f := range rep.Findings {
		if _, exists := rulesByID[f.RuleID]; !exists {
			if info, ok := catalog[f.RuleID]; ok {
				rulesByID[f.RuleID] = map[string]any{
					"id":               info.RuleID,
					"name":             info.Title,
					"shortDescription": map[string]any{"text": info.Title},
					"fullDescription":  map[string]any{"text": info.Description},
					"helpUri":          repoURI,
					"properties": map[string]any{
						"owasp_asvs":       info.OwaspASVS,
						"mitre_d3fend":     info.MitreD3FEND,
						"mitre_technique":  info.MitreTechnique,
						"default_severity": info.DefaultSeverity,
						"module":           info.Module,
					},
				}
			} else {
				rulesByID[f.RuleID] = map[string]any{
					"id":               f.RuleID,
					"name":             f.Title,
					"shortDescription": map[string]any{"text": f.Title},
					"fullDescription":  map[string]any{"text": f.Description},
					"helpUri":          repoURI,
				}
			}
		}

		level := "note"
		switch f.Severity {
		case schema.SeverityCritical, schema.SeverityHigh:
			level = "error"
		case schema.SeverityMedium:
			level = "warning"
		}

		uri := strings.TrimPrefix(f.Target, "file://")
		uri = strings.ReplaceAll(uri, `\`, "/")
		phys := map[string]any{
			"artifactLocation": map[string]any{"uri": uri},
		}
		if line, ok := extractLine(f.Evidence); ok && line >= 1 {
			phys["region"] = map[string]any{"startLine": line}
		}

		results = append(results, map[string]any{
			"ruleId": f.RuleID,
			"level":  level,
			"message": map[string]any{
				"text": fmt.Sprintf("%s Remediation: %s", f.Description, f.Remediation),
			},
			"locations": []map[string]any{
				{"physicalLocation": phys},
			},
			"partialFingerprints": map[string]any{
				"raksaFindingId": f.ID,
			},
			"properties": map[string]any{
				"severity":     f.Severity,
				"module":       f.Module,
				"layer":        f.Layer,
				"mitre_d3fend": f.MitreD3FEND,
				"evidence":     f.Evidence,
			},
		})
	}

	ruleIDs := make([]string, 0, len(rulesByID))
	for id := range rulesByID {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)

	sortedRules := make([]map[string]any, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		sortedRules = append(sortedRules, rulesByID[id])
	}

	doc := map[string]any{
		"$schema": sarifSchemaURI,
		"version": "2.1.0",
		"runs": []map[string]any{
			{
				"tool": map[string]any{
					"driver": map[string]any{
						"name":           rep.Tool,
						"version":        schema.Version,
						"informationUri": repoURI,
						"rules":          sortedRules,
					},
				},
				"results": results,
			},
		},
	}

	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	return string(raw) + "\n", nil
}

func extractLine(ev map[string]any) (int, bool) {
	if ev == nil {
		return 0, false
	}
	v, ok := ev["line"]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	default:
		return 0, false
	}
}

func truncateRunes(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	if max <= 3 {
		return string(runes[:max])
	}
	return string(runes[:max-3]) + "..."
}
