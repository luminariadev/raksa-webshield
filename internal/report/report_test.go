package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/luminariadev/raksa-webshield/internal/schema"
)

func TestTableSanitizesANSIEscapes(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	rep := schema.NewReport([]schema.Finding{
		{
			ID:          "web-005-test",
			RuleID:      "WEB-005",
			Module:      "headers",
			Layer:       schema.LayerWeb,
			Severity:    schema.SeverityLow,
			Title:       "Title\x1b]0;pwn\x07Clean",
			Description: "Banner exposed",
			Target:      "file:///tmp/\x1b[31mfake\x1b[0m.http",
			Remediation: "Hide server banner",
			MitreD3FEND: "D3-HI",
			Timestamp:   now,
		},
	}, now)

	out := FormatTableRender(rep)
	if strings.Contains(out, "\x1b") || strings.Contains(out, "\x07") {
		t.Fatalf("ANSI escape sequence was not stripped: %q", out)
	}
	if !strings.Contains(out, "TitleClean") || !strings.Contains(out, "WEB-005") {
		t.Fatalf("missing sanitized content in table: %s", out)
	}
}

func TestJSONAndSARIFReportFormats(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	rep := schema.NewReport([]schema.Finding{
		{
			ID:          "web-201-1",
			RuleID:      "WEB-201",
			Module:      "config",
			Layer:       schema.LayerWeb,
			Severity:    schema.SeverityHigh,
			Title:       "Deprecated TLS protocol",
			Description: "TLSv1 enabled",
			Target:      "file://testdata/nginx_insecure.conf",
			Evidence:    map[string]any{"line": 5},
			Remediation: "Restrict to TLSv1.2 TLSv1.3",
			MitreD3FEND: "D3-CH",
			Timestamp:   now,
		},
		{
			ID:          "web-201-2",
			RuleID:      "WEB-201",
			Module:      "config",
			Layer:       schema.LayerWeb,
			Severity:    schema.SeverityMedium,
			Title:       "Duplicate rule check",
			Description: "Second finding",
			Target:      "file://testdata/nginx_insecure.conf",
			Evidence:    map[string]any{"line": 8},
			Remediation: "Fix TLS",
			MitreD3FEND: "D3-CH",
			Timestamp:   now,
		},
		{
			ID:          "web-001-1",
			RuleID:      "WEB-001",
			Module:      "headers",
			Layer:       schema.LayerWeb,
			Severity:    schema.SeverityHigh,
			Title:       "Missing HSTS",
			Description: "No HSTS header",
			Target:      "https://example.com",
			Remediation: "Add HSTS",
			MitreD3FEND: "D3-HI",
			Timestamp:   now,
		},
	}, now)

	jsonOut, err := FormatJSONRender(rep)
	if err != nil {
		t.Fatal(err)
	}
	var parsedJSON map[string]any
	if err := json.Unmarshal([]byte(jsonOut), &parsedJSON); err != nil {
		t.Fatal(err)
	}
	if parsedJSON["schema_version"] != "1.0" || parsedJSON["layer"] != "web-defense" {
		t.Fatalf("unexpected JSON metadata: %+v", parsedJSON)
	}

	sarifOut, err := FormatSARIFRender(rep)
	if err != nil {
		t.Fatal(err)
	}
	var sarif map[string]any
	if err := json.Unmarshal([]byte(sarifOut), &sarif); err != nil {
		t.Fatal(err)
	}
	if sarif["version"] != "2.1.0" {
		t.Fatalf("unexpected SARIF version: %v", sarif["version"])
	}
	runs := sarif["runs"].([]any)
	run0 := runs[0].(map[string]any)
	driver := run0["tool"].(map[string]any)["driver"].(map[string]any)
	rules := driver["rules"].([]any)
	if len(rules) != 2 {
		t.Fatalf("expected 2 deduplicated rules, got %d", len(rules))
	}
	if rules[0].(map[string]any)["id"] != "WEB-001" || rules[1].(map[string]any)["id"] != "WEB-201" {
		t.Fatalf("rules not sorted deterministically: %+v", rules)
	}
	results := run0["results"].([]any)
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	loc0 := results[0].(map[string]any)["locations"].([]any)[0].(map[string]any)
	phys0 := loc0["physicalLocation"].(map[string]any)
	region0 := phys0["region"].(map[string]any)
	if int(region0["startLine"].(float64)) != 5 {
		t.Fatalf("expected startLine 5, got %v", region0["startLine"])
	}
}
