package schema

import (
	"testing"
	"time"
)

func TestParseSeverityAndThresholds(t *testing.T) {
	sev, err := ParseSeverity(" CRITICAL ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sev != SeverityCritical {
		t.Fatalf("got %q want %q", sev, SeverityCritical)
	}
	if !SeverityHigh.MeetsThreshold(SeverityMedium) {
		t.Fatalf("high should meet medium threshold")
	}
	if SeverityLow.MeetsThreshold(SeverityHigh) {
		t.Fatalf("low must not meet high threshold")
	}
	if _, err := ParseSeverity("bogus"); err == nil {
		t.Fatalf("expected error for invalid severity")
	}
}

func TestRuleCatalogContains18UniqueRules(t *testing.T) {
	rules := RuleCatalog()
	if len(rules) != 18 {
		t.Fatalf("expected 18 rules, got %d", len(rules))
	}
	seen := make(map[string]struct{}, len(rules))
	for _, r := range rules {
		if r.RuleID == "" || r.Title == "" || r.OwaspASVS == "" || r.MitreD3FEND == "" {
			t.Fatalf("incomplete rule metadata: %+v", r)
		}
		if _, dup := seen[r.RuleID]; dup {
			t.Fatalf("duplicate rule id %q", r.RuleID)
		}
		seen[r.RuleID] = struct{}{}
	}
}

func TestReportSummaryAndBreach(t *testing.T) {
	now := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	findings := []Finding{
		{RuleID: "WEB-001", Severity: SeverityHigh},
		{RuleID: "WEB-101", Severity: SeverityCritical},
		{RuleID: "WEB-005", Severity: SeverityLow},
	}
	rep := NewReport(findings, now)
	if rep.SchemaVersion != SchemaVersion || rep.Tool != ToolName || rep.Layer != LayerWeb {
		t.Fatalf("unexpected report header metadata: %+v", rep)
	}
	if rep.Summary.Total != 3 || rep.Summary.Critical != 1 || rep.Summary.High != 1 || rep.Summary.Low != 1 {
		t.Fatalf("unexpected summary: %+v", rep.Summary)
	}
	if !rep.HasThresholdBreach(SeverityCritical) {
		t.Fatalf("expected critical breach")
	}
	if rep.HasThresholdBreach("") {
		t.Fatalf("empty threshold must not breach")
	}
}
