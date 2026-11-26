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

func TestRuleCatalogContains30UniqueRules(t *testing.T) {
	rules := RuleCatalog()
	if len(rules) != 30 {
		t.Fatalf("expected 30 rules, got %d", len(rules))
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

func TestComputePostureBoundariesAndClamping(t *testing.T) {
	cases := []struct {
		name     string
		findings []Finding
		want     int
		grade    string
	}{
		{"clean", nil, 100, "A+"},
		{"one_low_and_info", []Finding{{Severity: SeverityLow}, {Severity: SeverityInfo}}, 97, "A+"},
		{"one_medium", []Finding{{Severity: SeverityMedium}}, 92, "A"},
		{"one_high", []Finding{{Severity: SeverityHigh}}, 82, "B"},
		{"one_critical", []Finding{{Severity: SeverityCritical}}, 70, "C"},
		{"high_and_three_medium", []Finding{{Severity: SeverityHigh}, {Severity: SeverityMedium}, {Severity: SeverityMedium}, {Severity: SeverityMedium}}, 58, "D"},
		{"critical_and_high", []Finding{{Severity: SeverityCritical}, {Severity: SeverityHigh}}, 52, "F"},
		{"clamp_zero", []Finding{{Severity: SeverityCritical}, {Severity: SeverityCritical}, {Severity: SeverityCritical}, {Severity: SeverityCritical}}, 0, "F"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := ComputePosture(tc.findings)
			if p.Score != tc.want || p.Grade != tc.grade {
				t.Fatalf("got %d (%s), want %d (%s)", p.Score, p.Grade, tc.want, tc.grade)
			}
		})
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
