package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luminariadev/raksa-webshield/internal/schema"
)

func TestApplyPolicySuppressionsAndExpiration(t *testing.T) {
	today := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	p := &Policy{
		MinSeverity: schema.SeverityMedium,
		Suppressions: []Suppression{
			{
				RuleID:         "WEB-004",
				TargetContains: "legacy.example",
				Reason:         "Tracked in ticket SEC-42",
				ExpiresOn:      "2026-12-31",
			},
			{
				RuleID:    "WEB-002",
				Reason:    "Expired exception",
				ExpiresOn: "2026-01-01",
			},
		},
	}

	findings := []schema.Finding{
		{RuleID: "WEB-005", Severity: schema.SeverityLow, Target: "https://app.example"},
		{RuleID: "WEB-004", Severity: schema.SeverityMedium, Target: "https://legacy.example/app"},
		{RuleID: "WEB-004", Severity: schema.SeverityMedium, Target: "https://prod.example/app"},
		{RuleID: "WEB-002", Severity: schema.SeverityHigh, Target: "https://prod.example/app"},
	}

	kept, count := ApplyPolicy(findings, p, today)
	if count != 2 {
		t.Fatalf("expected 2 filtered findings (1 min_severity + 1 active suppression), got %d", count)
	}
	if len(kept) != 2 || kept[0].Target != "https://prod.example/app" || kept[1].RuleID != "WEB-002" {
		t.Fatalf("unexpected kept findings: %+v", kept)
	}
}

func TestLoadPolicyValidation(t *testing.T) {
	dir := t.TempDir()
	badPath := filepath.Join(dir, "bad.yml")
	if err := os.WriteFile(badPath, []byte("suppressions:\n  - rule_id: WEB-001\n    reason: ok\n    expires_on: 2026/11/26\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicy(badPath); err == nil {
		t.Fatalf("expected invalid date format error")
	}

	goodPath := filepath.Join(dir, "good.yml")
	if err := os.WriteFile(goodPath, []byte("min_severity: low\nsuppressions:\n  - rule_id: WEB-005\n    reason: cdn sets server banner\n    expires_on: \"2027-06-30\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadPolicy(goodPath)
	if err != nil {
		t.Fatalf("unexpected error loading good policy: %v", err)
	}
	if loaded.MinSeverity != schema.SeverityLow || len(loaded.Suppressions) != 1 {
		t.Fatalf("unexpected loaded policy: %+v", loaded)
	}
}
