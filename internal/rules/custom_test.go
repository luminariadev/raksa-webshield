package rules

import (
	"path/filepath"
	"testing"
)

func TestLoadExampleCustomWAFRules(t *testing.T) {
	rs, err := LoadCustomRules(filepath.Join("..", "..", "examples", "custom-waf-rules.yml"))
	if err != nil {
		t.Fatalf("load example custom rules: %v", err)
	}
	if rs.RuleCount() != 3 {
		t.Fatalf("expected 3 rules in example file, got %d", rs.RuleCount())
	}

	findings, shouldBlock, score := rs.Evaluate(`{"query":"{ __schema { types { name } } }"}`, "body", "inline://gql")
	if len(findings) != 1 || !shouldBlock || score < 4 {
		t.Fatalf("expected GraphQL introspection rule hit with block, got findings=%+v block=%v score=%d", findings, shouldBlock, score)
	}
	if findings[0].RuleID != "WEB-311" {
		t.Fatalf("expected RuleID WEB-311, got %s", findings[0].RuleID)
	}

	cleanFindings, cleanBlock, cleanScore := rs.Evaluate(`{"query":"{ viewer { login } }"}`, "body", "inline://ok")
	if len(cleanFindings) != 0 || cleanBlock || cleanScore != 0 {
		t.Fatalf("expected benign GraphQL query to pass cleanly")
	}
}

func TestCustomRulesMatchingModesActionsScopesAndErrors(t *testing.T) {
	yamlDoc := []byte(`
version: "1.0"
rules:
  - id: VPATCH-EXACT
    title: Block exact debug path
    severity: medium
    targets: [path]
    match_type: exact
    pattern: "/debug/pprof"
    action: block
  - id: VPATCH-MON
    title: Monitor legacy token query parameter
    severity: low
    targets: [query]
    match_type: regex
    pattern: "legacy_secret=[A-Za-z0-9]{6,}"
    case_insensitive: true
    action: monitor
`)
	rs, err := ParseCustomRules(yamlDoc, "inline://rules.yml")
	if err != nil {
		t.Fatal(err)
	}

	// Wrong scope must skip exact path rule.
	fWrongScope, _, _ := rs.Evaluate("/debug/pprof", "body", "inline://t")
	if len(fWrongScope) != 0 {
		t.Fatalf("path rule should not match body scope")
	}

	// Right scope triggers exact block.
	fPath, blk, _ := rs.Evaluate("/debug/pprof", "path", "inline://t")
	if len(fPath) != 1 || !blk {
		t.Fatalf("expected exact path match to block")
	}

	// Monitor action emits finding without setting shouldBlock.
	fMon, monBlk, _ := rs.Evaluate("LEGACY_SECRET=Abc12345", "query", "inline://t")
	if len(fMon) != 1 || monBlk {
		t.Fatalf("expected monitor finding with shouldBlock=false, got len=%d blk=%v", len(fMon), monBlk)
	}

	// Validation error cases: bad regex, duplicate ID, empty pattern, bad action.
	for name, bad := range map[string]string{
		"bad_regex":     "rules:\n  - id: R1\n    match_type: regex\n    pattern: \"[unclosed\"\n",
		"dup_id":        "rules:\n  - id: R1\n    pattern: foo\n  - id: R1\n    pattern: bar\n",
		"empty_pattern": "rules:\n  - id: R1\n    pattern: \"\"\n",
		"bad_action":    "rules:\n  - id: R1\n    pattern: foo\n    action: drop_conn\n",
	} {
		if _, err := ParseCustomRules([]byte(bad), name); err == nil {
			t.Fatalf("expected validation error for %s", name)
		}
	}
}
