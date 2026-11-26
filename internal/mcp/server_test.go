package mcp

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luminariadev/raksa-webshield/internal/auditor"
)

func runSession(t *testing.T, lines []string) []map[string]any {
	t.Helper()
	input := strings.Join(lines, "\n") + "\n"
	var out bytes.Buffer
	if err := ServeStreams(strings.NewReader(input), &out); err != nil {
		t.Fatalf("ServeStreams failed: %v", err)
	}
	var res []map[string]any
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var item map[string]any
		if err := json.Unmarshal([]byte(line), &item); err != nil {
			t.Fatalf("invalid json response %q: %v", line, err)
		}
		res = append(res, item)
	}
	return res
}

func TestMCPLifecycleToolsListRulesAndErrorCodes(t *testing.T) {
	res := runSession(t, []string{
		"not-json",
		`{"jsonrpc":"1.0","id":0,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"webshield_list_rules","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"unknown/method"}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"missing_tool"}}`,
	})

	if len(res) != 7 {
		t.Fatalf("expected 7 responses (notification omitted), got %d", len(res))
	}
	if int(res[0]["error"].(map[string]any)["code"].(float64)) != -32700 {
		t.Fatalf("expected -32700 parse error")
	}
	if int(res[1]["error"].(map[string]any)["code"].(float64)) != -32600 {
		t.Fatalf("expected -32600 invalid request")
	}
	tools := res[3]["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 8 {
		t.Fatalf("expected 8 MCP tools, got %d", len(tools))
	}

	rulesText := res[4]["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	var rules []any
	if err := json.Unmarshal([]byte(rulesText), &rules); err != nil {
		t.Fatal(err)
	}
	if len(rules) != 30 {
		t.Fatalf("expected 30 rules, got %d", len(rules))
	}
	if int(res[5]["error"].(map[string]any)["code"].(float64)) != -32601 {
		t.Fatalf("expected -32601 method not found")
	}
	if int(res[6]["error"].(map[string]any)["code"].(float64)) != -32602 {
		t.Fatalf("expected -32602 invalid params")
	}
}

func TestMCPToolAuditsSizeGuardSSRFAndPolicy(t *testing.T) {
	oversized := strings.Repeat("A", auditor.MaxConfigBytes+10)
	bigReq, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      10,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "webshield_inspect_payload",
			"arguments": map[string]any{"payload": oversized},
		},
	})

	ssrfReq, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      11,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "webshield_audit_headers",
			"arguments": map[string]any{"url": "http://169.254.169.254/latest/meta-data/"},
		},
	})

	cspReq, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      12,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "webshield_audit_csp",
			"arguments": map[string]any{"csp": "default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval'"},
		},
	})

	wsPath := filepath.Join("..", "..", "testdata")
	polPath := filepath.Join("..", "..", "testdata", "policy_suppress.yml")
	wsReq, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      13,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "webshield_audit_workspace",
			"arguments": map[string]any{
				"path":        wsPath,
				"policy_path": polPath,
			},
		},
	})

	res := runSession(t, []string{string(bigReq), string(ssrfReq), string(cspReq), string(wsReq)})
	if len(res) != 4 {
		t.Fatalf("expected 4 responses, got %d", len(res))
	}
	if int(res[0]["error"].(map[string]any)["code"].(float64)) != -32602 {
		t.Fatalf("expected -32602 on oversized inline payload")
	}
	if !res[1]["result"].(map[string]any)["isError"].(bool) {
		t.Fatalf("expected SSRF block tool error")
	}

	cspText := res[2]["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	var cspRep map[string]any
	if err := json.Unmarshal([]byte(cspText), &cspRep); err != nil {
		t.Fatal(err)
	}
	if int(cspRep["summary"].(map[string]any)["total"].(float64)) == 0 {
		t.Fatalf("expected unsafe CSP findings")
	}

	wsText := res[3]["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	var wsRep map[string]any
	if err := json.Unmarshal([]byte(wsText), &wsRep); err != nil {
		t.Fatal(err)
	}
	for _, item := range wsRep["findings"].([]any) {
		f := item.(map[string]any)
		if f["rule_id"] == "WEB-005" && strings.Contains(f["target"].(string), "headers_insecure.http") {
			t.Fatalf("WEB-005 on headers_insecure.http should be suppressed by policy")
		}
	}

	remReq, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      14,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "webshield_generate_remediation",
			"arguments": map[string]any{
				"target":  "nginx",
				"profile": "strict",
			},
		},
	})
	wafThrReq, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      15,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "webshield_inspect_payload",
			"arguments": map[string]any{
				"payload":           "; id",
				"paranoia_level":    2,
				"anomaly_threshold": 9,
			},
		},
	})
	res2 := runSession(t, []string{string(remReq), string(wafThrReq)})
	remText := res2[0]["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(remText, "ssl_protocols TLSv1.2 TLSv1.3;") {
		t.Fatalf("expected hardened nginx snippet from MCP remediation tool, got: %s", remText)
	}
	wafText := res2[1]["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	var wafRep map[string]any
	if err := json.Unmarshal([]byte(wafText), &wafRep); err != nil {
		t.Fatal(err)
	}
	if int(wafRep["summary"].(map[string]any)["total"].(float64)) != 0 {
		t.Fatalf("expected anomaly_threshold=9 to suppress score-5 finding")
	}

	valOkReq, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      16,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "webshield_validate_custom_rules",
			"arguments": map[string]any{
				"yaml_content": "rules:\n  - id: R-GQL\n    match_type: regex\n    pattern: \"__schema\"\n    action: block\n",
				"test_payload": "{ __schema { queryType { name } } }",
			},
		},
	})
	valBadReq, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      17,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "webshield_validate_custom_rules",
			"arguments": map[string]any{
				"yaml_content": "rules:\n  - id: R-BAD\n    match_type: regex\n    pattern: \"[invalid\"\n",
			},
		},
	})
	customInspectReq, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      18,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "webshield_inspect_payload",
			"arguments": map[string]any{
				"payload":           "/actuator/env",
				"custom_rules_path": filepath.Join("..", "..", "examples", "custom-waf-rules.yml"),
			},
		},
	})
	res3 := runSession(t, []string{string(valOkReq), string(valBadReq), string(customInspectReq)})
	valOkText := res3[0]["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	var valOut map[string]any
	if err := json.Unmarshal([]byte(valOkText), &valOut); err != nil {
		t.Fatal(err)
	}
	if !valOut["valid"].(bool) || !valOut["dry_run_would_block"].(bool) {
		t.Fatalf("expected valid custom rules with dry_run_would_block=true, got %+v", valOut)
	}
	if !res3[1]["result"].(map[string]any)["isError"].(bool) {
		t.Fatalf("expected invalid regex YAML to return isError=true")
	}
	ciText := res3[2]["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(ciText, "WEB-311") {
		t.Fatalf("expected WEB-311 from custom_rules_path in MCP inspect, got %s", ciText)
	}
}
