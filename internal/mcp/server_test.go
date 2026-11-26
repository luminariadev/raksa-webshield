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
	if len(tools) != 6 {
		t.Fatalf("expected 6 MCP tools, got %d", len(tools))
	}

	rulesText := res[4]["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	var rules []any
	if err := json.Unmarshal([]byte(rulesText), &rules); err != nil {
		t.Fatal(err)
	}
	if len(rules) != 18 {
		t.Fatalf("expected 18 rules, got %d", len(rules))
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
}
