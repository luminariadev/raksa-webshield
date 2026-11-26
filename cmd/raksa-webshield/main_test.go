package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIVersionRulesAndErrors(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"version"}, nil, &out, &errOut)
	if code != 0 || !strings.Contains(out.String(), "raksa-webshield") || !strings.Contains(out.String(), "web-defense") {
		t.Fatalf("unexpected version output: code=%d out=%q err=%q", code, out.String(), errOut.String())
	}

	out.Reset()
	errOut.Reset()
	code = run([]string{"rules", "--format", "json"}, nil, &out, &errOut)
	if code != 0 {
		t.Fatalf("rules failed: code=%d err=%q", code, errOut.String())
	}
	var rules []any
	if err := json.Unmarshal(out.Bytes(), &rules); err != nil || len(rules) != 18 {
		t.Fatalf("expected 18 rules JSON, got len=%d err=%v", len(rules), err)
	}

	out.Reset()
	errOut.Reset()
	if code = run([]string{"unknown-cmd"}, nil, &out, &errOut); code != 1 {
		t.Fatalf("expected exit 1 on unknown subcommand, got %d", code)
	}

	out.Reset()
	errOut.Reset()
	if code = run([]string{"audit-headers", "--file", "missing_headers.http"}, nil, &out, &errOut); code != 1 {
		t.Fatalf("expected exit 1 on missing file, got %d", code)
	}
}

func TestCLIAuditHeadersConfigPayloadWorkspaceAndSARIF(t *testing.T) {
	td := filepath.Join("..", "..", "testdata")

	var out, errOut bytes.Buffer
	code := run([]string{"audit-headers", "--file", filepath.Join(td, "headers_hardened.http"), "--fail-on", "low"}, nil, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit 0 on hardened headers, got %d (%s)", code, errOut.String())
	}

	out.Reset()
	errOut.Reset()
	code = run([]string{
		"audit-headers",
		"--file", filepath.Join(td, "headers_insecure.http"),
		"--policy", filepath.Join(td, "policy_suppress.yml"),
		"--format", "sarif",
		"--fail-on", "critical",
	}, nil, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit 2 on insecure headers, got %d", code)
	}
	if !strings.Contains(out.String(), `"version": "2.1.0"`) || strings.Contains(out.String(), "demo_cookie_secret_123") {
		t.Fatalf("invalid SARIF or unredacted secret in CLI output")
	}

	out.Reset()
	errOut.Reset()
	code = run([]string{"audit-csp", "--policy-string", "script-src 'unsafe-inline'", "--fail-on", "high"}, nil, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit 2 on unsafe CSP, got %d", code)
	}

	out.Reset()
	errOut.Reset()
	code = run([]string{"audit-config", "--path", filepath.Join(td, "nginx_hardened.conf"), "--fail-on", "low"}, nil, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit 0 on hardened nginx config, got %d", code)
	}

	out.Reset()
	errOut.Reset()
	code = run([]string{"audit-config", "--path", filepath.Join(td, "nginx_insecure.conf"), "--fail-on", "high"}, nil, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit 2 on insecure nginx config, got %d", code)
	}

	out.Reset()
	errOut.Reset()
	code = run([]string{"inspect-request", "--file", filepath.Join(td, "payload_benign.json"), "--fail-on", "low"}, nil, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit 0 on benign payload, got %d", code)
	}

	out.Reset()
	errOut.Reset()
	code = run([]string{"inspect-request", "--file", filepath.Join(td, "payload_malicious.json"), "--fail-on", "critical"}, nil, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit 2 on malicious payload, got %d", code)
	}

	out.Reset()
	errOut.Reset()
	code = run([]string{"audit-workspace", "--path", td, "--format", "json", "--fail-on", "critical"}, nil, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit 2 on testdata workspace, got %d", code)
	}
}

func TestCLIMCPStdioHandshake(t *testing.T) {
	req := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
	}, "\n") + "\n"

	var out, errOut bytes.Buffer
	code := run([]string{"mcp"}, strings.NewReader(req), &out, &errOut)
	if code != 0 {
		t.Fatalf("mcp failed: code=%d err=%q", code, errOut.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 RPC response lines, got %d: %q", len(lines), out.String())
	}
	var listResp map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &listResp); err != nil {
		t.Fatal(err)
	}
	tools := listResp["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 6 {
		t.Fatalf("expected 6 MCP tools, got %d", len(tools))
	}
}
