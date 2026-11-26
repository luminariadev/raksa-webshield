package auditor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luminariadev/raksa-webshield/internal/schema"
)

func ruleSet(findings []schema.Finding) map[string]bool {
	out := make(map[string]bool, len(findings))
	for _, f := range findings {
		out[f.RuleID] = true
	}
	return out
}

func TestHeaderFixturesHardenedVsInsecureAndSecretRedaction(t *testing.T) {
	clean, err := AuditHeadersFile(filepath.Join("..", "..", "testdata", "headers_hardened.http"))
	if err != nil {
		t.Fatalf("audit hardened headers: %v", err)
	}
	if len(clean) != 0 {
		t.Fatalf("expected 0 findings on hardened headers, got %+v", clean)
	}

	bad, err := AuditHeadersFile(filepath.Join("..", "..", "testdata", "headers_insecure.http"))
	if err != nil {
		t.Fatalf("audit insecure headers: %v", err)
	}
	rules := ruleSet(bad)
	for _, expected := range []string{"WEB-001", "WEB-003", "WEB-004", "WEB-005", "WEB-101", "WEB-103", "WEB-104"} {
		if !rules[expected] {
			t.Fatalf("expected %s in insecure header findings, got %+v", expected, rules)
		}
	}

	rawJSON, err := json.Marshal(bad)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawJSON), "demo_cookie_secret_123") {
		t.Fatalf("cookie value leaked into serialized findings")
	}

	// Missing CSP triggers WEB-002; non-credential wildcard CORS triggers WEB-102.
	hdr, err := ParseRawHeaders("Strict-Transport-Security: max-age=31536000\nAccess-Control-Allow-Origin: *\nX-Frame-Options: DENY\nX-Content-Type-Options: nosniff\nReferrer-Policy: no-referrer\nPermissions-Policy: camera=()\n")
	if err != nil {
		t.Fatal(err)
	}
	minFindings := AuditHeaders(hdr, "inline://min")
	minRules := ruleSet(minFindings)
	if !minRules["WEB-002"] || !minRules["WEB-102"] {
		t.Fatalf("expected WEB-002 and WEB-102, got %+v", minRules)
	}
}

func TestProxyConfigFixturesAndDirectorySkips(t *testing.T) {
	clean, err := AuditConfigPath(filepath.Join("..", "..", "testdata", "nginx_hardened.conf"))
	if err != nil {
		t.Fatalf("audit hardened nginx: %v", err)
	}
	if len(clean) != 0 {
		t.Fatalf("expected 0 findings on hardened nginx config, got %+v", clean)
	}

	bad, err := AuditConfigPath(filepath.Join("..", "..", "testdata", "nginx_insecure.conf"))
	if err != nil {
		t.Fatalf("audit insecure nginx: %v", err)
	}
	rules := ruleSet(bad)
	for _, expected := range []string{"WEB-201", "WEB-202", "WEB-203", "WEB-204"} {
		if !rules[expected] {
			t.Fatalf("expected %s in insecure nginx findings, got %+v", expected, rules)
		}
	}
}

func TestPayloadBenignMaliciousAndEncodedEvasion(t *testing.T) {
	benign, err := InspectPayloadFile(filepath.Join("..", "..", "testdata", "payload_benign.json"))
	if err != nil {
		t.Fatalf("inspect benign payload: %v", err)
	}
	if len(benign) != 0 {
		t.Fatalf("expected 0 findings on benign payload, got %+v", benign)
	}

	bad, err := InspectPayloadFile(filepath.Join("..", "..", "testdata", "payload_malicious.json"))
	if err != nil {
		t.Fatalf("inspect malicious payload: %v", err)
	}
	rules := ruleSet(bad)
	for _, expected := range []string{"WEB-301", "WEB-302", "WEB-303", "WEB-304", "WEB-305"} {
		if !rules[expected] {
			t.Fatalf("expected %s in malicious payload findings, got %+v", expected, rules)
		}
	}

	encoded, err := InspectPayload("q=%253Cscript%253Ealert(1)%253C%252Fscript%253E&path=%2e%2e%2fetc%2fpasswd", "inline://encoded")
	if err != nil {
		t.Fatal(err)
	}
	encRules := ruleSet(encoded)
	if !encRules["WEB-301"] || !encRules["WEB-303"] {
		t.Fatalf("expected URL-decoded XSS & traversal findings, got %+v", encRules)
	}
}

func TestLiveSSRFProtectionAndLocalMockServerAudit(t *testing.T) {
	for _, blocked := range []string{
		"http://127.0.0.1:8080/health",
		"http://localhost:3000",
		"http://169.254.169.254/latest/meta-data/",
		"http://metadata.google.internal/computeMetadata/v1/",
		"file:///etc/passwd",
	} {
		if _, err := ValidateLiveURL(blocked, false); err == nil {
			t.Fatalf("expected SSRF block for %q when allowPrivate=false", blocked)
		}
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Header().Set("Server", "nginx/1.25.1")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	findings, err := FetchAndAuditURL(context.Background(), srv.URL, true)
	if err != nil {
		t.Fatalf("FetchAndAuditURL with allowPrivate=true failed: %v", err)
	}
	rules := ruleSet(findings)
	if !rules["WEB-101"] || !rules["WEB-002"] {
		t.Fatalf("expected reflected CORS WEB-101 and missing CSP WEB-002, got %+v", rules)
	}
}

func TestAuditWorkspaceSkipsIgnoredDirectories(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "nginx.conf"), []byte("server_tokens on;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app_headers.http"), []byte("HTTP/1.1 200 OK\nX-Powered-By: Express\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ignored := filepath.Join(dir, "node_modules")
	if err := os.MkdirAll(ignored, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ignored, "nginx.conf"), []byte("client_max_body_size 0;\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	findings, err := AuditWorkspace(dir)
	if err != nil {
		t.Fatalf("AuditWorkspace: %v", err)
	}
	rules := ruleSet(findings)
	if !rules["WEB-202"] || !rules["WEB-005"] {
		t.Fatalf("expected WEB-202 and WEB-005, got %+v", rules)
	}
	if rules["WEB-204"] {
		t.Fatalf("node_modules/nginx.conf should be skipped by AuditWorkspace")
	}
}
