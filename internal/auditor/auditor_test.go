package auditor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestV2CSPBypassNonceStrictDynamicCOOPAndSmartCookies(t *testing.T) {
	bypassCSP := AuditCSP("default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; object-src 'none'; base-uri 'self'", "inline://csp")
	if !ruleSet(bypassCSP)["WEB-006"] {
		t.Fatalf("expected WEB-006 for CDN bypass host and missing form-action")
	}

	modernNonceCSP := AuditCSP(
		"default-src 'none'; script-src 'nonce-abc123' 'strict-dynamic' 'unsafe-inline' https://cdn.jsdelivr.net; object-src 'none'; base-uri 'self'; form-action 'self'",
		"inline://modern",
	)
	if len(modernNonceCSP) != 0 {
		t.Fatalf("expected 0 findings when nonce + strict-dynamic ignores fallback unsafe-inline/CDN, got %+v", modernNonceCSP)
	}

	xsrfHdr, err := ParseRawHeaders(
		"Strict-Transport-Security: max-age=31536000\n" +
			"Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'\n" +
			"X-Content-Type-Options: nosniff\n" +
			"Referrer-Policy: no-referrer\n" +
			"Permissions-Policy: camera=()\n" +
			"Cross-Origin-Opener-Policy: same-origin\n" +
			"Cross-Origin-Resource-Policy: same-origin\n" +
			"Cache-Control: no-store\n" +
			"Set-Cookie: XSRF-TOKEN=abc; Secure; SameSite=Strict; Path=/\n",
	)
	if err != nil {
		t.Fatal(err)
	}
	xsrfFindings := AuditHeaders(xsrfHdr, "https://app.example.com")
	if ruleSet(xsrfFindings)["WEB-103"] {
		t.Fatalf("XSRF-TOKEN with Secure flag should not require HttpOnly, got %+v", xsrfFindings)
	}

	noCacheHdr, err := ParseRawHeaders("Strict-Transport-Security: max-age=31536000\nSet-Cookie: sid=secret; Secure; HttpOnly; SameSite=Strict\n")
	if err != nil {
		t.Fatal(err)
	}
	if !ruleSet(AuditHeaders(noCacheHdr, "https://app.example.com"))["WEB-007"] {
		t.Fatalf("expected WEB-007 for missing COOP/CORP/Cache-Control: no-store")
	}
}

func TestV2NginxASTCaddyVercelIngressAndLiveTLS(t *testing.T) {
	gixy, err := AuditConfigPath(filepath.Join("..", "..", "testdata", "nginx_gixy_bugs.conf"))
	if err != nil {
		t.Fatal(err)
	}
	gRules := ruleSet(gixy)
	for _, want := range []string{"WEB-205", "WEB-206", "WEB-207"} {
		if !gRules[want] {
			t.Fatalf("expected %s from nginx_gixy_bugs.conf, got %+v", want, gRules)
		}
	}

	caddy, err := AuditConfigPath(filepath.Join("..", "..", "testdata", "Caddyfile"))
	if err != nil {
		t.Fatal(err)
	}
	cRules := ruleSet(caddy)
	for _, want := range []string{"WEB-201", "WEB-202", "WEB-203", "WEB-207"} {
		if !cRules[want] {
			t.Fatalf("expected %s from Caddyfile, got %+v", want, cRules)
		}
	}

	vercel := AuditConfigContent(`{"headers":[{"source":"/(.*)","headers":[{"key":"Access-Control-Allow-Origin","value":"*"}]}]}`, "file://vercel.json")
	if !ruleSet(vercel)["WEB-203"] {
		t.Fatalf("expected WEB-203 from vercel.json")
	}

	netlify := AuditConfigContent("/*\n  Content-Security-Policy: script-src 'unsafe-inline'\n", "file://_headers")
	if !ruleSet(netlify)["WEB-203"] {
		t.Fatalf("expected WEB-203 from _headers")
	}

	k8s := AuditConfigContent("apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  annotations:\n    nginx.ingress.kubernetes.io/ssl-redirect: \"false\"\n    nginx.ingress.kubernetes.io/cors-allow-origin: \"*\"\n", "file://app-ingress.yaml")
	kRules := ruleSet(k8s)
	if !kRules["WEB-207"] || !kRules["WEB-203"] {
		t.Fatalf("expected WEB-207 and WEB-203 from k8s ingress, got %+v", kRules)
	}

	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	tlsFindings := inspectTLSState(&tls.ConnectionState{
		Version: tls.VersionTLS10,
		PeerCertificates: []*x509.Certificate{
			{NotAfter: now.Add(-24 * time.Hour)},
		},
	}, "https://expired.example.com", now)
	tlsRules := ruleSet(tlsFindings)
	if !tlsRules["WEB-201"] || !tlsRules["WEB-207"] {
		t.Fatalf("expected WEB-201 and WEB-207 on deprecated TLS + expired cert, got %+v", tlsRules)
	}
}

func TestV2AdvancedWAFLayersAnomalyScoringAndSelfAuditRemediation(t *testing.T) {
	adv, err := InspectPayloadFile(filepath.Join("..", "..", "testdata", "payload_advanced.json"))
	if err != nil {
		t.Fatal(err)
	}
	aRules := ruleSet(adv)
	for _, want := range []string{"WEB-302", "WEB-303", "WEB-305", "WEB-306", "WEB-307", "WEB-308", "WEB-309", "WEB-310"} {
		if !aRules[want] {
			t.Fatalf("expected %s in payload_advanced.json findings, got %+v", want, aRules)
		}
	}

	// Threshold 8 drops single Critical finding (score 5), passes combined score >= 9.
	lowScore, err := InspectPayloadWithOptions("; whoami", "inline://single", InspectOptions{ParanoiaLevel: 1, AnomalyThreshold: 8})
	if err != nil || len(lowScore) != 0 {
		t.Fatalf("expected findings below anomaly threshold 8 to be suppressed, got %+v err=%v", lowScore, err)
	}
	highScore, err := InspectPayloadWithOptions("; whoami && {{7*7}}", "inline://combo", InspectOptions{ParanoiaLevel: 1, AnomalyThreshold: 8})
	if err != nil || len(highScore) < 2 {
		t.Fatalf("expected combined findings to clear threshold 8, got %+v err=%v", highScore, err)
	}

	// Self-audit guarantee: generated snippets must yield 0 findings (100/100 A+).
	for _, profile := range []string{"strict", "balanced"} {
		hdrRaw, err := GenerateHardenedConfig("headers", profile, "https://app.example.com")
		if err != nil {
			t.Fatal(err)
		}
		hdr, err := ParseRawHeaders(hdrRaw)
		if err != nil {
			t.Fatal(err)
		}
		if f := AuditHeaders(hdr, "https://app.example.com"); len(f) != 0 {
			t.Fatalf("generated headers (%s) produced findings: %+v", profile, f)
		}

		nginxRaw, err := GenerateHardenedConfig("nginx", profile, "https://app.example.com")
		if err != nil {
			t.Fatal(err)
		}
		if f := AuditConfigContent(nginxRaw, "file://nginx.conf"); len(f) != 0 {
			t.Fatalf("generated nginx (%s) produced findings: %+v", profile, f)
		}

		caddyRaw, err := GenerateHardenedConfig("caddy", profile, "https://app.example.com")
		if err != nil {
			t.Fatal(err)
		}
		if f := AuditConfigContent(caddyRaw, "file://Caddyfile"); len(f) != 0 {
			t.Fatalf("generated caddy (%s) produced findings: %+v", profile, f)
		}
	}

	if _, err := GenerateHardenedConfig("nginx", "strict", "*"); err == nil {
		t.Fatalf("expected unsafe wildcard origin to be rejected")
	}
}

func TestV3SemanticSQLiAndXSSTokenizersAndZeroFalsePositives(t *testing.T) {
	sqliVectors := []string{
		`1' AND 2>1--`,
		`admin'/**/OR/**/'a'='a`,
		`1) UNION ALL SELECT NULL,NULL--`,
		`1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--`,
		`1' AND BENCHMARK(5000000,MD5(1))--`,
		`1' AND PG_SLEEP(5)--`,
		`1' ORDER BY 10--`,
		`1; EXEC xp_cmdshell`,
		`1' OR 1 IN (SELECT 1)--`,
	}
	for _, vec := range sqliVectors {
		findings, err := InspectPayload(vec, "inline://sqli")
		if err != nil {
			t.Fatalf("InspectPayload(%q): %v", vec, err)
		}
		if !ruleSet(findings)["WEB-302"] {
			t.Fatalf("expected WEB-302 SQLi detection for %q, got %+v", vec, findings)
		}
	}

	xssVectors := []string{
		`<img/src=x/onerror=alert(1)>`,
		`<details open ontoggle=alert(1)>`,
		`<body/onload=alert(1)>`,
		`<a href="java&#x09;script:alert(1)">tap</a>`,
		`<meta http-equiv="refresh" content="0;url=javascript:alert(1)">`,
		`<form action="javascript:alert(1)"><input type="submit"></form>`,
	}
	for _, vec := range xssVectors {
		findings, err := InspectPayload(vec, "inline://xss")
		if err != nil {
			t.Fatalf("InspectPayload(%q): %v", vec, err)
		}
		if !ruleSet(findings)["WEB-301"] {
			t.Fatalf("expected WEB-301 XSS detection for %q, got %+v", vec, findings)
		}
	}

	benignProse := []string{
		`{"comment":"Hello world 1+1=2","path":"/docs/security","author":"alice"}`,
		`Please select a book from our catalog and order by popularity`,
		`It's false and alice or bob agreed 1+1=2`,
		`Please use SELECT item_id FROM menu style descriptions in prose only.`,
		`<p>Comparison: x &lt; y is valid in math class.</p>`,
	}
	for _, text := range benignProse {
		findings, err := InspectPayload(text, "inline://benign")
		if err != nil {
			t.Fatalf("InspectPayload(%q): %v", text, err)
		}
		if len(findings) != 0 {
			t.Fatalf("unexpected false positive on benign prose %q: %+v", text, findings)
		}
	}
}
