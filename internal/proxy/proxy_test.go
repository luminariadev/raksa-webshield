package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luminariadev/raksa-webshield/internal/rules"
)

func TestProxyEnforceMonitorCustomRulesHeadersAndMetrics(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Server", "legacy-app/1.0")
		w.Header().Set("X-Powered-By", "Express")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"ok":true,"path":%q,"body":%q}`, r.URL.Path, string(body))
	}))
	defer upstream.Close()

	customRules, err := rules.LoadCustomRules(filepath.Join("..", "..", "examples", "custom-waf-rules.yml"))
	if err != nil {
		t.Fatal(err)
	}

	var telemetry bytes.Buffer
	handler, err := NewHandler(Config{
		UpstreamURL:     upstream.URL,
		Mode:            "enforce",
		Profile:         "strict",
		ParanoiaLevel:   1,
		CustomRules:     customRules,
		ExcludePaths:    []string{"/public-ping"},
		TelemetryWriter: &telemetry,
	})
	if err != nil {
		t.Fatal(err)
	}
	proxySrv := httptest.NewServer(handler)
	defer proxySrv.Close()

	// 1. Benign POST passes with intact body, hardened headers, and stripped Server/X-Powered-By.
	respOk, err := http.Post(proxySrv.URL+"/api/comment", "application/json", strings.NewReader(`{"text":"hello"}`))
	if err != nil {
		t.Fatal(err)
	}
	okBody, _ := io.ReadAll(respOk.Body)
	_ = respOk.Body.Close()
	var echo struct {
		Ok   bool   `json:"ok"`
		Path string `json:"path"`
		Body string `json:"body"`
	}
	if err := json.Unmarshal(okBody, &echo); err != nil || !echo.Ok || echo.Body != `{"text":"hello"}` {
		t.Fatalf("benign POST failed: status=%d body=%s err=%v", respOk.StatusCode, string(okBody), err)
	}
	if respOk.Header.Get("Server") != "" || respOk.Header.Get("X-Powered-By") != "" {
		t.Fatalf("expected Server and X-Powered-By headers to be stripped")
	}
	if respOk.Header.Get("X-Frame-Options") != "DENY" || respOk.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("expected injected hardened security headers")
	}

	// 2. Semantic SQLi payload is blocked with opaque HTTP 403 and emits Raksa NDJSON telemetry.
	respSQLi, err := http.Get(proxySrv.URL + "/items?id=1%27%20AND%20PG_SLEEP(5)--")
	if err != nil {
		t.Fatal(err)
	}
	sqliBody, _ := io.ReadAll(respSQLi.Body)
	_ = respSQLi.Body.Close()
	if respSQLi.StatusCode != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 on semantic SQLi, got %d (%s)", respSQLi.StatusCode, string(sqliBody))
	}
	if strings.Contains(string(sqliBody), "WEB-302") || strings.Contains(string(sqliBody), "matched_sample") {
		t.Fatalf("403 response leaked internal rule details: %s", string(sqliBody))
	}
	var blockedJSON map[string]string
	if err := json.Unmarshal(sqliBody, &blockedJSON); err != nil || !strings.HasPrefix(blockedJSON["incident_id"], "inc-") {
		t.Fatalf("expected opaque incident_id JSON on 403, got %s", string(sqliBody))
	}

	// 3. Custom YAML rule blocks /actuator/env cleanly.
	respAct, err := http.Get(proxySrv.URL + "/actuator/env")
	if err != nil {
		t.Fatal(err)
	}
	_ = respAct.Body.Close()
	if respAct.StatusCode != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 on custom rule /actuator/env, got %d", respAct.StatusCode)
	}

	// 4. Custom rule with action: monitor (?api_key=...) passes in enforce mode while logging WEB-311 telemetry.
	respMonRule, err := http.Get(proxySrv.URL + "/v1/data?api_key=abcdef123456")
	if err != nil {
		t.Fatal(err)
	}
	_ = respMonRule.Body.Close()
	if respMonRule.StatusCode != http.StatusOK {
		t.Fatalf("expected monitor-action custom rule to allow request, got %d", respMonRule.StatusCode)
	}

	// 5. Verify Prometheus /metrics exposition format & counters.
	metricsText := handler.Metrics().RenderPrometheus()
	if !strings.Contains(metricsText, `raksa_webshield_requests_blocked_total 2`) ||
		!strings.Contains(metricsText, `raksa_webshield_findings_by_rule_total{rule_id="WEB-302"} 1`) ||
		!strings.Contains(metricsText, `raksa_webshield_findings_by_rule_total{rule_id="WEB-311"} 2`) {
		t.Fatalf("unexpected Prometheus metrics output:\n%s", metricsText)
	}

	// 6. Verify NDJSON telemetry stream contains full Raksa Finding Schema v1 events.
	lines := strings.Split(strings.TrimSpace(telemetry.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 telemetry events, got %d:\n%s", len(lines), telemetry.String())
	}
	var ev0 TelemetryEvent
	if err := json.Unmarshal([]byte(lines[0]), &ev0); err != nil {
		t.Fatal(err)
	}
	if ev0.Action != "blocked" || ev0.Report.SchemaVersion != "1.0" || ev0.Report.Posture == nil {
		t.Fatalf("invalid telemetry event schema: %+v", ev0)
	}

	// 7. Monitor-mode proxy forwards XSS while still emitting telemetry and incrementing monitored counter.
	var monLog bytes.Buffer
	monHandler, err := NewHandler(Config{
		UpstreamURL:     upstream.URL,
		Mode:            "monitor",
		TelemetryWriter: &monLog,
	})
	if err != nil {
		t.Fatal(err)
	}
	monSrv := httptest.NewServer(monHandler)
	defer monSrv.Close()

	respMon, err := http.Get(monSrv.URL + "/search?q=%3Cdetails%20open%20ontoggle=alert(1)%3E")
	if err != nil {
		t.Fatal(err)
	}
	_ = respMon.Body.Close()
	if respMon.StatusCode != http.StatusOK {
		t.Fatalf("monitor mode must forward request, got %d", respMon.StatusCode)
	}
	if !strings.Contains(monHandler.Metrics().RenderPrometheus(), "raksa_webshield_requests_monitored_total 1") {
		t.Fatalf("expected monitored counter = 1")
	}
}

func TestProxyRateLimiterEnforces429AndCapsLRUKeys(t *testing.T) {
	rl := NewRateLimiter(2, 10*time.Second, 8)
	base := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

	if ok, _ := rl.AllowAt("10.0.0.1", base); !ok {
		t.Fatal("first request must be allowed")
	}
	if ok, _ := rl.AllowAt("10.0.0.1", base.Add(time.Second)); !ok {
		t.Fatal("second request must be allowed")
	}
	if ok, retry := rl.AllowAt("10.0.0.1", base.Add(2*time.Second)); ok || retry < 1 {
		t.Fatalf("third request should trigger 429 limit, got ok=%v retry=%d", ok, retry)
	}

	for i := 0; i < 20; i++ {
		rl.AllowAt(fmt.Sprintf("192.0.2.%d", i), base)
	}
	if rl.Size() > 8 {
		t.Fatalf("LRU rate limiter exceeded maxKeys=8: size=%d", rl.Size())
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	var logBuf bytes.Buffer
	h, err := NewHandler(Config{
		UpstreamURL:     upstream.URL,
		Mode:            "enforce",
		RateLimit:       1,
		RateWindow:      10 * time.Second,
		TelemetryWriter: &logBuf,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	r1, err := http.Get(srv.URL + "/ok")
	if err != nil {
		t.Fatal(err)
	}
	_ = r1.Body.Close()
	r2, err := http.Get(srv.URL + "/ok")
	if err != nil {
		t.Fatal(err)
	}
	_ = r2.Body.Close()
	if r1.StatusCode != http.StatusOK || r2.StatusCode != http.StatusTooManyRequests || r2.Header.Get("Retry-After") == "" {
		t.Fatalf("expected 200 then 429 with Retry-After, got %d then %d (Retry-After=%q)", r1.StatusCode, r2.StatusCode, r2.Header.Get("Retry-After"))
	}
	if !strings.Contains(logBuf.String(), "WEB-312") {
		t.Fatalf("expected WEB-312 rate-limit telemetry event, got: %s", logBuf.String())
	}
}
