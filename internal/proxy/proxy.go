package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/luminariadev/raksa-webshield/internal/auditor"
	"github.com/luminariadev/raksa-webshield/internal/rules"
	"github.com/luminariadev/raksa-webshield/internal/schema"
)

const DefaultMaxBodyBytes int64 = 1024 * 1024

type Config struct {
	ListenAddr       string
	UpstreamURL      string
	Mode             string // "enforce" | "monitor"
	Profile          string // "strict" | "balanced"
	ParanoiaLevel    int
	AnomalyThreshold int
	RateLimit        int
	RateWindow       time.Duration
	MaxRateKeys      int
	MaxBodyBytes     int64
	CustomRules      *rules.CompiledRuleSet
	ExcludePaths     []string
	MetricsAddr      string
	TelemetryWriter  io.Writer
}

type TelemetryEvent struct {
	Timestamp  time.Time     `json:"timestamp"`
	IncidentID string        `json:"incident_id"`
	Action     string        `json:"action"`
	ClientIP   string        `json:"client_ip"`
	Method     string        `json:"method"`
	Path       string        `json:"path"`
	Report     schema.Report `json:"report"`
}

type Handler struct {
	cfg        Config
	upstream   *url.URL
	reverse    *httputil.ReverseProxy
	limiter    *RateLimiter
	metrics    *Metrics
	secHeaders map[string]string
	logMu      sync.Mutex
}

func NewHandler(cfg Config) (*Handler, error) {
	u, err := url.Parse(strings.TrimSpace(cfg.UpstreamURL))
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL %q: %w", cfg.UpstreamURL, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "http" && scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("upstream URL %q must use http:// or https:// with a host", cfg.UpstreamURL)
	}

	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" {
		mode = "enforce"
	}
	if mode != "enforce" && mode != "monitor" {
		return nil, fmt.Errorf("invalid proxy mode %q: expected enforce or monitor", cfg.Mode)
	}
	cfg.Mode = mode

	profile := strings.ToLower(strings.TrimSpace(cfg.Profile))
	if profile == "" {
		profile = "strict"
	}
	if profile != "strict" && profile != "balanced" {
		return nil, fmt.Errorf("invalid header profile %q: expected strict or balanced", cfg.Profile)
	}
	cfg.Profile = profile

	if cfg.ParanoiaLevel == 0 {
		cfg.ParanoiaLevel = 1
	}
	if cfg.ParanoiaLevel < 1 || cfg.ParanoiaLevel > 3 {
		return nil, fmt.Errorf("invalid paranoia level %d: expected 1-3", cfg.ParanoiaLevel)
	}
	if cfg.AnomalyThreshold < 0 {
		return nil, fmt.Errorf("anomaly threshold must be >= 0")
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = DefaultMaxBodyBytes
	}

	var limiter *RateLimiter
	if cfg.RateLimit > 0 {
		window := cfg.RateWindow
		if window <= 0 {
			window = 60 * time.Second
		}
		limiter = NewRateLimiter(cfg.RateLimit, window, cfg.MaxRateKeys)
	}

	metrics := NewMetrics()
	secHeaders := profileSecurityHeaders(profile)

	h := &Handler{
		cfg:        cfg,
		upstream:   u,
		limiter:    limiter,
		metrics:    metrics,
		secHeaders: secHeaders,
	}

	rp := httputil.NewSingleHostReverseProxy(u)
	baseDirector := rp.Director
	rp.Director = func(req *http.Request) {
		baseDirector(req)
		req.Host = u.Host
	}
	rp.ModifyResponse = func(resp *http.Response) error {
		resp.Header.Del("Server")
		resp.Header.Del("X-Powered-By")
		for k, v := range secHeaders {
			resp.Header.Set(k, v)
		}
		return nil
	}
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, proxyErr error) {
		metrics.IncUpstreamErrors()
		applyHeaderMap(w.Header(), secHeaders)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":       "Upstream service unavailable",
			"incident_id": newIncidentID(),
		})
	}
	h.reverse = rp
	return h, nil
}

func (h *Handler) Metrics() *Metrics {
	return h.metrics
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.metrics.IncRequests()

	if isExcludedPath(r.URL.Path, h.cfg.ExcludePaths) {
		h.reverse.ServeHTTP(w, r)
		return
	}

	clientIP := extractClientIP(r)
	target := fmt.Sprintf("http://%s %s", r.Method, r.URL.Path)

	if h.limiter != nil {
		allowed, retryAfter := h.limiter.Allow(clientIP)
		if !allowed {
			h.metrics.IncRateLimited()
			h.metrics.AddRuleHit("WEB-312")
			incID := newIncidentID()
			now := time.Now().UTC()
			finding := schema.Finding{
				ID:          "web-312-ratelimit",
				RuleID:      "WEB-312",
				Module:      "waf",
				Layer:       schema.LayerWeb,
				Severity:    schema.SeverityMedium,
				Title:       "HTTP request rate limit exceeded in WebShield proxy",
				Description: fmt.Sprintf("Client %s exceeded proxy request rate limit.", clientIP),
				Target:      target,
				Evidence: map[string]any{
					"client_ip":           clientIP,
					"retry_after_seconds": retryAfter,
					"owasp_asvs":          "13.1.4",
				},
				Remediation: "Investigate burst traffic or tune --rate-limit / --rate-window thresholds.",
				MitreD3FEND: "D3-NI",
				Timestamp:   now,
			}
			rep := schema.NewReport([]schema.Finding{finding}, now)
			action := "monitored"
			if h.cfg.Mode == "enforce" {
				action = "rate_limited"
			}
			h.emitTelemetry(TelemetryEvent{
				Timestamp:  now,
				IncidentID: incID,
				Action:     action,
				ClientIP:   clientIP,
				Method:     r.Method,
				Path:       r.URL.Path,
				Report:     rep,
			})
			if h.cfg.Mode == "enforce" {
				h.metrics.IncBlocked()
				applyHeaderMap(w.Header(), h.secHeaders)
				w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusTooManyRequests)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error":       "Rate limit exceeded by raksa-webshield",
					"incident_id": incID,
				})
				return
			}
			h.metrics.IncMonitored()
		}
	}

	var bodyBytes []byte
	if r.Body != nil {
		limited := io.LimitReader(r.Body, h.cfg.MaxBodyBytes+1)
		rawBody, readErr := io.ReadAll(limited)
		_ = r.Body.Close()
		if readErr != nil {
			applyHeaderMap(w.Header(), h.secHeaders)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":       "Failed to read request payload",
				"incident_id": newIncidentID(),
			})
			return
		}
		if int64(len(rawBody)) > h.cfg.MaxBodyBytes {
			if h.cfg.Mode == "enforce" {
				h.metrics.IncBlocked()
				applyHeaderMap(w.Header(), h.secHeaders)
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error":       "Payload exceeds raksa-webshield inspection limit",
					"incident_id": newIncidentID(),
				})
				return
			}
		} else {
			bodyBytes = rawBody
		}
		r.Body = io.NopCloser(bytes.NewReader(rawBody))
		r.ContentLength = int64(len(rawBody))
	}

	headerText := extractProxyHeaderText(r.Header)
	parts := make([]string, 0, 3)
	if uri := r.URL.RequestURI(); uri != "" {
		parts = append(parts, uri)
	}
	if headerText != "" {
		parts = append(parts, headerText)
	}
	if len(bodyBytes) > 0 {
		parts = append(parts, string(bodyBytes))
	}
	combined := strings.Join(parts, "\n")

	builtInFindings, _ := auditor.InspectPayloadWithOptions(combined, target, auditor.InspectOptions{
		ParanoiaLevel:    h.cfg.ParanoiaLevel,
		AnomalyThreshold: 0,
	})

	allFindings := make([]schema.Finding, 0, len(builtInFindings))
	allFindings = append(allFindings, builtInFindings...)
	shouldBlock := len(builtInFindings) > 0

	if h.cfg.CustomRules != nil && h.cfg.CustomRules.RuleCount() > 0 {
		customHits, customBlock := evaluateScopedCustomRules(
			h.cfg.CustomRules,
			r.URL.Path,
			r.URL.RawQuery,
			headerText,
			string(bodyBytes),
			target,
		)
		allFindings = append(allFindings, customHits...)
		if customBlock {
			shouldBlock = true
		}
	}

	if len(allFindings) > 0 && h.cfg.AnomalyThreshold > 0 {
		totalScore := sumFindingScores(allFindings)
		if totalScore < h.cfg.AnomalyThreshold {
			allFindings = nil
			shouldBlock = false
		}
	}

	if len(allFindings) > 0 {
		now := time.Now().UTC()
		incID := newIncidentID()
		for _, f := range allFindings {
			h.metrics.AddRuleHit(f.RuleID)
		}
		rep := schema.NewReport(allFindings, now)

		enforceBlock := h.cfg.Mode == "enforce" && shouldBlock
		action := "monitored"
		if enforceBlock {
			action = "blocked"
		}
		h.emitTelemetry(TelemetryEvent{
			Timestamp:  now,
			IncidentID: incID,
			Action:     action,
			ClientIP:   clientIP,
			Method:     r.Method,
			Path:       r.URL.Path,
			Report:     rep,
		})

		if enforceBlock {
			h.metrics.IncBlocked()
			applyHeaderMap(w.Header(), h.secHeaders)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":       "Request blocked by raksa-webshield defensive policy",
				"incident_id": incID,
			})
			return
		}
		h.metrics.IncMonitored()
	}

	h.reverse.ServeHTTP(w, r)
}

func RunServer(ctx context.Context, cfg Config) error {
	if strings.TrimSpace(cfg.ListenAddr) == "" {
		cfg.ListenAddr = ":8443"
	}
	handler, err := NewHandler(cfg)
	if err != nil {
		return err
	}

	mainSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 2)
	var metricsSrv *http.Server
	if strings.TrimSpace(cfg.MetricsAddr) != "" {
		metricsSrv = &http.Server{
			Addr:              cfg.MetricsAddr,
			Handler:           handler.Metrics().Handler(),
			ReadHeaderTimeout: 5 * time.Second,
			IdleTimeout:       30 * time.Second,
		}
		go func() {
			if sErr := metricsSrv.ListenAndServe(); sErr != nil && !errors.Is(sErr, http.ErrServerClosed) {
				errCh <- fmt.Errorf("metrics server: %w", sErr)
			}
		}()
	}

	go func() {
		if sErr := mainSrv.ListenAndServe(); sErr != nil && !errors.Is(sErr, http.ErrServerClosed) {
			errCh <- fmt.Errorf("proxy server: %w", sErr)
		}
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = mainSrv.Shutdown(shutCtx)
		if metricsSrv != nil {
			_ = metricsSrv.Shutdown(shutCtx)
		}
		return nil
	case srvErr := <-errCh:
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = mainSrv.Shutdown(shutCtx)
		if metricsSrv != nil {
			_ = metricsSrv.Shutdown(shutCtx)
		}
		return srvErr
	}
}

func evaluateScopedCustomRules(
	cs *rules.CompiledRuleSet,
	pathStr, queryStr, hdrStr, bodyStr, target string,
) (findings []schema.Finding, shouldBlock bool) {
	seenIDs := make(map[string]bool)
	scopes := []struct {
		name string
		text string
	}{
		{"path", pathStr},
		{"query", queryStr},
		{"headers", hdrStr},
		{"body", bodyStr},
	}
	for _, sc := range scopes {
		if sc.text == "" {
			continue
		}
		hits, blk, _ := cs.Evaluate(sc.text, sc.name, target)
		if blk {
			shouldBlock = true
		}
		for _, f := range hits {
			cid, _ := f.Evidence["custom_rule_id"].(string)
			key := cid
			if key == "" {
				key = f.ID
			}
			if seenIDs[key] {
				continue
			}
			seenIDs[key] = true
			findings = append(findings, f)
		}
	}
	return findings, shouldBlock
}

func sumFindingScores(findings []schema.Finding) int {
	total := 0
	for _, f := range findings {
		if f.Evidence != nil {
			if w, ok := f.Evidence["anomaly_score"].(int); ok {
				total += w
				continue
			}
		}
		switch f.Severity {
		case schema.SeverityCritical:
			total += 5
		case schema.SeverityHigh:
			total += 4
		case schema.SeverityMedium:
			total += 3
		case schema.SeverityLow:
			total += 2
		default:
			total += 1
		}
	}
	return total
}

func (h *Handler) emitTelemetry(ev TelemetryEvent) {
	if h.cfg.TelemetryWriter == nil {
		return
	}
	line, err := json.Marshal(ev)
	if err != nil {
		return
	}
	h.logMu.Lock()
	_, _ = h.cfg.TelemetryWriter.Write(append(line, '\n'))
	h.logMu.Unlock()
}

func extractProxyHeaderText(hdr http.Header) string {
	var parts []string
	for _, name := range []string{"User-Agent", "Referer", "X-Forwarded-For", "Cookie"} {
		for _, v := range hdr.Values(name) {
			if strings.TrimSpace(v) != "" {
				parts = append(parts, v)
			}
		}
	}
	return strings.Join(parts, "\n")
}

func extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first := strings.TrimSpace(strings.Split(xff, ",")[0])
		if first != "" {
			return first
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	if r.RemoteAddr != "" {
		return r.RemoteAddr
	}
	return "unknown"
}

func isExcludedPath(path string, prefixes []string) bool {
	if path == "/healthz" {
		return true
	}
	for _, p := range prefixes {
		clean := strings.TrimSpace(p)
		if clean != "" && (path == clean || strings.HasPrefix(path, clean)) {
			return true
		}
	}
	return false
}

func profileSecurityHeaders(profile string) map[string]string {
	csp := "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
	xfo := "DENY"
	ref := "no-referrer"
	corp := "same-origin"
	if profile == "balanced" {
		csp = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' https:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'sameorigin'"
		xfo = "SAMEORIGIN"
		ref = "strict-origin-when-cross-origin"
		corp = "same-site"
	}
	return map[string]string{
		"Strict-Transport-Security":    "max-age=31536000; includeSubDomains; preload",
		"Content-Security-Policy":      csp,
		"X-Frame-Options":              xfo,
		"X-Content-Type-Options":       "nosniff",
		"Referrer-Policy":              ref,
		"Permissions-Policy":           "geolocation=(), microphone=(), camera=()",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": corp,
	}
}

func applyHeaderMap(dst http.Header, headers map[string]string) {
	dst.Del("Server")
	dst.Del("X-Powered-By")
	for k, v := range headers {
		dst.Set(k, v)
	}
}

func newIncidentID() string {
	var raw [6]byte
	_, _ = rand.Read(raw[:])
	return "inc-" + hex.EncodeToString(raw[:])
}
