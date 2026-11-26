package proxy

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

type Metrics struct {
	requestsTotal          atomic.Uint64
	requestsBlockedTotal   atomic.Uint64
	requestsMonitoredTotal atomic.Uint64
	rateLimitedTotal       atomic.Uint64
	upstreamErrorsTotal    atomic.Uint64

	ruleMu       sync.RWMutex
	findingsRule map[string]uint64
}

func NewMetrics() *Metrics {
	return &Metrics{
		findingsRule: make(map[string]uint64),
	}
}

func (m *Metrics) IncRequests()       { m.requestsTotal.Add(1) }
func (m *Metrics) IncBlocked()        { m.requestsBlockedTotal.Add(1) }
func (m *Metrics) IncMonitored()      { m.requestsMonitoredTotal.Add(1) }
func (m *Metrics) IncRateLimited()    { m.rateLimitedTotal.Add(1) }
func (m *Metrics) IncUpstreamErrors() { m.upstreamErrorsTotal.Add(1) }
func (m *Metrics) AddRuleHit(id string) {
	if id == "" {
		return
	}
	m.ruleMu.Lock()
	m.findingsRule[id]++
	m.ruleMu.Unlock()
}

func (m *Metrics) RenderPrometheus() string {
	var b strings.Builder

	writeCounter(&b, "raksa_webshield_requests_total", "Total HTTP requests observed by raksa-webshield proxy.", m.requestsTotal.Load())
	writeCounter(&b, "raksa_webshield_requests_blocked_total", "Total HTTP requests blocked (403/413/429) by raksa-webshield proxy.", m.requestsBlockedTotal.Load())
	writeCounter(&b, "raksa_webshield_requests_monitored_total", "Total suspicious HTTP requests forwarded in monitor mode.", m.requestsMonitoredTotal.Load())
	writeCounter(&b, "raksa_webshield_rate_limited_total", "Total HTTP requests exceeding per-client rate limit.", m.rateLimitedTotal.Load())
	writeCounter(&b, "raksa_webshield_upstream_errors_total", "Total upstream reverse-proxy errors.", m.upstreamErrorsTotal.Load())

	b.WriteString("# HELP raksa_webshield_findings_by_rule_total Total WAF findings grouped by rule_id.\n")
	b.WriteString("# TYPE raksa_webshield_findings_by_rule_total counter\n")

	m.ruleMu.RLock()
	keys := make([]string, 0, len(m.findingsRule))
	for k := range m.findingsRule {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "raksa_webshield_findings_by_rule_total{rule_id=%q} %d\n", k, m.findingsRule[k])
	}
	m.ruleMu.RUnlock()

	return b.String()
}

func (m *Metrics) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(m.RenderPrometheus()))
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{\"status\":\"ok\"}\n"))
	})
	return mux
}

func writeCounter(b *strings.Builder, name, help string, val uint64) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, val)
}
