package schema

import (
	"fmt"
	"strings"
	"time"
)

const (
	SchemaVersion = "1.0"
	ToolName      = "raksa-webshield"
	LayerWeb      = "web-defense"
)

// Version can be overridden at build time via -ldflags "-X github.com/luminariadev/raksa-webshield/internal/schema.Version=v0.1.0".
var Version = "0.1.0"

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

func ParseSeverity(raw string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical":
		return SeverityCritical, nil
	case "high":
		return SeverityHigh, nil
	case "medium":
		return SeverityMedium, nil
	case "low":
		return SeverityLow, nil
	case "info":
		return SeverityInfo, nil
	default:
		return "", fmt.Errorf("invalid severity %q: expected critical, high, medium, low, or info", raw)
	}
}

func (s Severity) Rank() int {
	switch s {
	case SeverityInfo:
		return 1
	case SeverityLow:
		return 2
	case SeverityMedium:
		return 3
	case SeverityHigh:
		return 4
	case SeverityCritical:
		return 5
	default:
		return 0
	}
}

func (s Severity) MeetsThreshold(threshold Severity) bool {
	if threshold == "" {
		return false
	}
	return s.Rank() >= threshold.Rank()
}

type Finding struct {
	ID          string         `json:"id"`
	RuleID      string         `json:"rule_id"`
	Module      string         `json:"module"`
	Layer       string         `json:"layer"`
	Severity    Severity       `json:"severity"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Target      string         `json:"target"`
	Evidence    map[string]any `json:"evidence,omitempty"`
	Remediation string         `json:"remediation"`
	MitreD3FEND string         `json:"mitre_d3fend"`
	Timestamp   time.Time      `json:"timestamp"`
}

type Summary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

type Report struct {
	SchemaVersion string    `json:"schema_version"`
	Tool          string    `json:"tool"`
	Layer         string    `json:"layer"`
	GeneratedAt   time.Time `json:"generated_at"`
	Summary       Summary   `json:"summary"`
	Findings      []Finding `json:"findings"`
}

func NewReport(findings []Finding, generatedAt time.Time) Report {
	if findings == nil {
		findings = []Finding{}
	}
	sum := Summary{Total: len(findings)}
	for _, f := range findings {
		switch f.Severity {
		case SeverityCritical:
			sum.Critical++
		case SeverityHigh:
			sum.High++
		case SeverityMedium:
			sum.Medium++
		case SeverityLow:
			sum.Low++
		case SeverityInfo:
			sum.Info++
		}
	}

	return Report{
		SchemaVersion: SchemaVersion,
		Tool:          ToolName,
		Layer:         LayerWeb,
		GeneratedAt:   generatedAt.UTC(),
		Summary:       sum,
		Findings:      findings,
	}
}

func (r Report) HasThresholdBreach(threshold Severity) bool {
	if threshold == "" {
		return false
	}
	for _, f := range r.Findings {
		if f.Severity.MeetsThreshold(threshold) {
			return true
		}
	}
	return false
}

func SanitizeIDPart(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			b.WriteByte(c)
		} else if c >= 'A' && c <= 'Z' {
			b.WriteByte(c + ('a' - 'A'))
		} else {
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
