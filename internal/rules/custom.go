package rules

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/luminariadev/raksa-webshield/internal/schema"
	"gopkg.in/yaml.v3"
)

const MaxCustomRuleBytes = 1024 * 1024

type CustomRuleFile struct {
	Version string       `yaml:"version" json:"version"`
	Rules   []CustomRule `yaml:"rules" json:"rules"`
}

type CustomRule struct {
	ID              string   `yaml:"id" json:"id"`
	Title           string   `yaml:"title" json:"title"`
	Severity        string   `yaml:"severity" json:"severity"`
	Weight          int      `yaml:"weight" json:"weight"`
	Targets         []string `yaml:"targets" json:"targets"`
	MatchType       string   `yaml:"match_type" json:"match_type"`
	Pattern         string   `yaml:"pattern" json:"pattern"`
	CaseInsensitive bool     `yaml:"case_insensitive" json:"case_insensitive"`
	Action          string   `yaml:"action" json:"action"`
	Remediation     string   `yaml:"remediation" json:"remediation"`
}

type compiledRule struct {
	id              string
	title           string
	severity        schema.Severity
	weight          int
	targets         map[string]bool
	matchType       string
	pattern         string
	lowerPattern    string
	caseInsensitive bool
	action          string
	remediation     string
	re              *regexp.Regexp
}

type CompiledRuleSet struct {
	source string
	rules  []compiledRule
}

func LoadCustomRules(path string) (*CompiledRuleSet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open custom rules %q: %w", path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat custom rules %q: %w", path, err)
	}
	if info.Size() > MaxCustomRuleBytes {
		return nil, fmt.Errorf("custom rules file %q exceeds %d byte limit", path, MaxCustomRuleBytes)
	}

	raw, err := io.ReadAll(io.LimitReader(f, MaxCustomRuleBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read custom rules %q: %w", path, err)
	}
	if len(raw) > MaxCustomRuleBytes {
		return nil, fmt.Errorf("custom rules file %q exceeds %d byte limit", path, MaxCustomRuleBytes)
	}

	return ParseCustomRules(raw, path)
}

func ParseCustomRules(raw []byte, source string) (*CompiledRuleSet, error) {
	if len(raw) > MaxCustomRuleBytes {
		return nil, fmt.Errorf("custom rules input exceeds %d byte limit", MaxCustomRuleBytes)
	}

	var doc CustomRuleFile
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse YAML custom rules (%s): %w", source, err)
	}

	seenIDs := make(map[string]struct{}, len(doc.Rules))
	compiled := make([]compiledRule, 0, len(doc.Rules))

	for idx, rawRule := range doc.Rules {
		id := strings.TrimSpace(rawRule.ID)
		if id == "" {
			return nil, fmt.Errorf("custom rule #%d in %s has empty id", idx, source)
		}
		if _, dup := seenIDs[id]; dup {
			return nil, fmt.Errorf("duplicate custom rule id %q in %s", id, source)
		}
		seenIDs[id] = struct{}{}

		pattern := rawRule.Pattern
		if strings.TrimSpace(pattern) == "" {
			return nil, fmt.Errorf("custom rule %q has empty pattern", id)
		}

		sev := schema.SeverityHigh
		if strings.TrimSpace(rawRule.Severity) != "" {
			parsedSev, err := schema.ParseSeverity(rawRule.Severity)
			if err != nil {
				return nil, fmt.Errorf("custom rule %q severity: %w", id, err)
			}
			sev = parsedSev
		}

		weight := rawRule.Weight
		if weight <= 0 {
			weight = defaultWeight(sev)
		}

		matchType := strings.ToLower(strings.TrimSpace(rawRule.MatchType))
		if matchType == "" {
			matchType = "contains"
		}
		var re *regexp.Regexp
		switch matchType {
		case "contains", "exact":
		case "regex":
			expr := pattern
			if rawRule.CaseInsensitive && !strings.HasPrefix(expr, "(?i)") {
				expr = "(?i)" + expr
			}
			var err error
			re, err = regexp.Compile(expr)
			if err != nil {
				return nil, fmt.Errorf("custom rule %q invalid regex %q: %w", id, pattern, err)
			}
		default:
			return nil, fmt.Errorf("custom rule %q unsupported match_type %q (expected contains, regex, or exact)", id, rawRule.MatchType)
		}

		action := strings.ToLower(strings.TrimSpace(rawRule.Action))
		if action == "" {
			action = "block"
		}
		if action != "block" && action != "monitor" {
			return nil, fmt.Errorf("custom rule %q invalid action %q (expected block or monitor)", id, rawRule.Action)
		}

		targets := make(map[string]bool)
		for _, t := range rawRule.Targets {
			clean := strings.ToLower(strings.TrimSpace(t))
			if clean != "" {
				targets[clean] = true
			}
		}

		title := strings.TrimSpace(rawRule.Title)
		if title == "" {
			title = fmt.Sprintf("Custom enterprise WAF rule %s matched", id)
		}
		remediation := strings.TrimSpace(rawRule.Remediation)
		if remediation == "" {
			remediation = fmt.Sprintf("Review traffic matching custom WAF rule %s and remediate the upstream endpoint or client.", id)
		}

		compiled = append(compiled, compiledRule{
			id:              id,
			title:           title,
			severity:        sev,
			weight:          weight,
			targets:         targets,
			matchType:       matchType,
			pattern:         pattern,
			lowerPattern:    strings.ToLower(pattern),
			caseInsensitive: rawRule.CaseInsensitive,
			action:          action,
			remediation:     remediation,
			re:              re,
		})
	}

	return &CompiledRuleSet{
		source: source,
		rules:  compiled,
	}, nil
}

func (cs *CompiledRuleSet) RuleCount() int {
	if cs == nil {
		return 0
	}
	return len(cs.rules)
}

func (cs *CompiledRuleSet) RuleIDs() []string {
	if cs == nil {
		return nil
	}
	out := make([]string, 0, len(cs.rules))
	for _, r := range cs.rules {
		out = append(out, r.id)
	}
	return out
}

func (cs *CompiledRuleSet) Evaluate(payload string, scope string, target string) (findings []schema.Finding, shouldBlock bool, addedScore int) {
	if cs == nil || len(cs.rules) == 0 || payload == "" {
		return nil, false, 0
	}

	normScope := strings.ToLower(strings.TrimSpace(scope))
	if normScope == "" {
		normScope = "all"
	}
	lowPayload := ""
	now := time.Now().UTC()

	for i := range cs.rules {
		r := &cs.rules[i]
		if !r.matchesScope(normScope) {
			continue
		}

		matchedSample := ""
		switch r.matchType {
		case "regex":
			if loc := r.re.FindString(payload); loc != "" {
				matchedSample = loc
			}
		case "exact":
			if r.caseInsensitive {
				if lowPayload == "" {
					lowPayload = strings.ToLower(payload)
				}
				if lowPayload == r.lowerPattern {
					matchedSample = payload
				}
			} else if payload == r.pattern {
				matchedSample = payload
			}
		case "contains":
			if r.caseInsensitive {
				if lowPayload == "" {
					lowPayload = strings.ToLower(payload)
				}
				if strings.Contains(lowPayload, r.lowerPattern) {
					matchedSample = r.pattern
				}
			} else if strings.Contains(payload, r.pattern) {
				matchedSample = r.pattern
			}
		}

		if matchedSample != "" {
			if r.action == "block" {
				shouldBlock = true
			}
			addedScore += r.weight
			findings = append(findings, schema.Finding{
				ID:          fmt.Sprintf("web-311-%s", schema.SanitizeIDPart(r.id)),
				RuleID:      "WEB-311",
				Module:      "waf",
				Layer:       schema.LayerWeb,
				Severity:    r.severity,
				Title:       r.title,
				Description: fmt.Sprintf("Payload matched enterprise custom WAF policy rule %s (%s).", r.id, r.matchType),
				Target:      target,
				Evidence: map[string]any{
					"custom_rule_id": r.id,
					"action":         r.action,
					"scope":          normScope,
					"matched_sample": truncateRuleSample(matchedSample, 80),
					"anomaly_score":  r.weight,
					"owasp_asvs":     "5.1.3",
				},
				Remediation: r.remediation,
				MitreD3FEND: "D3-IV",
				Timestamp:   now,
			})
		}
	}

	return findings, shouldBlock, addedScore
}

func (r *compiledRule) matchesScope(scope string) bool {
	if scope == "all" || len(r.targets) == 0 || r.targets["all"] {
		return true
	}
	return r.targets[scope]
}

func defaultWeight(sev schema.Severity) int {
	switch sev {
	case schema.SeverityCritical:
		return 5
	case schema.SeverityHigh:
		return 4
	case schema.SeverityMedium:
		return 3
	case schema.SeverityLow:
		return 2
	default:
		return 1
	}
}

func truncateRuleSample(s string, maxLen int) string {
	clean := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(clean) <= maxLen {
		return clean
	}
	return clean[:maxLen] + "..."
}
