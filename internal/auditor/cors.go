package auditor

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/luminariadev/raksa-webshield/internal/schema"
)

func AuditCORS(hdr http.Header, target string, probeOrigin string) []schema.Finding {
	now := time.Now().UTC()
	var findings []schema.Finding

	acao := strings.TrimSpace(hdr.Get("Access-Control-Allow-Origin"))
	acac := strings.EqualFold(strings.TrimSpace(hdr.Get("Access-Control-Allow-Credentials")), "true")
	acah := strings.TrimSpace(hdr.Get("Access-Control-Allow-Headers"))
	acam := strings.TrimSpace(hdr.Get("Access-Control-Allow-Methods"))

	if acao != "" {
		isWildcard := acao == "*"
		isNull := strings.EqualFold(acao, "null")
		isReflectedProbe := probeOrigin != "" && strings.EqualFold(acao, probeOrigin)

		if (isWildcard || isNull || isReflectedProbe) && acac {
			reason := "wildcard '*'"
			if isNull {
				reason = "'null' origin"
			} else if isReflectedProbe {
				reason = fmt.Sprintf("untrusted reflected origin %q", acao)
			}
			findings = append(findings, newFinding(
				"WEB-101", "cors", schema.SeverityCritical,
				"Dangerous CORS credential exposure",
				fmt.Sprintf("Access-Control-Allow-Credentials: true is paired with %s in Access-Control-Allow-Origin.", reason),
				target,
				map[string]any{
					"access_control_allow_origin":      acao,
					"access_control_allow_credentials": true,
					"owasp_asvs":                       "14.5.3",
				},
				"Validate Origin against an exact allowlist before echoing Access-Control-Allow-Origin, never trust 'null' or '*', and omit Allow-Credentials unless strictly necessary.",
				"D3-NI", "cors-credentials", now,
			))
		} else if isWildcard || isNull {
			findings = append(findings, newFinding(
				"WEB-102", "cors", schema.SeverityMedium,
				"Overly permissive CORS policy",
				fmt.Sprintf("Access-Control-Allow-Origin is set to %q, exposing responses cross-origin.", acao),
				target,
				map[string]any{
					"access_control_allow_origin": acao,
					"owasp_asvs":                  "14.5.3",
				},
				"Replace wildcard or null Access-Control-Allow-Origin with explicit trusted origin domains for non-public APIs.",
				"D3-NI", "cors-origin", now,
			))
		}
	}

	if acah == "*" || strings.Contains(acam, "*") {
		findings = append(findings, newFinding(
			"WEB-102", "cors", schema.SeverityMedium,
			"Overly permissive CORS headers or methods wildcard",
			"CORS response uses wildcard '*' in Access-Control-Allow-Headers or Access-Control-Allow-Methods.",
			target,
			map[string]any{
				"access_control_allow_headers": acah,
				"access_control_allow_methods": acam,
				"owasp_asvs":                   "14.5.3",
			},
			"Enumerate explicit safe methods (GET, POST) and required request headers instead of '*'.",
			"D3-NI", "cors-wildcard-headers-methods", now,
		))
	}

	return findings
}
