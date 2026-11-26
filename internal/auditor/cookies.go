package auditor

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/luminariadev/raksa-webshield/internal/schema"
)

func AuditCookies(hdr http.Header, target string) []schema.Finding {
	now := time.Now().UTC()
	var findings []schema.Finding

	for _, rawCookie := range hdr.Values("Set-Cookie") {
		parts := strings.Split(rawCookie, ";")
		if len(parts) == 0 {
			continue
		}
		nameVal := strings.TrimSpace(parts[0])
		if nameVal == "" {
			continue
		}
		cookieName := nameVal
		if eqIdx := strings.IndexByte(nameVal, '='); eqIdx >= 0 {
			cookieName = strings.TrimSpace(nameVal[:eqIdx])
		}
		if cookieName == "" {
			continue
		}

		var hasSecure, hasHTTPOnly, hasDomain bool
		var sameSite, pathVal string

		for _, attr := range parts[1:] {
			a := strings.TrimSpace(attr)
			if a == "" {
				continue
			}
			low := strings.ToLower(a)
			switch {
			case low == "secure":
				hasSecure = true
			case low == "httponly":
				hasHTTPOnly = true
			case strings.HasPrefix(low, "samesite="):
				sameSite = strings.TrimSpace(strings.SplitN(low, "=", 2)[1])
			case strings.HasPrefix(low, "path="):
				pathVal = strings.TrimSpace(strings.SplitN(a, "=", 2)[1])
			case strings.HasPrefix(low, "domain="):
				hasDomain = true
			}
		}

		// WEB-103: Missing Secure or HttpOnly (cookie values are redacted from findings).
		requireHTTPOnly := !isClientReadableNonSessionCookie(cookieName)
		if !hasSecure || (requireHTTPOnly && !hasHTTPOnly) {
			var missing []string
			if !hasSecure {
				missing = append(missing, "Secure")
			}
			if requireHTTPOnly && !hasHTTPOnly {
				missing = append(missing, "HttpOnly")
			}
			findings = append(findings, newFinding(
				"WEB-103", "cookies", schema.SeverityHigh,
				"Cookie missing Secure or HttpOnly attribute",
				fmt.Sprintf("Cookie '%s' omits %s (value redacted).", cookieName, strings.Join(missing, " and ")),
				target,
				map[string]any{
					"cookie_name":        cookieName,
					"missing_attributes": missing,
					"owasp_asvs":         "3.4.1 / 3.4.2",
				},
				fmt.Sprintf("Set %s on cookie '%s' so it cannot traverse cleartext HTTP or be read by document.cookie.", strings.Join(missing, "; "), cookieName),
				"D3-HI", "cookie-flags-"+cookieName, now,
			))
		}

		// WEB-104: Weak SameSite or RFC cookie prefix violations.
		if sameSite == "" || (sameSite == "none" && !hasSecure) {
			desc := fmt.Sprintf("Cookie '%s' omits SameSite attribute.", cookieName)
			if sameSite == "none" {
				desc = fmt.Sprintf("Cookie '%s' specifies SameSite=None without Secure.", cookieName)
			}
			findings = append(findings, newFinding(
				"WEB-104", "cookies", schema.SeverityMedium,
				"Weak SameSite cookie attribute",
				desc,
				target,
				map[string]any{
					"cookie_name": cookieName,
					"samesite":    sameSite,
					"owasp_asvs":  "3.4.3",
				},
				fmt.Sprintf("Add SameSite=Strict or SameSite=Lax (or SameSite=None; Secure if cross-site required) to cookie '%s'.", cookieName),
				"D3-HI", "cookie-samesite-"+cookieName, now,
			))
		}

		if strings.HasPrefix(cookieName, "__Secure-") && !hasSecure {
			findings = append(findings, newFinding(
				"WEB-104", "cookies", schema.SeverityMedium,
				"Cookie violates __Secure- prefix contract",
				fmt.Sprintf("Cookie '%s' uses the __Secure- prefix without setting the Secure flag.", cookieName),
				target,
				map[string]any{"cookie_name": cookieName, "owasp_asvs": "3.4.4"},
				"Include Secure on all __Secure- prefixed cookies.",
				"D3-HI", "cookie-secure-prefix-"+cookieName, now,
			))
		}

		if strings.HasPrefix(cookieName, "__Host-") && (!hasSecure || hasDomain || pathVal != "/") {
			findings = append(findings, newFinding(
				"WEB-104", "cookies", schema.SeverityMedium,
				"Cookie violates __Host- prefix contract",
				fmt.Sprintf("Cookie '%s' uses __Host- prefix but fails Secure, no-Domain, or Path=/ requirement.", cookieName),
				target,
				map[string]any{
					"cookie_name": cookieName,
					"has_secure":  hasSecure,
					"has_domain":  hasDomain,
					"path":        pathVal,
					"owasp_asvs":  "3.4.4",
				},
				"For __Host- cookies, always include Secure; Path=/ and omit the Domain attribute.",
				"D3-HI", "cookie-host-prefix-"+cookieName, now,
			))
		}
	}

	return findings
}

func isClientReadableNonSessionCookie(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "xsrf-token", "csrf-token", "csrftoken", "theme", "lang", "locale", "tz":
		return true
	default:
		return false
	}
}
