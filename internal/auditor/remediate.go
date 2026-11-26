package auditor

import (
	"fmt"
	"net/url"
	"strings"
)

type hardenedPreset struct {
	csp      string
	xfo      string
	referrer string
	corp     string
}

func GenerateHardenedConfig(target string, profile string, corsOrigin string) (string, error) {
	normTarget := strings.ToLower(strings.TrimSpace(target))
	normProfile := strings.ToLower(strings.TrimSpace(profile))
	if normProfile == "" {
		normProfile = "strict"
	}

	var preset hardenedPreset
	switch normProfile {
	case "strict":
		preset = hardenedPreset{
			csp:      "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
			xfo:      "DENY",
			referrer: "no-referrer",
			corp:     "same-origin",
		}
	case "balanced":
		preset = hardenedPreset{
			csp:      "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' https:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'sameorigin'",
			xfo:      "SAMEORIGIN",
			referrer: "strict-origin-when-cross-origin",
			corp:     "same-site",
		}
	default:
		return "", fmt.Errorf("invalid profile %q: expected strict or balanced", profile)
	}

	cleanOrigin, err := sanitizeOriginArg(corsOrigin)
	if err != nil {
		return "", err
	}

	switch normTarget {
	case "headers":
		return renderHardenedHeaders(preset, cleanOrigin), nil
	case "nginx":
		return renderHardenedNginx(preset, cleanOrigin), nil
	case "caddy":
		return renderHardenedCaddy(preset, cleanOrigin), nil
	case "nextjs":
		return renderHardenedNextJS(preset, cleanOrigin), nil
	default:
		return "", fmt.Errorf("unsupported remediation target %q: expected nginx, caddy, nextjs, or headers", target)
	}
}

func sanitizeOriginArg(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}
	if strings.ContainsAny(trimmed, "\r\n\"'`;{}") {
		return "", fmt.Errorf("invalid origin %q: contains forbidden control or quote characters", raw)
	}
	if trimmed == "*" || strings.EqualFold(trimmed, "null") {
		return "", fmt.Errorf("unsafe CORS origin %q: specify an explicit https:// or http:// origin", raw)
	}
	u, err := url.Parse(trimmed)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", fmt.Errorf("invalid CORS origin %q: expected scheme://host (e.g. https://app.example.com)", raw)
	}
	return fmt.Sprintf("%s://%s", strings.ToLower(u.Scheme), u.Host), nil
}

func renderHardenedHeaders(p hardenedPreset, origin string) string {
	var b strings.Builder
	b.WriteString("HTTP/1.1 200 OK\n")
	b.WriteString("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n")
	b.WriteString("Content-Security-Policy: " + p.csp + "\n")
	b.WriteString("X-Frame-Options: " + p.xfo + "\n")
	b.WriteString("X-Content-Type-Options: nosniff\n")
	b.WriteString("Referrer-Policy: " + p.referrer + "\n")
	b.WriteString("Permissions-Policy: geolocation=(), microphone=(), camera=()\n")
	b.WriteString("Cross-Origin-Opener-Policy: same-origin\n")
	b.WriteString("Cross-Origin-Resource-Policy: " + p.corp + "\n")
	b.WriteString("Cache-Control: no-store\n")
	if origin != "" {
		b.WriteString("Access-Control-Allow-Origin: " + origin + "\n")
		b.WriteString("Vary: Origin\n")
	}
	return b.String()
}

func renderHardenedNginx(p hardenedPreset, origin string) string {
	var b strings.Builder
	b.WriteString("server {\n")
	b.WriteString("    listen 443 ssl http2;\n")
	b.WriteString("    server_tokens off;\n")
	b.WriteString("    autoindex off;\n\n")
	b.WriteString("    ssl_protocols TLSv1.2 TLSv1.3;\n")
	b.WriteString("    ssl_prefer_server_ciphers on;\n")
	b.WriteString("    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;\n")
	b.WriteString("    client_max_body_size 10m;\n\n")
	b.WriteString("    add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n")
	b.WriteString("    add_header Content-Security-Policy \"" + p.csp + "\" always;\n")
	b.WriteString("    add_header X-Frame-Options \"" + p.xfo + "\" always;\n")
	b.WriteString("    add_header X-Content-Type-Options \"nosniff\" always;\n")
	b.WriteString("    add_header Referrer-Policy \"" + p.referrer + "\" always;\n")
	b.WriteString("    add_header Permissions-Policy \"geolocation=(), microphone=(), camera=()\" always;\n")
	b.WriteString("    add_header Cross-Origin-Opener-Policy \"same-origin\" always;\n")
	b.WriteString("    add_header Cross-Origin-Resource-Policy \"" + p.corp + "\" always;\n")
	if origin != "" {
		b.WriteString("    add_header Access-Control-Allow-Origin \"" + origin + "\" always;\n")
		b.WriteString("    add_header Vary \"Origin\" always;\n")
	}
	b.WriteString("}\n")
	return b.String()
}

func renderHardenedCaddy(p hardenedPreset, origin string) string {
	var b strings.Builder
	b.WriteString("example.org {\n")
	b.WriteString("    tls {\n")
	b.WriteString("        protocols tls1.2 tls1.3\n")
	b.WriteString("        ciphers TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256\n")
	b.WriteString("    }\n\n")
	b.WriteString("    header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"\n")
	b.WriteString("    header Content-Security-Policy \"" + p.csp + "\"\n")
	b.WriteString("    header X-Frame-Options \"" + p.xfo + "\"\n")
	b.WriteString("    header X-Content-Type-Options \"nosniff\"\n")
	b.WriteString("    header Referrer-Policy \"" + p.referrer + "\"\n")
	b.WriteString("    header Permissions-Policy \"geolocation=(), microphone=(), camera=()\"\n")
	b.WriteString("    header Cross-Origin-Opener-Policy \"same-origin\"\n")
	b.WriteString("    header Cross-Origin-Resource-Policy \"" + p.corp + "\"\n")
	if origin != "" {
		b.WriteString("    header Access-Control-Allow-Origin \"" + origin + "\"\n")
		b.WriteString("    header Vary \"Origin\"\n")
	}
	b.WriteString("    header -Server\n")
	b.WriteString("    file_server\n")
	b.WriteString("}\n")
	return b.String()
}

func renderHardenedNextJS(p hardenedPreset, origin string) string {
	var b strings.Builder
	b.WriteString("/** @type {import('next').NextConfig} */\n")
	b.WriteString("const securityHeaders = [\n")
	b.WriteString("  { key: \"Strict-Transport-Security\", value: \"max-age=31536000; includeSubDomains; preload\" },\n")
	b.WriteString("  { key: \"Content-Security-Policy\", value: \"" + p.csp + "\" },\n")
	b.WriteString("  { key: \"X-Frame-Options\", value: \"" + p.xfo + "\" },\n")
	b.WriteString("  { key: \"X-Content-Type-Options\", value: \"nosniff\" },\n")
	b.WriteString("  { key: \"Referrer-Policy\", value: \"" + p.referrer + "\" },\n")
	b.WriteString("  { key: \"Permissions-Policy\", value: \"geolocation=(), microphone=(), camera=()\" },\n")
	b.WriteString("  { key: \"Cross-Origin-Opener-Policy\", value: \"same-origin\" },\n")
	b.WriteString("  { key: \"Cross-Origin-Resource-Policy\", value: \"" + p.corp + "\" },\n")
	if origin != "" {
		b.WriteString("  { key: \"Access-Control-Allow-Origin\", value: \"" + origin + "\" },\n")
		b.WriteString("  { key: \"Vary\", value: \"Origin\" },\n")
	}
	b.WriteString("];\n\n")
	b.WriteString("const nextConfig = {\n")
	b.WriteString("  poweredByHeader: false,\n")
	b.WriteString("  async headers() {\n")
	b.WriteString("    return [{ source: \"/(.*)\", headers: securityHeaders }];\n")
	b.WriteString("  },\n")
	b.WriteString("};\n\n")
	b.WriteString("export default nextConfig;\n")
	return b.String()
}
