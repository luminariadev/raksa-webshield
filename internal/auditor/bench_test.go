package auditor

import "testing"

const benchRawHeaders = `HTTP/1.1 200 OK
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
Set-Cookie: __Host-sid=redacted; Secure; HttpOnly; SameSite=Strict; Path=/
`

const benchCSP = "default-src 'self'; script-src 'self' https://cdn.example.org; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"

const benchNginxConf = `server {
    listen 443 ssl http2;
    server_tokens off;
    autoindex off;
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 10m;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
}`

const benchPayload = `{"comment":"Hello world 1+1=2","path":"/docs/security","author":"alice"}`

func BenchmarkAuditHeaders(b *testing.B) {
	hdr, err := ParseRawHeaders(benchRawHeaders)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = AuditHeaders(hdr, "https://app.example.org")
	}
}

func BenchmarkAuditCSP(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = AuditCSP(benchCSP, "https://app.example.org")
	}
}

func BenchmarkAuditConfig(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = AuditConfigContent(benchNginxConf, "file://nginx.conf")
	}
}

func BenchmarkInspectPayload(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = InspectPayload(benchPayload, "inline://req")
	}
}
