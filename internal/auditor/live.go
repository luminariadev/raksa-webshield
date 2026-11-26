package auditor

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/luminariadev/raksa-webshield/internal/schema"
)

const LiveProbeOrigin = "https://audit.raksa.invalid"

var cgnatCIDR = mustParseCIDR("100.64.0.0/10")

func mustParseCIDR(cidr string) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	return ipNet
}

func ValidateLiveURL(rawURL string, allowPrivate bool) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, fmt.Errorf("invalid URL %q: %w", rawURL, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("unsupported URL scheme %q (expected http or https)", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("URL %q has no host", rawURL)
	}

	if !allowPrivate {
		lowHost := strings.ToLower(host)
		if lowHost == "localhost" || strings.HasSuffix(lowHost, ".localhost") ||
			lowHost == "metadata.google.internal" || strings.HasSuffix(lowHost, ".internal") {
			return nil, fmt.Errorf("blocked private or internal host %q (pass --allow-private to override intentionally)", host)
		}

		if ip := net.ParseIP(host); ip != nil {
			if isDisallowedIP(ip) {
				return nil, fmt.Errorf("blocked non-public IP address %q (pass --allow-private to override intentionally)", ip.String())
			}
			return u, nil
		}

		ips, err := net.LookupIP(host)
		if err != nil {
			return nil, fmt.Errorf("resolve host %q: %w", host, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("host %q resolved to no IP addresses", host)
		}
		for _, ip := range ips {
			if isDisallowedIP(ip) {
				return nil, fmt.Errorf("host %q resolved to non-public IP %q (pass --allow-private to override)", host, ip.String())
			}
		}
	}

	return u, nil
}

func FetchAndAuditURL(ctx context.Context, rawURL string, allowPrivate bool) ([]schema.Finding, error) {
	parsedURL, err := ValidateLiveURL(rawURL, allowPrivate)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		DialContext: func(dCtx context.Context, network, addr string) (net.Conn, error) {
			if !allowPrivate {
				host, port, splitErr := net.SplitHostPort(addr)
				if splitErr != nil {
					return nil, splitErr
				}
				ips, lookupErr := net.DefaultResolver.LookupIPAddr(dCtx, host)
				if lookupErr != nil {
					return nil, lookupErr
				}
				for _, ipAddr := range ips {
					if isDisallowedIP(ipAddr.IP) {
						return nil, fmt.Errorf("blocked connection to non-public IP %s", ipAddr.IP.String())
					}
				}
				if len(ips) > 0 {
					return dialer.DialContext(dCtx, network, net.JoinHostPort(ips[0].IP.String(), port))
				}
			}
			return dialer.DialContext(dCtx, network, addr)
		},
	}

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("stopped after %d redirects", len(via))
			}
			_, redirErr := ValidateLiveURL(req.URL.String(), allowPrivate)
			return redirErr
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build GET request: %w", err)
	}
	req.Header.Set("Origin", LiveProbeOrigin)
	req.Header.Set("User-Agent", "raksa-webshield/"+schema.Version)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %q: %w", parsedURL.String(), err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	findings := AuditHeadersWithProbe(resp.Header, parsedURL.String(), LiveProbeOrigin)
	if resp.TLS != nil {
		findings = append(findings, inspectTLSState(resp.TLS, parsedURL.String(), time.Now().UTC())...)
	}
	return findings, nil
}

func inspectTLSState(state *tls.ConnectionState, target string, now time.Time) []schema.Finding {
	if state == nil {
		return nil
	}
	var findings []schema.Finding
	if state.Version != 0 && state.Version < tls.VersionTLS12 {
		findings = append(findings, newFinding(
			"WEB-201", "config", schema.SeverityHigh,
			"Live endpoint negotiated deprecated TLS protocol",
			fmt.Sprintf("Live TLS handshake negotiated deprecated protocol version 0x%04x.", state.Version),
			target,
			map[string]any{"tls_version": state.Version, "owasp_asvs": "9.1.2"},
			"Disable TLSv1.0 and TLSv1.1 on the edge/reverse proxy and enforce TLSv1.2+.",
			"D3-CH", "live-tls-version", now,
		))
	}
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		remaining := leaf.NotAfter.Sub(now)
		if remaining <= 0 {
			findings = append(findings, newFinding(
				"WEB-207", "config", schema.SeverityHigh,
				"Live TLS certificate has expired",
				fmt.Sprintf("Server leaf certificate expired on %s.", leaf.NotAfter.UTC().Format(time.RFC3339)),
				target,
				map[string]any{"not_after": leaf.NotAfter.UTC().Format(time.RFC3339), "subject": leaf.Subject.CommonName, "owasp_asvs": "9.1.3"},
				"Renew and deploy a valid TLS certificate immediately.",
				"D3-CH", "live-tls-cert-expired", now,
			))
		} else if remaining < 14*24*time.Hour {
			findings = append(findings, newFinding(
				"WEB-207", "config", schema.SeverityMedium,
				"Live TLS certificate expires within 14 days",
				fmt.Sprintf("Server leaf certificate expires in %.1f days (%s).", remaining.Hours()/24, leaf.NotAfter.UTC().Format(time.RFC3339)),
				target,
				map[string]any{"not_after": leaf.NotAfter.UTC().Format(time.RFC3339), "subject": leaf.Subject.CommonName, "owasp_asvs": "9.1.3"},
				"Renew the TLS certificate before expiration or automate renewal.",
				"D3-CH", "live-tls-cert-expiring", now,
			))
		}
	}
	return findings
}

func isDisallowedIP(ip net.IP) bool {
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() ||
		cgnatCIDR.Contains(ip)
}
