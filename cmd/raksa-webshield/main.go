package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/luminariadev/raksa-webshield/internal/auditor"
	"github.com/luminariadev/raksa-webshield/internal/mcp"
	"github.com/luminariadev/raksa-webshield/internal/policy"
	"github.com/luminariadev/raksa-webshield/internal/report"
	"github.com/luminariadev/raksa-webshield/internal/schema"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		printUsage(stdout)
		return 0
	}

	subcmd := args[0]
	subArgs := args[1:]

	switch subcmd {
	case "version", "-V", "--version":
		fmt.Fprintf(stdout, "%s v%s (schema %s, layer %s)\n", schema.ToolName, schema.Version, schema.SchemaVersion, schema.LayerWeb)
		return 0
	case "rules":
		return cmdRules(subArgs, stdout, stderr)
	case "audit-headers":
		return cmdAuditHeaders(subArgs, stdout, stderr)
	case "audit-csp":
		return cmdAuditCSP(subArgs, stdout, stderr)
	case "audit-config":
		return cmdAuditConfig(subArgs, stdout, stderr)
	case "inspect-request":
		return cmdInspectRequest(subArgs, stdout, stderr)
	case "audit-workspace":
		return cmdAuditWorkspace(subArgs, stdout, stderr)
	case "mcp":
		if err := mcp.ServeStreams(stdin, stdout); err != nil {
			fmt.Fprintf(stderr, "error: mcp server failed: %v\n", err)
			return 1
		}
		return 0
	default:
		fmt.Fprintf(stderr, "error: unknown subcommand %q\n\n", subcmd)
		printUsage(stderr)
		return 1
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, `raksa-webshield v%s - Defensive Web Security, Header, CSP, Proxy, and Mini-WAF CLI (Raksa Layer 3)

Usage: raksa-webshield <command> [flags]

Commands:
  audit-headers    Audit HTTP headers from --file or read-only SSRF-safe --url (WEB-001..104)
  audit-csp        Audit Content-Security-Policy from --policy-string or --file (WEB-003)
  audit-config     Audit Nginx/Caddy reverse-proxy configs statically (WEB-201..204)
  inspect-request  Defensively inspect request/JSON payload for XSS/SQLi/LFI/Proto/SSRF (WEB-301..305)
  audit-workspace  Recursively audit repository web configs and header dumps
  rules            List all 18 detection rules mapped to OWASP ASVS and MITRE D3FEND
  mcp              Start stdio JSON-RPC 2.0 MCP server (6 tools)
  version          Print version and Raksa schema contract
`, schema.Version)
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func parseReportFlags(fs *flag.FlagSet) (format *string, failOn *string, policyPath *string, output *string) {
	format = fs.String("format", "table", "Report format: table, json, or sarif")
	failOn = fs.String("fail-on", "", "Exit with code 2 when findings meet this severity (critical|high|medium|low|info)")
	policyPath = fs.String("policy", "", "Optional YAML/JSON suppression policy file")
	output = fs.String("output", "", "Write formatted report to file instead of stdout")
	return
}

func parseArgsWithHelp(fs *flag.FlagSet, args []string) (done bool, code int) {
	err := fs.Parse(args)
	if err == nil {
		return false, 0
	}
	if errors.Is(err, flag.ErrHelp) {
		return true, 0
	}
	return true, 1
}

func cmdRules(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("rules", stderr)
	format := fs.String("format", "table", "Output format: table or json")
	if done, code := parseArgsWithHelp(fs, args); done {
		return code
	}

	rules := schema.RuleCatalog()
	switch strings.ToLower(strings.TrimSpace(*format)) {
	case "json":
		enc, err := json.MarshalIndent(rules, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "error: encode rules: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, string(enc))
	case "table":
		fmt.Fprintf(stdout, "%-9s %-9s %-8s %-23s %-8s %s\n", "RULE", "SEVERITY", "MODULE", "OWASP ASVS", "D3FEND", "TITLE")
		fmt.Fprintln(stdout, strings.Repeat("-", 96))
		for _, r := range rules {
			fmt.Fprintf(
				stdout,
				"%-9s %-9s %-8s %-23s %-8s %s\n",
				r.RuleID,
				strings.ToUpper(string(r.DefaultSeverity)),
				r.Module,
				r.OwaspASVS,
				r.MitreD3FEND,
				r.Title,
			)
		}
	default:
		fmt.Fprintf(stderr, "error: invalid format %q: expected table or json\n", *format)
		return 1
	}
	return 0
}

func cmdAuditHeaders(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("audit-headers", stderr)
	filePath := fs.String("file", "", "Path to saved HTTP response headers file")
	urlTarget := fs.String("url", "", "Read-only HTTP/HTTPS URL to fetch and audit response headers")
	allowPrivate := fs.Bool("allow-private", false, "Allow loopback/private IP targets intentionally")
	formatStr, failOnStr, polStr, outStr := parseReportFlags(fs)
	if done, code := parseArgsWithHelp(fs, args); done {
		return code
	}

	hasFile := strings.TrimSpace(*filePath) != ""
	hasURL := strings.TrimSpace(*urlTarget) != ""
	if hasFile == hasURL {
		fmt.Fprintln(stderr, "error: provide exactly one of --file or --url")
		return 1
	}

	var findings []schema.Finding
	var err error
	if hasFile {
		findings, err = auditor.AuditHeadersFile(*filePath)
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		findings, err = auditor.FetchAndAuditURL(ctx, *urlTarget, *allowPrivate)
	}
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	return emitReport(findings, *formatStr, *failOnStr, *polStr, *outStr, stdout, stderr)
}

func cmdAuditCSP(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("audit-csp", stderr)
	policyStr := fs.String("policy-string", "", "Inline Content-Security-Policy string")
	filePath := fs.String("file", "", "Path to file containing Content-Security-Policy text")
	formatStr, failOnStr, polStr, outStr := parseReportFlags(fs)
	if done, code := parseArgsWithHelp(fs, args); done {
		return code
	}

	hasInline := strings.TrimSpace(*policyStr) != ""
	hasFile := strings.TrimSpace(*filePath) != ""
	if hasInline == hasFile {
		fmt.Fprintln(stderr, "error: provide exactly one of --policy-string or --file")
		return 1
	}

	var findings []schema.Finding
	if hasFile {
		var err error
		findings, err = auditor.AuditCSPFile(*filePath)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
	} else {
		if len(*policyStr) > auditor.MaxConfigBytes {
			fmt.Fprintf(stderr, "error: --policy-string exceeds %d byte limit\n", auditor.MaxConfigBytes)
			return 1
		}
		findings = auditor.AuditCSP(*policyStr, "inline://csp")
	}

	return emitReport(findings, *formatStr, *failOnStr, *polStr, *outStr, stdout, stderr)
}

func cmdAuditConfig(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("audit-config", stderr)
	cfgPath := fs.String("path", ".", "Path to Nginx/Caddy configuration file or directory")
	formatStr, failOnStr, polStr, outStr := parseReportFlags(fs)
	if done, code := parseArgsWithHelp(fs, args); done {
		return code
	}

	findings, err := auditor.AuditConfigPath(*cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	return emitReport(findings, *formatStr, *failOnStr, *polStr, *outStr, stdout, stderr)
}

func cmdInspectRequest(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("inspect-request", stderr)
	inputStr := fs.String("input", "", "Inline payload string to inspect")
	filePath := fs.String("file", "", "Path to saved payload file to inspect")
	formatStr, failOnStr, polStr, outStr := parseReportFlags(fs)
	if done, code := parseArgsWithHelp(fs, args); done {
		return code
	}

	hasInput := strings.TrimSpace(*inputStr) != ""
	hasFile := strings.TrimSpace(*filePath) != ""
	if hasInput == hasFile {
		fmt.Fprintln(stderr, "error: provide exactly one of --input or --file")
		return 1
	}

	var findings []schema.Finding
	var err error
	if hasFile {
		findings, err = auditor.InspectPayloadFile(*filePath)
	} else {
		findings, err = auditor.InspectPayload(*inputStr, "inline://request")
	}
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	return emitReport(findings, *formatStr, *failOnStr, *polStr, *outStr, stdout, stderr)
}

func cmdAuditWorkspace(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("audit-workspace", stderr)
	wsPath := fs.String("path", ".", "Workspace directory path")
	formatStr, failOnStr, polStr, outStr := parseReportFlags(fs)
	if done, code := parseArgsWithHelp(fs, args); done {
		return code
	}

	findings, err := auditor.AuditWorkspace(*wsPath)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	return emitReport(findings, *formatStr, *failOnStr, *polStr, *outStr, stdout, stderr)
}

func emitReport(
	findings []schema.Finding,
	formatRaw string,
	failOnRaw string,
	policyPath string,
	outputPath string,
	stdout io.Writer,
	stderr io.Writer,
) int {
	fmtKind, err := report.ParseFormat(formatRaw)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	var threshold schema.Severity
	if strings.TrimSpace(failOnRaw) != "" {
		threshold, err = schema.ParseSeverity(failOnRaw)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
	}

	if strings.TrimSpace(policyPath) != "" {
		pol, err := policy.LoadPolicy(policyPath)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		findings, _ = policy.ApplyPolicy(findings, pol, time.Now().UTC())
	}

	rep := schema.NewReport(findings, time.Now().UTC())

	if strings.TrimSpace(outputPath) != "" {
		if parent := filepath.Dir(outputPath); parent != "." && parent != "" {
			if err := os.MkdirAll(parent, 0o755); err != nil {
				fmt.Fprintf(stderr, "error: create output directory: %v\n", err)
				return 1
			}
		}
		f, err := os.Create(outputPath)
		if err != nil {
			fmt.Fprintf(stderr, "error: create output file %q: %v\n", outputPath, err)
			return 1
		}
		writeErr := report.WriteReport(f, rep, fmtKind)
		closeErr := f.Close()
		if writeErr != nil {
			fmt.Fprintf(stderr, "error: write report: %v\n", writeErr)
			return 1
		}
		if closeErr != nil {
			fmt.Fprintf(stderr, "error: close report file: %v\n", closeErr)
			return 1
		}
	} else if err := report.WriteReport(stdout, rep, fmtKind); err != nil {
		fmt.Fprintf(stderr, "error: write report: %v\n", err)
		return 1
	}

	if rep.HasThresholdBreach(threshold) {
		return 2
	}
	return 0
}
