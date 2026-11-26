package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/luminariadev/raksa-webshield/internal/auditor"
	"github.com/luminariadev/raksa-webshield/internal/policy"
	"github.com/luminariadev/raksa-webshield/internal/schema"
)

const (
	mcpProtocolVersion = "2024-11-05"
	maxRPCLineBytes    = 2 * 1024 * 1024
)

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

func ServeStdio() error {
	return ServeStreams(os.Stdin, os.Stdout)
}

func ServeStreams(r io.Reader, w io.Writer) error {
	br := bufio.NewReaderSize(r, 64*1024)
	bw := bufio.NewWriter(w)

	for {
		line, err := readBoundedLine(br, maxRPCLineBytes)
		if errors.Is(err, io.EOF) && len(line) == 0 {
			break
		}
		if err != nil && !errors.Is(err, io.EOF) {
			resp := rpcResponse{
				JSONRPC: "2.0",
				ID:      json.RawMessage("null"),
				Error:   &rpcError{Code: -32600, Message: fmt.Sprintf("Invalid Request: %v", err)},
			}
			if wErr := writeRPCResponse(bw, resp); wErr != nil {
				return wErr
			}
			continue
		}

		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			if resp := handleLine([]byte(trimmed)); resp != nil {
				if wErr := writeRPCResponse(bw, *resp); wErr != nil {
					return wErr
				}
			}
		}

		if errors.Is(err, io.EOF) {
			break
		}
	}
	return nil
}

func readBoundedLine(br *bufio.Reader, limit int) (string, error) {
	var buf []byte
	for {
		frag, err := br.ReadSlice('\n')
		if len(buf)+len(frag) > limit {
			// Drain remainder of oversized line so next lines stay aligned.
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = br.ReadSlice('\n')
			}
			return "", fmt.Errorf("JSON-RPC line exceeds %d byte limit", limit)
		}
		buf = append(buf, frag...)
		if !errors.Is(err, bufio.ErrBufferFull) {
			return string(buf), err
		}
	}
}

func writeRPCResponse(bw *bufio.Writer, resp rpcResponse) error {
	encoded, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	if _, err := bw.Write(encoded); err != nil {
		return err
	}
	if err := bw.WriteByte('\n'); err != nil {
		return err
	}
	return bw.Flush()
}

func handleLine(raw []byte) *rpcResponse {
	var req rpcRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return &rpcResponse{
			JSONRPC: "2.0",
			ID:      json.RawMessage("null"),
			Error:   &rpcError{Code: -32700, Message: fmt.Sprintf("Parse error: %v", err)},
		}
	}

	reqID := req.ID
	if req.JSONRPC != "2.0" || strings.TrimSpace(req.Method) == "" {
		if len(reqID) == 0 {
			reqID = json.RawMessage("null")
		}
		return &rpcResponse{
			JSONRPC: "2.0",
			ID:      reqID,
			Error:   &rpcError{Code: -32600, Message: "Invalid Request: expected jsonrpc '2.0' and non-empty method"},
		}
	}

	// JSON-RPC 2.0 notifications omit id and receive no response.
	if len(reqID) == 0 {
		return nil
	}

	switch req.Method {
	case "initialize":
		return &rpcResponse{
			JSONRPC: "2.0",
			ID:      reqID,
			Result: map[string]any{
				"protocolVersion": mcpProtocolVersion,
				"capabilities": map[string]any{
					"tools": map[string]any{"listChanged": false},
				},
				"serverInfo": map[string]any{
					"name":    schema.ToolName,
					"version": schema.Version,
				},
			},
		}
	case "ping":
		return &rpcResponse{JSONRPC: "2.0", ID: reqID, Result: map[string]any{}}
	case "tools/list":
		return &rpcResponse{
			JSONRPC: "2.0",
			ID:      reqID,
			Result:  map[string]any{"tools": toolDefinitions()},
		}
	case "tools/call":
		return handleToolCall(reqID, req.Params)
	default:
		return &rpcResponse{
			JSONRPC: "2.0",
			ID:      reqID,
			Error:   &rpcError{Code: -32601, Message: fmt.Sprintf("Method not found: %s", req.Method)},
		}
	}
}

type callParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

func handleToolCall(reqID json.RawMessage, rawParams json.RawMessage) *rpcResponse {
	var p callParams
	if len(rawParams) == 0 || json.Unmarshal(rawParams, &p) != nil || strings.TrimSpace(p.Name) == "" {
		return &rpcResponse{
			JSONRPC: "2.0",
			ID:      reqID,
			Error:   &rpcError{Code: -32602, Message: "Invalid params: missing tool 'name'"},
		}
	}
	if p.Arguments == nil {
		p.Arguments = map[string]any{}
	}

	switch p.Name {
	case "webshield_list_rules":
		raw, err := json.MarshalIndent(schema.RuleCatalog(), "", "  ")
		if err != nil {
			return toolResultErr(reqID, fmt.Sprintf("encode rules: %v", err))
		}
		return toolResultOK(reqID, string(raw))
	case "webshield_audit_headers":
		return callAuditHeaders(reqID, p.Arguments)
	case "webshield_audit_csp":
		return callAuditCSP(reqID, p.Arguments)
	case "webshield_audit_config":
		return callAuditConfig(reqID, p.Arguments)
	case "webshield_inspect_payload":
		return callInspectPayload(reqID, p.Arguments)
	case "webshield_audit_workspace":
		return callAuditWorkspace(reqID, p.Arguments)
	default:
		return &rpcResponse{
			JSONRPC: "2.0",
			ID:      reqID,
			Error:   &rpcError{Code: -32602, Message: fmt.Sprintf("Unknown tool: %s", p.Name)},
		}
	}
}

func callAuditHeaders(reqID json.RawMessage, args map[string]any) *rpcResponse {
	rawHdr, hasRaw := optString(args, "raw_headers")
	filePath, hasFile := optString(args, "file_path")
	liveURL, hasURL := optString(args, "url")

	count := 0
	for _, b := range []bool{hasRaw, hasFile, hasURL} {
		if b {
			count++
		}
	}
	if count != 1 {
		return invalidParams(reqID, "provide exactly one of 'raw_headers', 'file_path', or 'url'")
	}

	target, _ := optString(args, "target")
	if target == "" {
		target = "inline://headers"
	}

	var findings []schema.Finding
	var err error
	switch {
	case hasRaw:
		if len(rawHdr) > auditor.MaxConfigBytes {
			return invalidParams(reqID, fmt.Sprintf("'raw_headers' exceeds %d byte limit", auditor.MaxConfigBytes))
		}
		hdr, parseErr := auditor.ParseRawHeaders(rawHdr)
		if parseErr != nil {
			return toolResultErr(reqID, fmt.Sprintf("parse headers failed: %v", parseErr))
		}
		findings = auditor.AuditHeaders(hdr, target)
	case hasFile:
		findings, err = auditor.AuditHeadersFile(filePath)
		if err != nil {
			return toolResultErr(reqID, fmt.Sprintf("audit headers file failed: %v", err))
		}
	case hasURL:
		allowPrivate := optBool(args, "allow_private", false)
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		findings, err = auditor.FetchAndAuditURL(ctx, liveURL, allowPrivate)
		if err != nil {
			return toolResultErr(reqID, fmt.Sprintf("live URL header audit failed: %v", err))
		}
	}

	return finishReportTool(reqID, findings, args)
}

func callAuditCSP(reqID json.RawMessage, args map[string]any) *rpcResponse {
	csp, ok := optString(args, "csp")
	if !ok || strings.TrimSpace(csp) == "" {
		return invalidParams(reqID, "missing non-empty string 'csp'")
	}
	if len(csp) > auditor.MaxConfigBytes {
		return invalidParams(reqID, fmt.Sprintf("'csp' exceeds %d byte limit", auditor.MaxConfigBytes))
	}
	target, _ := optString(args, "target")
	if target == "" {
		target = "inline://csp"
	}
	findings := auditor.AuditCSP(csp, target)
	return finishReportTool(reqID, findings, args)
}

func callAuditConfig(reqID json.RawMessage, args map[string]any) *rpcResponse {
	pathVal, hasPath := optString(args, "path")
	content, hasContent := optString(args, "content")
	if hasPath == hasContent {
		return invalidParams(reqID, "provide exactly one of 'path' or 'content'")
	}

	var findings []schema.Finding
	if hasPath {
		res, err := auditor.AuditConfigPath(pathVal)
		if err != nil {
			return toolResultErr(reqID, fmt.Sprintf("audit config path failed: %v", err))
		}
		findings = res
	} else {
		if len(content) > auditor.MaxConfigBytes {
			return invalidParams(reqID, fmt.Sprintf("'content' exceeds %d byte limit", auditor.MaxConfigBytes))
		}
		label, _ := optString(args, "source_label")
		if label == "" {
			label = "inline://nginx.conf"
		}
		findings = auditor.AuditConfigContent(content, label)
	}

	return finishReportTool(reqID, findings, args)
}

func callInspectPayload(reqID json.RawMessage, args map[string]any) *rpcResponse {
	payload, ok := optString(args, "payload")
	if !ok {
		return invalidParams(reqID, "missing string 'payload'")
	}
	if len(payload) > auditor.MaxConfigBytes {
		return invalidParams(reqID, fmt.Sprintf("'payload' exceeds %d byte limit", auditor.MaxConfigBytes))
	}
	label, _ := optString(args, "source_label")
	if label == "" {
		label = "inline://payload"
	}

	findings, err := auditor.InspectPayload(payload, label)
	if err != nil {
		return invalidParams(reqID, err.Error())
	}
	return finishReportTool(reqID, findings, args)
}

func callAuditWorkspace(reqID json.RawMessage, args map[string]any) *rpcResponse {
	wsPath, ok := optString(args, "path")
	if !ok || strings.TrimSpace(wsPath) == "" {
		return invalidParams(reqID, "missing string 'path'")
	}
	findings, err := auditor.AuditWorkspace(wsPath)
	if err != nil {
		return toolResultErr(reqID, fmt.Sprintf("audit workspace failed: %v", err))
	}
	return finishReportTool(reqID, findings, args)
}

func finishReportTool(reqID json.RawMessage, findings []schema.Finding, args map[string]any) *rpcResponse {
	if polPath, hasPol := optString(args, "policy_path"); hasPol && strings.TrimSpace(polPath) != "" {
		pol, err := policy.LoadPolicy(polPath)
		if err != nil {
			return toolResultErr(reqID, fmt.Sprintf("load policy %q failed: %v", polPath, err))
		}
		findings, _ = policy.ApplyPolicy(findings, pol, time.Now().UTC())
	}

	rep := schema.NewReport(findings, time.Now().UTC())
	encoded, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return toolResultErr(reqID, fmt.Sprintf("encode report: %v", err))
	}
	return toolResultOK(reqID, string(encoded))
}

func optString(args map[string]any, key string) (string, bool) {
	v, ok := args[key]
	if !ok || v == nil {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func optBool(args map[string]any, key string, fallback bool) bool {
	v, ok := args[key]
	if !ok || v == nil {
		return fallback
	}
	b, ok := v.(bool)
	if !ok {
		return fallback
	}
	return b
}

func invalidParams(reqID json.RawMessage, msg string) *rpcResponse {
	return &rpcResponse{
		JSONRPC: "2.0",
		ID:      reqID,
		Error:   &rpcError{Code: -32602, Message: "Invalid params: " + msg},
	}
}

func toolResultOK(reqID json.RawMessage, text string) *rpcResponse {
	return &rpcResponse{
		JSONRPC: "2.0",
		ID:      reqID,
		Result: map[string]any{
			"content": []map[string]any{{"type": "text", "text": text}},
			"isError": false,
		},
	}
}

func toolResultErr(reqID json.RawMessage, text string) *rpcResponse {
	return &rpcResponse{
		JSONRPC: "2.0",
		ID:      reqID,
		Result: map[string]any{
			"content": []map[string]any{{"type": "text", "text": text}},
			"isError": true,
		},
	}
}

func toolDefinitions() []map[string]any {
	return []map[string]any{
		{
			"name":        "webshield_list_rules",
			"description": "List all 18 HTTP header, CSP, CORS, cookie, reverse-proxy config, and defensive WAF rules supported by raksa-webshield.",
			"inputSchema": map[string]any{
				"type":                 "object",
				"properties":           map[string]any{},
				"additionalProperties": false,
			},
		},
		{
			"name":        "webshield_audit_headers",
			"description": "Audit HTTP response headers (from raw text, file dump, or SSRF-protected live HTTP/HTTPS URL) against OWASP ASVS security header, CORS, and Set-Cookie rules.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"raw_headers":   map[string]any{"type": "string", "description": "Raw HTTP response header block (max 1 MiB)."},
					"file_path":     map[string]any{"type": "string", "description": "Path to saved HTTP response header file."},
					"url":           map[string]any{"type": "string", "description": "Read-only HTTP/HTTPS URL to fetch response headers from."},
					"allow_private": map[string]any{"type": "boolean", "description": "Allow localhost/private IP targets intentionally (default false)."},
					"target":        map[string]any{"type": "string", "description": "Optional target label for inline headers."},
					"policy_path":   map[string]any{"type": "string", "description": "Optional YAML/JSON suppression policy path."},
				},
				"additionalProperties": false,
			},
		},
		{
			"name":        "webshield_audit_csp",
			"description": "Audit a Content-Security-Policy string for unsafe-inline, unsafe-eval, wildcards, data:/http: sources, and missing object-src/base-uri guards.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"csp":         map[string]any{"type": "string", "description": "Content-Security-Policy header value (max 1 MiB)."},
					"target":      map[string]any{"type": "string", "description": "Optional target identifier."},
					"policy_path": map[string]any{"type": "string", "description": "Optional YAML/JSON suppression policy path."},
				},
				"required":             []string{"csp"},
				"additionalProperties": false,
			},
		},
		{
			"name":        "webshield_audit_config",
			"description": "Audit Nginx or Caddyfile web server configuration files or inline snippets for legacy TLS protocols, version banners, unsafe CORS/CSP headers, and body limits.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":         map[string]any{"type": "string", "description": "File or directory path containing Nginx/Caddy configs."},
					"content":      map[string]any{"type": "string", "description": "Inline Nginx/Caddy config text (max 1 MiB)."},
					"source_label": map[string]any{"type": "string", "description": "Optional label for inline config findings."},
					"policy_path":  map[string]any{"type": "string", "description": "Optional YAML/JSON suppression policy path."},
				},
				"additionalProperties": false,
			},
		},
		{
			"name":        "webshield_inspect_payload",
			"description": "Defensively inspect HTTP parameters or JSON/text payloads for XSS, SQLi, Path Traversal, Prototype Pollution, and metadata SSRF patterns.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"payload":      map[string]any{"type": "string", "description": "Payload string to inspect (max 1 MiB)."},
					"source_label": map[string]any{"type": "string", "description": "Optional label identifying request context."},
					"policy_path":  map[string]any{"type": "string", "description": "Optional YAML/JSON suppression policy path."},
				},
				"required":             []string{"payload"},
				"additionalProperties": false,
			},
		},
		{
			"name":        "webshield_audit_workspace",
			"description": "Recursively audit an entire workspace for insecure reverse-proxy configurations and saved HTTP header dumps with optional suppression policy.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":        map[string]any{"type": "string", "description": "Workspace directory path."},
					"policy_path": map[string]any{"type": "string", "description": "Optional YAML/JSON suppression policy path."},
				},
				"required":             []string{"path"},
				"additionalProperties": false,
			},
		},
	}
}
