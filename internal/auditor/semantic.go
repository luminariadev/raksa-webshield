package auditor

import (
	"strings"
)

type sqlTokKind byte

const (
	tokKeyword sqlTokKind = 'k'
	tokString  sqlTokKind = 's'
	tokNumber  sqlTokKind = '1'
	tokOp      sqlTokKind = 'o'
	tokIdent   sqlTokKind = 'n'
	tokComment sqlTokKind = 'c'
	tokLParen  sqlTokKind = '('
	tokRParen  sqlTokKind = ')'
	tokComma   sqlTokKind = ','
	tokSemi    sqlTokKind = ';'
)

type sqlTok struct {
	kind sqlTokKind
	raw  string
}

var sqlSemanticKeywords = map[string]struct{}{
	"union": {}, "select": {}, "from": {}, "where": {},
	"or": {}, "and": {}, "having": {}, "order": {}, "group": {}, "by": {},
	"insert": {}, "into": {}, "values": {}, "update": {}, "set": {},
	"delete": {}, "drop": {}, "alter": {}, "create": {},
	"exec": {}, "execute": {}, "sleep": {}, "pg_sleep": {}, "benchmark": {},
	"waitfor": {}, "delay": {}, "extractvalue": {}, "updatexml": {},
	"concat": {}, "cast": {}, "convert": {}, "case": {}, "when": {}, "then": {},
	"in": {}, "not": {}, "null": {}, "xp_cmdshell": {},
}

var sqlExploitFunctions = map[string]struct{}{
	"pg_sleep": {}, "benchmark": {}, "extractvalue": {}, "updatexml": {}, "sleep": {},
}

var htmlExecutableTags = map[string]struct{}{
	"script": {}, "iframe": {}, "object": {}, "embed": {}, "applet": {},
	"base": {}, "svg": {}, "math": {}, "template": {}, "xmp": {}, "noscript": {},
}

var htmlURIAttributes = map[string]struct{}{
	"href": {}, "src": {}, "action": {}, "formaction": {}, "data": {},
	"poster": {}, "xlink:href": {}, "codebase": {}, "srcdoc": {},
}

func AnalyzeSQLiSemantic(input string) (fingerprint string, sample string, matched bool) {
	if !hasSQLSemanticQuickTrigger(input) {
		return "", "", false
	}

	// Scan both from start and immediately after quote boundaries so string-terminating payloads (e.g., 1' OR 2>1--) parse accurately.
	if fp, smp, ok := scanSQLFragment(input, false); ok {
		return fp, smp, true
	}

	for i := 0; i < len(input); i++ {
		if input[i] == '\'' || input[i] == ')' {
			if fp, smp, ok := scanSQLFragment(input[i+1:], true); ok {
				return fp, smp, true
			}
			// Also check if another quote appears later inside JSON/form values.
			if input[i] == '\'' {
				break
			}
		}
	}

	// Also scan right after closing paren/quote at later single quotes (max 3 offsets bounded).
	offsets := 0
	for i := 0; i < len(input) && offsets < 3; i++ {
		if input[i] == '\'' {
			offsets++
			if offsets > 1 {
				if fp, smp, ok := scanSQLFragment(input[i+1:], true); ok {
					return fp, smp, true
				}
			}
		}
	}

	return "", "", false
}

func hasSQLSemanticQuickTrigger(s string) bool {
	if len(s) < 5 {
		return false
	}
	hasBreak := false
	hasAlpha := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\'' || c == ';' || c == '(' || c == ')' || c == '=' || c == '<' || c == '>' || c == '-' || c == '/' {
			hasBreak = true
		} else if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			hasAlpha = true
		}
	}
	if !hasBreak || !hasAlpha {
		return false
	}
	low := strings.ToLower(s)
	return hasAnyBoundedKeyword(low)
}

func hasAnyBoundedKeyword(low string) bool {
	i := 0
	for i < len(low) {
		if isASCIIIdentStart(low[i]) {
			start := i
			i++
			for i < len(low) && isASCIIIdentCont(low[i]) {
				i++
			}
			word := low[start:i]
			if _, ok := sqlSemanticKeywords[word]; ok {
				if word != "from" && word != "in" && word != "set" && word != "not" && word != "null" && word != "by" {
					return true
				}
			}
			continue
		}
		i++
	}
	return false
}

func scanSQLFragment(frag string, afterContextBreak bool) (string, string, bool) {
	if len(frag) < 4 {
		return "", "", false
	}
	tokens := tokenizeSQL(frag)
	if len(tokens) == 0 {
		return "", "", false
	}

	// Strip comment tokens for structural grammar checks while remembering whether comments appeared.
	hadComment := false
	compact := make([]sqlTok, 0, len(tokens))
	for _, t := range tokens {
		if t.kind == tokComment {
			hadComment = true
			continue
		}
		compact = append(compact, t)
	}
	if len(compact) == 0 {
		return "", "", false
	}

	// 1. Exploit function call signature: pg_sleep(, benchmark(, extractvalue(, updatexml(, sleep(
	for i := 0; i+1 < len(compact); i++ {
		if compact[i].kind == tokKeyword && compact[i+1].kind == tokLParen {
			if _, isFn := sqlExploitFunctions[compact[i].raw]; isFn {
				return buildFingerprint(compact, i, 4), collectSample(compact, i, 4), true
			}
		}
	}

	// 2. UNION [ALL] SELECT
	for i := 0; i+1 < len(compact); i++ {
		if compact[i].kind == tokKeyword && compact[i].raw == "union" {
			if compact[i+1].kind == tokKeyword && (compact[i+1].raw == "select" || (compact[i+1].raw == "all" && i+2 < len(compact) && compact[i+2].raw == "select")) {
				return buildFingerprint(compact, i, 5), collectSample(compact, i, 5), true
			}
		}
	}

	// 3. Stacked statement: ; EXEC/EXECUTE/DROP/ALTER/CREATE <ident>
	for i := 0; i+2 < len(compact); i++ {
		if compact[i].kind == tokSemi && compact[i+1].kind == tokKeyword {
			switch compact[i+1].raw {
			case "exec", "execute", "drop", "alter", "create":
				return buildFingerprint(compact, i, 4), collectSample(compact, i, 4), true
			}
		}
	}

	// 4. Context-break boolean tautology/comparison or subquery:
	// Requires leading context break (afterContextBreak == true OR comment/semicolon delimiter) to eliminate prose false positives.
	if afterContextBreak && compact[0].kind == tokKeyword && (compact[0].raw == "and" || compact[0].raw == "or") {
		// 4a. AND|OR <expr> <op> <expr> (e.g., AND 2>1--, OR 'a'='a)
		if len(compact) >= 4 && isScalarTok(compact[1].kind) && compact[2].kind == tokOp && isScalarTok(compact[3].kind) {
			return buildFingerprint(compact, 0, 5), collectSample(compact, 0, 5), true
		}
		// 4b. AND|OR <expr> IN ( SELECT ... )
		for i := 1; i+3 < len(compact); i++ {
			if compact[i].kind == tokKeyword && compact[i].raw == "in" && compact[i+1].kind == tokLParen && compact[i+2].kind == tokKeyword && compact[i+2].raw == "select" {
				return buildFingerprint(compact, 0, i+4), collectSample(compact, 0, i+4), true
			}
		}
		// 4c. AND|OR followed by exploit SQL function (after intermediate operator/keyword)
		for i := 1; i+1 < len(compact); i++ {
			if compact[i].kind == tokKeyword && compact[i+1].kind == tokLParen {
				if _, isFn := sqlExploitFunctions[compact[i].raw]; isFn {
					return buildFingerprint(compact, 0, i+3), collectSample(compact, 0, i+3), true
				}
			}
		}
	}

	// 5. Context-break ORDER BY <number> (column enumeration probe, e.g., 1' ORDER BY 10--)
	if afterContextBreak && len(compact) >= 3 && compact[0].kind == tokKeyword && compact[0].raw == "order" &&
		compact[1].kind == tokKeyword && compact[1].raw == "by" && compact[2].kind == tokNumber &&
		(hadComment || len(compact) == 3 || compact[3].kind == tokSemi || compact[3].kind == tokComma) {
		return buildFingerprint(compact, 0, 4), collectSample(compact, 0, 4), true
	}

	return "", "", false
}

func isScalarTok(k sqlTokKind) bool {
	return k == tokNumber || k == tokString || k == tokIdent
}

func tokenizeSQL(s string) []sqlTok {
	toks := make([]sqlTok, 0, 16)
	i := 0
	n := len(s)
	for i < n && len(toks) < 64 {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			i++
			continue
		}
		if c == '-' && i+1 < n && s[i+1] == '-' {
			toks = append(toks, sqlTok{kind: tokComment, raw: "--"})
			break
		}
		if c == '#' {
			toks = append(toks, sqlTok{kind: tokComment, raw: "#"})
			break
		}
		if c == '/' && i+1 < n && s[i+1] == '*' {
			end := strings.Index(s[i+2:], "*/")
			if end >= 0 {
				toks = append(toks, sqlTok{kind: tokComment, raw: "/*"})
				i += 2 + end + 2
				continue
			}
			toks = append(toks, sqlTok{kind: tokComment, raw: "/*"})
			break
		}
		if c == '\'' {
			j := i + 1
			for j < n && s[j] != '\'' {
				j++
			}
			if j < n {
				toks = append(toks, sqlTok{kind: tokString, raw: s[i : j+1]})
				i = j + 1
			} else {
				toks = append(toks, sqlTok{kind: tokString, raw: s[i:]})
				break
			}
			continue
		}
		if c == '"' {
			// Skip bare JSON envelope quotes cleanly instead of swallowing entire payload as one SQL string.
			i++
			continue
		}
		if c >= '0' && c <= '9' {
			j := i + 1
			for j < n && ((s[j] >= '0' && s[j] <= '9') || (s[j] >= 'a' && s[j] <= 'f') || (s[j] >= 'A' && s[j] <= 'F') || s[j] == 'x' || s[j] == '.') {
				j++
			}
			toks = append(toks, sqlTok{kind: tokNumber, raw: s[i:j]})
			i = j
			continue
		}
		if isASCIIIdentStart(c) {
			j := i + 1
			for j < n && isASCIIIdentCont(s[j]) {
				j++
			}
			low := strings.ToLower(s[i:j])
			if _, ok := sqlSemanticKeywords[low]; ok {
				toks = append(toks, sqlTok{kind: tokKeyword, raw: low})
			} else {
				toks = append(toks, sqlTok{kind: tokIdent, raw: low})
			}
			i = j
			continue
		}
		switch c {
		case '(':
			toks = append(toks, sqlTok{kind: tokLParen, raw: "("})
		case ')':
			toks = append(toks, sqlTok{kind: tokRParen, raw: ")"})
		case ',':
			toks = append(toks, sqlTok{kind: tokComma, raw: ","})
		case ';':
			toks = append(toks, sqlTok{kind: tokSemi, raw: ";"})
		case '=', '<', '>', '!':
			if i+1 < n && (s[i+1] == '=' || s[i+1] == '>') {
				toks = append(toks, sqlTok{kind: tokOp, raw: s[i : i+2]})
				i++
			} else {
				toks = append(toks, sqlTok{kind: tokOp, raw: s[i : i+1]})
			}
		}
		i++
	}
	return toks
}

func buildFingerprint(toks []sqlTok, start, maxCount int) string {
	var b strings.Builder
	end := start + maxCount
	if end > len(toks) {
		end = len(toks)
	}
	for i := start; i < end; i++ {
		b.WriteByte(byte(toks[i].kind))
	}
	return b.String()
}

func collectSample(toks []sqlTok, start, maxCount int) string {
	end := start + maxCount
	if end > len(toks) {
		end = len(toks)
	}
	parts := make([]string, 0, end-start)
	for i := start; i < end; i++ {
		parts = append(parts, toks[i].raw)
	}
	return strings.Join(parts, " ")
}

func isASCIIIdentStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'
}

func isASCIIIdentCont(c byte) bool {
	return isASCIIIdentStart(c) || (c >= '0' && c <= '9')
}

func AnalyzeXSSSemantic(input string) (vector string, sample string, matched bool) {
	if strings.IndexByte(input, '<') < 0 {
		return "", "", false
	}

	n := len(input)
	for i := 0; i < n; i++ {
		if input[i] != '<' {
			continue
		}
		j := i + 1
		if j >= n || !isASCIIAlpha(input[j]) {
			continue
		}
		nameStart := j
		for j < n && (isASCIIAlpha(input[j]) || (input[j] >= '0' && input[j] <= '9') || input[j] == '-') {
			j++
		}
		tagName := strings.ToLower(input[nameStart:j])

		tagEnd := findHTMLTagClose(input, j)
		rawTag := input[i:tagEnd]

		if _, execTag := htmlExecutableTags[tagName]; execTag {
			// Skip ambiguous harmless text only if tag is malformed (no space, '/', or '>') right after tagName.
			if j == n || input[j] == '>' || input[j] == '/' || input[j] <= ' ' {
				return "executable-tag:" + tagName, rawTag, true
			}
		}

		attrSlice := input[j:tagEnd]
		if tagEnd > j && attrSlice[len(attrSlice)-1] == '>' {
			attrSlice = attrSlice[:len(attrSlice)-1]
		}
		if vec, attrHit := scanTagAttributesForXSS(tagName, attrSlice); vec != "" {
			return vec, attrHit, true
		}
	}

	return "", "", false
}

func findHTMLTagClose(s string, start int) int {
	var quote byte
	for i := start; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			continue
		}
		if c == '>' {
			return i + 1
		}
		if c == '<' {
			return i
		}
	}
	return len(s)
}

func scanTagAttributesForXSS(tagName string, attrs string) (string, string) {
	i := 0
	n := len(attrs)
	isMetaTag := tagName == "meta"

	for i < n {
		// Treat whitespace and '/' as valid HTML5 attribute separators (<img/src=x/onerror=...>).
		for i < n && (attrs[i] <= ' ' || attrs[i] == '/') {
			i++
		}
		if i >= n {
			break
		}
		nameStart := i
		for i < n && attrs[i] != '=' && attrs[i] > ' ' && attrs[i] != '/' && attrs[i] != '>' {
			i++
		}
		attrName := strings.ToLower(strings.Trim(attrs[nameStart:i], `"'`))
		for i < n && attrs[i] <= ' ' {
			i++
		}

		attrVal := ""
		if i < n && attrs[i] == '=' {
			i++
			for i < n && attrs[i] <= ' ' {
				i++
			}
			if i < n && (attrs[i] == '"' || attrs[i] == '\'') {
				q := attrs[i]
				i++
				vStart := i
				for i < n && attrs[i] != q {
					i++
				}
				attrVal = attrs[vStart:i]
				if i < n {
					i++
				}
			} else {
				vStart := i
				for i < n && attrs[i] > ' ' && attrs[i] != '>' {
					i++
				}
				attrVal = attrs[vStart:i]
			}
		}

		if strings.HasPrefix(attrName, "on") && len(attrName) >= 5 && isAllASCIIAlpha(attrName) && attrVal != "" {
			return "event-handler:" + attrName, attrName + "=" + attrVal
		}

		if _, isURI := htmlURIAttributes[attrName]; isURI {
			norm := stripControlCharsLower(attrVal)
			if strings.HasPrefix(norm, "javascript:") || strings.HasPrefix(norm, "vbscript:") || strings.HasPrefix(norm, "data:text/html") || strings.HasPrefix(norm, "data:application/xhtml") {
				return "dangerous-uri:" + attrName, attrName + "=" + attrVal
			}
		}

		if isMetaTag && attrName == "content" {
			norm := stripControlCharsLower(attrVal)
			if strings.Contains(norm, "url=javascript:") || strings.Contains(norm, "url=data:text/html") {
				return "meta-refresh-uri", attrVal
			}
		}
	}
	return "", ""
}

func stripControlCharsLower(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x20 || c == 0x7f {
			continue
		}
		if c >= 'A' && c <= 'Z' {
			b.WriteByte(c + ('a' - 'A'))
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func isASCIIAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isAllASCIIAlpha(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isASCIIAlpha(s[i]) {
			return false
		}
	}
	return len(s) > 0
}
