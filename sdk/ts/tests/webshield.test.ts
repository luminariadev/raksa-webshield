import test from "node:test";
import assert from "node:assert/strict";

import {
  buildSecurityHeaders,
  createWebShieldMiddleware,
  escapeHtml,
  inspectInput,
  isSafeUrl,
  sanitizeHtml,
  type RaksaReport,
  type WebShieldResponseLike,
} from "../dist/index.js";

test("escapeHtml encodes dangerous characters safely", () => {
  assert.equal(
    escapeHtml(`<div class="a" data-x='1'>a & b \`c\`</div>`),
    "&lt;div class=&quot;a&quot; data-x=&#39;1&#39;&gt;a &amp; b &#96;c&#96;&lt;/div&gt;",
  );
});

test("sanitizeHtml preserves benign rich markup and neutralizes 20+ XSS bypass vectors", () => {
  const safe = sanitizeHtml(
    `<p class="lead">Hello <strong>world</strong> &amp; <a href="https://example.org/docs" target="_blank">docs</a></p>`,
  );
  assert.match(safe, /^<p class="lead">Hello <strong>world<\/strong>/);
  assert.match(safe, /rel="noopener noreferrer"/);

  const vectors = [
    `<script>alert(1)</script>`,
    `<SCRIPT SRC="https://evil.invalid/x.js"></SCRIPT>`,
    `<scr<script>ipt>alert(1)</scr</script>ipt>`,
    `<img src=x onerror=alert(1)>`,
    `<svg onload="alert(1)"><circle/></svg>`,
    `<svg/onload=alert(1)>`,
    `<iframe srcdoc="<script>alert(1)</script>"></iframe>`,
    `<math><mi xlink:href="javascript:alert(1)">x</mi></math>`,
    `<style>body{background:url(javascript:alert(1))}</style>`,
    `<a href="javascript:alert(1)">click</a>`,
    `<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert(1)">ent</a>`,
    `<a href="&#x6a;avascript:alert(1)">hex</a>`,
    `<a href="java\tscript:alert(1)">tab</a>`,
    `<a href="java\nscript:alert(1)">nl</a>`,
    `<a href="vbscript:msgbox(1)">vb</a>`,
    `<a href="data:text/html,<script>alert(1)</script>">data</a>`,
    `<p onclick="fetch('https://evil.invalid')">tap</p>`,
    `<p onmouseover=alert(1) style="color:expression(alert(1))">hover</p>`,
    `<a href="//evil.invalid/phish">proto-rel</a>`,
    `<object data="data:text/html,xss"></object>`,
    `<script>unclosed`,
  ];

  for (const payload of vectors) {
    const cleaned = sanitizeHtml(payload);
    assert.equal(/<script\b/i.test(cleaned), false, `script leaked for: ${payload} -> ${cleaned}`);
    assert.equal(/\bon\w+\s*=/i.test(cleaned), false, `event handler leaked for: ${payload} -> ${cleaned}`);
    assert.equal(/(javascript|vbscript|data:text\/html)/i.test(cleaned), false, `scheme leaked for: ${payload} -> ${cleaned}`);
    assert.equal(/href="\/\//i.test(cleaned), false, `protocol-relative link leaked for: ${payload}`);
  }
});

test("isSafeUrl rejects dangerous schemes and permits https, mailto, and single-slash relative paths", () => {
  assert.equal(isSafeUrl("https://luminariadev.github.io/docs"), true);
  assert.equal(isSafeUrl("http://example.com/status"), true);
  assert.equal(isSafeUrl("mailto:security@example.com"), true);
  assert.equal(isSafeUrl("/login?next=/dashboard"), true);
  assert.equal(isSafeUrl("#section-2"), true);

  assert.equal(isSafeUrl("&#x09;javascript:alert(1)"), false);
  assert.equal(isSafeUrl("data:text/html;base64,PHNjcmlwdD4="), false);
  assert.equal(isSafeUrl("//attacker.invalid/login"), false);
});

test("buildSecurityHeaders returns complete hardened defaults", () => {
  const hdrs = buildSecurityHeaders();
  assert.match(hdrs["Strict-Transport-Security"] ?? "", /^max-age=31536000/);
  assert.match(hdrs["Content-Security-Policy"] ?? "", /object-src 'none'/);
  assert.equal(hdrs["X-Frame-Options"], "DENY");
  assert.equal(hdrs["X-Content-Type-Options"], "nosniff");
  assert.equal(hdrs["Cross-Origin-Opener-Policy"], "same-origin");
});

test("inspectInput flags XSS, SQLi, traversal, prototype pollution, and SSRF while allowing benign prose", () => {
  assert.equal(
    inspectInput(JSON.stringify({ comment: "1 + 1 = 2 for Go & TypeScript team", page: "/docs" })).length,
    0,
  );

  const findings = inspectInput(
    JSON.stringify({
      xss: "<svg onload=alert(1)>",
      sqli: "' OR '1'='1' UNION SELECT * FROM users;--",
      lfi: "%2e%2e%2fetc%2fpasswd",
      proto: JSON.parse('{"__proto__":{"admin":true}}') as unknown,
      ssrf: "http://169.254.169.254/latest/meta-data/",
    }),
  );
  const rules = new Set(findings.map((f) => f.rule_id));
  for (const id of ["WEB-301", "WEB-302", "WEB-303", "WEB-304", "WEB-305"]) {
    assert.equal(rules.has(id), true, `missing expected finding ${id}`);
  }
});

test("createWebShieldMiddleware blocks attacks in enforce mode and logs Raksa report in monitor mode", () => {
  const mkRes = () => {
    const headers: Record<string, string> = { "X-Powered-By": "Express" };
    let endedBody = "";
    const res: WebShieldResponseLike & { headers: Record<string, string>; endedBody: string } = {
      statusCode: 200,
      headers,
      endedBody,
      setHeader(name: string, value: string) {
        headers[name] = value;
      },
      removeHeader(name: string) {
        delete headers[name];
      },
      end(chunk?: string) {
        this.endedBody = chunk ?? "";
      },
    };
    return res;
  };

  // Enforce mode blocks malicious request with 403 and removes X-Powered-By.
  const enforceMw = createWebShieldMiddleware({ mode: "enforce" });
  const resBlocked = mkRes();
  let nextCalled = false;
  enforceMw(
    { method: "POST", url: "/api/comment", body: { text: "<script>alert(1)</script>" } },
    resBlocked,
    () => {
      nextCalled = true;
    },
  );
  assert.equal(nextCalled, false);
  assert.equal(resBlocked.statusCode, 403);
  assert.equal(resBlocked.headers["X-Powered-By"], undefined);
  assert.equal(resBlocked.headers["X-Content-Type-Options"], "nosniff");
  const blockedPayload = JSON.parse(resBlocked.endedBody) as { report: RaksaReport };
  assert.equal(blockedPayload.report.schema_version, "1.0");
  assert.equal(blockedPayload.report.layer, "web-defense");

  // Enforce mode permits benign request.
  const resOk = mkRes();
  let okNext = false;
  enforceMw(
    { method: "GET", url: "/health", query: { ok: "true" } },
    resOk,
    () => {
      okNext = true;
    },
  );
  assert.equal(okNext, true);
  assert.equal(resOk.statusCode, 200);

  // Monitor mode invokes onReport callback and allows request through.
  let observedReport: RaksaReport | undefined;
  const monitorMw = createWebShieldMiddleware({
    mode: "monitor",
    onReport(rep) {
      observedReport = rep;
    },
  });
  const resMon = mkRes();
  let monNext = false;
  monitorMw(
    { method: "GET", url: "/fetch?target=http://169.254.169.254/latest/meta-data/" },
    resMon,
    () => {
      monNext = true;
    },
  );
  assert.equal(monNext, true);
  assert.equal(observedReport?.summary.critical, 1);
  assert.equal(observedReport?.findings[0]?.rule_id, "WEB-305");
});
