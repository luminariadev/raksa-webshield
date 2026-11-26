import { inspectInput, sanitizeHtml, buildSecurityHeaders } from "../dist/index.js";

const iters = 20_000;
const htmlSample = `<p class="msg">Hello <a href="https://example.org" target="_blank">world</a> <img src=x onerror=alert(1)><script>alert(1)</script></p>`;
const wafSample = `{"username":"alice","bio":"Go & TypeScript defense guide","next":"/dashboard"}`;

// Warmup
for (let i = 0; i < 1000; i++) {
  sanitizeHtml(htmlSample);
  inspectInput(wafSample);
  buildSecurityHeaders();
}

const t0 = performance.now();
let sinkLen = 0;
for (let i = 0; i < iters; i++) {
  sinkLen += sanitizeHtml(htmlSample).length;
}
const dtSan = (performance.now() - t0) / 1000;

const t1 = performance.now();
for (let i = 0; i < iters; i++) {
  sinkLen += inspectInput(wafSample).length;
}
const dtWaf = (performance.now() - t1) / 1000;

console.log(`raksa-webshield ts-sdk benchmark (iters=${iters}, sink=${sinkLen})`);
console.log(
  `ts_sanitizeHtml : ${iters} iters | ${dtSan.toFixed(4)}s | ${(iters / dtSan).toFixed(1)} ops/s`,
);
console.log(
  `ts_inspectInput : ${iters} iters | ${dtWaf.toFixed(4)}s | ${(iters / dtWaf).toFixed(1)} ops/s`,
);
