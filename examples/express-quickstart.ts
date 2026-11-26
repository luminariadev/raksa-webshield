import http from "node:http";
import {
  createWebShieldMiddleware,
  sanitizeHtml,
  type RaksaReport,
} from "../sdk/ts/dist/index.js";

const shield = createWebShieldMiddleware({
  mode: "enforce",
  cspNonce: true,
  anomalyThreshold: 4,
  excludePaths: ["/healthz"],
  rateLimit: { windowMs: 60_000, maxRequests: 120 },
  onReport(report: RaksaReport, _req, incidentId: string) {
    console.warn("blocked web request:", incidentId, JSON.stringify(report));
  },
});

const server = http.createServer((req, res) => {
  shield(req, res, () => {
    const cleanHtml = sanitizeHtml("<p>Welcome to <strong>Raksa WebShield</strong></p>");
    res.statusCode = 200;
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.end(cleanHtml);
  });
});

if (process.env.RAKSA_START_EXAMPLE === "1") {
  server.listen(8080, "127.0.0.1");
}
