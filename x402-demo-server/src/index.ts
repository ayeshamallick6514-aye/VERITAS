import { Hono } from "hono";
import { cors } from "hono/cors";
import { serve } from "@hono/node-server";
import { paymentMiddleware } from "@x402-avm/hono";
import { HTTPFacilitatorClient, x402ResourceServer } from "@x402-avm/core/server";
import { registerExactAvmScheme } from "@x402-avm/avm/exact/server";
import { routesConfig } from "./endpoints.config.js";
import { handleFreeAudit, handleAuditExplain } from "./handlers/audit-agent.js";
import { handleGithubWebhook } from "./handlers/github-webhook.js";
import dotenv from "dotenv";

dotenv.config();

const app = new Hono();

app.use(
  "*",
  cors({
    origin: "*",
    allowMethods: ["GET", "POST", "OPTIONS"],
    allowHeaders: [
      "Content-Type",
      "Authorization",
      "PAYMENT-SIGNATURE",
      "PAYMENT-REQUIRED",
      "PAYMENT-RESPONSE",
      "X-PAYMENT",
    ],
    exposeHeaders: [
      "PAYMENT-SIGNATURE",
      "PAYMENT-REQUIRED",
      "PAYMENT-RESPONSE",
      "Content-Type",
    ],
  })
);

const facilitatorUrl =
  process.env.FACILITATOR_URL || "https://facilitator.goplausible.xyz";
const facilitatorClient = new HTTPFacilitatorClient({
  url: facilitatorUrl,
});

const resourceServer = new x402ResourceServer(facilitatorClient);
registerExactAvmScheme(resourceServer, {});

app.get("/api/health", (c) => {
  return c.json({
    status: "healthy",
    service: "AuditAgent-X Security Intelligence Engine",
    protocol: "x402-avm",
    timestamp: new Date().toISOString(),
  });
});

app.post("/api/audit-free", handleFreeAudit);
app.post("/api/github-webhook", handleGithubWebhook);

app.use(paymentMiddleware(routesConfig, resourceServer));

app.post("/api/audit-explain", handleAuditExplain);

const port = Number(process.env.PORT) || 4021;

console.log(`[AuditAgent-X] Initializing backend daemon on port ${port}...`);
console.log(`[AuditAgent-X] Facilitator endpoint configured at: ${facilitatorUrl}`);
console.log(`[AuditAgent-X] Gated route mounted: POST /api/audit-explain ($0.005 USDC)`);
console.log(`[AuditAgent-X] GitHub Bot webhook mounted: POST /api/github-webhook`);

serve({
  fetch: app.fetch,
  port,
});
