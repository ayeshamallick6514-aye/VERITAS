async function runTest() {
  const baseUrl = "http://localhost:4021";

  console.log("--> Testing GET /api/health...");
  const health = await fetch(`${baseUrl}/api/health`);
  console.log(`[Health] Status: ${health.status}`);
  console.log(await health.json());

  console.log("\n--> Testing POST /api/audit-free (Unprotected)...");
  const free = await fetch(`${baseUrl}/api/audit-free`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      code: "Assert(Txn.sender() == Global.creator_address())",
      language: "pyteal",
    }),
  });
  console.log(`[Free Scan] Status: ${free.status}`);
  console.log(await free.json());

  console.log("\n--> Testing POST /api/audit-explain (Monetized x402 Route)...");
  const explain = await fetch(`${baseUrl}/api/audit-explain`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      code: 'InnerTxnBuilder.Submit()\nApp.globalPut(Bytes("stake"), Int(0))',
      language: "pyteal",
    }),
  });
  console.log(`[Gated Scan] Status (Expect 402): ${explain.status}`);
  const payReqHeader = explain.headers.get("payment-required");
  console.log(`[Gated Scan] PAYMENT-REQUIRED header present: ${!!payReqHeader}`);
  if (payReqHeader) {
    try {
      console.log("[Gated Scan] Decoded terms:", Buffer.from(payReqHeader, "base64").toString("utf-8"));
    } catch {
      console.log("[Gated Scan] Raw header:", payReqHeader);
    }
  }
  console.log("[Gated Scan] Response body:", await explain.json());
}

runTest().catch(console.error);
