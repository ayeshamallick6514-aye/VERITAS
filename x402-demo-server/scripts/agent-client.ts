/**
 * AuditAgent-X: Headless Autonomous Agent Consumer (CLI)
 *
 * Demonstrates autonomous machine-to-machine consumption of x402-gated security telemetry.
 * The agent automatically discovers the HTTP 402 challenge, inspects CAIP-2 terms and price,
 * constructs the signed AVM transaction group headlessly using its local Ed25519 key,
 * and settles on Algorand Testnet without human intervention or UI prompts.
 */

import algosdk from "algosdk";
import dotenv from "dotenv";

dotenv.config();

const API_BASE_URL = process.env.API_URL || "http://localhost:4021";
const ALGOD_SERVER = process.env.ALGOD_SERVER || "https://testnet-api.algonode.cloud";
const USDC_ASA_ID = Number(process.env.USDC_ASA_ID) || 10458941;
const AGENT_MNEMONIC = process.env.AGENT_MNEMONIC;

// Sample vulnerable PyTeal code payload
const SAMPLE_CONTRACT = `# Autonomous Agent Audit Request Payload
from pyteal import *

def approval_program():
    on_withdraw = Seq([
        # Defect 1: State updated AFTER inner transaction invocation (Reentrancy vector)
        InnerTxnBuilder.Begin(),
        InnerTxnBuilder.SetFields({
            TxnField.type_enum: TxnType.AssetTransfer,
            TxnField.xfer_asset: Int(10458941),
            TxnField.asset_amount: App.globalGet(Bytes("stake")),
            TxnField.asset_receiver: Txn.sender(),
        }),
        InnerTxnBuilder.Submit(),
        App.globalPut(Bytes("stake"), Int(0)),
        Approve()
    ])

    return Cond(
        [Txn.application_id() == Int(0), Approve()],
        [Txn.on_completion() == OnComplete.NoOp, on_withdraw]
    )
`;

async function runAutonomousAgent() {
  console.log("\n=======================================================");
  console.log("🤖 [AuditAgent-X Autonomous Consumer] Starting Daemon...");
  console.log("=======================================================\n");

  let agentAccount: algosdk.Account;

  if (AGENT_MNEMONIC) {
    try {
      agentAccount = algosdk.mnemonicToSecretKey(AGENT_MNEMONIC);
      console.log(`[Agent] Loaded autonomous agent identity: ${agentAccount.addr}`);
    } catch (e) {
      console.error("[Agent] Error parsing AGENT_MNEMONIC, generating ephemeral key for simulation");
      agentAccount = algosdk.generateAccount();
      console.log(`[Agent] Generated ephemeral agent address: ${agentAccount.addr}`);
    }
  } else {
    agentAccount = algosdk.generateAccount();
    console.log(`[Agent] Notice: AGENT_MNEMONIC not specified. Generated ephemeral address: ${agentAccount.addr}`);
    console.log(`[Agent] To execute live on-chain settlement, fund this address with Testnet USDC (ASA 10458941)`);
  }

  const algodClient = new algosdk.Algodv2("", ALGOD_SERVER, 443);

  // Step 1: Request unprotected free evaluation
  console.log("\n[Step 1] Requesting free static audit from resource server...");
  try {
    const freeRes = await fetch(`${API_BASE_URL}/api/audit-free`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code: SAMPLE_CONTRACT, language: "pyteal" }),
    });
    const freeData = await freeRes.json();
    console.log(`[Step 1 Result] Free Score: ${freeData.vulnerabilityScore}/100 | Total Risks: ${freeData.totalIssuesCount}`);
    console.log(`[Step 1 Notice] ${freeData.upgradePrompt}`);
  } catch (err: any) {
    console.error(`[Step 1 Failed] Ensure backend is running on ${API_BASE_URL}:`, err.message);
    return;
  }

  // Step 2: Attempt unauthenticated request to monetized route -> Expect HTTP 402
  console.log("\n[Step 2] Requesting deep XAI audit from gated endpoint POST /api/audit-explain...");
  const initialRes = await fetch(`${API_BASE_URL}/api/audit-explain`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code: SAMPLE_CONTRACT, language: "pyteal" }),
  });

  console.log(`[Step 2 Response] Received HTTP Status: ${initialRes.status} ${initialRes.statusText}`);

  if (initialRes.status !== 402) {
    console.log("[Step 2] Expected HTTP 402, received:", initialRes.status);
    return;
  }

  // Step 3: Parse machine-readable 402 challenge terms
  console.log("\n[Step 3] Parsing machine-readable 402 terms from server challenge...");
  const paymentRequiredHeader =
    initialRes.headers.get("payment-required") ||
    initialRes.headers.get("PAYMENT-REQUIRED");

  let challengeBody: any = {};
  if (paymentRequiredHeader) {
    try {
      challengeBody = JSON.parse(
        Buffer.from(paymentRequiredHeader, "base64").toString("utf-8")
      );
    } catch {
      challengeBody = await initialRes.json().catch(() => ({}));
    }
  } else {
    challengeBody = await initialRes.json().catch(() => ({}));
  }

  const acceptTerm = challengeBody.accepts ? challengeBody.accepts[0] : null;

  const receiverAddress =
    acceptTerm?.payTo ||
    challengeBody.payTo ||
    process.env.RECEIVER_AVM_ADDRESS ||
    "GD64YIY3TWGDM6D26YSOMW3PINZJOH4AAOWP2UQ2V2B2Y3V4V2ZAUQ5WGY";

  const facilitatorFeeAddress =
    acceptTerm?.extra?.feePayer ||
    challengeBody.feePayer ||
    receiverAddress;

  console.log(`  - Scheme:     ${acceptTerm?.scheme || "exact"}`);
  console.log(`  - Network:    ${acceptTerm?.network || "algorand:testnet"}`);
  console.log(`  - Amount:     ${acceptTerm?.amount || "5000"} microUSDC ($0.005)`);
  console.log(`  - Payee:      ${receiverAddress}`);
  console.log(`  - Fee Payer:  ${facilitatorFeeAddress}`);

  // Step 4: Construct fee-abstracted 2-transaction atomic group
  console.log("\n[Step 4] Headlessly assembling 2-transaction atomic group (Fee Abstracted)...");
  const suggestedParams = await algodClient.getTransactionParams().do();

  // Tx 0: Facilitator fee sponsorship (0 ALGO payment, 2000 microAlgos fee)
  suggestedParams.fee = BigInt(2000);
  suggestedParams.flatFee = true;
  const txn0 = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: facilitatorFeeAddress,
    receiver: facilitatorFeeAddress,
    amount: BigInt(0),
    suggestedParams,
  });

  // Tx 1: Agent USDC micropayment ($0.005 = 5000 microUSDC, 0 ALGO fee)
  suggestedParams.fee = BigInt(0);
  suggestedParams.flatFee = true;
  const txn1 = algosdk.makeAssetTransferTxnWithSuggestedParamsFromObject({
    sender: agentAccount.addr.toString(),
    receiver: receiverAddress,
    assetIndex: BigInt(USDC_ASA_ID),
    amount: BigInt(5000),
    suggestedParams,
  });

  algosdk.assignGroupID([txn0, txn1]);

  // Step 5: Headless cryptographic signing
  console.log("\n[Step 5] Signing Tx 1 with agent private key...");
  const signedTxn1 = txn1.signTxn(agentAccount.sk);

  const base64Txn0 = Buffer.from(txn0.toByte()).toString("base64");
  const base64Txn1 = Buffer.from(signedTxn1).toString("base64");

  const paymentEnvelope = {
    x402Version: 2,
    scheme: "exact",
    network: acceptTerm?.network || "algorand:SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=",
    payload: {
      paymentGroup: [base64Txn0, base64Txn1],
      paymentIndex: 1,
    },
  };

  const paymentSignatureHeader = Buffer.from(JSON.stringify(paymentEnvelope)).toString("base64");

  // Step 6: Resubmit request with PAYMENT-SIGNATURE header
  console.log("\n[Step 6] Submitting signed proof envelope via PAYMENT-SIGNATURE header...");
  const paidRes = await fetch(`${API_BASE_URL}/api/audit-explain`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "PAYMENT-SIGNATURE": paymentSignatureHeader,
    },
    body: JSON.stringify({ code: SAMPLE_CONTRACT, language: "pyteal" }),
  });

  console.log(`[Step 6 Response] HTTP ${paidRes.status} ${paidRes.statusText}`);

  if (paidRes.ok) {
    const paymentResponseHeader = paidRes.headers.get("PAYMENT-RESPONSE");
    console.log("\n🎉 [Success] Payment settled! Received PAYMENT-RESPONSE header:");
    console.log(paymentResponseHeader ? Buffer.from(paymentResponseHeader, "base64").toString("utf-8") : "N/A");

    const report = await paidRes.json();
    console.log("\n================= UNLOCKED EXPLAINABLE AI REPORT =================");
    console.log(`Protocol:           ${report.paymentProtocol}`);
    console.log(`Settled:            ${report.settled}`);
    console.log(`AST Nodes Analyzed: ${report.astMetrics.nodeCount}`);
    console.log(`Complexity:         ${report.astMetrics.cyclomaticComplexity}`);
    console.log(`Entropy:            ${report.astMetrics.riskWeightedEntropy}`);
    console.log(`Detailed Findings:  ${report.detailedFindings?.length} vulnerabilities with counterfactual fixes.`);
    if (report.detailedFindings?.[0]) {
      const f = report.detailedFindings[0];
      console.log(`\n[Vulnerability #1] ${f.id}: ${f.title} (${f.severity})`);
      console.log(`Synthesized Patch:\n${f.counterfactualFix.diff}`);
    }
    console.log("==================================================================\n");
  } else {
    const errorText = await paidRes.text();
    console.log("[Step 6 Note] Settlement response (as expected if account is unfunded/simulated):", errorText);
  }
}

runAutonomousAgent().catch(console.error);
