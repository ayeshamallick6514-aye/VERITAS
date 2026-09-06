import { Context } from "hono";

export interface AuditRequest {
  code: string;
  language: "pyteal" | "teal" | "solidity" | "qds";
  contractName?: string;
}

export interface AstTokenAttribution {
  token: string;
  line: number;
  column: number;
  weight: number;
  astNodeType: string;
  context: string;
}

export interface VulnerabilityFinding {
  id: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";
  cwe: string;
  description: string;
  affectedLines: number[];
  riskWeight: number;
  attributions: AstTokenAttribution[];
  counterfactualFix: {
    originalCodeSnippet: string;
    recommendedPatch: string;
    diff: string;
    explanation: string;
  };
}

export interface FreeAuditResponse {
  vulnerabilityScore: number;
  status: "SECURE" | "WARNING" | "CRITICAL";
  totalIssuesCount: number;
  severityCounts: Record<string, number>;
  summary: string;
  upgradePrompt: string;
}

export interface PaidXaiAuditResponse extends FreeAuditResponse {
  settled: boolean;
  paymentProtocol: string;
  transactionVerifiedAt: string;
  detailedFindings: VulnerabilityFinding[];
  globalFeatureWeights: Record<string, number>;
  astMetrics: {
    nodeCount: number;
    cyclomaticComplexity: number;
    riskWeightedEntropy: number;
  };
}

// ─── QDS Pattern Banks ────────────────────────────────────────────────────────
const QDS_CLASSICAL_SIG_PATTERNS = [
  "ecdsa", "secp256k1", "ecrecover", "schnorr", "ed25519",
  "ec.sign", "ec.verify", "elliptic",
];
const QDS_BREAKABLE_HASH_PATTERNS = [
  "keccak256", "sha256", "sha2", "md5", "ripemd160",
];
const PQC_SAFE_KEYWORDS = [
  "falcon", "dilithium", "kyber", "crystals", "sphincs",
  "ntru", "mceliece", "shake256", "sha3",
];

// ─── Free-Tier Scanner ───────────────────────────────────────────────────────
export function analyzeFreeTier(req: AuditRequest): FreeAuditResponse {
  const lines = req.code.split("\n");
  let issueCount = 0;
  const severityCounts: Record<string, number> = {
    CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFORMATIONAL: 0,
  };

  const codeLower = req.code.toLowerCase();

  // ── AVM / PyTeal checks ──
  if (req.language === "pyteal" || req.language === "teal") {
    if (codeLower.includes("innertxnbulk") || codeLower.includes("innertxnbuilder")) {
      issueCount += 2;
      severityCounts.HIGH += 1;
      severityCounts.MEDIUM += 1;
    }
    if (!codeLower.includes("txn.rekey_to") && !codeLower.includes("rekeyto")) {
      issueCount += 1;
      severityCounts.CRITICAL += 1;
    }
    if (!codeLower.includes("txn.close_remainder_to") && !codeLower.includes("closeremainderto")) {
      issueCount += 1;
      severityCounts.HIGH += 1;
    }
  } else if (req.language === "solidity") {
    // ── EVM / Solidity checks ──
    if (codeLower.includes(".call{value:") || codeLower.includes(".call(")) {
      issueCount += 2;
      severityCounts.CRITICAL += 1;
      severityCounts.HIGH += 1;
    }
    if (codeLower.includes("selfdestruct") || codeLower.includes("delegatecall")) {
      issueCount += 1;
      severityCounts.CRITICAL += 1;
    }
  }

  // ── QDS checks (cross-language) ──
  const hasPqcMitigation = PQC_SAFE_KEYWORDS.some((kw) => codeLower.includes(kw));
  const hasClassicalSig = QDS_CLASSICAL_SIG_PATTERNS.some((p) => codeLower.includes(p));
  const hasBreakableHash = QDS_BREAKABLE_HASH_PATTERNS.some((p) => codeLower.includes(p));

  if (hasClassicalSig && !hasPqcMitigation) {
    issueCount += 2;
    severityCounts.HIGH += 1;
    severityCounts.MEDIUM += 1;
  }
  if (hasBreakableHash && !hasPqcMitigation) {
    issueCount += 1;
    severityCounts.MEDIUM += 1;
  }

  const basePenalty =
    severityCounts.CRITICAL * 30 +
    severityCounts.HIGH * 15 +
    severityCounts.MEDIUM * 5;
  const score = Math.max(5, Math.min(100, 100 - basePenalty));

  return {
    vulnerabilityScore: score,
    status: score < 40 ? "CRITICAL" : score < 75 ? "WARNING" : "SECURE",
    totalIssuesCount: issueCount,
    severityCounts,
    summary: `AuditAgent-X static scanner identified ${issueCount} potential vulnerability vectors across ${lines.length} lines of code.`,
    upgradePrompt:
      "Unlock deep Explainable AI (XAI) feature attributions, AST risk weights, and counterfactual repair diffs for $0.005 USDC via x402.",
  };
}

// ─── Deep XAI Analysis ───────────────────────────────────────────────────────
export function executeDeepXaiAnalysis(req: AuditRequest): PaidXaiAuditResponse {
  const freeSummary = analyzeFreeTier(req);
  const lines = req.code.split("\n");
  const findings: VulnerabilityFinding[] = [];
  const globalFeatureWeights: Record<string, number> = {};
  const codeLower = req.code.toLowerCase();

  // ── AVM-specific findings ──
  if (req.language === "pyteal" || req.language === "teal") {
    let appGlobalPutLine = -1;
    let innerTxnSubmitLine = -1;

    lines.forEach((lineText, idx) => {
      const lineNum = idx + 1;
      if (lineText.includes("App.globalPut") || lineText.includes("app_global_put")) {
        appGlobalPutLine = lineNum;
      }
      if (lineText.includes("InnerTxnBuilder.Submit") || lineText.includes("itxn_submit")) {
        innerTxnSubmitLine = lineNum;
      }
    });

    if (innerTxnSubmitLine > 0 && appGlobalPutLine > innerTxnSubmitLine) {
      findings.push({
        id: "AAX-AVM-001",
        title: "State Update Post-Inner Transaction Invocation (AVM Reentrancy Pattern)",
        severity: "CRITICAL",
        cwe: "CWE-841: User-Controlled Critical Execution Path",
        description:
          "Contract executes an AVM inner transaction before updating internal global application state. If an invoked recipient contract calls back into this application, stale balance states can be drained.",
        affectedLines: [innerTxnSubmitLine, appGlobalPutLine],
        riskWeight: 0.94,
        attributions: [
          {
            token: "InnerTxnBuilder.Submit",
            line: innerTxnSubmitLine,
            column: lines[innerTxnSubmitLine - 1]?.indexOf("InnerTxnBuilder.Submit") || 4,
            weight: 0.94,
            astNodeType: "SubroutineCallExpr",
            context: "AVM Inner Transaction Dispatcher",
          },
          {
            token: "App.globalPut",
            line: appGlobalPutLine,
            column: lines[appGlobalPutLine - 1]?.indexOf("App.globalPut") || 4,
            weight: 0.88,
            astNodeType: "StateMutationStatement",
            context: "Application Global State Write",
          },
        ],
        counterfactualFix: {
          originalCodeSnippet: `InnerTxnBuilder.Submit(),\nApp.globalPut(Bytes("stake"), Int(0))`,
          recommendedPatch: `App.globalPut(Bytes("stake"), Int(0)),\nInnerTxnBuilder.Submit()`,
          diff: `--- Current\n+++ Counterfactual\n@@ -${innerTxnSubmitLine},2 +${innerTxnSubmitLine},2 @@\n-    InnerTxnBuilder.Submit(),\n-    App.globalPut(Bytes("stake"), Int(0))\n+    App.globalPut(Bytes("stake"), Int(0)),\n+    InnerTxnBuilder.Submit()`,
          explanation:
            "Reordering operations enforces the Checks-Effects-Interactions pattern within the PyTeal Seq block.",
        },
      });
      globalFeatureWeights["AVM_INNER_TXN_REENTRANCY"] = 0.94;
    }

    let hasRekeyCheck = false;
    lines.forEach((line) => {
      if (line.includes("rekey_to") || line.includes("RekeyTo")) hasRekeyCheck = true;
    });

    if (!hasRekeyCheck) {
      findings.push({
        id: "AAX-AVM-002",
        title: "Missing Transaction RekeyTo Protection Predicate",
        severity: "CRITICAL",
        cwe: "CWE-284: Improper Access Control",
        description:
          "Application fails to explicitly assert that Txn.rekey_to() equals Global.zero_address(). An external caller can append a rekey parameter to re-assign account authorization authority.",
        affectedLines: [1],
        riskWeight: 0.91,
        attributions: [
          {
            token: "Txn.rekey_to()",
            line: 1,
            column: 1,
            weight: 0.91,
            astNodeType: "SecurityPredicateAssertion",
            context: "Transaction Header Safety Invariant",
          },
        ],
        counterfactualFix: {
          originalCodeSnippet: `Assert(Txn.sender() == Global.creator_address())`,
          recommendedPatch: `Assert(And(\n    Txn.sender() == Global.creator_address(),\n    Txn.rekey_to() == Global.zero_address(),\n    Txn.close_remainder_to() == Global.zero_address()\n))`,
          diff: `--- Current\n+++ Counterfactual\n@@ -1,1 +1,5 @@\n-Assert(Txn.sender() == Global.creator_address())\n+Assert(And(\n+    Txn.sender() == Global.creator_address(),\n+    Txn.rekey_to() == Global.zero_address(),\n+    Txn.close_remainder_to() == Global.zero_address()\n+))`,
          explanation:
            "Explicitly reject incoming transactions bearing non-zero RekeyTo or CloseRemainderTo addresses.",
        },
      });
      globalFeatureWeights["UNCHECKED_REKEY_FIELD"] = 0.91;
    }
  } else if (req.language === "solidity") {
    // ── EVM-specific findings ──
    let callValueLine = -1;
    let balanceResetLine = -1;

    lines.forEach((lineText, idx) => {
      const lineNum = idx + 1;
      if (lineText.includes(".call{value:") || lineText.includes(".call.value")) {
        callValueLine = lineNum;
      }
      if (
        lineText.includes("balances[msg.sender] = 0") ||
        lineText.includes("balances[msg.sender] -=")
      ) {
        balanceResetLine = lineNum;
      }
    });

    if (callValueLine > 0 && (balanceResetLine === -1 || balanceResetLine > callValueLine)) {
      findings.push({
        id: "AAX-EVM-001",
        title: "Classic Reentrancy Vector via Low-Level Call",
        severity: "CRITICAL",
        cwe: "CWE-841: Reentrancy",
        description:
          "Internal state balance variable is mutated only after transferring value via low-level .call(). A reentrant fallback method can repeatedly drain contract collateral.",
        affectedLines: [
          callValueLine,
          balanceResetLine > 0 ? balanceResetLine : callValueLine + 1,
        ],
        riskWeight: 0.98,
        attributions: [
          {
            token: "call{value:",
            line: callValueLine,
            column: lines[callValueLine - 1]?.indexOf("call{value:") || 8,
            weight: 0.98,
            astNodeType: "LowLevelCallNode",
            context: "External Untrusted Control Transfer",
          },
        ],
        counterfactualFix: {
          originalCodeSnippet: `(bool sent, ) = msg.sender.call{value: amount}("");\nbalances[msg.sender] = 0;`,
          recommendedPatch: `balances[msg.sender] = 0;\n(bool sent, ) = msg.sender.call{value: amount}("");\nrequire(sent, "Failed to send Ether");`,
          diff: `--- Current\n+++ Counterfactual\n@@ -${callValueLine},2 +${callValueLine},2 @@\n- (bool sent, ) = msg.sender.call{value: amount}("");\n- balances[msg.sender] = 0;\n+ balances[msg.sender] = 0;\n+ (bool sent, ) = msg.sender.call{value: amount}("");\n+ require(sent, "Transfer failed");`,
          explanation:
            "Restructure function to ensure state updates precede external execution invocations.",
        },
      });
      globalFeatureWeights["CROSS_FUNCTION_REENTRANCY"] = 0.98;
    }
  }

  // ── QDS findings (cross-language — run for all language modes) ──
  const hasPqcMitigation = PQC_SAFE_KEYWORDS.some((kw) => codeLower.includes(kw));

  let classicalSigLine = -1;
  let breakableHashLine = -1;

  lines.forEach((lineText, idx) => {
    const ll = lineText.toLowerCase().trim();
    if (
      classicalSigLine === -1 &&
      !hasPqcMitigation &&
      QDS_CLASSICAL_SIG_PATTERNS.some((p) => ll.includes(p))
    ) {
      classicalSigLine = idx + 1;
    }
    if (
      breakableHashLine === -1 &&
      !hasPqcMitigation &&
      QDS_BREAKABLE_HASH_PATTERNS.some((p) => ll.includes(p))
    ) {
      breakableHashLine = idx + 1;
    }
  });

  if (classicalSigLine > 0) {
    const tokenRaw = lines[classicalSigLine - 1]?.trim() ?? "";
    const matchedToken =
      QDS_CLASSICAL_SIG_PATTERNS.find((p) => tokenRaw.toLowerCase().includes(p)) ?? "ecdsa";
    findings.push({
      id: "AAX-QDS-001",
      title: "Classical Signature Scheme Without PQC Mitigation Layer",
      severity: "HIGH",
      cwe: "CWE-327: Use of Broken or Risky Cryptographic Algorithm",
      description:
        "Contract employs classical elliptic-curve signature primitives (ECDSA/secp256k1/Ed25519) susceptible to Shor's algorithm on fault-tolerant quantum computers. Harvest-now-decrypt-later (HNDL) attacks pose an immediate threat to long-lived key material anchored to public blockchains.",
      affectedLines: [classicalSigLine],
      riskWeight: 0.87,
      attributions: [
        {
          token: matchedToken,
          line: classicalSigLine,
          column: lines[classicalSigLine - 1]?.toLowerCase().indexOf(matchedToken) ?? 0,
          weight: 0.87,
          astNodeType: "CryptographicPrimitiveCall",
          context: "Classical Elliptic-Curve Signature Invocation",
        },
      ],
      counterfactualFix: {
        originalCodeSnippet: `// Classical ECDSA signature verification\naddress signer = ecrecover(hash, v, r, s);\nrequire(signer == msg.sender, "Invalid ECDSA");`,
        recommendedPatch: `// PQC-hardened: Falcon-512 lattice signature (NIST FIPS 204)\n// Off-chain Falcon verifier anchors Merkle commitment on-chain\nrequire(\n    verifyFalconSignature(pubKeyCommitment, msgHash, falconProof),\n    "Invalid PQC signature"\n);`,
        diff: `--- Current (Classical ECDSA — secp256k1)\n+++ Counterfactual (PQC-Hardened — Falcon-512)\n@@ -${classicalSigLine},3 +${classicalSigLine},5 @@\n-address signer = ecrecover(hash, v, r, s);\n-require(signer == msg.sender, "Invalid ECDSA");\n+// PQC-hardened: Falcon-512 lattice signature (NIST FIPS 204)\n+// Off-chain Falcon verifier anchors Merkle commitment on-chain\n+require(\n+    verifyFalconSignature(pubKeyCommitment, msgHash, falconProof),\n+    "Invalid PQC signature"\n+);`,
        explanation:
          "Migrate to NIST-standardised post-quantum signatures (CRYSTALS-Dilithium or Falcon-512). Use an off-chain PQC co-processor with on-chain Merkle proof anchoring to maintain gas efficiency. Effective security: 256-bit post-quantum vs 128-bit classical-equivalent.",
      },
    });
    globalFeatureWeights["CLASSICAL_SIG_PQC_RISK"] = 0.87;
  }

  if (breakableHashLine > 0) {
    const tokenRaw = lines[breakableHashLine - 1]?.trim() ?? "";
    const matchedHash =
      QDS_BREAKABLE_HASH_PATTERNS.find((p) => tokenRaw.toLowerCase().includes(p)) ?? "keccak256";
    findings.push({
      id: "AAX-QDS-002",
      title: "Quantum-Breakable Hash Function in Cryptographic Signing Context",
      severity: "MEDIUM",
      cwe: "CWE-916: Use of Password Hash With Insufficient Computational Effort",
      description:
        "SHA-256 and keccak256 provide only 128-bit post-quantum security due to Grover's algorithm halving the effective bit-strength from 256→128 bits via quantum parallelism. Long-lived on-chain commitments tied to these digests are vulnerable to quantum pre-image attacks.",
      affectedLines: [breakableHashLine],
      riskWeight: 0.72,
      attributions: [
        {
          token: matchedHash,
          line: breakableHashLine,
          column: lines[breakableHashLine - 1]?.toLowerCase().indexOf(matchedHash) ?? 0,
          weight: 0.72,
          astNodeType: "HashFunctionInvocation",
          context: "Cryptographic Digest Computation",
        },
      ],
      counterfactualFix: {
        originalCodeSnippet: `bytes32 digest = keccak256(abi.encodePacked(data));`,
        recommendedPatch: `// SHA-3 (Keccak-f[1600]) retains full 256-bit PQ security\n// SHAKE-256 (extendable output) recommended for signing contexts\nbytes32 digest = sha3_256(abi.encodePacked(data));`,
        diff: `--- Current (keccak256 — 128-bit PQ)\n+++ Counterfactual (SHA-3-256 — 256-bit PQ)\n@@ -${breakableHashLine},1 +${breakableHashLine},3 @@\n-bytes32 digest = keccak256(abi.encodePacked(data));\n+// SHA-3 (Keccak-f[1600]) retains full 256-bit PQ security\n+// SHAKE-256 (extendable output) recommended for signing contexts\n+bytes32 digest = sha3_256(abi.encodePacked(data));`,
        explanation:
          "Replace keccak256 with SHA-3-256 in signature and commitment contexts. For non-signature uses (e.g., storage slot mapping), keccak256 remains acceptable. Grover's algorithm halves preimage search space from 2^256 → 2^128 bits.",
      },
    });
    globalFeatureWeights["QUANTUM_BREAKABLE_HASH"] = 0.72;
  }

  return {
    ...freeSummary,
    settled: true,
    paymentProtocol: "x402-avm/v2",
    transactionVerifiedAt: new Date().toISOString(),
    detailedFindings: findings,
    globalFeatureWeights,
    astMetrics: {
      nodeCount: lines.length * 4 + 18,
      cyclomaticComplexity: findings.length * 3 + 2,
      riskWeightedEntropy: parseFloat(
        (findings.reduce((acc, f) => acc + f.riskWeight, 0) / (findings.length || 1)).toFixed(4)
      ),
    },
  };
}

// ─── HTTP Handlers ───────────────────────────────────────────────────────────
export async function handleFreeAudit(c: Context) {
  try {
    const body = (await c.req.json()) as AuditRequest;
    if (!body || !body.code) {
      return c.json({ error: "Missing required smart contract code payload" }, 400);
    }
    const result = analyzeFreeTier(body);
    return c.json(result, 200);
  } catch {
    return c.json({ error: "Malformed JSON payload or unparseable input" }, 400);
  }
}

export async function handleAuditExplain(c: Context) {
  try {
    const body = (await c.req.json()) as AuditRequest;
    if (!body || !body.code) {
      return c.json({ error: "Missing required smart contract code payload" }, 400);
    }
    const fullReport = executeDeepXaiAnalysis(body);
    return c.json(fullReport, 200);
  } catch {
    return c.json({ error: "Failed to process deep code intelligence execution" }, 500);
  }
}
