# VERTIAS: Autonomous Security Auditing Powered by x402 on Algorand (AVM)

[![Algorand Testnet](https://img.shields.io/badge/Algorand-Testnet-blue.svg)](https://testnet.algoexplorer.io)
[![x402 Protocol](https://img.shields.io/badge/x402-Enabled-emerald.svg)](https://x402.org)
[![Settlement](https://img.shields.io/badge/Settlement-3.3s%20Deterministic-success.svg)](#)
[![Fee Abstraction](https://img.shields.io/badge/Gas-Abstracted%20(0%20ALGO)-purple.svg)](#)

> **AuditAgent-X** is a production-grade Explainable AI (XAI) smart contract security auditor that embeds the **HTTP 402 Payment Required** protocol directly into static AST vulnerability analysis and counterfactual code repair on the Algorand Virtual Machine (AVM).

---

## ⚡ Key Architectural Highlights

1. **Deterministic 3.3-Second Consensus Finality**: Algorand Pure Proof-of-Stake (PPoS) enables real-time HTTP 402 challenge-settlement loops without risk of block reorganizations.
2. **True Gas Fee Abstraction**: Uses Algorand atomic transaction groups ($N=2$) where the GoPlausible Facilitator pays 2,000 microAlgos on Tx 0, allowing the client/agent on Tx 1 to pay **0 ALGO in gas** and only $0.005 Testnet USDC.
3. **Dual Client Paradigms**:
   - **Interactive Web App**: Modern React + Vite dashboard with Pera Wallet connectivity and visual AST/counterfactual patch inspection.
   - **Autonomous Headless Agent**: CLI agent script (`agent-client.ts`) demonstrating machine-to-machine HTTP 402 discovery, signing, and settlement without human mediation.
4. **Browser-Native Resilience**: Zero-dependency browser-safe base64 conversions (eliminating Vite `Buffer` runtime issues) with 8s/12s request timeout safeguards.

---

## 🔄 End-to-End Sequence Flow

| Stage | Phase | Initiator | Target | Payload / Headers | System Operation |
|---|---|---|---|---|---|
| **1** | Request | Client / Agent | Server | Unauthenticated `POST /api/audit-explain` | Submits smart contract code for deep diagnostic evaluation. |
| **2** | Challenge | Server Middleware | Client / Agent | `HTTP 402 Payment Required` (`PAYMENT-REQUIRED`) | Middleware returns terms: CAIP-2, price ($0.005), ASA ID (10458941), payee address. |
| **3** | Assembly | Client / Agent | Local Wallet | Unsigned Transaction Group | Constructs 2-tx atomic group: Facilitator fee sponsorship (Tx 0) + USDC transfer (Tx 1). |
| **4** | Signing | Client Wallet / Key | Client / Agent | Signed Tx 1 Blob | Client/Agent signs solely the USDC transfer (Tx 1), leaving Tx 0 unsigned. |
| **5** | Resubmission | Client / Agent | Server | `POST /api/audit-explain` (`PAYMENT-SIGNATURE`) | Submits partially signed atomic transaction group in base64 envelope. |
| **6** | Verification | Server | Facilitator | `POST /verify` | Server verifies Tx 1 meets price requirements and Tx 0 satisfies fee rules. |
| **7** | Computation | Server Engine | Server Engine | AST & XAI Diagnostics | Server executes AST analysis, risk weighting, and counterfactual synthesis. |
| **8** | Settlement | Server | Facilitator | `POST /settle` | Server requests Facilitator to append signature to Tx 0 and broadcast group to Algorand Testnet. |
| **9** | Confirmation | Facilitator | Consensus Node | Atomic Group Broadcast | Algorand consensus confirms atomic group in a single round (~3.3 seconds). |
| **10** | Delivery | Server | Client / Agent | `HTTP 200 OK` (`PAYMENT-RESPONSE`) | Server delivers full Explainable AI report and confirmed transaction ID. |

---

## 📊 Economic Comparison

| Dimension | Web2 SaaS Code Security | Generic EVM Micropayment | AuditAgent-X (x402 on AVM) |
|---|---|---|---|
| **Payment Protocol** | Credit Card / Stripe | ERC-20 Transfer + Allowance | Native AVM ASA Transfer over HTTP 402 |
| **Agent Autonomy** | Zero (Requires human signup & KYC) | Low (Requires approval transactions) | **High (Autonomous HTTP negotiation)** |
| **Payer Gas Barrier** | Centralized fiat abstraction | High (Requires native ETH for gas) | **Zero (Gas abstracted via Facilitator)** |
| **Settlement Finality** | Off-chain ledger credit | 12.0s - 60.0s (Probabilistic) | **3.3s (Deterministic Pure PoS)** |
| **Granularity** | Monthly subscription tiers | Inefficient below $1.00 | **Sub-cent capable (exact $0.005)** |
| **Settlement Verifiability** | Centralized database | Contract event polling | **Live explorer link via AVM TxID** |

---

## 🚀 15-Minute Quickstart

### Prerequisites
- Node.js v18+ (v20+ recommended)
- Pera Wallet with Algorand Testnet enabled
- Testnet USDC (ASA 10458941) from [Circle Faucet](https://faucet.circle.com/)

### Step 1: Install Dependencies

```bash
# 1. Install Backend Dependencies
cd x402-demo-server
npm install

# 2. Install Frontend Dependencies
cd ../X402-Usecase/projects/X402-Usecase
npm install
```

### Step 2: Start Backend Daemon

```bash
cd x402-demo-server
npm run dev
# Server listens on http://localhost:4021
```

### Step 3: Start Frontend Client

```bash
cd X402-Usecase/projects/X402-Usecase
npm run dev
# UI opens at http://localhost:5173
```

### Step 4: Run Headless Autonomous Agent (CLI Demo)

In a separate terminal, trigger the headless autonomous consumer:

```bash
cd x402-demo-server
npm run agent
```

---

## 🔬 API Verification via cURL

### 1. Test Unprotected Free Scan Endpoint:
```bash
curl -s -X POST http://localhost:4021/api/audit-free \
  -H "Content-Type: application/json" \
  -d '{"code": "Assert(Txn.sender() == Global.creator_address())", "language": "pyteal"}'
```

### 2. Test Monetized Gated Endpoint (Inspects HTTP 402 Challenge):
```bash
curl -i -X POST http://localhost:4021/api/audit-explain \
  -H "Content-Type: application/json" \
  -d '{"code": "InnerTxnBuilder.Submit()\nApp.globalPut(Bytes(\"st\"), Int(0))", "language": "pyteal"}'
```

Expected response headers & body:
```http
HTTP/1.1 402 Payment Required
payment-required: eyJ4NDAyVmVyc2lvbiI6Miwic2NoZW1lIjoiZXhhY3QiLCJuZXR3b3JrIjoiYWxnb3JhbmQ6U0dPMUdLU3p5RTdJRVBJdFR4Q0J5dzl4OEZtbnJDRGV4aTkvY09VSk9pST0i...

{
  "statusCode": 402,
  "message": "Payment Required",
  "accepts": [
    {
      "scheme": "exact",
      "network": "algorand:SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=",
      "payTo": "GD64YIY3TWGDM6D26YSOMW3PINZJOH4AAOWP2UQ2V2B2Y3V4V2ZAUQ5WGY",
      "price": "$0.005",
      "extra": {
        "asset": "10458941"
      }
    }
  ]
}
```.

---

## 📂 Repository Structure

```
AgentAuditX/
├── x402-demo-server/                  # Backend Resource Server (Hono + TypeScript)
│   ├── src/
│   │   ├── endpoints.config.ts        # Route monetization & x402 pricing terms
│   │   ├── handlers/audit-agent.ts    # AST parsing, XAI attribution & repair synthesis
│   │   └── index.ts                   # Hono server entry & payment middleware
│   ├── scripts/
│   │   └── agent-client.ts            # Headless autonomous agent consumer CLI
│   ├── .env.example
│   ├── package.json
│   └── tsconfig.json
├── X402-Usecase/
│   └── projects/
│       └── X402-Usecase/              # Frontend Application (React + Vite + Tailwind)
│           ├── src/
│           │   ├── components/
│           │   │   └── AuditDashboard.tsx # Wallet connect, atomic signing, XAI visualizer
│           │   ├── App.tsx
│           │   ├── main.tsx
│           │   └── index.css
│           ├── .env.example
│           ├── .env.local
│           ├── package.json
│           └── vite.config.ts
├── PITCH_SCRIPT.md                    # 3-minute hackathon pitch script & live checklist
└── README.md
```
