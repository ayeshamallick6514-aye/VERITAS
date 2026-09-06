# Product Requirement Document (PRD)

**Project Name:** AuditAgent-X  
**Tagline:** Pay-Per-Explanation Security Intelligence for Autonomous AI Agents & Web3 Developers  
**Track:** Agentic Solutions: Powered by x402 (NIT Delhi Hackathon)  
**Version:** 1.0.0  
**Status:** Approved / Production  
**Target Blockchain:** Algorand Virtual Machine (AVM) Testnet (`algorand:SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=`)

---

## 1. Executive Summary & Product Vision

### 1.1 Executive Summary
AuditAgent-X is an autonomous, on-demand Explainable AI (XAI) smart contract security auditor designed specifically for autonomous software agents and Web3 developers. Built on the HTTP 402 Payment Required standard using the `@x402-avm` framework, AuditAgent-X allows autonomous agents to programmatically request, pay for, and receive deep AST-level vulnerability diagnoses and counterfactual code repair patches without human intervention, credit cards, or subscription keys.

### 1.2 Product Vision
To establish the industry standard for machine-to-machine security verification in the Web3 AI ecosystem. By providing micro-monetized ($0.005 USDC) deep security diagnostics with native fee abstraction on Algorand, AuditAgent-X aims to make autonomous smart contract deployment safer, faster, and economically frictionless.

---

## 2. Problem Statement & Target Audience

### 2.1 The Problem
1. **The Machine Economic Impasse:** Autonomous AI agents write, test, and deploy smart contracts at high speeds, but cannot interact with traditional SaaS billing models (credit cards, CAPTCHA, monthly subscriptions).
2. **High Friction in Web3 Auditing:** Traditional Web3 audits cost thousands of dollars and take weeks. Instant automated scanners provide high-level scores but hide crucial line-level context and repair logic behind expensive paywalls.
3. **Gas Token Friction:** Payer accounts (especially transient agents) often lack native gas tokens (ALGO), preventing them from executing micropayments even when holding stablecoins (USDC).

### 2.2 Target Audience
- **Autonomous AI Coding & Deployment Agents:** Headless LLM agents operating in multi-agent workflows that require automated code verification before submitting smart contract deployment transactions.
- **Web3 Smart Contract Developers:** PyTeal, TEAL, and Solidity developers seeking instant, pay-per-use XAI analysis without committing to recurring SaaS plans.
- **DeFi Protocol Security Bots:** Automated monitoring bots evaluating contract upgrades or external integration risks in real time.

---

## 3. High-Level Product Architecture & Key Features

### 3.1 Product Tiers

| Feature / Metric | Free Tier (`POST /api/audit-free`) | Monetized Tier (`POST /api/audit-explain`) |
|---|---|---|
| **Price** | $0.00 (Free) | $0.005 USDC (5,000 microUSDC, ASA 10458941) |
| **Protocol Rail** | Standard HTTP 200 | HTTP 402 Payment Required (`@x402-avm`) |
| **Gas Cost to User** | 0 ALGO | 0 ALGO (Fee Abstracted via Pooled Tx Group) |
| **Output Provided** | Basic Vulnerability Score (0–100) & Issue Count | Full XAI Report: AST Node Attributions, Risk Weights, Counterfactual Repair Diffs |
| **Access Method** | Browser / REST | Browser (Pera Wallet) & Headless CLI (`agent-client.ts`) |

---

## 4. Detailed Technical Architecture & Workflows

### 4.1 System Components
1. **Frontend Dashboard (`X402-Usecase`):** React + Vite + Tailwind CSS dashboard with `@perawallet/connect` integration, code editor, risk heatmaps, and counterfactual diff viewers.
2. **Resource Backend (`x402-demo-server`):** Node.js/TypeScript server built on Hono utilizing `@x402-avm/hono` and `@x402-avm/avm` middleware.
3. **GoPlausible Facilitator:** Off-chain verification gateway handling transaction verification (`/verify`) and signature-sponsoring settlement (`/settle`).
4. **Algorand Testnet Ledger:** Decentralized ledger facilitating 3.3-second block finality for 2-transaction atomic payment groups.

### 4.2 Sequence Flow (HTTP 402 Lifecycle)
1. **Request:** Agent/Client submits unauthenticated contract payload to `POST /api/audit-explain`.
2. **Challenge:** Server middleware intercepts request and responds with `HTTP 402 Payment Required` with `PAYMENT-REQUIRED` header specifying CAIP-2 terms and price ($0.005 USDC).
3. **Assembly:** Client or Agent constructs a 2-tx atomic group: Tx 0 (Facilitator gas sponsor) + Tx 1 (User $0.005 USDC payment).
4. **Signing:** User wallet or Agent private key signs only Tx 1 (0 ALGO fee).
5. **Resubmission:** Request resubmitted with base64 `PAYMENT-SIGNATURE` envelope.
6. **Verification & Settlement:** GoPlausible Facilitator verifies, signs Tx 0, and broadcasts the atomic group on Algorand Testnet.
7. **Delivery:** Ledger commits in ~3.3 seconds; Server returns HTTP 200 with XAI telemetry and LoRA Explorer transaction proof.
