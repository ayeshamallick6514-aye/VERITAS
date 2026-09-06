# The 3-Minute Hackathon Winning Pitch & Live Demo Script

**Track**: Agentic Solutions: Powered by x402  
**Project**: AuditAgent-X (Autonomous Security Auditing on Algorand)  
**Time Limit**: 180 Seconds (3 Minutes)

---

## ⏱️ Pitch Presentation Script

### 0:00 - 0:30 | The Problem: The Economic Impasse of Agentic Commerce
> *"Judges, autonomous software agents are writing, optimizing, and deploying smart contracts at machine speed. But when an agent identifies a potential vulnerability and requires a deep, explainable security audit, it encounters a fundamental barrier: Web2 SaaS billing models.*
> 
> *Autonomous agents do not hold credit cards, cannot solve CAPTCHA puzzles, and cannot sign up for $5,000 monthly enterprise auditing subscriptions. What the decentralized AI ecosystem needs is not more LLMs—it is a standardized, machine-readable micropayment protocol running directly over native HTTP.*
> 
> *This is **AuditAgent-X**: an on-demand, Explainable AI smart contract security auditor built on Algorand and powered by the x402 payment protocol."*

### 0:30 - 1:15 | The Solution: x402 Micropayments Meet Explainable AI
> *"With AuditAgent-X, any developer or autonomous coding agent can access a free high-level vulnerability scan. But when they require deep explainability—line-by-line AST risk attributions, cyclomatic complexity analysis, and synthesized counterfactual code fixes—our server issues an **HTTP 402 Payment Required** challenge.*
> 
> *The price is set at exactly **$0.005 USDC** on Algorand Testnet.*
> 
> *Using `@x402-avm` middleware and the GoPlausible Facilitator, the client settles the request through a 2-transaction atomic group. The user pays only the $0.005 USDC. The facilitator covers the network fees through fee abstraction. The payer account requires **zero native ALGO balance**.*
> 
> *Algorand delivers this settlement with deterministic finality in **3.3 seconds**, eliminating block reorganization risks, subscription overhead, and API keys."*

### 1:15 - 2:30 | The Live Demonstration (Dual Paradigms: Web & Headless Agent)
> *"Let us demonstrate this live:*
> 
> *First, in our Web UI, we load a vulnerable PyTeal staking contract with an inner transaction reentrancy defect. Clicking **Analyze Code (Free)** returns an immediate preliminary score of 35/100, but the detailed explainability telemetry remains locked.*
> 
> *Next, we click **Unlock Deep XAI Report ($0.005 USDC)**. The client intercepts the HTTP 402 challenge, prompts Pera Wallet for signature confirmation, and submits the proof. The GoPlausible Facilitator validates the signature, sponsors the transaction fees, and settles the atomic group on Algorand Testnet in under 4 seconds.*
> 
> *The full diagnostic unlocks instantly: AST node attributions, risk weights, and synthesized counterfactual code diffs.*
> 
> *Now watch our terminal: Here is `agent-client.ts`—a headless autonomous AI agent running in Python or TypeScript. It hits the same route, receives the HTTP 402 challenge, automatically signs using its local key, and settles on Algorand without touching a browser or clicking a button. Machine-to-machine commerce in action."*

### 2:30 - 3:00 | Market Impact & Architectural Vision
> *"AuditAgent-X demonstrates the practical application of agentic commerce. By removing manual checkout friction and leveraging Algorand's 3.3-second finality and fee abstraction, autonomous agents can verify and secure their own code autonomously. This establishes a sustainable micro-economy for developer tooling. Thank you."*

---

## 📋 Step-by-Step Live Demo Execution Checklist

1. **Pre-Demo Verification**:
   - Backend daemon listening on port `4021` (`node dist/index.js` or `npm run dev`).
   - Frontend Vite server running on port `5173` (`npm run dev`).
   - Pera Wallet set to Algorand Testnet with at least $1.00 USDC (ASA 10458941).
   - Pre-load [LoRA Testnet Explorer](https://lora.algokit.io/testnet) in an adjacent browser tab as a network latency safeguard.
2. **Step 1 (Wallet Authentication)**:
   - Open `http://localhost:5173`, click **Connect Pera Wallet**, approve session. Confirm ALGO and USDC balances render.
3. **Step 2 (Free Assessment Execution)**:
   - Select PyTeal Sample, click **Analyze Code (Free)**. Show basic score (35/100, CRITICAL) with deep fields locked.
4. **Step 3 (x402 Micropayment Trigger)**:
   - Click **Unlock Deep XAI Report ($0.005 USDC)**. Approve Pera Wallet popup. Show 0 ALGO fee charged to user.
5. **Step 4 (XAI Telemetry Inspection)**:
   - Inspect AST nodes (`InnerTxnBuilder.Submit`, `App.globalPut`), risk weights, and synthesized counterfactual diff.
6. **Step 5 (Headless Agent Demo)**:
   - In terminal, execute `npm run agent` to show the headless autonomous consumer solving the same HTTP 402 challenge.
