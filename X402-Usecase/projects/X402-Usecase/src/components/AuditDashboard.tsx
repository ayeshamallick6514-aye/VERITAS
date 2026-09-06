import React, { useState, useEffect, useCallback } from "react";
import { createPortal } from "react-dom";
import { PeraWalletConnect } from "@perawallet/connect";
import algosdk from "algosdk";
import TextBlockAnimation from "@/components/ui/text-block-animation";
import { ArrowDown, Zap, Shield, Terminal } from "lucide-react";

// Browser-native base64 helpers (zero dependency, zero polyfill risk)
const toBase64 = (data: Uint8Array | string): string => {
  if (typeof data === "string") {
    return btoa(unescape(encodeURIComponent(data)));
  }
  let binary = "";
  const bytes = new Uint8Array(data);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
};

const fromBase64 = (str: string): string => {
  try {
    return decodeURIComponent(escape(atob(str)));
  } catch {
    return atob(str);
  }
};

const peraWallet = new PeraWalletConnect({
  chainId: 416002,
});

const USDC_ASA_ID = Number(import.meta.env.VITE_USDC_ASA_ID) || 10458941;
const ALGOD_SERVER = import.meta.env.VITE_ALGOD_SERVER || "https://testnet-api.algonode.cloud";
const API_BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:4021";

const SAMPLE_VULNERABLE_PYTEAL = `# Vulnerable Algorand Staking Contract (PyTeal sample)
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

const SAMPLE_VULNERABLE_SOLIDITY = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "Zero balance");

        // Defect: Low-level transfer before state balance update
        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "Failed to send Ether");

        balances[msg.sender] = 0;
    }
}
`;

const SAMPLE_QDS_VULNERABLE = `// QDS-Vulnerable Solidity Contract (SIH 26141 Alignment)
// Classical ECDSA + keccak256 — susceptible to Shor's & Grover's algorithms
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ClassicalSignatureVault {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() { owner = msg.sender; }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // Defect 1: ECDSA secp256k1 — quantum-breakable via Shor's algorithm
    function verifyAndWithdraw(
        bytes32 hash, uint8 v, bytes32 r, bytes32 s
    ) external {
        address signer = ecrecover(hash, v, r, s);
        require(signer == msg.sender, "Invalid ECDSA signature");

        // Defect 2: keccak256 digest — 128-bit PQ security only (Grover halving)
        bytes32 digest = keccak256(abi.encodePacked(msg.sender, block.timestamp));
        require(digest != bytes32(0), "Invalid digest");

        uint256 amount = balances[msg.sender];
        require(amount > 0, "Zero balance");
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }

    // Defect 3: secp256k1 public key registration — HNDL attack surface
    function registerPublicKey(bytes32 pubKeyX, bytes32 pubKeyY) external {
        // secp256k1 curve point stored on-chain indefinitely
        emit PublicKeyRegistered(msg.sender, pubKeyX, pubKeyY);
    }

    event PublicKeyRegistered(address indexed user, bytes32 x, bytes32 y);
}
`;

export const AuditDashboard: React.FC = () => {
  const [accountAddress, setAccountAddress] = useState<string | null>(null);
  const [algoBalance, setAlgoBalance] = useState<string>("0.00");
  const [usdcBalance, setUsdcBalance] = useState<string>("0.00");
  const [isUsdcOptedIn, setIsUsdcOptedIn] = useState<boolean>(false);
  const [isConnecting, setIsConnecting] = useState<boolean>(false);
  const [contractCode, setContractCode] = useState<string>(SAMPLE_VULNERABLE_PYTEAL);
  const [language, setLanguage] = useState<"pyteal" | "solidity" | "qds">("pyteal");
  const [appliedPatches, setAppliedPatches] = useState<Set<string>>(new Set());

  const [freeReport, setFreeReport] = useState<any | null>(null);
  const [paidReport, setPaidReport] = useState<any | null>(null);
  const [confirmedTxId, setConfirmedTxId] = useState<string | null>(null);
  const [paymentStatus, setPaymentStatus] = useState<string>("");
  const [isProcessingPayment, setIsProcessingPayment] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const algodClient = new algosdk.Algodv2("", ALGOD_SERVER, 443);

  const refreshAccountBalances = useCallback(async (address: string) => {
    try {
      const acctInfo: any = await algodClient.accountInformation(address).do();
      const rawAlgos = (Number(acctInfo.amount) / 1_000_000).toFixed(3);
      setAlgoBalance(rawAlgos);

      const assets: any[] = acctInfo.assets || [];
      const usdcAsset = assets.find(
        (a: any) =>
          Number(a.assetId || a["asset-id"] || 0) === USDC_ASA_ID
      );

      if (usdcAsset) {
        setIsUsdcOptedIn(true);
        setUsdcBalance((Number(usdcAsset.amount) / 1_000_000).toFixed(3));
      } else {
        setIsUsdcOptedIn(false);
        setUsdcBalance("0.00 (Not Opted In)");
      }
    } catch (err) {
      console.error("Failed to query Algorand node account balance", err);
    }
  }, []);

  useEffect(() => {
    peraWallet
      .reconnectSession()
      .then((accounts) => {
        if (accounts.length > 0) {
          setAccountAddress(accounts[0]);
          refreshAccountBalances(accounts[0]);
        }
      })
      .catch((err) => console.log("Session reconnection idle", err));

    peraWallet.connector?.on("disconnect", () => {
      setAccountAddress(null);
      setAlgoBalance("0.00");
      setUsdcBalance("0.00");
    });
  }, [refreshAccountBalances]);

  const connectWallet = async () => {
    setErrorMessage(null);
    setIsConnecting(true);
    try {
      const accounts = await peraWallet.connect();
      if (accounts.length > 0) {
        setAccountAddress(accounts[0]);
        await refreshAccountBalances(accounts[0]);
      }
    } catch (err: any) {
      if (err?.data?.type !== "CONNECT_MODAL_CLOSED") {
        setErrorMessage("Wallet connection rejected or session failed.");
      }
    } finally {
      setIsConnecting(false);
    }
  };

  const cancelConnect = async () => {
    try {
      await peraWallet.disconnect();
    } catch {
      // ignore — modal may already be closed
    } finally {
      setIsConnecting(false);
      setErrorMessage(null);
    }
  };

  const disconnectWallet = async () => {
    await peraWallet.disconnect();
    setAccountAddress(null);
    setConfirmedTxId(null);
    setPaidReport(null);
  };

  const optInToUsdc = async () => {
    if (!accountAddress) return;
    setErrorMessage(null);
    setPaymentStatus("Submitting USDC opt-in zero-balance transaction...");
    try {
      const suggestedParams = await algodClient.getTransactionParams().do();
      const optInTxn = algosdk.makeAssetTransferTxnWithSuggestedParamsFromObject({
        sender: accountAddress,
        receiver: accountAddress,
        assetIndex: BigInt(USDC_ASA_ID),
        amount: BigInt(0),
        suggestedParams,
      });

      const singleTxnGroup = [{ txn: optInTxn, signers: [accountAddress] }];
      const signedTxns = await peraWallet.signTransaction([singleTxnGroup]);
      const txConfirmation: any = await algodClient.sendRawTransaction(signedTxns).do();
      const txId = txConfirmation.txid || txConfirmation.txId;
      await algosdk.waitForConfirmation(algodClient, txId, 4);
      setPaymentStatus("Asset Opt-In Confirmed!");
      await refreshAccountBalances(accountAddress);
    } catch (err: any) {
      setErrorMessage("USDC Opt-in failed: " + (err.message || String(err)));
      setPaymentStatus("");
    }
  };

  const applyPatch = (findingId: string, original: string, patch: string) => {
    setContractCode((prev) => {
      const updated = prev.includes(original)
        ? prev.replace(original, patch)
        : prev + "\n\n// ✅ AI Patch Applied — " + findingId + "\n" + patch;
      return updated;
    });
    setAppliedPatches((prev) => new Set([...prev, findingId]));
  };

  const runFreeScan = async () => {
    setErrorMessage(null);
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 8000); // 8s timeout safeguard

      const res = await fetch(`${API_BASE_URL}/api/audit-free`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: contractCode, language }),
        signal: controller.signal,
      });
      clearTimeout(timeoutId);

      const data = await res.json();
      setFreeReport(data);
    } catch (err: any) {
      if (err.name === "AbortError") {
        setErrorMessage("Request timed out (8s limit). Please check backend connection.");
      } else {
        setErrorMessage("Free scan query failed: " + err.message);
      }
    }
  };

  const triggerX402PaymentAndUnlock = async () => {
    if (!accountAddress) {
      setErrorMessage("Connect Pera Wallet before purchasing audit telemetry.");
      return;
    }
    if (!isUsdcOptedIn) {
      setErrorMessage("Your address must opt-in to Testnet USDC (ASA 10458941) first.");
      return;
    }

    setErrorMessage(null);
    setIsProcessingPayment(true);
    setPaymentStatus("Sending request to resource server (Waiting for HTTP 402)...");

    try {
      const controller1 = new AbortController();
      const timeoutId1 = setTimeout(() => controller1.abort(), 8000);

      const initialResponse = await fetch(`${API_BASE_URL}/api/audit-explain`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: contractCode, language }),
        signal: controller1.signal,
      });
      clearTimeout(timeoutId1);

      if (initialResponse.status !== 402) {
        throw new Error(`Expected HTTP 402 response, received status ${initialResponse.status}`);
      }

      setPaymentStatus("Received 402 Challenge. Inspecting payment parameters...");
      const payReqHeader =
        initialResponse.headers.get("payment-required") ||
        initialResponse.headers.get("PAYMENT-REQUIRED");

      let challengeData: any = {};
      if (payReqHeader) {
        try {
          challengeData = JSON.parse(fromBase64(payReqHeader));
        } catch {
          challengeData = await initialResponse.json().catch(() => ({}));
        }
      } else {
        challengeData = await initialResponse.json().catch(() => ({}));
      }

      const acceptRequirement = challengeData.accepts ? challengeData.accepts[0] : null;

      const receiverAddress =
        acceptRequirement?.payTo ||
        challengeData.payTo ||
        "AEXVG5ROA44Z5ZU2RQGUSFU2KJKRYGH6ZECJMAP5PUFNFYNLLFA2TN3N7M";

      setPaymentStatus("Constructing 2-transaction fee-abstracted atomic group...");
      const suggestedParams = await algodClient.getTransactionParams().do();

      const facilitatorFeeAddress =
        acceptRequirement?.extra?.feePayer ||
        challengeData.feePayer ||
        receiverAddress;
      suggestedParams.fee = BigInt(2000);
      suggestedParams.flatFee = true;

      const txn0 = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: facilitatorFeeAddress,
        receiver: facilitatorFeeAddress,
        amount: BigInt(0),
        suggestedParams,
      });

      suggestedParams.fee = BigInt(0);
      suggestedParams.flatFee = true;

      const txn1 = algosdk.makeAssetTransferTxnWithSuggestedParamsFromObject({
        sender: accountAddress,
        receiver: receiverAddress,
        assetIndex: BigInt(USDC_ASA_ID),
        amount: BigInt(5000),
        suggestedParams,
      });

      algosdk.assignGroupID([txn0, txn1]);

      setPaymentStatus("Sign Transaction 1 in Pera Wallet (USDC payment, $0 gas fee)...");
      const signedTxnsFromWallet = await peraWallet.signTransaction([
        [
          { txn: txn0, signers: [] },
          { txn: txn1, signers: [accountAddress] },
        ],
      ]);

      setPaymentStatus("Serializing payment signature envelope for facilitator settlement...");
      // Browser-safe base64 conversion without reliance on Node Buffer
      const base64Txn0 = toBase64(txn0.toByte());
      const base64Txn1 = toBase64(signedTxnsFromWallet[1]);

      const paymentEnvelope = {
        x402Version: 2,
        scheme: "exact",
        network: "algorand:SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=",
        payload: {
          paymentGroup: [base64Txn0, base64Txn1],
          paymentIndex: 1,
        },
      };

      const paymentSignatureHeader = toBase64(JSON.stringify(paymentEnvelope));

      setPaymentStatus("Submitting proof with PAYMENT-SIGNATURE header to /api/audit-explain...");
      const controller2 = new AbortController();
      const timeoutId2 = setTimeout(() => controller2.abort(), 12000); // 12s timeout safeguard for settlement

      const paidResponse = await fetch(`${API_BASE_URL}/api/audit-explain`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "PAYMENT-SIGNATURE": paymentSignatureHeader,
        },
        body: JSON.stringify({ code: contractCode, language }),
        signal: controller2.signal,
      });
      clearTimeout(timeoutId2);

      if (!paidResponse.ok) {
        const errBody = await paidResponse.json().catch(() => ({}));
        throw new Error(errBody.error || `Settlement error (HTTP ${paidResponse.status}).`);
      }

      const paymentResponseHeader = paidResponse.headers.get("PAYMENT-RESPONSE");
      let extractedTxId = "N/A";
      if (paymentResponseHeader) {
        try {
          const parsedRes = JSON.parse(fromBase64(paymentResponseHeader));
          extractedTxId = parsedRes.txId || parsedRes.transactionId || extractedTxId;
        } catch {
          extractedTxId = paymentResponseHeader;
        }
      }

      const xaiPayload = await paidResponse.json();
      setPaidReport(xaiPayload);
      setConfirmedTxId(extractedTxId);
      setPaymentStatus("Payment Settled Live on Algorand Testnet!");
      await refreshAccountBalances(accountAddress);
    } catch (err: any) {
      console.error(err);
      if (err.name === "AbortError") {
        setErrorMessage("Network request timed out. Please verify your connection or retry.");
      } else {
        setErrorMessage(err.message || "Failed to complete x402 transaction pipeline");
      }
      setPaymentStatus("");
    } finally {
      setIsProcessingPayment(false);
    }
  };

  return (
    <div className="min-h-screen bg-white text-black font-sans p-6 md:p-12 selection:bg-black selection:text-white">

      {/* Pera Wallet Modal Close Button — portalled to body to beat SDK z-index */}
      {isConnecting && createPortal(
        <button
          onClick={cancelConnect}
          style={{ zIndex: 2147483647 }}
          className="fixed top-5 right-5 w-10 h-10 rounded-full bg-black text-white flex items-center justify-center shadow-2xl hover:bg-zinc-700 transition text-lg font-bold"
          title="Close Pera Wallet"
        >
          ✕
        </button>,
        document.body
      )}

      <header className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between border-b border-zinc-100 pb-6 mb-8 gap-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="h-9 w-9 rounded-lg bg-black flex items-center justify-center font-black text-white text-xl shadow-sm">
              X
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-2xl md:text-3xl font-black tracking-tight text-black">
                  AuditAgent-X
                </h1>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-zinc-100 text-black border border-zinc-300 font-mono uppercase">
                  x402-AVM
                </span>
              </div>
            </div>
          </div>
          <p className="text-sm text-zinc-500 mt-1">
            Pay-Per-Explanation Smart Contract Security Auditor Powered by AVM x402 Micropayments
          </p>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          {accountAddress ? (
            <div className="flex items-center gap-3 bg-white border border-zinc-200 p-2.5 rounded-lg text-xs">
              <div className="flex flex-col">
                <span className="text-zinc-500">Connected Pera Account</span>
                <span className="font-mono text-black font-bold">
                  {accountAddress.slice(0, 6)}...{accountAddress.slice(-6)}
                </span>
              </div>
              <div className="border-l border-zinc-200 pl-3 flex flex-col font-medium text-zinc-900">
                <span>{algoBalance} ALGO</span>
                <span className="text-zinc-500">{usdcBalance} USDC</span>
              </div>
              {!isUsdcOptedIn && (
                <button
                  onClick={optInToUsdc}
                  className="bg-black hover:bg-zinc-800 text-white px-2.5 py-1 rounded font-semibold transition"
                >
                  Opt-In USDC
                </button>
              )}
              <button
                onClick={disconnectWallet}
                className="bg-zinc-200 hover:bg-zinc-300 text-black px-3 py-1.5 rounded transition font-medium"
              >
                Disconnect
              </button>
            </div>
          ) : isConnecting ? (
            <div className="flex items-center gap-2">
              <div className="flex items-center gap-2 px-4 py-2.5 rounded-lg border border-zinc-200 text-sm text-zinc-500 font-medium">
                <svg className="animate-spin w-4 h-4 text-black" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
                </svg>
                Connecting…
              </div>
              <button
                onClick={cancelConnect}
                className="bg-white hover:bg-zinc-100 text-black font-semibold px-4 py-2.5 rounded-lg border border-zinc-300 transition text-sm"
              >
                ← Cancel
              </button>
            </div>
          ) : (
            <button
              onClick={connectWallet}
              className="bg-black hover:bg-zinc-800 text-white font-bold px-5 py-2.5 rounded-lg shadow-sm transition"
            >
              Connect Pera Wallet
            </button>
          )}
        </div>
      </header>

      {/* 1. HERO SECTION: The Hook with TextBlockAnimation */}
      <section className="min-h-[75vh] flex flex-col justify-center items-center relative px-4 py-12 text-center max-w-5xl mx-auto">
        <div className="w-full flex flex-col items-center">
          <div className="mb-6 inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-white border border-zinc-200 text-zinc-800 text-xs font-mono">
            <span className="h-2 w-2 rounded-full bg-black animate-pulse"></span>
            Algorand Testnet (CAIP-2) &bull; x402 Micropayment Protocol
          </div>

          <TextBlockAnimation
            blockColor="#000000"
            animateOnScroll={false}
            delay={0.1}
            duration={0.8}
            className="flex flex-col items-center"
          >
            <h1 className="text-5xl md:text-7xl lg:text-8xl font-black tracking-tighter leading-tight text-black">
              Don&apos;t just audit.
              <br />
              <span className="inline-block bg-black text-white px-5 pb-2 pt-1 rounded-lg mt-3 tracking-tight font-black shadow-md">
                Explain.
              </span>
            </h1>
          </TextBlockAnimation>

          <div className="mt-8 max-w-2xl">
            <TextBlockAnimation blockColor="#000000" delay={0.35} duration={0.65}>
              <p className="text-base md:text-xl text-zinc-700 leading-relaxed font-normal">
                Autonomous AI agents and Web3 developers can now purchase
                line-level AST vulnerability attribution and counterfactual code repairs
                in <strong className="text-black font-bold">3.3s deterministic consensus</strong> for{" "}
                <strong className="text-black font-bold">$0.005 USDC</strong> with{" "}
                <strong className="text-black font-bold">0 ALGO gas fees</strong>.
              </p>
            </TextBlockAnimation>
          </div>

          {/* Quick Value Props Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mt-10 w-full max-w-3xl">
            <div className="p-5 rounded-xl bg-white border border-zinc-200 text-left hover:border-black transition">
              <div className="flex items-center gap-2 text-black font-bold text-sm mb-1">
                <Zap className="w-4 h-4" /> 3.3s Finality
              </div>
              <p className="text-xs text-zinc-600 leading-relaxed">
                Algorand Pure PoS delivers instant irrevocable settlement within standard HTTP timeout limits.
              </p>
            </div>

            <div className="p-5 rounded-xl bg-white border border-zinc-200 text-left hover:border-black transition">
              <div className="flex items-center gap-2 text-black font-bold text-sm mb-1">
                <Shield className="w-4 h-4" /> Fee Abstraction
              </div>
              <p className="text-xs text-zinc-600 leading-relaxed">
                Facilitator sponsors gas fees via pooled atomic groups. Payer requires zero ALGO balance.
              </p>
            </div>

            <div className="p-5 rounded-xl bg-white border border-zinc-200 text-left hover:border-black transition">
              <div className="flex items-center gap-2 text-black font-bold text-sm mb-1">
                <Terminal className="w-4 h-4" /> Headless Ready
              </div>
              <p className="text-xs text-zinc-600 leading-relaxed">
                Autonomous AI agents negotiate HTTP 402 terms and sign via CLI script without browser UI.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-4 mt-10 flex-wrap justify-center">
            <a
              href="#audit-workspace"
              className="bg-black hover:bg-zinc-800 text-white font-bold px-6 py-3 rounded-lg shadow-sm transition flex items-center gap-2 text-sm"
            >
              Launch Live Code Auditor <ArrowDown className="w-4 h-4" />
            </a>
            {!accountAddress && (
              isConnecting ? (
                <button
                  onClick={cancelConnect}
                  className="bg-white hover:bg-zinc-100 text-black font-semibold px-5 py-3 rounded-lg border border-zinc-300 transition text-sm flex items-center gap-2"
                >
                  <svg className="animate-spin w-4 h-4 text-black" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
                  </svg>
                  ← Cancel
                </button>
              ) : (
                <button
                  onClick={connectWallet}
                  className="bg-white hover:bg-zinc-100 text-black font-semibold px-5 py-3 rounded-lg border border-zinc-300 transition text-sm"
                >
                  Connect Pera Wallet
                </button>
              )
            )}
          </div>

          {/* Scroll Down Indicator */}
          <a
            href="#audit-workspace"
            className="mt-14 flex flex-col items-center gap-2 opacity-60 hover:opacity-100 transition cursor-pointer"
          >
            <span className="text-[10px] uppercase tracking-widest text-zinc-500 font-semibold font-mono">
              Scroll to Audit Workspace
            </span>
            <ArrowDown className="w-4 h-4 text-black animate-bounce" />
          </a>
        </div>
      </section>

      <main id="audit-workspace" className="max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-12 gap-8 pt-10 border-t border-zinc-100">
        <div className="lg:col-span-6 flex flex-col gap-6">
          <div className="bg-white border border-zinc-200 rounded-xl p-5 shadow-sm">
            <div className="flex items-center justify-between mb-3">
              <label className="text-sm font-bold uppercase tracking-wider text-zinc-800">
                Source Code
              </label>
              <div className="flex gap-2 flex-wrap">
                <button
                  onClick={() => {
                    setLanguage("pyteal");
                    setContractCode(SAMPLE_VULNERABLE_PYTEAL);
                    setAppliedPatches(new Set());
                  }}
                  className={`px-3 py-1 rounded text-xs font-semibold transition ${
                    language === "pyteal"
                      ? "bg-black text-white"
                      : "bg-zinc-200 text-zinc-700 hover:bg-zinc-300"
                  }`}
                >
                  PyTeal Sample
                </button>
                <button
                  onClick={() => {
                    setLanguage("solidity");
                    setContractCode(SAMPLE_VULNERABLE_SOLIDITY);
                    setAppliedPatches(new Set());
                  }}
                  className={`px-3 py-1 rounded text-xs font-semibold transition ${
                    language === "solidity"
                      ? "bg-black text-white"
                      : "bg-zinc-200 text-zinc-700 hover:bg-zinc-300"
                  }`}
                >
                  Solidity Sample
                </button>
                <button
                  onClick={() => {
                    setLanguage("qds");
                    setContractCode(SAMPLE_QDS_VULNERABLE);
                    setAppliedPatches(new Set());
                  }}
                  className={`px-3 py-1 rounded text-xs font-semibold transition ${
                    language === "qds"
                      ? "bg-black text-white"
                      : "bg-zinc-200 text-zinc-700 hover:bg-zinc-300"
                  }`}
                >
                  ⚛ QDS Sample
                </button>
              </div>
            </div>

            <textarea
              value={contractCode}
              onChange={(e) => setContractCode(e.target.value)}
              rows={16}
              className="w-full bg-white font-mono text-xs text-black p-4 rounded-lg border border-zinc-300 focus:outline-none focus:border-black transition leading-relaxed resize-none shadow-inner"
            />

            <div className="flex flex-col sm:flex-row gap-3 mt-4">
              <button
                onClick={runFreeScan}
                className="flex-1 bg-white hover:bg-zinc-100 text-black font-semibold py-2.5 px-4 rounded-lg transition border border-zinc-300 text-sm"
              >
                Analyze Code (Free)
              </button>
              <button
                onClick={triggerX402PaymentAndUnlock}
                disabled={isProcessingPayment}
                className="flex-1 bg-black hover:bg-zinc-800 text-white font-bold py-2.5 px-4 rounded-lg shadow-sm transition disabled:opacity-50 text-sm flex items-center justify-center gap-2"
              >
                {isProcessingPayment ? "Settling via x402..." : "Unlock Deep XAI Report ($0.005 USDC)"}
              </button>
            </div>

            {paymentStatus && (
              <div className="mt-4 p-3 rounded-lg bg-white border border-zinc-200 text-zinc-900 text-xs font-mono">
                {paymentStatus}
              </div>
            )}
            {errorMessage && (
              <div className="mt-4 p-3 rounded-lg bg-white border border-black text-black text-xs font-mono flex items-center justify-between gap-2">
                <span>{errorMessage}</span>
                <a
                  href="https://lora.algokit.io/testnet"
                  target="_blank"
                  rel="noreferrer"
                  className="underline text-[10px] text-zinc-600 hover:text-black shrink-0 font-bold"
                >
                  Check Testnet Status ↗
                </a>
              </div>
            )}
          </div>

          {freeReport && !paidReport && (
            <div className="bg-white border border-zinc-200 rounded-xl p-5 shadow-sm">
              <h3 className="text-md font-bold text-black mb-2">Free Vulnerability Assessment</h3>
              <div className="flex items-center gap-4 mb-4">
                <div className="text-4xl font-black text-black">
                  {freeReport.vulnerabilityScore} / 100
                </div>
                <div className="text-xs text-zinc-600">
                  <p>Status: <span className="font-bold text-black">{freeReport.status}</span></p>
                  <p>Identified Risks: <span className="font-bold text-black">{freeReport.totalIssuesCount}</span></p>
                </div>
              </div>
              <p className="text-xs text-zinc-700 mb-3">{freeReport.summary}</p>
              <div className="p-3 bg-white rounded border border-dashed border-zinc-300 text-xs text-zinc-600 font-mono">
                🔒 {freeReport.upgradePrompt}
              </div>
            </div>
          )}
        </div>

        <div className="lg:col-span-6 flex flex-col gap-6">
          {paidReport ? (
            <div className="bg-white border border-zinc-200 rounded-xl p-5 shadow-sm">
              <div className="bg-white border border-zinc-200 rounded-lg p-3 mb-5 flex items-center justify-between">
                <div>
                  <span className="inline-block px-2 py-0.5 rounded text-[10px] font-bold bg-black text-white uppercase tracking-wide">
                    Payment Verified
                  </span>
                  <p className="text-xs text-zinc-600 mt-1 font-mono">
                    Protocol: {paidReport.paymentProtocol} | Fee Abstracted: 0 ALGO
                  </p>
                </div>
                {confirmedTxId && confirmedTxId !== "N/A" && (
                  <a
                    href={`https://lora.algokit.io/testnet/transaction/${confirmedTxId}`}
                    target="_blank"
                    rel="noreferrer"
                    className="text-xs font-bold text-black underline hover:text-zinc-600"
                  >
                    View on LoRA Explorer ↗
                  </a>
                )}
              </div>

              <div className="grid grid-cols-3 gap-3 mb-5">
                <div className="bg-white p-3 rounded-lg border border-zinc-200">
                  <span className="text-[10px] uppercase text-zinc-500 font-bold">AST Nodes</span>
                  <p className="text-lg font-mono font-bold text-black">{paidReport.astMetrics.nodeCount}</p>
                </div>
                <div className="bg-white p-3 rounded-lg border border-zinc-200">
                  <span className="text-[10px] uppercase text-zinc-500 font-bold">Complexity</span>
                  <p className="text-lg font-mono font-bold text-black">{paidReport.astMetrics.cyclomaticComplexity}</p>
                </div>
                <div className="bg-white p-3 rounded-lg border border-zinc-200">
                  <span className="text-[10px] uppercase text-zinc-500 font-bold">Risk Entropy</span>
                  <p className="text-lg font-mono font-bold text-black">{paidReport.astMetrics.riskWeightedEntropy}</p>
                </div>
              </div>

              <h3 className="text-sm font-bold uppercase tracking-wider text-zinc-800 mb-3">
                XAI Attributions & Counterfactual Fixes
              </h3>

              <div className="flex flex-col gap-4">
                {paidReport.detailedFindings.map((finding: any) => (
                  <div key={finding.id} className="bg-white border border-zinc-200 rounded-lg p-4 shadow-sm">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-bold text-black font-mono">
                        {finding.id}: {finding.title}
                      </span>
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-zinc-100 text-black border border-zinc-300">
                        {finding.severity} (Weight: {finding.riskWeight})
                      </span>
                    </div>
                    <p className="text-xs text-zinc-600 mb-3">{finding.description}</p>

                    <div className="flex flex-wrap gap-2 mb-3">
                      {finding.attributions.map((attr: any, i: number) => (
                        <div
                          key={i}
                          className="text-[10px] bg-zinc-50 border border-zinc-200 px-2 py-1 rounded text-zinc-800 flex items-center gap-1.5 font-mono"
                        >
                          <span className="font-bold text-black">Node:</span> {attr.astNodeType}
                          <span className="text-zinc-400">|</span>
                          <span className="font-semibold text-black">Line {attr.line}</span>
                          <span className="text-zinc-400">|</span>
                          <span>Weight: {attr.weight}</span>
                        </div>
                      ))}
                    </div>

                    <div className="mt-3">
                      <div className="text-[11px] font-bold text-zinc-700 mb-2 uppercase tracking-wider">
                        Counterfactual Diff Viewer
                      </div>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-2 mb-2">
                        <div>
                          <div className="text-[10px] font-bold text-red-500 mb-1 uppercase tracking-wider">⛔ Vulnerable (Before)</div>
                          <pre className="bg-red-50 p-3 rounded text-[11px] font-mono text-red-800 overflow-x-auto border border-red-200 leading-relaxed min-h-[60px]">
                            {finding.counterfactualFix.originalCodeSnippet}
                          </pre>
                        </div>
                        <div>
                          <div className="text-[10px] font-bold text-green-600 mb-1 uppercase tracking-wider">✅ Safe (After)</div>
                          <pre className="bg-green-50 p-3 rounded text-[11px] font-mono text-green-800 overflow-x-auto border border-green-200 leading-relaxed min-h-[60px]">
                            {finding.counterfactualFix.recommendedPatch}
                          </pre>
                        </div>
                      </div>
                      <p className="text-[11px] text-zinc-500 mb-3 italic">
                        {finding.counterfactualFix.explanation}
                      </p>
                      <button
                        onClick={() =>
                          applyPatch(
                            finding.id,
                            finding.counterfactualFix.originalCodeSnippet,
                            finding.counterfactualFix.recommendedPatch
                          )
                        }
                        disabled={appliedPatches.has(finding.id)}
                        className={`w-full py-2 px-4 rounded-lg text-xs font-bold transition flex items-center justify-center gap-2 ${
                          appliedPatches.has(finding.id)
                            ? "bg-green-50 text-green-700 border border-green-200 cursor-default"
                            : "bg-black text-white hover:bg-zinc-800 shadow-sm"
                        }`}
                      >
                        {appliedPatches.has(finding.id) ? (
                          <>
                            <span>✓</span> Patch Applied to Editor
                          </>
                        ) : (
                          <>
                            <span>⚡</span> 1-Click Apply Patch
                          </>
                        )}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="bg-white border border-zinc-200 rounded-xl p-12 flex flex-col items-center justify-center text-center shadow-sm">
              <div className="h-12 w-12 rounded-full bg-zinc-100 flex items-center justify-center text-black mb-3 text-xl font-bold">
                ⚡
              </div>
              <h3 className="text-md font-bold text-black mb-1">Deep Diagnostic Intelligence Locked</h3>
              <p className="text-xs text-zinc-600 max-w-sm mb-4">
                Execute an x402 micropayment of $0.005 USDC on Algorand Testnet to unlock line-by-line feature attributions, AST weights, and code repair diffs.
              </p>
              <div className="text-[11px] text-zinc-500 font-mono">
                Settled on-chain via GoPlausible Facilitator (Gas Sponsored)
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
};

export default AuditDashboard;
