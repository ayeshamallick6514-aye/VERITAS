import { ALGORAND_TESTNET_CAIP2, USDC_TESTNET_ASA_ID } from "@x402-avm/avm";
import type { RoutesConfig } from "@x402-avm/core/server";

const receiverAddress =
  process.env.RECEIVER_AVM_ADDRESS ||
  "AEXVG5ROA44Z5ZU2RQGUSFU2KJKRYGH6ZECJMAP5PUFNFYNLLFA2TN3N7M";

export const routesConfig: RoutesConfig = {
  "POST /api/audit-explain": {
    accepts: {
      scheme: "exact",
      network: ALGORAND_TESTNET_CAIP2,
      payTo: receiverAddress,
      price: "$0.005",
      extra: {
        asset: USDC_TESTNET_ASA_ID,
      },
    },
    description:
      "AuditAgent-X Deep Explainable AI diagnostic report providing token-level AST attribution and counterfactual code repair",
    mimeType: "application/json",
  },
};
