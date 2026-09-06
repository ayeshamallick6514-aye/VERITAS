/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_ALGOD_SERVER: string;
  readonly VITE_ALGOD_PORT: string;
  readonly VITE_FACILITATOR_URL: string;
  readonly VITE_API_URL: string;
  readonly VITE_USDC_ASA_ID: string;
  readonly VITE_NETWORK: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
