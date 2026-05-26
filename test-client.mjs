import { x402Client, wrapFetchWithPayment } from "@x402/fetch";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";
import dotenv from "dotenv";
dotenv.config();

const signer = privateKeyToAccount(process.env.TEST_PRIVATE_KEY);
console.log("Paying from:", signer.address);

const client = new x402Client();
registerExactEvmScheme(client, { signer });
const fetchWithPayment = wrapFetchWithPayment(fetch, client);

console.log("Calling TrustScore API...");
const response = await fetchWithPayment(
  "https://trustsource.cc/sslcheck?domain=google.com"
);

const data = await response.json();
console.log("\n✅ Response:");
console.log(JSON.stringify(data, null, 2));
