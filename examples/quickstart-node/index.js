import { commandlayer } from "@commandlayer/sdk";

const receipt = await commandlayer.run("summarize", {
  text: "Agent receipts prove what happened."
});

console.log("Receipt:", JSON.stringify(receipt, null, 2));

const verification = await commandlayer.verify(receipt, {
  publicKey: process.env.COMMANDLAYER_PUBLIC_KEY
});

console.log("Verification passed:", verification.ok);
