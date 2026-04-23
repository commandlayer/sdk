# Quickstart (Node.js)

Install dependencies and run:

```bash
npm install
COMMANDLAYER_PUBLIC_KEY='ed25519:BASE64_PUBLIC_KEY' npm start
```

This example:
1. Runs a sample `summarize` action with `commandlayer.run(...)`.
2. Prints the returned receipt payload.
3. Verifies the receipt with `commandlayer.verify(...)`.
4. Prints whether verification passed.
