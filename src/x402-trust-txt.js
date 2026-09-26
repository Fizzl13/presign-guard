// x402-trust.com provider verification: https://<host>/.well-known/x402-trust.txt
// carries the line from their /verify page ("x402-trust-verification=v1:<public
// key>"), set in Render as X402_TRUST_TXT. It is a public key, safe to publish;
// the private key stays with the owner. Only a well-formed line is served.
const LINE = /^x402-trust-verification=v1:[A-Za-z0-9_-]{40,400}$/;

export function x402TrustTxt(value) {
  const line = String(value ?? "").trim();
  return LINE.test(line) ? `${line}\n` : null;
}

export function x402TrustTxtRoute(env = process.env) {
  return (_req, res) => {
    const body = x402TrustTxt(env.X402_TRUST_TXT);
    if (!body) return res.status(404).type("text/plain").send("Not found\n");
    res.type("text/plain").set("Cache-Control", "public, max-age=300").send(body);
  };
}
