// The certificate signing page (GET /sign-receipt-key) for presign-guard and
// for the other Fizzl services with receipts. ?service=x402-doctor builds
// Doctor's certificate here, so the payout wallet only ever signs on this one
// site (MetaMask flags some onrender.com hosts). The page reads the current
// signer through /sign-receipt-key/<service>-signer.json: for presign-guard its
// own signer, for another service that service's published signer file,
// fetched server side (no CORS needed) and reduced to what the page uses.

import { Router } from "express";

const TIMEOUT_MS = 8000;

/**
 * @param {object} o
 * @param {string} o.page      the HTML template
 * @param {string} o.authority the payout wallet that signs certificates
 * @param {string} o.self      this service's name
 * @param {() => Promise<object>} o.localSigner  this service's signer file
 * @param {Record<string, string>} o.remotes     other services: name → signer file URL
 */
export function signPageRouter({ page, authority, self, localSigner, remotes = {}, fetchImpl = fetch }) {
  const services = [self, ...Object.keys(remotes)];
  const router = Router();

  const render = (service) => {
    const others = services.filter((s) => s !== service)
      .map((s) => `<a href="/sign-receipt-key${s === self ? "" : `?service=${s}`}" style="color:var(--accent)">${s}</a>`).join(", ");
    return page
      .replaceAll("{{SERVICE}}", service)
      .replaceAll("{{AUTHORITY}}", authority)
      .replaceAll("{{WELL_KNOWN}}", `/sign-receipt-key/${service}-signer.json`)
      .replaceAll("{{SIGNER_PAGE}}", service === self ? `/.well-known/${self}-signer.json` : remotes[service])
      .replaceAll("{{OTHERS}}", others);
  };

  router.get("/sign-receipt-key", (req, res) => {
    const service = req.query.service === undefined ? self : String(req.query.service);
    if (!services.includes(service)) return res.status(404).type("text").send(`unknown service; one of: ${services.join(", ")}`);
    res.type("html").send(render(service));
  });

  router.get("/sign-receipt-key/:service-signer.json", async (req, res) => {
    const { service } = req.params;
    if (!services.includes(service)) return res.status(404).json({ error: "unknown service" });
    try {
      let d;
      if (service === self) d = await localSigner();
      else {
        const r = await fetchImpl(remotes[service], { headers: { accept: "application/json" }, signal: AbortSignal.timeout(TIMEOUT_MS) });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        d = await r.json();
      }
      const signers = Array.isArray(d.signers) ? d.signers.map((s) => ({ address: s.address, status: s.status })) : [];
      const c = d.certificate;
      res.set("cache-control", "no-store").json({
        service,
        signing: d.signing === true,
        signers,
        certificate: c ? { signer: c.signer, valid_from: c.valid_from } : null,
      });
    } catch (err) {
      res.status(502).json({ error: `could not read ${service}'s signer: ${err.message}` });
    }
  });

  return router;
}
