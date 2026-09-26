// nohumans.directory listing claims. To take ownership of a listing (and edit its
// description), the directory asks for a one-time challenge token, valid 24h and
// not a credential, either as an x-nohumans-claim header on the listed endpoint
// or as plain text at /.well-known/nohumans-claim. The tokens are public by
// design; empty CLAIMS again once the claims are done. Same as in x402-doctor
// and ichimoku-signal.
export const CLAIMS = {
  headers: {},
  wellKnown: "857bd9d55cb8d42eb41f294993a7f420223870a976d70460", // listing ee5c650c-d63 (/v1/token)
};

export function nohumansClaim(claims = CLAIMS) {
  return (req, res, next) => {
    if (req.path === "/.well-known/nohumans-claim") {
      if (!claims.wellKnown) return next();
      return res.type("text/plain").send(claims.wellKnown);
    }
    const token = claims.headers[req.path];
    if (token) res.set("x-nohumans-claim", token);
    next();
  };
}
