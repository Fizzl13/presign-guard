// nohumans.directory listing claims. To take ownership of a listing (and edit its
// description), the directory asks for a one-time challenge token, valid 24h and
// not a credential, either as an x-nohumans-claim header on the listed endpoint
// or as plain text at /.well-known/nohumans-claim. The tokens are public by
// design; empty CLAIMS again once the claims are done. Same as in x402-doctor
// and ichimoku-signal.
export const CLAIMS = {
  headers: {
    "/v1/check": "020b9323050d8e581f31efb341ff9996b39d53398aa0f5ae",
    "/v1/token": "0e7df9e10c9447df53fa46d72908bd76f7729b4e2d6abe3b",
  },
  wellKnown: null,
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
