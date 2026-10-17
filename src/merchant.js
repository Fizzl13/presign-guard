import { BUILDER_CODE, BUILDER_CODE_PATTERN, declareBuilderCodeExtension } from "@x402/extensions/builder-code";

// Who sells this, for x402 discovery lists. GoPlausible's catalog reads the
// "x402-merchant" extension of a 402 challenge (name, website, logo, categories)
// when it settles a payment, and shows it on the merchant: one per pay-to
// address, which all four fizzl.eu services share on Algorand. So the info is
// the same on every fizzl.eu service.
export const MERCHANT = {
  name: "Fizzl",
  website: "https://fizzl.eu",
  logo: "https://fizzl.eu/logo-512.png",
  categories: ["ai-agents", "security", "trading-signals", "developer-tools", "x402", "algorand"],
};

export const merchantExtension = {
  "x402-merchant": {
    info: MERCHANT,
    schema: {
      $schema: "https://json-schema.org/draft/2020-12/schema",
      type: "object",
      required: ["name"],
      properties: {
        name: { type: "string" },
        website: { type: "string" },
        logo: { type: "string" },
        categories: { type: "array", items: { type: "string" } },
      },
    },
  },
};

// Base Builder Code (ERC-8021): a buyer's x402 client echoes this app code back with its payment, and the
// facilitator writes it into the settlement calldata, so Base counts the payment as Fizzl's. Minted at base.dev
// and set as env BUILDER_CODE; unset, or not a valid code (a-z, 0-9 and _, at most 32), the 402 has none.
export function builderCodeExtension(value) {
  const code = (value || "").trim();
  if (!code) return {};
  if (!BUILDER_CODE_PATTERN.test(code)) {
    console.warn(`[x402] BUILDER_CODE "${code}" is not a valid builder code (a-z, 0-9 and _, at most 32): left out`);
    return {};
  }
  return { [BUILDER_CODE]: declareBuilderCodeExtension(code) };
}
