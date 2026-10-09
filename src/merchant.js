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
