// The facilitators' supported kinds, fetched without x402's start-up exit.
//
// paymentMiddleware() normally checks every route against the facilitators at start and exits the process when a
// network has no facilitator answering: one facilitator down during a restart kept the whole service down, free
// routes included, until it answered again. Here the middleware runs with that check off (syncFacilitatorOnStart
// false) and this module fetches the kinds instead:
// - every facilitator is asked first, at most askMs each, and initialize() then gets those answers at once, so the
//   kinds the paid routes use are never empty while a slow facilitator is being asked;
// - a network no facilitator supports is left out of the 402 (the other networks still pay) and asked again every
//   retryMs until it answers;
// - with nothing loaded at all, the paid routes answer 500 and the next paid call asks again.
//
// The same file is copied into each Fizzl service.

'use strict';

function createFacilitatorStart(facilitators, { log = console, askMs = 15 * 1000, retryMs = 60 * 1000 } = {}) {
  const clients = facilitators.map((facilitator) => {
    let answer = null;
    return {
      verify: (...args) => facilitator.verify(...args),
      settle: (...args) => facilitator.settle(...args),
      getSupported: () => answer || facilitator.getSupported(),
      ask() {
        let timer;
        const limit = new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error(`no answer within ${askMs / 1000} s`)), askMs);
        });
        answer = Promise.race([facilitator.getSupported(), limit]).finally(() => clearTimeout(timer));
        return answer.catch(() => {});
      },
      forget() { answer = null; },
    };
  });

  // Wraps the resource server built on `clients`; networks are the ones its routes offer.
  function attach(resourceServer, networks) {
    const initialize = resourceServer.initialize.bind(resourceServer);
    const build = resourceServer.buildPaymentRequirements.bind(resourceServer);
    const supports = (network, scheme = 'exact') => Boolean(resourceServer.getSupportedKind(2, network, scheme));
    const missing = () => networks.filter((network) => !supports(network));
    const anyLoaded = () => missing().length < networks.length;
    let loading = null;
    let refilling = null;
    let timer = null;

    function load() {
      loading ??= (async () => {
        await Promise.all(clients.map((c) => c.ask()));
        // initialize() empties the kinds and asks every client again; all answers are in, so it refills them
        // without waiting on the network.
        refilling = initialize().catch((err) => log.warn(`[x402] facilitators: ${err.message}`));
        await refilling;
        refilling = null;
        clients.forEach((c) => c.forget());
        clearTimeout(timer);
        const gone = missing();
        if (gone.length) {
          log.warn(`[x402] no facilitator answers for ${gone.join(', ')}; asking again in ${Math.round(retryMs / 1000)} s`);
          timer = setTimeout(load, retryMs);
          timer.unref?.();
        }
      })().finally(() => { loading = null; });
      return loading;
    }

    resourceServer.initialize = load; // the MCP tools' initialize() goes through here too
    resourceServer.buildPaymentRequirements = async (config, ...rest) => {
      if (refilling) await refilling;
      if (!anyLoaded()) await load();
      if (anyLoaded() && !supports(config.network, config.scheme)) return [];
      return build(config, ...rest);
    };
    const ready = load();
    return { ready, missing };
  }

  return { clients, attach };
}

module.exports = { createFacilitatorStart };
