// NEAR Builders Activity (activity.nearbuilders.org): a public, signed record of what people do across NEAR, scored
// on leaderboards. presign-guard reports one thing there, the only action where it knows the user's NEAR account:
//   check.paid   an agent paid for a check (or a credit pack) in USDC on NEAR. Actor: the buyer (the delegate's signer).
// The payload holds only what the chain already shows (transaction, amount). Events are public and permanent.
//
// Off unless ACTIVITY_API_KEY is set (the Source API Key, a server-side secret: never logged). A report never holds
// up or breaks the payment: it runs after the settle, retries a 503 or a network error twice with the same body (the
// idempotency key makes a retry safe), and otherwise logs one line.
export const ACTIVITY_URL = "https://activity.nearbuilders.org/api/v1/events";
// Activity's own pattern for an actor (a NEAR account id).
const ACTOR = /^(?=.{2,64}$)([a-z0-9]+(?:[-_][a-z0-9]+)*)(\.([a-z0-9]+(?:[-_][a-z0-9]+)*))*$/;
const RETRY_MS = [2000, 10000];

export function createActivityReporter({ env = process.env, fetchImpl = globalThis.fetch, log = console, url = ACTIVITY_URL, retryMs = RETRY_MS, sleep = (ms) => new Promise((r) => setTimeout(r, ms).unref?.()) } = {}) {
  const key = (env.ACTIVITY_API_KEY || "").trim();
  const stats = { sent: 0, failed: 0 };

  async function send(event) {
    const body = JSON.stringify({ payload: {}, ...event });
    for (let attempt = 0; ; attempt++) {
      let status = 0;
      let detail = "";
      try {
        const res = await fetchImpl(url, {
          method: "POST",
          headers: { authorization: `Bearer ${key}`, "content-type": "application/json", "user-agent": "presign-guard" },
          body,
          signal: AbortSignal.timeout(10000),
        });
        if (res.ok) { stats.sent++; return (await res.json().catch(() => ({}))).eventId || null; }
        status = res.status;
        detail = (await res.text().catch(() => "")).slice(0, 200);
        if (status === 409) { stats.sent++; return null; } // already reported with this key
      } catch (err) { detail = err.message; }
      if ((status === 0 || status === 503) && attempt < retryMs.length) { await sleep(retryMs[attempt]); continue; }
      stats.failed++;
      log.error(`[activity] ${event.eventType} for ${event.actor} not reported: ${status || "network"} ${detail}`);
      return null;
    }
  }

  // A settled USDC payment on NEAR to presign-guard. Returns the report's promise (tests wait on it; the payment
  // does not). Nothing for our own payout account paying itself.
  function checkPaid({ payer, payTo, transaction, amount, asset, network }) {
    if (!key || !transaction || !ACTOR.test(String(payer)) || payer === payTo) return Promise.resolve(null);
    return send({ eventType: "check.paid", actor: payer, idempotencyKey: `${network}:${transaction}:paid`, payload: { network, transaction, asset, amount: String(amount ?? "") } });
  }

  return { enabled: Boolean(key), checkPaid, stats: () => ({ enabled: Boolean(key), ...stats }) };
}
