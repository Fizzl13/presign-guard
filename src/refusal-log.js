// Refusal counts across restarts (src/refusal.js): the counted reports of presign-guard's refusal endpoint go to a small
// usage-log service of their own (events/presign-refusals/) and are read back when the server starts, so a deploy or
// restart no longer empties the public counts at /.well-known/x402-refusal. The same as x402-doctor's lib/refusal-log.js.
//
// A line holds only what the counts need: the route the seller declares, the reason, signed or not, and the report's key
// (a sha256 of the exact report, so a report posted again after a restart still counts once). Never the URL as the
// buyer sent it, nothing about the buyer.
//
// Written at most once a minute and with no shutdown handler of its own (the main log has one), so a report counted in
// the minute before a restart can be missing. Read with a usage reader of its own.
import usageLog from "./usage-log.cjs";
import usageReader from "./usage-reader.cjs";

export const ROUTE = "refusal counted";

// { record, history } for createRefusalRoutes. log / reader: stand-ins for tests.
export function createRefusalLog({ service, env = process.env, log = null, reader = null, days = 30, now = () => Date.now() } = {}) {
  if (!service) throw new Error("createRefusalLog needs the usage-log service name");
  const writer = log || usageLog.createUsageLog({ service, env, exitOnSignal: false, flushDelayMs: 60 * 1000 });
  const source = reader || usageReader.createUsageReader({ env });
  return {
    record(report, { signer = null, key } = {}) {
      writer.record({ route: ROUTE, via: "api", input: { route: report.resource, reason: report.reason, signed: Boolean(signer), key }, result: { counted: true } });
    },
    // The reports counted before this process started (events it wrote itself come later and are left out); null
    // when there is no log to read, so GET keeps saying since_restart: true.
    async history() {
      if (!source || !source.configured) return null;
      const started = new Date(now()).toISOString();
      const { events = [] } = await source.load({ days, service, max: 50000 });
      return events.filter((e) => e && e.route === ROUTE && e.input && e.t < started)
        .map((e) => ({ at: e.t, resource: e.input.route, reason: e.input.reason, signed: e.input.signed === true, key: e.input.key }));
    },
  };
}
