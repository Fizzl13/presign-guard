// This process's memory for /health, like x402 Doctor's and the wallet server's, so a leak shows before Render stops
// the server: the Starter plan has 512 MB, and V8 gives up ("heap out of memory", exit 134) at heap_limit_mb, which
// can sit well below that (268 MB without NODE_OPTIONS). uptime_s shows a restart.
import { getHeapStatistics } from "node:v8";

export function memoryStatus() {
  const { rss, heapUsed, heapTotal, external } = process.memoryUsage();
  const mb = (n) => Math.round(n / 1048576);
  return {
    memory: { rss_mb: mb(rss), heap_mb: mb(heapUsed), heap_total_mb: mb(heapTotal), heap_limit_mb: mb(getHeapStatistics().heap_size_limit), external_mb: mb(external) },
    uptime_s: Math.round(process.uptime()),
  };
}
