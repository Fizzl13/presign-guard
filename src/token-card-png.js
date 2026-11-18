// The share card as a PNG (GET /v/token/<link>/card.png): X/Twitter and many chat apps don't preview an SVG og:image.
//
// The SVG of src/token-share.js's shareCard, rendered by resvg compiled to WebAssembly (@resvg/resvg-wasm, pinned):
// no native dependency, so `npm ci` on Render needs nothing else. The wasm is loaded once, on the first card. resvg
// has no system fonts here: the card's text is set in Inter (assets/fonts, Latin only, OFL; see its OFL.txt), which
// stands in for the SVG's system-ui/sans-serif. Characters outside Latin (a token named in emoji or CJK) are left out.
//
// Bounds: the link is at most 2,400 characters and shareCard clips every string, so the SVG is small; one that is
// not is refused before rendering. The output is always 1200x630 (3 MB of pixels while rendering, ~40 KB of PNG).
// Rendering is synchronous and takes tens of milliseconds; a small LRU keyed by the link keeps repeat previews
// (every chat app fetches the image itself) from rendering again.

import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { initWasm, Resvg } from "@resvg/resvg-wasm";

export const CARD_WIDTH = 1200;
export const CARD_HEIGHT = 630;
const MAX_SVG_CHARS = 32 * 1024;
const SLOW_MS = 500;

const FONTS = ["Inter-Regular.otf", "Inter-Bold.otf"].map((f) => new URL(`../assets/fonts/${f}`, import.meta.url));
const WASM = createRequire(import.meta.url).resolve("@resvg/resvg-wasm/index_bg.wasm");

let ready = null;
// Once per process; a failed load is tried again on the next card.
function load() {
  ready ??= (async () => {
    const [wasm, ...fonts] = await Promise.all([readFile(WASM), ...FONTS.map((f) => readFile(f))]);
    await initWasm(wasm);
    return fonts.map((b) => new Uint8Array(b));
  })().catch((err) => { ready = null; throw err; });
  return ready;
}

// SVG text to PNG bytes (a Buffer), 1200x630.
export async function renderPng(svg) {
  if (typeof svg !== "string" || svg.length > MAX_SVG_CHARS) throw new Error("card SVG too large to render");
  const fontBuffers = await load();
  const resvg = new Resvg(svg, {
    fitTo: { mode: "width", value: CARD_WIDTH },
    font: { fontBuffers, defaultFontFamily: "Inter", sansSerifFamily: "Inter" },
  });
  try {
    const image = resvg.render();
    try {
      if (image.width !== CARD_WIDTH || image.height !== CARD_HEIGHT) throw new Error(`rendered ${image.width}x${image.height}, not ${CARD_WIDTH}x${CARD_HEIGHT}`);
      return Buffer.from(image.asPng());
    } finally { image.free(); }
  } finally { resvg.free(); }
}

// A small least-recently-used cache: a Map keeps insertion order, so the first key is the oldest.
export function createLru(max = 200) {
  const map = new Map();
  return {
    get(key) {
      if (!map.has(key)) return undefined;
      const value = map.get(key);
      map.delete(key);
      map.set(key, value);
      return value;
    },
    set(key, value) {
      map.delete(key);
      map.set(key, value);
      while (map.size > max) map.delete(map.keys().next().value);
    },
    get size() { return map.size; },
  };
}

// render(key, svg) -> PNG, from the cache when this key was rendered before. The key is the verified share link.
export function createPngCards({ render = renderPng, max = 200 } = {}) {
  const cache = createLru(max);
  return async (key, svg) => {
    const hit = cache.get(key);
    if (hit) return hit;
    const started = performance.now();
    const png = await render(svg);
    const ms = performance.now() - started;
    if (ms > SLOW_MS) console.warn(`[token-share] slow PNG card: ${Math.round(ms)} ms`);
    cache.set(key, png);
    return png;
  };
}
