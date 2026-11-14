// pairir off the page's thread (Argon2 takes seconds). Calls: {id, op, args};
// answers: {id, code} (give's code), then {id, ok} or {id, err}.
import init, * as p from './pkg/pairir_web.js';

const ready = init();
const ops = new Set(['give', 'take', 'password', 'seal_qr', 'open_qr', 'qr_svg']);

onmessage = async ({ data: { id, op, args } }) => {
  try {
    await ready;
    if (!ops.has(op)) throw new Error(`no op ${op}`);
    const r = op === 'give'
      ? await p.give(...args, (code) => postMessage({ id, code }))
      : await p[op](...args);
    postMessage({ id, ok: r }, r instanceof Uint8Array ? [r.buffer] : []);
  } catch (e) {
    postMessage({ id, err: String(e?.message ?? e) });
  }
};
