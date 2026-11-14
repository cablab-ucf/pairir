// The page: inputs to the worker and back. Secrets reach the DOM as text only.
// A blob worker keeps this page's CSP, its <meta> included, on any host; a
// worker from a URL has only its own response's headers.
const src = `import ${JSON.stringify(new URL('worker.js', location.href).href)};`;
const w = new Worker(URL.createObjectURL(new Blob([src], { type: 'text/javascript' })), { type: 'module' });
const calls = new Map();
let n = 0;
// A worker that stopped (a panic, out of memory) fails every call, said.
let dead;
w.onerror = (e) => {
  dead = new Error(`the worker stopped${e.message ? ` (${e.message})` : ''}: reload`);
  calls.forEach((c) => c.no(dead));
  calls.clear();
};
w.onmessage = ({ data }) => {
  const c = calls.get(data.id);
  if ('code' in data) return c.code(data.code);
  calls.delete(data.id);
  'err' in data ? c.no(new Error(data.err)) : c.ok(data.ok);
};
const call = (op, args, code) => new Promise((ok, no) => {
  if (dead) return no(dead);
  calls.set(++n, { ok, no, code });
  // Moved, not copied: the page keeps no copy of a secret it sends.
  w.postMessage({ id: n, op, args }, args.filter((a) => a instanceof Uint8Array).map((a) => a.buffer));
});

const $ = (id) => document.getElementById(id);
const enc = (s) => new TextEncoder().encode(s);
const dec = (b) => { const s = new TextDecoder().decode(b); b.fill(0); return s; };
const app = () => $('app').value;
const pw = (id) => $(id).value || undefined;
const say = (id, s) => { $(id).textContent = s; };
// Whoever has the code or the QR text may guess its password offline.
const strong = (id) => {
  const p = pw(id);
  if (p && p.length < 16) throw new Error('a password under 16 characters can be guessed offline: generate one');
  return p;
};
const busy = async (b, f) => {
  b.disabled = true;
  try { await f(); } catch (e) { say(b.id[0] + '-out', e.message); } finally { b.disabled = false; }
};

$('g-gen').onclick = async () => { $('g-pw').value = await call('password', []); };
$('q-gen').onclick = async () => { $('q-pw').value = await call('password', []); };

$('g-go').onclick = () => busy($('g-go'), async () => {
  const p = strong('g-pw');
  say('g-code', ''); say('g-out', p ? 'locking (Argon2)...' : 'reaching the relay...');
  const end = await call('give', [app(), enc($('g-secret').value), p], (code) => {
    say('g-code', code);
    let s = 60;
    const t = setInterval(() => { if (--s < 0 || $('g-code').textContent !== code) clearInterval(t); else say('g-out', `${s} s`); }, 1000);
    $('g-secret').value = '';
  }).finally(() => say('g-code', ''));
  say('g-out', { Taken: 'Taken.', Spent: 'Spent: someone used the code wrongly. Give again; tell the taker.', Expired: 'Expired: nobody took it.' }[end] ?? end);
});

$('t-go').onclick = () => busy($('t-go'), async () => {
  say('t-out', 'taking...'); $('t-secret').value = '';
  $('t-secret').value = dec(await call('take', [app(), $('t-code').value, pw('t-pw')]));
  say('t-out', 'Taken.');
});
$('t-copy').onclick = () => navigator.clipboard.writeText($('t-secret').value);
// All of it: every field, the worker and its memory.
$('t-clear').onclick = () => { $('t-secret').value = ''; location.reload(); };

$('q-seal').onclick = () => busy($('q-seal'), async () => {
  say('q-out', 'sealing (Argon2)...');
  const text = await call('seal_qr', [app(), enc($('q-secret').value), strong('q-pw') ?? '']);
  $('q-img').src = 'data:image/svg+xml,' + encodeURIComponent(await call('qr_svg', [text]));
  $('q-secret').value = text;
  say('q-out', 'Sealed: the code, or the text above.');
});
$('q-open').onclick = () => busy($('q-open'), async () => {
  say('q-out', 'opening (Argon2)...'); $('q-img').removeAttribute('src');
  $('q-secret').value = dec(await call('open_qr', [app(), $('q-secret').value, $('q-pw').value]));
  say('q-out', 'Opened.');
});
