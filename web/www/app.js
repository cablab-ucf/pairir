// The page: inputs to the worker and back. Secrets reach the DOM as text only.
const w = new Worker('worker.js', { type: 'module' });
const calls = new Map();
let n = 0;
w.onmessage = ({ data }) => {
  const c = calls.get(data.id);
  if ('code' in data) return c.code(data.code);
  calls.delete(data.id);
  'err' in data ? c.no(new Error(data.err)) : c.ok(data.ok);
};
const call = (op, args, code) => new Promise((ok, no) => {
  calls.set(++n, { ok, no, code });
  w.postMessage({ id: n, op, args });
});

const $ = (id) => document.getElementById(id);
const enc = (s) => new TextEncoder().encode(s);
const dec = (b) => new TextDecoder().decode(b);
const app = () => $('app').value;
const pw = (id) => $(id).value || undefined;
const say = (id, s) => { $(id).textContent = s; };
const busy = async (b, f) => {
  b.disabled = true;
  try { await f(); } catch (e) { say(b.id[0] + '-out', e.message); } finally { b.disabled = false; }
};

$('g-gen').onclick = async () => { $('g-pw').value = await call('password', []); };
$('q-gen').onclick = async () => { $('q-pw').value = await call('password', []); };

$('g-go').onclick = () => busy($('g-go'), async () => {
  say('g-code', ''); say('g-out', pw('g-pw') ? 'locking (Argon2)...' : 'reaching the relay...');
  const end = await call('give', [app(), enc($('g-secret').value), pw('g-pw')], (code) => {
    say('g-code', code);
    let s = 60;
    const t = setInterval(() => { if (--s < 0 || $('g-code').textContent !== code) clearInterval(t); else say('g-out', `${s} s`); }, 1000);
    $('g-secret').value = '';
  });
  say('g-code', '');
  say('g-out', { Taken: 'Taken.', Spent: 'Spent: someone used the code wrongly. Give again; tell the taker.', Expired: 'Expired: nobody took it.' }[end] ?? end);
});

$('t-go').onclick = () => busy($('t-go'), async () => {
  say('t-out', 'taking...'); $('t-secret').value = '';
  $('t-secret').value = dec(await call('take', [app(), $('t-code').value, pw('t-pw')]));
  say('t-out', 'Taken.');
});
$('t-copy').onclick = () => navigator.clipboard.writeText($('t-secret').value);
$('t-clear').onclick = () => { $('t-secret').value = ''; say('t-out', ''); };

$('q-seal').onclick = () => busy($('q-seal'), async () => {
  say('q-out', 'sealing (Argon2)...');
  const text = await call('seal_qr', [app(), enc($('q-secret').value), $('q-pw').value]);
  $('q-img').src = 'data:image/svg+xml,' + encodeURIComponent(await call('qr_svg', [text]));
  $('q-secret').value = text;
  say('q-out', 'Sealed: the code, or the text above.');
});
$('q-open').onclick = () => busy($('q-open'), async () => {
  say('q-out', 'opening (Argon2)...'); $('q-img').removeAttribute('src');
  $('q-secret').value = dec(await call('open_qr', [app(), $('q-secret').value, $('q-pw').value]));
  say('q-out', 'Opened.');
});
