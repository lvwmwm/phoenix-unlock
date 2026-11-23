import { IOS_DEFAULT_IPA, IOS_DEFAULT_NAME, PROXY as DEFAULT_PROXY, VERIFIED } from './config.js';
import { ABIS, abiOf, buildPatchedApk } from './lib/apk.js';
import { BOOTSTRAP_URL, bundleScripts, GADGET_URLS, gunzip } from './lib/frida.js';
import { keysFrom } from './lib/sign.js';
import { readZip } from './lib/zip.js';
import { buildPatchedIpa } from './lib/ios.js';

const TRACKER = 'https://tracker.vendetta.rocks';
const PROXY = (new URLSearchParams(location.search).get('proxy') ?? DEFAULT_PROXY).replace(/\/$/, '');
const DENSITIES = [['ldpi', 120], ['mdpi', 160], ['hdpi', 240], ['xhdpi', 320], ['xxhdpi', 480], ['xxxhdpi', 640]];
const LANGS = ['en', 'ar', 'bg', 'cs', 'da', 'de', 'el', 'es', 'fi', 'fr', 'hi', 'hr', 'hu', 'id', 'it', 'ja', 'ko', 'lt', 'nl', 'no', 'pl', 'pt', 'ro', 'ru', 'sv', 'th', 'tr', 'uk', 'vi', 'zh'];
const ABI = 'arm64-v8a'; // the only ABI with a loader build (web/plugins)
const $ = (id) => document.getElementById(id);

// --- setup ------------------------------------------------------------------------------
const dpi = Math.round((window.devicePixelRatio || 1) * 160);
const bestDensity = (DENSITIES.find(([, d]) => d >= dpi) || DENSITIES.at(-1))[0];
$('dpi').innerHTML = DENSITIES.map(([n, d]) => `<option value="${n}" ${n === bestDensity ? 'selected' : ''}>${n} (${d})</option>`).join('');
const myLang = (navigator.language || 'en').slice(0, 2).toLowerCase();
$('lang').innerHTML = ['none', ...LANGS].map((l) => `<option ${l === (LANGS.includes(myLang) ? myLang : 'en') ? 'selected' : ''}>${l}</option>`).join('');

function setVersions(latest) {
  const vs = [...new Set([...VERIFIED, ...(latest ? [latest] : [])])].sort((a, b) => b - a);
  $('ver').innerHTML = vs.map((v) => `<option value="${v}" ${v === VERIFIED[0] ? 'selected' : ''}>${v}${VERIFIED.includes(v) ? ' (verified)' : ' (latest alpha, untested)'}</option>`).join('');
}
setVersions();
fetch(`${TRACKER}/tracker/index`).then((r) => r.json()).then((j) => setVersions(j.latest?.alpha)).catch(() => {});

// --- fixed keys for every build (the patcher's, see lib/sign.js), so each patched APK installs as an update ---
async function fetchOk(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res;
}
const fetchBytes = async (url) => new Uint8Array(await (await fetchOk(url)).arrayBuffer());

// --- progress UI -------------------------------------------------------------------------
function step(label) {
  const li = document.createElement('li');
  li.innerHTML = `<span></span><span class="state">waiting</span><span class="bar"><i></i></span>`;
  li.firstChild.textContent = label;
  $('steps').append(li);
  const st = li.querySelector('.state'), bar = li.querySelector('i');
  return {
    progress(f, text) { bar.style.width = `${Math.round(f * 100)}%`; st.textContent = text ?? `${Math.round(f * 100)}%`; },
    done(text = 'done') { li.className = 'done'; bar.style.width = '100%'; st.textContent = text; },
    fail(text = 'failed') { li.className = 'fail'; st.textContent = text; },
  };
}
const log = (s) => { $('log').textContent += s + '\n'; $('log').scrollTop = 1e9; };
const mb = (n) => `${(n / 1048576).toFixed(1)} MB`;

// --- downloads ---------------------------------------------------------------------------
async function download(vc, split, optional) {
  const s = step(`Download ${split}`);
  const res = await fetch(`${PROXY}/tracker/download/${vc}/${split}`);
  if (!res.ok) {
    if (optional) { s.done('not available'); return null; }
    s.fail(`HTTP ${res.status}`); throw new Error(`${split}: HTTP ${res.status}`);
  }
  const total = +res.headers.get('Content-Length') || 0;
  const reader = res.body.getReader();
  let buf = new Uint8Array(total || 1 << 24), n = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (n + value.length > buf.length) { const b = new Uint8Array(Math.max(buf.length * 2, n + value.length)); b.set(buf.subarray(0, n)); buf = b; }
    buf.set(value, n); n += value.length;
    s.progress(total ? n / total : 0, total ? `${mb(n)} / ${mb(total)}` : mb(n));
  }
  s.done(mb(n));
  return buf.length === n ? buf : buf.slice(0, n);
}

function splitNames() {
  const lang = $('lang').value;
  return { abi: ABIS[ABI].split, density: `config.${$('dpi').value}`, lang: lang === 'none' ? null : `config.${lang}` };
}

async function patchAndOffer(vc, base, abi, configs) {
  const plugins = await pluginInput();
  const frida = $('frida-on').checked ? await fridaInput() : null;
  const s = step('Patch and sign');
  s.progress(0.5, 'working…');
  const packageName = chosenPackage(), side = packageName !== 'com.discord';
  const libraries = !plugins ? [] : await Promise.all(Object.entries(ABIS[ABI].libs).map(async ([name, url]) => ({ name, bytes: await fetchBytes(url) })));
  const keys = keysFrom(await (await fetchOk('signing-key.json')).json());
  const parts = await buildPatchedApk({ base, abi, configs, keys, libraries, plugins, frida, packageName, label: side ? 'Discord Phoenix' : null, log });
  const blob = new Blob(parts, { type: 'application/vnd.android.package-archive' });
  s.done(mb(blob.size));
  $('note-side').hidden = !side; $('note-replace').hidden = side;
  const a = $('dl');
  a.href = URL.createObjectURL(blob);
  a.download = `discord-${vc}-phoenix-unlock${side ? '-side' : ''}.apk`;
  $('result').hidden = false;
  a.scrollIntoView({ behavior: 'smooth' });
}

function fail(e) {
  console.error(e);
  $('err').textContent = `Something went wrong: ${e.message || e}`;
  $('err').hidden = false;
  $('go').disabled = false;
}

// The tracker only mirrors some density splits per build (356207: hdpi and xxhdpi), so fall back
// to the nearest one it has. Any density works; Android scales the drawables.
async function downloadDensity(vc) {
  const want = DENSITIES.find(([n]) => n === $('dpi').value)[1];
  const order = [...DENSITIES].sort((a, b) => Math.abs(a[1] - want) - Math.abs(b[1] - want) || b[1] - a[1]);
  for (const [n] of order) {
    const buf = await download(vc, `config.${n}`, true);
    if (buf) return buf;
  }
  throw new Error('this build has no density split on the tracker');
}

// --- plugin runtime: the bundled plugins (web/plugins, tools/bundle-plugins.mjs), picked .js files and the editor ---
($('runtime').onchange = () => { $('jsp').hidden = !$('runtime').checked; })(); // browsers may restore the box on reload
fetchOk('plugins/index.json').then((r) => r.json()).then((list) => {
  for (const p of list) {
    const l = document.createElement('label');
    l.className = 'plugin';
    l.innerHTML = '<input type="checkbox"><b></b><span></span>';
    l.querySelector('input').value = p.name;
    l.querySelector('input').checked = p.name !== 'example'; // a demo of the API: opt-in
    l.querySelector('b').textContent = p.name;
    l.querySelector('span').textContent = p.description;
    if (p.warning) {
      const w = document.createElement('small');
      w.className = 'warn';
      w.textContent = `\u26A0 ${p.warning}`;
      l.append(w);
    }
    $('jsp-bundled').append(l);
  }
}).catch(fail);
/** [{name, source}], or null with the runtime off */
async function pluginInput() {
  if (!$('runtime').checked) return null;
  const picked = [...document.querySelectorAll('#jsp-bundled input:checked')].map((i) => i.value);
  const plugins = await Promise.all(picked.map(async (name) => ({ name, source: await (await fetchOk(`plugins/${name}.js`)).text() })));
  plugins.push(...await Promise.all([...$('jsp-files').files].map(async (f) => ({ name: f.name.replace(/\.[^.]*$/, ''), source: await f.text() }))));
  const code = $('jsp-code').value.trim();
  if (code) plugins.push({ name: 'my-plugin', source: code });
  return plugins;
}

// Frida: Frida scripts from picked files and the editor (prefilled with the example), bundled into one script
($('frida-on').onchange = () => { $('frida').hidden = !$('frida-on').checked; })();
fetch('plugins/frida-example.js').then((r) => r.text()).then((t) => { if (!$('frida-code').value) $('frida-code').value = t; }).catch(() => {});
async function fridaInput() {
  const scripts = await Promise.all([...$('frida-files').files].map(async (f) => ({ name: f.name, code: await f.text() })));
  const code = $('frida-code').value.trim();
  if (code) scripts.push({ name: 'editor.js', code });
  const script = bundleScripts(scripts, await (await fetchOk(BOOTSTRAP_URL)).text());
  const s = step('Download frida-gadget');
  const res = await fetch(GADGET_URLS[ABI]);
  if (!res.ok) { s.fail(`HTTP ${res.status}`); throw new Error(`frida-gadget: HTTP ${res.status}`); }
  const gadget = await gunzip(new Uint8Array(await res.arrayBuffer()));
  s.done(mb(gadget.length));
  log(`Frida: ${scripts.map((x) => x.name).join(', ')}`);
  return { gadget, script };
}

// --- package name: "Replace" keeps com.discord, "Next to" uses the editable name ---------
const PKG_RE = /^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$/;
const chosenPackage = () => ($('mode').value === 'replace' ? 'com.discord' : $('pkg').value.trim());
function checkPackage() {
  const p = $('pkg').value.trim();
  const bad = $('mode').value === 'side' && (!PKG_RE.test(p) || p === 'com.discord' || p.length > 127);
  $('pkg').setAttribute('aria-invalid', bad);
  return !bad;
}
$('mode').onchange = () => { $('pkg-row').hidden = $('mode').value === 'replace'; checkPackage(); };
$('pkg').oninput = checkPackage;

$('go').onclick = async () => {
  if (!checkPackage()) {
    $('err').textContent = 'Package name must look like com.example.app (letters, digits, _; at least two parts) and differ from com.discord.';
    $('err').hidden = false; $('pkg').focus();
    return;
  }
  const vc = +$('ver').value;
  $('go').disabled = true; $('err').hidden = true; $('result').hidden = true;
  $('steps').textContent = ''; $('log').textContent = ''; $('progress').hidden = false;
  if (!PROXY) return showManual(vc);
  try {
    const n = splitNames();
    const base = await download(vc, 'base');
    const abi = await download(vc, n.abi);
    const configs = [await downloadDensity(vc), n.lang && (await download(vc, n.lang, true))].filter(Boolean);
    await patchAndOffer(vc, base, abi, configs);
    $('go').disabled = false;
  } catch (e) {
    if (e instanceof TypeError) { log(`download blocked (${e.message}); switching to manual mode`); return showManual(vc); }
    fail(e);
  }
};

// --- manual mode: user downloads the splits, we tell them apart by content ---------------
function showManual(vc) {
  const n = splitNames();
  $('links').innerHTML = ['base', n.abi, n.density, n.lang].filter(Boolean)
    .map((s) => `<li><a href="${TRACKER}/tracker/download/${vc}/${s}" target="_blank" rel="noopener">${s}.apk</a></li>`).join('');
  $('manual').hidden = false;
  $('files').onchange = async (ev) => {
    try {
      const found = { configs: [] };
      for (const f of ev.target.files) {
        const u8 = new Uint8Array(await f.arrayBuffer());
        const entries = readZip(u8), names = entries.map((e) => e.name), abi = abiOf(entries);
        if (names.includes('classes.dex')) found.base = u8;
        else if (abi) found.abi = u8;
        else if (names.includes('resources.arsc')) found.configs.push(u8);
        log(`${f.name}: ${names.includes('classes.dex') ? 'base' : abi ? `native libs (${abi})` : names.some((x) => x.startsWith('lib/')) ? 'native libs (unsupported CPU, ignored)' : 'config split'}`);
      }
      if (!found.base || !found.abi) throw new Error('need at least base and config.arm64_v8a');
      await patchAndOffer(vc, found.base, found.abi, found.configs);
      $('go').disabled = false;
    } catch (e) { fail(e); }
  };
}

// --- iOS tab ------------------------------------------------------------------------------
for (const t of document.querySelectorAll('.tab')) {
  t.onclick = () => {
    for (const x of document.querySelectorAll('.tab')) x.classList.toggle('active', x === t);
    $('android').hidden = t.dataset.tab !== 'android';
    $('ios').hidden = t.dataset.tab !== 'ios';
  };
}

function iosStep(label) {
  const li = document.createElement('li');
  li.innerHTML = `<span></span><span class="state">waiting</span><span class="bar"><i></i></span>`;
  li.firstChild.textContent = label;
  $('ios-steps').append(li);
  const st = li.querySelector('.state'), bar = li.querySelector('i');
  return {
    progress(f, text) { bar.style.width = `${Math.round(f * 100)}%`; st.textContent = text ?? `${Math.round(f * 100)}%`; },
    done(text = 'done') { li.className = 'done'; bar.style.width = '100%'; st.textContent = text; },
    fail(text = 'failed') { li.className = 'fail'; st.textContent = text; },
  };
}
const iosLog = (s) => { $('ios-log').textContent += s + '\n'; $('ios-log').scrollTop = 1e9; };

/** Read the picked file, or stream the bundled decrypted IPA as a fallback. */
async function iosInput(s) {
  const file = $('ios-file').files[0];
  if (file) {
    s.progress(0.1, 'reading…');
    const u8 = new Uint8Array(await file.arrayBuffer());
    s.done(mb(u8.length));
    return { u8, name: file.name.replace(/\.ipa$/i, '') };
  }
  if (!IOS_DEFAULT_IPA) throw new Error('Pick a decrypted .ipa first.');
  iosLog(`No file picked — using ${IOS_DEFAULT_NAME}.`);
  const res = await fetch(IOS_DEFAULT_IPA);
  if (!res.ok) throw new Error(`${IOS_DEFAULT_IPA}: HTTP ${res.status}`);
  const total = +res.headers.get('Content-Length') || 0;
  const reader = res.body.getReader();
  let buf = new Uint8Array(total || 1 << 24), n = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (n + value.length > buf.length) {
      const b = new Uint8Array(Math.max(buf.length * 2, n + value.length));
      b.set(buf.subarray(0, n)); buf = b;
    }
    buf.set(value, n); n += value.length;
    s.progress(total ? n / total : 0, total ? `${mb(n)} / ${mb(total)}` : mb(n));
  }
  s.done(mb(n));
  return { u8: buf.length === n ? buf : buf.slice(0, n), name: 'discord-357.0-unlocked' };
}

$('ios-go').onclick = async () => {
  $('ios-go').disabled = true;
  $('ios-err').hidden = true;
  $('ios-result').hidden = true;
  $('ios-steps').textContent = '';
  $('ios-log').textContent = '';
  $('ios-progress').hidden = false;
  try {
    const { u8, name } = await iosInput(iosStep('Read IPA'));
    const patch = iosStep('Patch PhoenixFatClient');
    patch.progress(0.5, 'working…');
    const parts = await buildPatchedIpa(u8, iosLog);
    patch.done('2 evaluators + staff experiments patched');

    const blob = new Blob(parts, { type: 'application/octet-stream' });
    const a = $('ios-dl');
    a.href = URL.createObjectURL(blob);
    a.download = name + '-unlocked.ipa';
    $('ios-size').textContent = `Patched IPA: ${mb(blob.size)}.`;
    $('ios-result').hidden = false;
    a.scrollIntoView({ behavior: 'smooth' });
  } catch (e) {
    console.error(e);
    $('ios-err').textContent = `Something went wrong: ${e.message || e}`;
    $('ios-err').hidden = false;
  } finally {
    $('ios-go').disabled = false;
  }
};
