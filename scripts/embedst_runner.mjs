#!/usr/bin/env node
// embedst_runner.mjs - Headless (no-browser) extractor for embed.st / embedsports.
//
// Runs embed.st's own obfuscated bundle-jw.js + wasm-bindgen lock.js/lock.wasm
// inside a Node vm sandbox with stubbed DOM/fetch, and captures the .m3u8 URL
// that the WASM computes and fetches at runtime.
//
// Usage: node --experimental-vm-modules embedst_runner.mjs <embed_url> [--debug]
// Outputs JSON to stdout: {"m3u8": "...", "headers": {...}}
//
// Requires Node >= 18 (WebAssembly + native fetch). Must be run with
// --experimental-vm-modules because embed.st uses dynamic ESM import().

import fs from 'node:fs';
import vm from 'node:vm';

const DEBUG = process.env.EMBEDST_DEBUG === '1' || process.argv.includes('--debug');
function L(...a) { if (DEBUG) console.error('[embedst]', ...a); }

const EMBED = process.argv[2];
if (!EMBED) { console.error('usage: embedst_runner.mjs <embed_url>'); process.exit(2); }
const u = new URL(EMBED);
const ORIGIN = u.origin;
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36';

const realFetch = globalThis.fetch;
let capturedStreamUrl = null;

// ---------------------------------------------------------------------------
// DOM stubs (just enough for wasm-bindgen lock.js to run)
// ---------------------------------------------------------------------------
function stubEl(tag) {
  const o = { tagName: (tag || 'div').toUpperCase(), style: {}, dataset: {}, children: [],
    _attrs: {}, _listeners: {}, _id: '', _textContent: '', _innerHTML: '',
    parentNode: null, parentElement: null,
    clientWidth: 1920, clientHeight: 1080, offsetWidth: 1920, offsetHeight: 1080,
    src: '', href: '', onload: null, onerror: null, defer: false, async: false,
    muted: false, volume: 1, currentTime: 0, duration: 0 };
  Object.defineProperty(o, 'id', { get() { return o._id; }, set(v) { o._id = String(v); }, enumerable: true, configurable: true });
  Object.defineProperty(o, 'textContent', { get() { return o._textContent; }, set(v) { o._textContent = String(v ?? ''); }, enumerable: true, configurable: true });
  Object.defineProperty(o, 'innerHTML', { get() { return o._innerHTML; }, set(v) { o._innerHTML = String(v ?? ''); }, enumerable: true, configurable: true });
  o.setAttribute = (k, v) => { o._attrs[k] = String(v); if (k === 'id') o._id = String(v); };
  o.getAttribute = (k) => (k in o._attrs ? o._attrs[k] : (k === 'id' ? o._id : null));
  o.removeAttribute = (k) => { delete o._attrs[k]; };
  o.hasAttribute = (k) => k in o._attrs;
  o.appendChild = (c) => { if (c && typeof c === 'object') { o.children.push(c); try { c.parentNode = o; c.parentElement = o; } catch (e) {} } return c; };
  o.removeChild = (c) => { const i = o.children.indexOf(c); if (i >= 0) o.children.splice(i, 1); return c; };
  o.remove = () => { if (o.parentNode) { const i = o.parentNode.children.indexOf(o); if (i >= 0) o.parentNode.children.splice(i, 1); o.parentNode = null; } };
  o.insertBefore = (n) => { if (n) o.children.push(n); return n; };
  o.replaceChild = (n, old) => { const i = o.children.indexOf(old); if (i >= 0) o.children[i] = n; return old; };
  o.insertAdjacentHTML = (p, html) => { o._innerHTML += String(html ?? ''); };
  o.insertAdjacentElement = (p, el) => { if (el) o.children.push(el); return el; };
  o.insertAdjacentText = (p, t) => { o._textContent += String(t ?? ''); };
  o.cloneNode = () => stubEl(o.tagName.toLowerCase());
  o.contains = () => false; o.matches = () => false; o.closest = () => null;
  o.scrollIntoView = () => {};
  o.getBoundingClientRect = () => ({ left: 0, top: 0, right: 1920, bottom: 1080, width: 1920, height: 1080, x: 0, y: 0 });
  o.querySelector = () => null; o.querySelectorAll = () => [];
  o.getElementsByTagName = () => []; o.getElementsByClassName = () => [];
  o.classList = { _s: new Set(), add(v) { this._s.add(v); }, remove(v) { this._s.delete(v); }, contains(v) { return this._s.has(v); }, toggle(v) { if (this._s.has(v)) this._s.delete(v); else this._s.add(v); } };
  o.addEventListener = (ev, fn) => { (o._listeners[ev] = o._listeners[ev] || []).push(fn); };
  o.removeEventListener = () => {};
  o.dispatchEvent = () => true;
  o.click = () => {}; o.focus = () => {}; o.blur = () => {};
  o.play = () => Promise.resolve(); o.load = () => Promise.resolve(); o.pause = () => {};
  o.append = (...nodes) => { for (const n of nodes) o.children.push(n); };
  return o;
}
const _idRegistry = {};
const _bodyEl = stubEl('body');
const _headEl = stubEl('head');
const _htmlEl = stubEl('html');
const document = {
  body: _bodyEl, head: _headEl, documentElement: _htmlEl,
  createElement: (t) => stubEl(t),
  createTextNode: (t) => { const e = stubEl('#text'); e._textContent = String(t ?? ''); return e; },
  getElementById: (id) => { if (!_idRegistry[id]) { _idRegistry[id] = stubEl('div'); _idRegistry[id].id = id; } return _idRegistry[id]; },
  querySelector: (s) => { if (s === 'body') return _bodyEl; if (s === 'head') return _headEl; return stubEl('div'); },
  querySelectorAll: () => [], getElementsByTagName: () => [], getElementsByClassName: () => [],
  addEventListener() {}, removeEventListener() {}, cookie: '', readyState: 'complete', title: '', location: undefined,
};
const navigator = { userAgent: UA, platform: 'Win32', language: 'en', languages: ['en'], vendor: 'Google Inc.', sendBeacon: () => true, userAgentData: {}, plugins: [], mimeTypes: [] };
const location = { href: EMBED, protocol: u.protocol, host: u.host, hostname: u.hostname, port: u.port, pathname: u.pathname, search: u.search, hash: u.hash, origin: ORIGIN, toString() { return EMBED; }, reload() {}, replace() {}, assign() {} };
const _ls = {};
const localStorage = { getItem: k => _ls[k] ?? null, setItem: (k, v) => _ls[k] = String(v), removeItem: k => delete _ls[k], clear() {} };
const sessionStorage = { getItem: k => _ls['s_' + k] ?? null, setItem: (k, v) => _ls['s_' + k] = String(v), removeItem: k => delete _ls['s_' + k], clear() {} };

// ---------------------------------------------------------------------------
// fetch / Web APIs
// ---------------------------------------------------------------------------
const RawURL = URL;
function ResolvingURL(input, base) {
  if (base !== undefined) return new RawURL(input, base);
  try { return new RawURL(input); } catch (e) {
    try { return new RawURL(input, 'https://embed.st/js/wasm/'); } catch (e2) { throw e; }
  }
}
ResolvingURL.prototype = RawURL.prototype;
ResolvingURL.canParse = RawURL.canParse;

function resolveUrl(x) {
  if (typeof x === 'string' && !/^[a-zA-Z]+:/.test(x)) { try { return new RawURL(x, EMBED).href; } catch (e) {} }
  else if (x && typeof x === 'object' && typeof x.url === 'string' && !/^[a-zA-Z]+:/.test(x.url)) { try { x = new RawURL(x.url, EMBED).href; } catch (e) {} }
  return x;
}

const fetchImpl = async (url, opts) => {
  url = resolveUrl(url);
  const displayUrl = typeof url === 'string' ? url : (url && url.url) || String(url);
  L('FETCH', (opts && opts.method) || 'GET', displayUrl);
  // CAPTURE: first .m3u8 request URL is the manifest we want.
  if (typeof displayUrl === 'string' && displayUrl.includes('.m3u8') && !capturedStreamUrl) {
    capturedStreamUrl = displayUrl;
    L('CAPTURED', displayUrl);
    finish();
  }
  const headers = Object.assign({ 'User-Agent': UA, 'Referer': EMBED, 'Origin': ORIGIN }, (opts && opts.headers) || {});
  const resp = await realFetch(url, Object.assign({}, opts || {}, { headers }));
  L('FETCH-RESP', resp.status, displayUrl);
  return resp;
};

const XHR = function () {
  this._h = {};
  this.open = (m, uri) => { this._method = m; this._uri = uri; };
  this.send = async (body) => {
    const abs = /^\//.test(this._uri) ? ORIGIN + this._uri : this._uri;
    const hdrs = Object.assign({ 'User-Agent': UA, 'Referer': EMBED, 'Origin': ORIGIN }, this._h);
    try {
      const r = await realFetch(abs, { method: this._method || 'GET', headers: hdrs, body });
      const txt = await r.text();
      this.status = r.status; this.responseText = txt; this.response = txt; this.readyState = 4;
      if (this.onload) { try { this.onload.call(this, {}); } catch (e) {} }
      if (this.onreadystatechange) { try { this.onreadystatechange.call(this); } catch (e) {} }
    } catch (e) { this.status = 0; if (this.onerror) { try { this.onerror.call(this, e); } catch {} } }
  };
  this.setRequestHeader = (k, v) => { this._h[k] = v; };
  this.getResponseHeader = () => null; this.getAllResponseHeaders = () => '';
  this.addEventListener = (ev, fn) => { if (ev === 'load') this.onload = fn; if (ev === 'error') this.onerror = fn; if (ev === 'readystatechange') this.onreadystatechange = fn; };
  this.onload = null; this.onerror = null; this.onreadystatechange = null;
  this.withCredentials = false; this.status = 200; this.responseText = ''; this.response = '';
};

// ---------------------------------------------------------------------------
// vm context
// ---------------------------------------------------------------------------
const ctx = {
  console, setTimeout, clearTimeout, setInterval, clearInterval, setImmediate, clearImmediate,
  Buffer, URLSearchParams, URL: ResolvingURL, TextEncoder, TextDecoder,
  atob: s => Buffer.from(s, 'base64').toString('binary'),
  btoa: s => Buffer.from(s, 'binary').toString('base64'),
  fetch: fetchImpl, XMLHttpRequest: XHR, navigator, location, document, localStorage, sessionStorage,
  // Web / fetch APIs (Node native)
  Request: class RequestWrap extends globalThis.Request {
    constructor(input, init) {
      if (typeof input === 'string' && !/^[a-zA-Z]+:/.test(input)) { try { input = new RawURL(input, EMBED).href; } catch (e) {} }
      else if (input && typeof input === 'object' && typeof input.url === 'string' && !/^[a-zA-Z]+:/.test(input.url)) { try { input = new RawURL(input.url, EMBED).href; } catch (e) {} }
      super(input, init);
    }
  },
  Response: globalThis.Response,
  Headers: globalThis.Headers,
  FormData: globalThis.FormData,
  AbortController: globalThis.AbortController,
  AbortSignal: globalThis.AbortSignal,
  ReadableStream: globalThis.ReadableStream,
  Blob: globalThis.Blob,
  File: globalThis.File,
  TextEncoderStream: globalThis.TextEncoderStream,
  TextDecoderStream: globalThis.TextDecoderStream,
  WebAssembly: new Proxy(globalThis.WebAssembly, {
    get(t, k) {
      if (k === 'instantiate') return async function (a, b) {
        if (a && typeof a.arrayBuffer === 'function' && !(a instanceof ArrayBuffer) && typeof a.byteLength !== 'number') { a = await a.arrayBuffer(); }
        return t.instantiate(a, b);
      };
      if (k === 'instantiateStreaming') return async function (a, b) {
        if (a && typeof a.arrayBuffer === 'function') { a = await a.arrayBuffer(); return t.instantiate(a, b); }
        return t.instantiateStreaming(a, b);
      };
      return t[k];
    }
  }),
  queueMicrotask: (typeof queueMicrotask !== 'undefined') ? queueMicrotask : (fn) => Promise.resolve().then(fn),
  structuredClone: (typeof structuredClone !== 'undefined') ? structuredClone : (x) => JSON.parse(JSON.stringify(x)),
  MessageChannel: (typeof MessageChannel !== 'undefined') ? MessageChannel : function () { return { port1: { postMessage() {}, close() {} }, port2: { postMessage() {}, close() {} } }; },
  CustomEvent: function (t, o) { this.type = t; this.detail = (o && o.detail) || null; },
  Event: function (t) { this.type = t; },
  EventTarget: function () { this.addEventListener = function () {}; this.removeEventListener = function () {}; this.dispatchEvent = function () { return true; }; },
  requestIdleCallback: (fn) => setTimeout(() => fn({ didTimeout: false, timeRemaining: () => 50 }), 0),
  cancelIdleCallback: (id) => clearTimeout(id),
  Image: function () { return stubEl('img'); },
  Audio: function () { return stubEl('audio'); },
  Worker: function () { return { postMessage() {}, terminate() {}, onmessage: null, onerror: null, addEventListener() {}, removeEventListener() {} }; },
};
// Browser-type constructors so wasm `instanceof Window/Document` checks pass.
ctx.Window = function Window() {};
ctx.Document = function Document() {};
ctx.HTMLDocument = ctx.Document;
ctx.HTMLElement = function HTMLElement() {};
ctx.Node = function Node() {};
ctx.Element = function Element() {};
ctx.HTMLDivElement = function HTMLDivElement() {};
ctx.window = ctx; ctx.self = ctx; ctx.globalThis = ctx; ctx.global = ctx;
ctx.document.location = location;
ctx.crypto = globalThis.crypto;
ctx.performance = globalThis.performance;
// Browser window stubs the wasm probes for.
ctx.history = { pushState() {}, replaceState() {}, back() {}, forward() {}, go() {}, scrollRestoration: 'auto', state: null, length: 1 };
ctx.screen = { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040, colorDepth: 24, pixelDepth: 24, orientation: { type: 'landscape-primary', angle: 0 } };
ctx.matchMedia = (q) => ({ matches: false, media: q, onchange: null, addListener() {}, removeListener() {}, addEventListener() {}, removeEventListener() {}, dispatchEvent() { return false; } });
ctx.innerWidth = 1920; ctx.innerHeight = 1080; ctx.outerWidth = 1920; ctx.outerHeight = 1080; ctx.devicePixelRatio = 1;
ctx.scrollX = 0; ctx.scrollY = 0; ctx.pageXOffset = 0; ctx.pageYOffset = 0;
ctx.screenX = 0; ctx.screenY = 0; ctx.screenLeft = 0; ctx.screenTop = 0;
ctx.top = ctx; ctx.parent = ctx; ctx.frames = ctx; ctx.opener = null; ctx.closed = false;
ctx.confirm = () => true; ctx.alert = () => {}; ctx.prompt = () => null; ctx.focus = () => {}; ctx.blur = () => {};
ctx.addEventListener = () => {}; ctx.removeEventListener = () => {}; ctx.dispatchEvent = () => true; ctx.postMessage = () => {};
ctx.getComputedStyle = () => ({ getPropertyValue: () => '', getPropertyPriority: () => '', cssText: '' });
ctx.requestAnimationFrame = (cb) => 0; ctx.cancelAnimationFrame = () => {};

vm.createContext(ctx);
// vm.createContext resets the global's prototype; set it back inside the vm.
try { vm.runInContext('Object.setPrototypeOf(globalThis, Window.prototype); Object.setPrototypeOf(document, Document.prototype);', ctx); } catch (e) { L('setproto-err', e.message); }

process.on('unhandledRejection', (r) => { L('unhandled', r && r.message ? r.message : String(r)); });

// ---------------------------------------------------------------------------
// Fetch bundle-jw.js, extract the appended program (the Function() body)
// ---------------------------------------------------------------------------
const modCache = {};
async function fetchText(url) {
  if (modCache[url]) return modCache[url];
  const r = await realFetch(url, { headers: { 'User-Agent': UA, 'Referer': EMBED } });
  if (!r.ok) throw new Error('fetch ' + url + ' -> ' + r.status);
  const t = await r.text();
  modCache[url] = t;
  return t;
}

function extractProgram(bundle) {
  const HEAD = 'Function("OoS1vi",';
  let i = bundle.indexOf(HEAD) + HEAD.length;
  if (bundle[i] !== '\'') throw new Error('program literal not found');
  let j = i + 1, out = '';
  while (j < bundle.length) {
    const c = bundle[j];
    if (c === '\\') { out += '\\' + bundle[j + 1]; j += 2; continue; }
    if (c === '\'') break;
    out += c; j++;
  }
  const literal = "'" + out + "'";
  return vm.runInContext('(' + literal + ')', ctx);
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------
const optsObj = '{get define(){return typeof define!=="undefined"?define:undefined},get module(){return typeof module!=="undefined"?module:undefined},get angular(){return typeof angular!=="undefined"?angular:undefined},get global(){return globalThis},get F6P7kK(){return typeof exports!=="undefined"?exports:undefined},get TW8AKss(){return typeof define},get G7Q5ExK(){return typeof module},get kzlLPB(){return typeof angular},get Uy7o_GN(){return typeof exports}}';

let finished = false;
function finish() {
  if (finished) return;
  finished = true;
  if (capturedStreamUrl) {
    const out = { m3u8: capturedStreamUrl, headers: { 'User-Agent': UA, 'Referer': EMBED, 'Origin': ORIGIN } };
    process.stdout.write(JSON.stringify(out));
    process.exit(0);
  } else {
    process.stdout.write(JSON.stringify({ error: 'no m3u8 captured' }));
    process.exit(1);
  }
}

(async () => {
  try {
    const bundleUrl = ORIGIN + '/js/bundle-jw.js';
    const bundle = await fetchText(bundleUrl);
    const programSource = extractProgram(bundle);
    L('program len', programSource.length);

    const runner = '(function(OoS1vi){\n' + programSource + '\n})(' + optsObj + ')';

    vm.runInContext(runner, ctx, {
      timeout: 25000,
      filename: 'program.js',
      importModuleDynamically: async (spec) => {
        L('IMPORT', spec);
        try {
          if (!spec.startsWith('http')) { L('non-http import', spec); return new vm.SourceTextModule('export{}', { context: ctx }); }
          const src = await fetchText(spec);
          const mod = new vm.SourceTextModule(src, { context: ctx, identifier: 'embedst_mod' });
          await mod.link(async () => new vm.SourceTextModule('export{}', { context: ctx }));
          await mod.evaluate();
          return mod;
        } catch (e) { L('IMPORT-ERR', e.message); return new vm.SourceTextModule('export{}', { context: ctx }); }
      }
    });
  } catch (e) {
    L('RUN-ERR', e && e.message);
  }
  // Wait a bit for async wasm continuation to fire the m3u8 fetch.
  setTimeout(() => finish(), 8000);
})();
