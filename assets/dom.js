// JS-side DOM shim.
//
// The real DOM tree lives in Rust. This file only builds a wrapper so QuickJS
// can see it, exposing `__f1host` — callbacks down into Rust. All reads/writes
// go through it, so there is no second source of truth.
(function () {
  'use strict';

  const H = globalThis.__f1host; // installed by Rust before this script runs

  class F1Node {
    constructor(id) { this.__id = id; }
    get nodeType() { return H.name(this.__id) === '#text' ? 3 : 1; }
    get nodeName() { return H.name(this.__id); }
    get tagName() { return H.name(this.__id).toUpperCase(); }
    get parentNode() { const p = H.parent(this.__id); return p < 0 ? null : new F1Node(p); }
    get parentElement() { const p = H.parent(this.__id); return p < 0 ? null : new F1Node(p); }
    get children() { return H.children(this.__id).map((i) => new F1Node(i)); }
    get childNodes() { return this.children; }
    get firstChild() { const c = this.children; return c[0] || null; }
    get nextSibling() {
      const p = this.parentNode; if (!p) return null;
      const s = p.children; const i = s.indexOf(this);
      return i >= 0 && i + 1 < s.length ? s[i + 1] : null;
    }
    get attributes() {
      const out = [];
      for (const [k, v] of H.attrs(this.__id)) out.push({ name: k, value: v });
      return out;
    }
    getAttribute(n) { const v = H.attr(this.__id, n); return v === null ? undefined : v; }
    hasAttribute(n) { return H.attr(this.__id, n) !== null; }
    setAttribute(n, v) { H.setAttr(this.__id, n, String(v)); }
    removeAttribute(n) { H.setAttr(this.__id, n, ''); }
    get id() { return this.getAttribute('id') || ''; }
    get className() { return this.getAttribute('class') || ''; }
    get classList() {
      const self = this;
      return {
        contains: (c) => self.className.split(/\s+/).includes(c),
        add: (c) => { const l = self.className.split(/\s+/).filter(Boolean); if (!l.includes(c)) { l.push(c); self.className = l.join(' '); } },
        remove: (c) => { self.className = self.className.split(/\s+/).filter((x) => x && x !== c).join(' '); },
      };
    }
    get innerHTML() { return H.innerHtml(this.__id); }
    get outerHTML() { return H.innerHtml(this.__id); }
    get textContent() { return H.text(this.__id); }
    set textContent(v) { H.setText(this.__id, String(v)); }
    querySelector(sel) { const r = H.query(sel, this.__id); return r.length ? new F1Node(r[0]) : null; }
    querySelectorAll(sel) { return H.query(sel, this.__id).map((i) => new F1Node(i)); }
    getElementsByTagName(t) { return this.querySelectorAll(t.toUpperCase() === '*' ? '*' : t.toLowerCase()); }
    getElementsByClassName(c) { return this.querySelectorAll('.' + c); }
    getElementById(i) { return this.querySelector('#' + i); }
    get elements() { return this.querySelectorAll('input,select,textarea,button'); }
    get value() { const v = this.getAttribute('value'); return v === undefined ? '' : v; }
    set value(v) { this.setAttribute('value', String(v)); }
    matches(sel) { const p = H.parent(this.__id); return H.query(sel, p < 0 ? 0 : p).includes(this.__id); }
    closest(sel) {
      let n = this;
      while (n) { if (n.matches(sel)) return n; n = n.parentNode; }
      return null;
    }
    contains(o) { let n = o; while (n) { if (n.__id === this.__id) return true; n = n.parentNode; } return false; }
    remove() { H.remove(this.__id); }
    click() { H.log('click', this.__id); }
    focus() {}
    blur() {}
    addEventListener() {}
    removeEventListener() {}
    getBoundingClientRect() {
      // No layout engine. Return a zero rect so page code doesn't crash.
      return { x: 0, y: 0, top: 0, left: 0, right: 0, bottom: 0, width: 0, height: 0 };
    }
    get scrollTop() { return 0; }
    get offsetHeight() { return 0; }
  }

  class F1Text extends F1Node {
    constructor(id) { super(id); }
    get nodeValue() { return this.textContent; }
    get data() { return this.textContent; }
  }

  function wrap(id) { return H.name(id) === '#text' ? new F1Text(id) : new F1Node(id); }

  const document = {
    documentElement: wrap(1),
    body: H.query('body', 0).length ? wrap(H.query('body', 0)[0]) : wrap(0),
    head: H.query('head', 0).length ? wrap(H.query('head', 0)[0]) : wrap(0),
    title: H.title(),
    readyState: 'complete',
    cookie: H.cookie(),
    location: { href: H.url(), protocol: 'https:', host: 'localhost', hostname: 'localhost' },
    URL: H.url(),
    documentURI: H.url(),
    characterSet: 'utf-8',
    createElement: (t) => H.create(String(t).toLowerCase()),
    createTextNode: (t) => H.createText(String(t)),
    querySelector: (s) => { const r = H.query(s, 0); return r.length ? wrap(r[0]) : null; },
    querySelectorAll: (s) => H.query(s, 0).map(wrap),
    getElementById: (i) => { const r = H.query('#' + i, 0); return r.length ? wrap(r[0]) : null; },
    getElementsByTagName: (t) => H.query(t === '*' ? '*' : String(t).toLowerCase(), 0).map(wrap),
    getElementsByClassName: (c) => H.query('.' + c, 0).map(wrap),
    get forms() { return H.query('form', 0).map(wrap); },
    get images() { return H.query('img', 0).map(wrap); },
    get links() { return H.query('a[href]', 0).map(wrap); },
    get scripts() { return H.query('script', 0).map(wrap); },
    addEventListener: () => {},
    removeEventListener: () => {},
  };

  // console: nearly every page calls it. Wired into H.log so tools can read it.
  const fmt = (a) => a.map((x) => { try { return typeof x === 'string' ? x : JSON.stringify(x); } catch (e) { return String(x); } }).join(' ');
  globalThis.console = {
    log: (...a) => H.log('log', fmt(a)),
    info: (...a) => H.log('info', fmt(a)),
    warn: (...a) => H.log('warn', fmt(a)),
    error: (...a) => H.log('error', fmt(a)),
    debug: (...a) => H.log('debug', fmt(a)),
  };
  const navigator = {
    userAgent: H.ua(),
    platform: H.platform(),
    language: 'vi-VN',
    languages: ['vi-VN', 'vi', 'en-US', 'en'],
    hardwareConcurrency: H.concurrency(),
    deviceMemory: H.deviceMemory(),
    maxTouchPoints: 5,
    webdriver: false,           // spoofed. We are a browser, not automation.
    plugins: [],
    languages_len: 4,
    cookieEnabled: true,
    doNotTrack: null,
    pdfViewerEnabled: true,
    onLine: true,
    };
  Object.defineProperty(globalThis, '__f1tz', { value: H.timezone() });

  const screen = { width: H.screenW(), height: H.screenH(), availWidth: H.screenW(), availHeight: H.screenH(), colorDepth: 24, pixelDepth: 24 };
  globalThis.window = globalThis;
  globalThis.self = globalThis;
  globalThis.globalThis = globalThis;

  globalThis.document = document;
  globalThis.navigator = navigator;
  globalThis.screen = screen;
  globalThis.location = document.location;
  globalThis.Node = F1Node;
  globalThis.Element = F1Node;
  globalThis.Text = F1Text;
  globalThis.HTMLElement = F1Node;
  globalThis.__f1doc = document;

  // window.alert/confirm/prompt: blocking calls would self-expose. Return harmless values.
  globalThis.alert = () => {};
  globalThis.confirm = () => false;
  globalThis.prompt = () => null;
  globalThis.print = () => {};
  globalThis.open = () => null;
  globalThis.requestAnimationFrame = (cb) => H.timeout(cb, 16);
  globalThis.cancelAnimationFrame = () => {};
  globalThis.fetch = () => Promise.reject(new Error('fetch not available'));
  globalThis.XMLHttpRequest = function () { throw new Error('XHR not available'); };
  function mkStorage() {
    return {
      getItem: (k) => H.storageGet(String(k)) ?? null,
      setItem: (k, v) => { H.storageSet(String(k), String(v)); },
      removeItem: (k) => { H.storageRemove(String(k)); },
      clear: () => { H.storageClear(); },
      get length() { return 0; },
    };
  }
  globalThis.localStorage = mkStorage();
  globalThis.sessionStorage = mkStorage();
})();