/*
 * EASYapi page capture. Runs in the page's own JavaScript world.
 *
 * It watches the API traffic the page generates and sends redacted
 * observations to the extension. It stores nothing itself.
 *
 * Design rules:
 *   1. Never change what the page sees. Hooks call the original function once,
 *      with the original arguments, and return its result untouched.
 *   2. Never block the page. Bodies are read from clones, in the background,
 *      with a byte cap and a timeout.
 *   3. Never throw into page code. Every capture path is wrapped.
 *   4. Redact before anything leaves this script.
 */
(() => {
  "use strict";

  const FLAG = "__EASYAPI_V2__";
  if (window[FLAG]) return;
  try {
    Object.defineProperty(window, FLAG, { value: true, configurable: true, writable: true, enumerable: false });
  } catch (_) {
    window[FLAG] = true;
  }

  const EVT_OUT = "__easyapi_out__";
  const EVT_IN = "__easyapi_in__";

  const CONFIG = {
    maxRequestBodyChars: 2000,
    maxResponseBodyChars: 1500,
    maxRequestBytesRead: 65536,
    maxResponseBytesRead: 16384,
    maxJsonParseChars: 262144,
    readTimeoutMs: 3000,

    scanJavaScript: true,
    scanForms: true,
    usePerformanceEntries: true,
    maxScripts: 60,
    maxScriptChars: 3000000,
    maxRefsPerScript: 400,
    scriptConcurrency: 3,
    scriptTimeoutMs: 15000,

    redactSensitive: true,
    showResponseBody: true,

    flushMs: 200,
    maxBuffered: 500
  };

  // ---------------------------------------------------------------------
  // Native references, captured once so later page changes cannot break us
  // ---------------------------------------------------------------------
  const setT = window.setTimeout.bind(window);
  const clearT = window.clearTimeout.bind(window);
  const nativeFetch = typeof window.fetch === "function" ? window.fetch : null;
  const nativeDispatch = window.dispatchEvent.bind(window);
  const NativeCustomEvent = window.CustomEvent;
  const nativeStringify = JSON.stringify;
  const nativeParse = JSON.parse;

  let active = true;
  const cleanups = [];
  const hooks = [];
  const errBuf = [];

  function fail(where, err) {
    if (errBuf.length < 20) errBuf.push({ where: String(where), message: String((err && err.message) || err).slice(0, 200) });
  }

  // ---------------------------------------------------------------------
  // Redaction
  // ---------------------------------------------------------------------
  const SENSITIVE_EXACT = new Set([
    "pass", "pwd", "auth", "sig", "sid", "otp", "pin", "jwt", "key",
    "session", "sessionid", "ssid", "csrf", "xsrf"
  ]);
  const SENSITIVE_PARTS = [
    "password", "passwd", "passphrase", "secret", "token", "apikey", "authorization",
    "cookie", "credential", "privatekey", "accesskey", "signature", "bearer",
    "sessionid", "verificationcode", "otpcode", "csrf", "xsrf"
  ];

  function normKey(k) {
    return String(k).toLowerCase().replace(/[^a-z0-9]/g, "");
  }

  function isSensitiveKey(k) {
    const n = normKey(k);
    if (!n) return false;
    if (SENSITIVE_EXACT.has(n)) return true;
    for (const p of SENSITIVE_PARTS) if (n.includes(p)) return true;
    return false;
  }

  const VALUE_PATTERNS = [
    [/\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*/g, "[REDACTED_JWT]"],
    [/\b(Bearer|Basic)\s+[A-Za-z0-9._~+\/=-]{8,}/gi, "$1 [REDACTED]"],
    [/\bAKIA[0-9A-Z]{16}\b/g, "[REDACTED_AWS_KEY]"],
    [/\bAIza[0-9A-Za-z_-]{35}\b/g, "[REDACTED_GOOGLE_KEY]"],
    [/\bgh[pousr]_[A-Za-z0-9]{30,}\b/g, "[REDACTED_GITHUB_TOKEN]"],
    [/\bxox[abprs]-[A-Za-z0-9-]{10,}/g, "[REDACTED_SLACK_TOKEN]"],
    [/\b[sr]k_(?:live|test)_[A-Za-z0-9]{10,}\b/g, "[REDACTED_STRIPE_KEY]"]
  ];

  const KV_PATTERN = /([A-Za-z0-9_.\-]{1,64})(["']?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;&"'{}\[\]]+)/g;

  function applyValuePatterns(s) {
    let out = s;
    for (const [re, rep] of VALUE_PATTERNS) out = out.replace(re, rep);
    return out;
  }

  function redactString(s) {
    if (!CONFIG.redactSensitive) return String(s);
    let out = applyValuePatterns(String(s));
    out = out.replace(KV_PATTERN, (m, key, sep, val) => {
      if (!isSensitiveKey(key)) return m;
      return key + sep + (/^["']/.test(val) ? '"[REDACTED]"' : "[REDACTED]");
    });
    return out;
  }

  function redactValue(v, depth) {
    if (v === null || v === undefined) return v;
    if (typeof v === "string") return redactString(v);
    if (typeof v !== "object") return v;
    if (depth > 8) return "[depth limit]";
    if (Array.isArray(v)) {
      const out = v.slice(0, 50).map(x => redactValue(x, depth + 1));
      if (v.length > 50) out.push("[+" + (v.length - 50) + " more]");
      return out;
    }
    const out = Object.create(null);
    let n = 0;
    for (const k of Object.keys(v)) {
      if (++n > 100) { out["[more keys]"] = "..."; break; }
      out[k] = isSensitiveKey(k) ? "[REDACTED]" : redactValue(v[k], depth + 1);
    }
    return out;
  }

  function clip(text, max) {
    return text.length <= max ? text : text.slice(0, max) + " ... [truncated, " + text.length + " chars]";
  }

  // ---------------------------------------------------------------------
  // URL helpers
  // ---------------------------------------------------------------------
  const WEB_PROTOCOLS = new Set(["http:", "https:", "ws:", "wss:"]);

  function baseURI() {
    try { return document.baseURI || location.href; } catch (_) { return location.href; }
  }

  function parseURL(input) {
    try {
      const u = new URL(String(input), baseURI());
      return WEB_PROTOCOLS.has(u.protocol) ? u : null;
    } catch (_) {
      return null;
    }
  }

  function decodeBraces(s) {
    return s.replace(/%7B/gi, "{").replace(/%7D/gi, "}");
  }

  // Display URL without userinfo, with sensitive query and fragment values removed.
  function redactURL(u) {
    if (!CONFIG.redactSensitive) return u.href;
    const params = str => str.split("&").map(part => {
      const i = part.indexOf("=");
      if (i < 0) return part;
      const k = part.slice(0, i);
      let dk = k;
      try { dk = decodeURIComponent(k.replace(/\+/g, " ")); } catch (_) {}
      return isSensitiveKey(dk) ? k + "=[REDACTED]" : part;
    }).join("&");
    let out = u.protocol + "//" + u.host + decodeBraces(u.pathname);
    if (u.search.length > 1) out += "?" + params(u.search.slice(1));
    if (u.hash.length > 1) out += "#" + (u.hash.includes("=") ? params(u.hash.slice(1)) : u.hash.slice(1));
    return applyValuePatterns(out);
  }

  const NOISE_HOSTS = /(^|\.)(w3\.org|schema\.org|schemas\.microsoft\.com|ietf\.org|reactjs\.org|react\.dev|npmjs\.com|github\.com|githubusercontent\.com|gnu\.org|apache\.org|creativecommons\.org|wikipedia\.org|mozilla\.org|json-schema\.org|purl\.org|opensource\.org|fb\.me)$/i;

  // ---------------------------------------------------------------------
  // Body and header description
  // ---------------------------------------------------------------------
  const TEXTUAL = /json|graphql|xml|text|javascript|x-www-form-urlencoded|html|csv/i;
  const RAW_CAP = 65536;

  function describeText(text, maxChars) {
    let json;
    if (text.length <= CONFIG.maxJsonParseChars && /^\s*[\[{]/.test(text)) {
      try { json = nativeParse(text); } catch (_) {}
    }
    let display;
    if (json !== undefined) {
      display = nativeStringify(CONFIG.redactSensitive ? redactValue(json, 0) : json);
    } else {
      display = redactString(text.length > RAW_CAP ? text.slice(0, RAW_CAP) : text);
    }
    return { display: clip(display || "", maxChars), json };
  }

  function describeEntries(entries, max) {
    const obj = Object.create(null);
    for (const [k, v] of entries) {
      const val = (typeof File !== "undefined" && v instanceof File)
        ? "[File " + v.name + ", " + v.size + " bytes]"
        : String(v);
      obj[k] = k in obj ? [].concat(obj[k], val) : val;
    }
    const shown = CONFIG.redactSensitive ? redactValue(obj, 0) : obj;
    return { display: clip(nativeStringify(shown), max), json: obj };
  }

  function describeBody(body) {
    if (body === undefined || body === null) return null;
    const max = CONFIG.maxRequestBodyChars;
    try {
      if (typeof body === "string") return describeText(body, max);
      if (typeof URLSearchParams !== "undefined" && body instanceof URLSearchParams) return describeEntries(body.entries(), max);
      if (typeof FormData !== "undefined" && body instanceof FormData) return describeEntries(body.entries(), max);
      if (typeof Blob !== "undefined" && body instanceof Blob) return { display: "[Blob " + (body.type || "unknown type") + ", " + body.size + " bytes]" };
      if (typeof ArrayBuffer !== "undefined" && (body instanceof ArrayBuffer || ArrayBuffer.isView(body))) return { display: "[binary, " + body.byteLength + " bytes]" };
      if (typeof ReadableStream !== "undefined" && body instanceof ReadableStream) return { display: "[ReadableStream]" };
      return describeText(String(body), max);
    } catch (e) {
      fail("describeBody", e);
      return null;
    }
  }

  function putHeader(obj, name, value) {
    const key = String(name).toLowerCase();
    if (key === "__proto__") return;
    obj[key] = CONFIG.redactSensitive && isSensitiveKey(key) ? "[REDACTED]" : redactString(String(value));
  }

  function headersToObject(h) {
    const out = {};
    if (!h) return out;
    try {
      if (typeof Headers !== "undefined" && h instanceof Headers) {
        h.forEach((v, k) => putHeader(out, k, v));
      } else if (Array.isArray(h)) {
        for (const pair of h) if (pair && pair.length >= 2) putHeader(out, pair[0], pair[1]);
      } else if (typeof h === "object") {
        for (const k of Object.keys(h)) putHeader(out, k, h[k]);
      }
    } catch (e) {
      fail("headers", e);
    }
    return out;
  }

  function withTimeout(promise, ms) {
    return new Promise((resolve, reject) => {
      const t = setT(() => reject(new Error("timeout")), ms);
      promise.then(v => { clearT(t); resolve(v); }, e => { clearT(t); reject(e); });
    });
  }

  // Reads at most maxBytes from a stream, then cancels it. Never waits longer than readTimeoutMs per chunk.
  async function readPreview(body, maxBytes) {
    if (!body || typeof body.getReader !== "function") return { text: "", truncated: false };
    const reader = body.getReader();
    const decoder = typeof TextDecoder !== "undefined" ? new TextDecoder("utf-8", { fatal: false }) : null;
    let received = 0;
    let text = "";
    let truncated = false;
    try {
      while (true) {
        if (received >= maxBytes) { truncated = true; break; }
        const { done, value } = await withTimeout(reader.read(), CONFIG.readTimeoutMs);
        if (done) break;
        received += value.byteLength;
        text += decoder ? decoder.decode(value, { stream: true }) : "";
      }
    } catch (_) {
      truncated = true;
    } finally {
      try { reader.cancel().catch(() => {}); } catch (_) {}
    }
    return { text, truncated };
  }

  // ---------------------------------------------------------------------
  // GraphQL detection (structured, not keyword matching)
  // ---------------------------------------------------------------------
  const GQL_DOC = /^\s*(?:#[^\n]*\n\s*)*(?:(query|mutation|subscription)\b\s*([A-Za-z_]\w*)?\s*(?:\([^)]*\))?\s*\{|\{)/;

  function detectGraphQL(u, json, path) {
    const ops = [];
    const items = Array.isArray(json) ? json.slice(0, 20) : (json && typeof json === "object" ? [json] : []);
    for (const it of items) {
      if (!it || typeof it !== "object") continue;
      const q = typeof it.query === "string" ? it.query : null;
      const opName = typeof it.operationName === "string" ? it.operationName.slice(0, 80) : null;
      if (q !== null) {
        const m = GQL_DOC.exec(q);
        if (m) ops.push({ type: m[1] || "query", operation: m[2] || opName });
      } else if (it.extensions && typeof it.extensions === "object" && it.extensions.persistedQuery) {
        ops.push({ type: "persisted", operation: opName });
      }
    }
    if (!ops.length) {
      const q = u.searchParams.get("query");
      if (q) {
        const m = GQL_DOC.exec(q);
        if (m) ops.push({ type: m[1] || "query", operation: m[2] || u.searchParams.get("operationName") });
      }
    }
    if (!ops.length && /(^|\/)(graphql|gql)(\/|$)/i.test(path)) ops.push({ type: "unknown", operation: null });
    return ops.length ? { operations: ops.slice(0, 10), batched: ops.length > 1 } : null;
  }

  // ---------------------------------------------------------------------
  // Messaging to the extension (through the bridge content script)
  // ---------------------------------------------------------------------
  let bridged = false;
  let helloTries = 0;
  let infoSent = false;
  let flushTimer = null;
  let uid = 0;
  const agg = new Map();

  function send(payload) {
    try {
      nativeDispatch(new NativeCustomEvent(EVT_OUT, { detail: nativeStringify(payload) }));
    } catch (e) {
      fail("send", e);
    }
  }

  function scheduleFlush() {
    if (!flushTimer && active) flushTimer = setT(flush, bridged ? CONFIG.flushMs : 250);
  }

  function flush() {
    flushTimer = null;
    if (!active) return;
    if (!bridged) {
      if (helloTries < 40) {
        helloTries++;
        send({ v: 1, hello: true });
        flushTimer = setT(flush, 250);
      }
      return;
    }
    if (!agg.size && infoSent && !errBuf.length) return;
    const msg = { v: 1, obs: [...agg.values()] };
    agg.clear();
    if (!infoSent) {
      msg.info = { hooks: hooks.slice(), origin: String(location.origin), top: window === window.top };
      infoSent = true;
    }
    if (errBuf.length) msg.errs = errBuf.splice(0, 10);
    send(msg);
  }

  function queueObs(obs) {
    if (!active) return;
    // Identical observations in one window are merged into a hit count.
    const key = obs.w
      ? "w" + (++uid)
      : obs.s + "|" + obs.m + "|" + obs.u + "|" + (obs.st === undefined ? "" : obs.st);
    const existing = agg.get(key);
    if (existing) { existing.n += 1; return; }
    if (agg.size >= CONFIG.maxBuffered) return;
    obs.n = 1;
    agg.set(key, obs);
    scheduleFlush();
  }

  function observe(raw) {
    try {
      if (!active) return;
      const u = parseURL(raw.url);
      if (!u) return;
      if (raw.source === "javascript" && NOISE_HOSTS.test(u.hostname)) return;
      const path = applyValuePatterns(decodeBraces(u.pathname));
      const gq = detectGraphQL(u, raw.requestJson, path);
      const obs = {
        s: raw.source,
        m: raw.method ? String(raw.method).toUpperCase().slice(0, 16) : "?",
        u: redactURL(u),
        ob: !!raw.observed
      };
      if (typeof raw.status === "number") obs.st = raw.status;
      if (raw.requestContentType) obs.qct = String(raw.requestContentType).slice(0, 120);
      if (raw.responseContentType) obs.rct = String(raw.responseContentType).slice(0, 120);
      if (raw.requestBody) obs.qb = String(raw.requestBody);
      if (raw.responseBody) obs.rb = String(raw.responseBody);
      if (raw.requestHeaders && Object.keys(raw.requestHeaders).length) obs.qh = raw.requestHeaders;
      if (gq) obs.gq = gq;
      if (raw.wsSample) obs.w = raw.wsSample;
      queueObs(obs);
    } catch (e) {
      fail("observe", e);
    }
  }

  function applyConfig(c) {
    if (!c || typeof c !== "object") return;
    for (const k of ["redactSensitive", "showResponseBody", "scanJavaScript", "scanForms", "usePerformanceEntries"]) {
      if (typeof c[k] === "boolean") CONFIG[k] = c[k];
    }
  }

  function onCommand(ev) {
    let cmd;
    try { cmd = nativeParse(ev.detail); } catch (_) { return; }
    if (!cmd || typeof cmd !== "object") return;
    if (cmd.cmd === "config") {
      applyConfig(cmd.config);
      bridged = true;
      if (flushTimer) { clearT(flushTimer); flushTimer = null; }
      flush();
    } else if (cmd.cmd === "stop") {
      stop();
    }
  }

  window.addEventListener(EVT_IN, onCommand);
  cleanups.push(() => window.removeEventListener(EVT_IN, onCommand));

  // ---------------------------------------------------------------------
  // Hooks. Each one calls the original exactly once and never throws.
  // ---------------------------------------------------------------------
  function installFetch() {
    if (!nativeFetch) return;
    const original = window.fetch;

    const wrapper = function fetch(...args) {
      let ctx = null;
      if (active) {
        try { ctx = captureFetchRequest(args[0], args[1]); } catch (e) { fail("fetch.capture", e); }
      }
      const p = Reflect.apply(original, this, args);
      if (ctx) {
        try {
          if (p && typeof p.then === "function") {
            p.then(res => onFetchResponse(ctx, res), () => onFetchError(ctx));
          }
        } catch (e) { fail("fetch.attach", e); }
      }
      return p;
    };

    window.fetch = wrapper;
    cleanups.push(() => { if (window.fetch === wrapper) window.fetch = original; });
    hooks.push("fetch");
  }

  function captureFetchRequest(input, init) {
    const isRequest = typeof Request !== "undefined" && input instanceof Request;
    const ctx = { url: "", method: "GET", headers: {}, bodyInfo: null, requestClone: null };

    if (isRequest) {
      ctx.url = input.url;
      ctx.method = input.method || "GET";
      ctx.headers = headersToObject(input.headers);
    } else {
      ctx.url = String(input);
    }
    if (init && init.method) ctx.method = String(init.method).toUpperCase();
    if (init && init.headers) Object.assign(ctx.headers, headersToObject(init.headers));

    if (init && init.body !== undefined && init.body !== null) {
      ctx.bodyInfo = describeBody(init.body);
    } else if (isRequest && input.body && !input.bodyUsed) {
      // Clone synchronously. Only textual bodies, so large uploads are never buffered.
      if (TEXTUAL.test(ctx.headers["content-type"] || "")) {
        try { ctx.requestClone = input.clone(); } catch (_) {}
      } else {
        ctx.bodyInfo = { display: "[" + (ctx.headers["content-type"] || "binary") + " body]" };
      }
    }
    return ctx;
  }

  function onFetchResponse(ctx, res) {
    try {
      // The clone must be taken now, before page code can consume the body.
      const ct = (res.headers && res.headers.get("content-type")) || "";
      let clone = null;
      if (CONFIG.showResponseBody && res.body && res.type !== "opaque" && TEXTUAL.test(ct) && !/event-stream/i.test(ct)) {
        try { clone = res.clone(); } catch (_) {}
      }
      const meta = {
        source: "fetch", url: ctx.url, method: ctx.method, observed: true,
        requestHeaders: ctx.headers, requestContentType: ctx.headers["content-type"] || "",
        status: res.status, responseContentType: ct
      };
      finishFetch(ctx, meta, clone).catch(e => fail("fetch.finish", e));
    } catch (e) {
      fail("fetch.response", e);
    }
  }

  async function finishFetch(ctx, meta, clone) {
    let reqInfo = ctx.bodyInfo;
    if (!reqInfo && ctx.requestClone) {
      const r = await readPreview(ctx.requestClone.body, CONFIG.maxRequestBytesRead);
      reqInfo = describeText(r.text, CONFIG.maxRequestBodyChars);
    }
    if (clone) {
      const r = await readPreview(clone.body, CONFIG.maxResponseBytesRead);
      if (r.text) meta.responseBody = describeText(r.text, CONFIG.maxResponseBodyChars).display;
    }
    if (reqInfo) { meta.requestBody = reqInfo.display; meta.requestJson = reqInfo.json; }
    observe(meta);
  }

  function onFetchError(ctx) {
    try {
      if (ctx.requestClone && ctx.requestClone.body) { try { ctx.requestClone.body.cancel().catch(() => {}); } catch (_) {} }
      const info = ctx.bodyInfo;
      observe({
        source: "fetch", url: ctx.url, method: ctx.method, observed: true,
        requestHeaders: ctx.headers, requestContentType: ctx.headers["content-type"] || "",
        requestBody: info ? info.display : "", requestJson: info ? info.json : undefined, status: 0
      });
    } catch (e) {
      fail("fetch.error", e);
    }
  }

  function installXHR() {
    if (typeof XMLHttpRequest === "undefined") return;
    const proto = XMLHttpRequest.prototype;
    const origOpen = proto.open;
    const origSend = proto.send;
    const origSetHeader = proto.setRequestHeader;
    const meta = new WeakMap();

    const open = function open(method, url) {
      if (active) {
        try { meta.set(this, { method: String(method || "GET").toUpperCase(), url: String(url), headers: {} }); } catch (e) { fail("xhr.open", e); }
      }
      return Reflect.apply(origOpen, this, arguments);
    };
    const setRequestHeader = function setRequestHeader(name, value) {
      if (active) {
        try { const m = meta.get(this); if (m) putHeader(m.headers, name, value); } catch (e) { fail("xhr.header", e); }
      }
      return Reflect.apply(origSetHeader, this, arguments);
    };
    const sendFn = function send(body) {
      if (active) {
        try {
          const m = meta.get(this);
          if (m) {
            const info = describeBody(body);
            const xhr = this;
            xhr.addEventListener("loadend", () => onXhrDone(xhr, m, info), { once: true });
          }
        } catch (e) { fail("xhr.send", e); }
      }
      return Reflect.apply(origSend, this, arguments);
    };

    proto.open = open;
    proto.setRequestHeader = setRequestHeader;
    proto.send = sendFn;
    cleanups.push(() => {
      if (proto.open === open) proto.open = origOpen;
      if (proto.setRequestHeader === setRequestHeader) proto.setRequestHeader = origSetHeader;
      if (proto.send === sendFn) proto.send = origSend;
    });
    hooks.push("xhr");
  }

  function onXhrDone(xhr, m, info) {
    try {
      const ct = xhr.getResponseHeader("content-type") || "";
      let text = "";
      if (CONFIG.showResponseBody && TEXTUAL.test(ct)) {
        try {
          if (xhr.responseType === "" || xhr.responseType === "text") text = xhr.responseText || "";
          else if (xhr.responseType === "json" && xhr.response !== null) text = nativeStringify(xhr.response) || "";
        } catch (_) {}
      }
      observe({
        source: "xhr", url: m.url, method: m.method, observed: true,
        requestHeaders: m.headers, requestContentType: m.headers["content-type"] || "",
        requestBody: info ? info.display : "", requestJson: info ? info.json : undefined,
        status: xhr.status, responseContentType: ct,
        responseBody: text ? describeText(text.slice(0, RAW_CAP), CONFIG.maxResponseBodyChars).display : ""
      });
    } catch (e) {
      fail("xhr.done", e);
    }
  }

  function installBeacon() {
    if (typeof navigator === "undefined" || typeof navigator.sendBeacon !== "function") return;
    const original = navigator.sendBeacon;
    const hadOwn = Object.prototype.hasOwnProperty.call(navigator, "sendBeacon");
    const wrapper = function sendBeacon(url, data) {
      if (active) {
        try {
          const info = describeBody(data);
          observe({
            source: "beacon", url, method: "POST", observed: true,
            requestBody: info ? info.display : "", requestJson: info ? info.json : undefined,
            requestContentType: (data && data.type) || ""
          });
        } catch (e) { fail("beacon", e); }
      }
      return Reflect.apply(original, this, arguments);
    };
    navigator.sendBeacon = wrapper;
    cleanups.push(() => {
      if (navigator.sendBeacon !== wrapper) return;
      if (hadOwn) navigator.sendBeacon = original; else delete navigator.sendBeacon;
    });
    hooks.push("beacon");
  }

  function describeWsData(d) {
    if (typeof d === "string") return describeText(d, 400).display;
    if (typeof Blob !== "undefined" && d instanceof Blob) return "[Blob " + d.size + " bytes]";
    if (d && typeof d.byteLength === "number") return "[binary " + d.byteLength + " bytes]";
    return "[unknown]";
  }

  function instrumentSocket(ws, url) {
    let inCount = 0;
    let outCount = 0;
    const limit = 3;
    const sample = (dir, data) => observe({
      source: "websocket", url, method: "WS_SAMPLE", observed: true,
      wsSample: { dir, data: describeWsData(data) }
    });
    ws.addEventListener("message", ev => {
      if (!active || inCount >= limit) return;
      inCount++;
      try { sample("in", ev.data); } catch (e) { fail("ws.message", e); }
    });
    const origSend = ws.send;
    ws.send = function send(data) {
      if (active && outCount < limit) {
        outCount++;
        try { sample("out", data); } catch (e) { fail("ws.send", e); }
      }
      return Reflect.apply(origSend, this, arguments);
    };
  }

  function installWebSocket() {
    const Original = window.WebSocket;
    if (typeof Original !== "function" || typeof Proxy === "undefined") return;
    const proxy = new Proxy(Original, {
      construct(Target, args, newTarget) {
        const ws = Reflect.construct(Target, args, newTarget);
        if (active) {
          try {
            observe({ source: "websocket", url: args[0], method: "WEBSOCKET", observed: true });
            instrumentSocket(ws, args[0]);
          } catch (e) { fail("ws.construct", e); }
        }
        return ws;
      }
    });
    window.WebSocket = proxy;
    cleanups.push(() => { if (window.WebSocket === proxy) window.WebSocket = Original; });
    hooks.push("websocket");
  }

  // ---------------------------------------------------------------------
  // Resource Timing: sees requests made before capture started
  // (URL and status only, limited by the browser's timing buffer).
  // ---------------------------------------------------------------------
  const PERF_API_INITIATORS = new Set(["fetch", "xmlhttprequest", "beacon"]);
  const JS_EXT = /\.m?js(?:[?#]|$)/i;

  function handlePerf(entries) {
    for (const e of entries) {
      const name = e && e.name;
      if (typeof name !== "string") continue;
      if (JS_EXT.test(name)) { enqueueScript(name); continue; }
      if (!CONFIG.usePerformanceEntries || !PERF_API_INITIATORS.has(e.initiatorType)) continue;
      observe({
        source: "performance", url: name, method: "?", observed: true,
        status: typeof e.responseStatus === "number" && e.responseStatus > 0 ? e.responseStatus : undefined
      });
    }
  }

  function startPerformanceObserver() {
    if (typeof PerformanceObserver === "undefined") return;
    const obs = new PerformanceObserver(list => {
      try { handlePerf(list.getEntries()); } catch (e) { fail("perf", e); }
    });
    try {
      obs.observe({ type: "resource", buffered: true });
    } catch (_) {
      obs.observe({ entryTypes: ["resource"] });
      handlePerf(performance.getEntriesByType("resource"));
    }
    cleanups.push(() => obs.disconnect());
    hooks.push("resource-timing");
  }

  // ---------------------------------------------------------------------
  // Static scanning of JavaScript (queued, capped, never blocks the page)
  // ---------------------------------------------------------------------
  const REF_PATTERNS = [
    /\b(?:https?|wss?):\/\/[^\s"'`<>\\)]{4,}/gi,
    /["'`](\/(?:api|apis|graphql|gql|rest|rpc|jsonrpc|odata|trpc|v\d+|wp-json)(?:[\/?#][^\s"'`<>\\]*)?)["'`]/gi,
    /["'`](\/[^\s"'`<>\\]*(?:users?|accounts?|profiles?|auth|login|logout|oauth|orders?|products?|payments?|bookings?|files?|upload|download|messages?|notifications?|settings?|config|search|admin)[^\s"'`<>\\]*)["'`]/gi
  ];

  function extractRefs(text) {
    const found = new Set();
    for (const proto of REF_PATTERNS) {
      const re = new RegExp(proto.source, proto.flags);
      let m;
      while ((m = re.exec(text)) !== null) {
        let c = (m[1] || m[0]).replace(/[),;.]+$/, "");
        c = c.replace(/\$\{[^}]*\}/g, "{param}").replace(/\{\{[^}]*\}\}/g, "{param}");
        found.add(c);
        if (found.size >= CONFIG.maxRefsPerScript) return [...found];
        if (m[0].length === 0) re.lastIndex++;
      }
    }
    return [...found];
  }

  function recordRefs(text, source) {
    for (const url of extractRefs(text)) observe({ source, url, method: "?", observed: false });
  }

  const scriptSeen = new Set();
  const scriptQueue = [];
  let scriptActive = 0;

  function enqueueScript(src) {
    if (!CONFIG.scanJavaScript || !active) return;
    const u = parseURL(src);
    if (!u || (u.protocol !== "http:" && u.protocol !== "https:")) return;
    const key = u.origin + u.pathname + u.search;
    if (scriptSeen.has(key) || scriptSeen.size >= CONFIG.maxScripts) return;
    scriptSeen.add(key);
    scriptQueue.push(u.href);
    pumpScripts();
  }

  function pumpScripts() {
    while (active && scriptActive < CONFIG.scriptConcurrency && scriptQueue.length) {
      const href = scriptQueue.shift();
      scriptActive++;
      scanScript(href)
        .catch(e => fail("scanScript", e))
        .finally(() => { scriptActive--; pumpScripts(); });
    }
  }

  const yieldToMain = () => new Promise(r => setT(r, 0));

  async function scanScript(href) {
    if (!nativeFetch) return;
    let timer = null;
    try {
      const sameOrigin = new URL(href).origin === location.origin;
      const ctl = typeof AbortController !== "undefined" ? new AbortController() : null;
      if (ctl) timer = setT(() => ctl.abort(), CONFIG.scriptTimeoutMs);
      // Same-origin scripts normally come from the browser cache. Cross-origin
      // scripts are fetched without credentials and skipped if CORS blocks them.
      const res = await nativeFetch.call(window, href, {
        credentials: sameOrigin ? "same-origin" : "omit",
        cache: "force-cache",
        signal: ctl ? ctl.signal : undefined
      });
      if (!res.ok || /html/i.test(res.headers.get("content-type") || "")) return;
      const text = await res.text();
      if (text.length > CONFIG.maxScriptChars) return;
      await yieldToMain();
      if (active) recordRefs(text, "javascript");
    } catch (_) {
      // CORS or network failure on a script we are only reading for hints. Ignore.
    } finally {
      if (timer) clearT(timer);
    }
  }

  // ---------------------------------------------------------------------
  // DOM scanning
  // ---------------------------------------------------------------------
  const seenForms = new WeakSet();
  const seenInline = new WeakSet();

  function scanDOM() {
    try {
      if (CONFIG.scanForms) {
        document.querySelectorAll("form[action]").forEach(form => {
          if (seenForms.has(form)) return;
          seenForms.add(form);
          // getAttribute, because form.action can be shadowed by an input named "action".
          const action = form.getAttribute("action");
          if (!action) return;
          observe({ source: "form", url: action, method: form.getAttribute("method") || "GET", observed: false });
        });
      }
      document.querySelectorAll("script").forEach(s => {
        if (s.src) { enqueueScript(s.src); return; }
        if (!CONFIG.scanJavaScript || seenInline.has(s)) return;
        seenInline.add(s);
        const text = s.textContent || "";
        if (text && text.length <= CONFIG.maxScriptChars) recordRefs(text, "javascript");
      });
    } catch (e) {
      fail("scanDOM", e);
    }
  }

  function startDomScanning() {
    let timer = null;
    const later = () => { if (timer) clearT(timer); timer = setT(scanDOM, 500); };
    if (typeof MutationObserver !== "undefined") {
      const obs = new MutationObserver(later);
      // childList only. Observing attributes on the whole document is far too noisy.
      obs.observe(document, { childList: true, subtree: true });
      cleanups.push(() => obs.disconnect());
    }
    document.addEventListener("DOMContentLoaded", scanDOM);
    window.addEventListener("load", scanDOM);
    cleanups.push(() => {
      if (timer) clearT(timer);
      document.removeEventListener("DOMContentLoaded", scanDOM);
      window.removeEventListener("load", scanDOM);
    });
    hooks.push("dom");
  }

  // ---------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------
  function stop() {
    if (!active) return;
    active = false;
    for (const fn of cleanups.splice(0)) { try { fn(); } catch (_) {} }
    agg.clear();
    if (flushTimer) { clearT(flushTimer); flushTimer = null; }
    try { delete window[FLAG]; } catch (_) { window[FLAG] = false; }
  }

  for (const [name, fn] of [
    ["fetch", installFetch], ["xhr", installXHR], ["beacon", installBeacon],
    ["websocket", installWebSocket], ["resource-timing", startPerformanceObserver],
    ["dom", startDomScanning]
  ]) {
    try { fn(); } catch (e) { fail("install " + name, e); }
  }

  send({ v: 1, hello: true });
  flushTimer = setT(flush, 250);
  scanDOM();
})();
