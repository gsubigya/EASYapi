/*
 * EASYapi v2
 * Passive browser-side API discovery for authorized security testing.
 *
 * Paste into the DevTools console of a page you are allowed to test, then browse.
 *
 * Design rules:
 *   1. Never change what the page sees. Hooks call the original function once,
 *      with the original arguments, and return its result untouched.
 *   2. Never block the page. Bodies are read from clones, in the background,
 *      with a byte cap and a timeout.
 *   3. Never throw into page code. Every capture path is wrapped.
 *   4. Redact before storing. Raw secrets are never kept in the findings store.
 */
(() => {
  "use strict";

  const VERSION = "2.0.0";

  // Stop a previous instance (this version or the old Smart API Discovery).
  try {
    if (window.EASYapi && typeof window.EASYapi.stop === "function") {
      window.EASYapi.stop({ silent: true });
    } else if (typeof window.__SMART_API_DISCOVERY_CLEANUP__ === "function") {
      window.__SMART_API_DISCOVERY_CLEANUP__();
    }
  } catch (_) {}

  // ---------------------------------------------------------------------
  // Configuration (editable at runtime through EASYapi.config)
  // ---------------------------------------------------------------------
  const CONFIG = {
    // capture limits
    maxRequestBodyChars: 3000,
    maxResponseBodyChars: 2500,
    maxRequestBytesRead: 65536,
    maxResponseBytesRead: 16384,
    maxJsonParseChars: 262144,
    readTimeoutMs: 3000,

    // store limits
    maxFindings: 2000,
    maxExamples: 5,
    maxWsSamples: 6,

    // static scanning
    scanJavaScript: true,
    scanForms: true,
    usePerformanceEntries: true,
    maxScripts: 60,
    maxScriptChars: 3000000,
    maxRefsPerScript: 400,
    scriptConcurrency: 3,
    scriptTimeoutMs: 15000,

    // output
    live: true,
    minConfidence: "LOW", // LOW | MEDIUM | HIGH
    thirdParty: "tag", // "tag" or "hide"
    showRequestHeaders: true,
    showResponseBody: true,
    redactSensitive: true,
    livePrintBudget: 40,
    livePrintWindowMs: 2000,
    printDelayMs: 250,
    debug: false
  };

  const CONF_RANK = { IGNORE: 0, LOW: 1, MEDIUM: 2, HIGH: 3 };

  // ---------------------------------------------------------------------
  // Native references, captured once so later page changes cannot break us
  // ---------------------------------------------------------------------
  const nativeConsole = {};
  for (const m of ["log", "group", "groupCollapsed", "groupEnd", "table", "debug"]) {
    nativeConsole[m] = typeof console[m] === "function" ? console[m].bind(console) : null;
  }
  if (!nativeConsole.log) nativeConsole.log = () => {};
  if (!nativeConsole.groupCollapsed) nativeConsole.groupCollapsed = nativeConsole.group || nativeConsole.log;
  if (!nativeConsole.groupEnd) nativeConsole.groupEnd = () => {};
  if (!nativeConsole.debug) nativeConsole.debug = nativeConsole.log;

  const setT = window.setTimeout.bind(window);
  const clearT = window.clearTimeout.bind(window);
  const nativeFetch = typeof window.fetch === "function" ? window.fetch : null;

  // ---------------------------------------------------------------------
  // State
  // ---------------------------------------------------------------------
  let active = true;
  let seq = 0;
  const cleanups = [];
  const store = new Map(); // key -> finding
  const pathIndex = new Map(); // host|path -> Set(keys)
  const pending = new Map(); // finding -> event name (print queue)
  const errors = [];
  const hooks = [];

  const stats = {
    fetch: 0, xhr: 0, beacon: 0, websocket: 0, performance: 0,
    scripts: 0, scriptsSkipped: 0, scriptRefs: 0,
    ignored: 0, hidden: 0, skipped: 0, errors: 0, printSuppressed: 0
  };

  function fail(where, err) {
    stats.errors++;
    if (errors.length < 50) {
      errors.push({ where, message: String((err && err.message) || err), at: new Date().toISOString() });
    }
    if (CONFIG.debug) {
      try { nativeConsole.debug("[EASYapi] internal error in " + where, err); } catch (_) {}
    }
  }

  // ---------------------------------------------------------------------
  // Redaction
  // ---------------------------------------------------------------------
  // Keys are normalized (lowercase, letters and digits only) so "x-api-key",
  // "X_API_KEY" and "apiKey" all map to "xapikey" / "apikey".
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

  // key=value / "key": value pairs inside free text (form bodies, truncated JSON)
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

  // Builds a display URL without userinfo, with sensitive query/fragment values removed.
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

  function redactHref(href) {
    const u = parseURL(href);
    return u ? redactURL(u) : String(href);
  }

  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

  function normalizeSegment(seg) {
    if (!seg) return seg;
    let s = seg;
    try { s = decodeURIComponent(seg); } catch (_) {}
    if (/^\d+$/.test(s)) return "{id}";
    if (UUID_RE.test(s)) return "{uuid}";
    if (/^[0-9a-f]{16,}$/i.test(s)) return "{hex}";
    if (/^[A-Za-z0-9_-]{22,}$/.test(s) && /\d/.test(s) && /[A-Za-z]/.test(s)) return "{token}";
    if (/^\{[^}]*\}$/.test(s) || /^:[A-Za-z_]\w*$/.test(s)) return "{param}";
    return seg;
  }

  function normalizePath(p) {
    let s = p.split("/").map(normalizeSegment).join("/");
    if (s.length > 1 && s.endsWith("/")) s = s.slice(0, -1);
    return s || "/";
  }

  const MULTI_TLD = new Set([
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp",
    "co.in", "com.br", "com.cn", "com.mx", "com.tr", "co.za", "com.sg", "com.np", "com.pk", "com.bd"
  ]);

  // Heuristic registrable-domain guess. Good enough to tag third-party traffic.
  function siteOf(hostname) {
    const h = String(hostname).toLowerCase();
    if (h.startsWith("[") || /^\d+\.\d+\.\d+\.\d+$/.test(h)) return h;
    const parts = h.split(".");
    if (parts.length <= 2) return h;
    const last2 = parts.slice(-2).join(".");
    return MULTI_TLD.has(last2) ? parts.slice(-3).join(".") : last2;
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
      try { json = JSON.parse(text); } catch (_) {}
    }
    let display;
    if (json !== undefined) {
      display = JSON.stringify(CONFIG.redactSensitive ? redactValue(json, 0) : json);
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
    return { display: clip(JSON.stringify(shown), max), json: obj };
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

  // Reads at most maxBytes from a stream, then cancels it. Never waits longer than timeoutMs.
  function withTimeout(promise, ms) {
    return new Promise((resolve, reject) => {
      const t = setT(() => reject(new Error("timeout")), ms);
      promise.then(v => { clearT(t); resolve(v); }, e => { clearT(t); reject(e); });
    });
  }

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
      const opName = typeof it.operationName === "string" ? it.operationName : null;
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
  // Scoring
  // ---------------------------------------------------------------------
  const RESOURCE_WORDS = new Set([
    "users", "user", "accounts", "account", "profiles", "profile", "auth", "login", "logout",
    "register", "session", "token", "customers", "customer", "products", "product", "orders",
    "order", "payments", "payment", "invoices", "invoice", "bookings", "booking", "files",
    "file", "upload", "download", "messages", "message", "notifications", "notification",
    "settings", "config", "configuration", "admin", "search", "reports", "report",
    "analytics", "health", "status"
  ]);
  const API_SEGMENT = /^(?:api|apis|graphql|gql|rest|rpc|jsonrpc|odata|trpc)(?:[-_]?v?\d+)?$/;
  const SPEC_SEGMENT = /^(?:swagger|openapi|api-docs|wp-json|admin-ajax\.php|swagger\.json|openapi\.json)$/;
  const STATIC_EXT = /\.(?:js|mjs|css|map|png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|otf|eot|mp4|webm|mp3|wav|pdf|zip|wasm)$/i;

  function scoreFinding(i) {
    let score = 0;
    const why = [];
    const add = (pts, reason) => { score += pts; if (reason) why.push(reason); };
    const p = i.path.toLowerCase();
    const segs = p.split("/").filter(Boolean);

    if (segs.some(s => API_SEGMENT.test(s))) add(35, "API path segment");
    if (segs.some(s => SPEC_SEGMENT.test(s))) add(40, "API spec or framework");
    if (segs.some(s => /^v\d+(?:\.\d+)?$/.test(s))) add(18, "versioned path");
    if (/(^|[.-])(api|apis|backend|gateway|graphql|rest|svc|services?)([.-]|$)/.test(i.hostname)) add(25, "API-like hostname");

    const hits = p.split(/[\/_.\-]+/).filter(t => RESOURCE_WORDS.has(t));
    if (hits.length) add(Math.min(new Set(hits).size * 6, 24), "resource:" + [...new Set(hits)].slice(0, 4).join(","));

    if (["POST", "PUT", "PATCH", "DELETE"].includes(i.method)) add(15, i.method);
    if (i.hasBody) add(8, "request body");
    if (/json|graphql|xml|form/i.test(i.requestContentType || "")) add(10, "structured request");
    if (/json|graphql|xml/i.test(i.responseContentType || "")) add(15, "structured response");
    if (/html/i.test(i.responseContentType || "") && i.status >= 200 && i.status < 300) add(-15, "html response");
    if (i.graphql) add(35, "GraphQL");
    if (i.method === "WEBSOCKET") add(35, "WebSocket");
    if (["fetch", "xhr", "beacon", "websocket"].includes(i.source)) add(12, "runtime request");
    if ([401, 403, 405, 429].includes(i.status)) add(12, "HTTP " + i.status);
    if (i.status >= 200 && i.status < 300 && /json|graphql/i.test(i.responseContentType || "")) add(20, "successful JSON response");
    if (i.source === "javascript") add(8, "referenced in code");
    if (i.source === "performance") add(5, "resource timing");
    if (STATIC_EXT.test(p)) add(-30, null);
    else if (/\.html?$/.test(p)) add(-15, null);

    return { score: Math.max(0, score), reasons: why };
  }

  function confidenceFrom(score, observed) {
    let c = score >= 75 ? "HIGH" : score >= 45 ? "MEDIUM" : score >= 22 ? "LOW" : "IGNORE";
    // A string in a JS file is a lead, not proof. Cap unobserved findings at MEDIUM.
    if (!observed && c === "HIGH") c = "MEDIUM";
    return c;
  }

  // ---------------------------------------------------------------------
  // Findings store
  // ---------------------------------------------------------------------
  function compareFindings(a, b) {
    return (CONF_RANK[b.confidence] - CONF_RANK[a.confidence])
      || ((b.observed ? 1 : 0) - (a.observed ? 1 : 0))
      || (b.score - a.score)
      || (b.count - a.count)
      || a.host.localeCompare(b.host)
      || a.normalizedPath.localeCompare(b.normalizedPath)
      || a.method.localeCompare(b.method);
  }

  function indexAdd(pathKey, key) {
    let set = pathIndex.get(pathKey);
    if (!set) { set = new Set(); pathIndex.set(pathKey, set); }
    set.add(key);
  }

  function removeFinding(key) {
    const f = store.get(key);
    if (!f) return;
    store.delete(key);
    pending.delete(f);
    const set = pathIndex.get(f.host + "|" + f.normalizedPath);
    if (set) { set.delete(key); if (!set.size) pathIndex.delete(f.host + "|" + f.normalizedPath); }
  }

  function specificSiblings(pathKey) {
    const keys = pathIndex.get(pathKey);
    const out = [];
    if (!keys) return out;
    for (const k of keys) {
      if (k.charAt(0) !== "?") { const f = store.get(k); if (f) out.push(f); }
    }
    return out;
  }

  function enforceCap() {
    if (store.size <= CONFIG.maxFindings) return;
    let worst = null;
    for (const f of store.values()) if (!worst || compareFindings(worst, f) < 0) worst = f;
    if (worst) removeFinding(worst.key);
  }

  function addCapped(arr, value, cap) {
    if (arr.length < cap && !arr.includes(value)) arr.push(value);
  }

  function record(raw) {
    try {
      return recordUnsafe(raw);
    } catch (e) {
      fail("record", e);
      return null;
    }
  }

  function recordUnsafe(raw) {
    if (!active || !raw || !raw.url) return null;
    const u = parseURL(raw.url);
    if (!u) { stats.skipped++; return null; }

    const method = raw.method ? String(raw.method).toUpperCase() : "?";
    const host = u.host.toLowerCase();
    const path = applyValuePatterns(decodeBraces(u.pathname));
    const normalizedPath = normalizePath(path);
    const thirdParty = siteOf(u.hostname) !== siteOf(location.hostname);
    if (thirdParty && CONFIG.thirdParty === "hide") { stats.hidden++; return null; }
    if (raw.source === "javascript" && NOISE_HOSTS.test(u.hostname)) { stats.skipped++; return null; }

    const graphql = detectGraphQL(u, raw.requestJson, path);
    const status = typeof raw.status === "number" ? raw.status : undefined;
    const scored = scoreFinding({
      path, hostname: u.hostname.toLowerCase(), method, source: raw.source, status,
      hasBody: !!raw.requestBody, requestContentType: raw.requestContentType,
      responseContentType: raw.responseContentType, graphql
    });

    const pathKey = host + "|" + normalizedPath;
    const key = method + "|" + pathKey;
    const ts = Date.now();

    // Method-less evidence (resource timing, code references) attaches to an
    // existing method-specific finding instead of creating a guessed "GET".
    if (method === "?") {
      const siblings = specificSiblings(pathKey);
      if (siblings.length) {
        for (const f of siblings) {
          f.sources.add(raw.source);
          f.lastSeen = ts;
          if (raw.observed && !f.observed) {
            f.observed = true;
            f.confidence = confidenceFrom(f.score, true);
            queuePrint(f, "SEEN");
          }
        }
        return siblings[0];
      }
    }

    let f = store.get(key);
    let isNew = false;
    let absorbed = null;

    if (!f) {
      if (method !== "?") absorbed = store.get("?|" + pathKey) || null;
      const score = Math.max(scored.score, absorbed ? absorbed.score : 0);
      const observed = !!raw.observed || (absorbed ? absorbed.observed : false);
      const conf = confidenceFrom(score, observed);
      if (conf === "IGNORE" || CONF_RANK[conf] < CONF_RANK[String(CONFIG.minConfidence).toUpperCase()]) {
        stats.ignored++;
        return null;
      }
      f = {
        id: ++seq, key, method, host, hostname: u.hostname.toLowerCase(), normalizedPath, thirdParty,
        score, confidence: conf, observed, printed: false,
        reasons: new Set(), sources: new Set(), examples: [], queryParams: new Set(), statuses: new Map(),
        requestContentType: "", responseContentType: "", requestHeaders: null,
        requestBody: "", responseBody: "", graphql: null, wsSamples: [], lastStatus: undefined,
        count: 0, firstSeen: ts, lastSeen: ts
      };
      if (absorbed) {
        const perfOnly = absorbed.sources.size === 1 && absorbed.sources.has("performance");
        removeFinding(absorbed.key);
        for (const r of absorbed.reasons) f.reasons.add(r);
        for (const s of absorbed.sources) f.sources.add(s);
        for (const e of absorbed.examples) f.examples.push(e);
        for (const q of absorbed.queryParams) f.queryParams.add(q);
        if (!perfOnly) {
          f.count = absorbed.count;
          for (const [s, n] of absorbed.statuses) f.statuses.set(s, n);
        }
        f.firstSeen = absorbed.firstSeen;
        f.printed = absorbed.printed;
        f.requestBody = absorbed.requestBody;
        f.responseBody = absorbed.responseBody;
      }
      store.set(key, f);
      indexAdd(pathKey, key);
      isNew = true;
    }

    const before = { conf: f.confidence, observed: f.observed, hadStatus: status !== undefined && f.statuses.has(status) };

    f.count += 1;
    f.lastSeen = ts;
    f.sources.add(raw.source);
    for (const r of scored.reasons) f.reasons.add(r);
    if (scored.score > f.score) f.score = scored.score;
    if (raw.observed) f.observed = true;
    addCapped(f.examples, redactURL(u), CONFIG.maxExamples);
    for (const k of u.searchParams.keys()) { if (f.queryParams.size < 30) f.queryParams.add(k); }
    if (status !== undefined) {
      f.statuses.set(status, (f.statuses.get(status) || 0) + 1);
      f.lastStatus = status;
    }
    if (raw.requestContentType && !f.requestContentType) f.requestContentType = raw.requestContentType;
    if (raw.responseContentType) f.responseContentType = raw.responseContentType;
    if (raw.requestHeaders && !f.requestHeaders) f.requestHeaders = raw.requestHeaders;
    if (raw.requestBody && !f.requestBody) f.requestBody = raw.requestBody;
    if (raw.responseBody && !f.responseBody) f.responseBody = raw.responseBody;
    if (graphql && !f.graphql) f.graphql = graphql;
    f.confidence = confidenceFrom(f.score, f.observed);

    let ev = null;
    if (isNew) ev = absorbed && absorbed.printed ? "METHOD" : "NEW";
    else if (!before.observed && f.observed) ev = "SEEN";
    else if (CONF_RANK[f.confidence] > CONF_RANK[before.conf]) ev = "UPGRADED";
    else if (status !== undefined && !before.hadStatus && f.statuses.size > 1) ev = "STATUS";
    if (ev) queuePrint(f, ev);

    enforceCap();
    return f;
  }

  // ---------------------------------------------------------------------
  // Output
  // ---------------------------------------------------------------------
  const STYLE = {
    HIGH: "color:#d6336c;font-weight:bold",
    MEDIUM: "color:#e8890c;font-weight:bold",
    LOW: "color:#868e96",
    dim: "color:#868e96",
    ok: "color:#2f9e44;font-weight:bold"
  };
  const EVENT_PRIORITY = { NEW: 5, METHOD: 4, SEEN: 3, UPGRADED: 2, STATUS: 1 };

  // The text is always passed as an argument, never as the format string,
  // so a URL containing %c, %s or %d cannot corrupt the output.
  function styled(text, css) {
    nativeConsole.log("%c%s", css || "", text);
  }

  const pad = (s, n) => (s.length >= n ? s : s + " ".repeat(n - s.length));
  const shortType = ct => String(ct || "").split(";")[0].trim().replace(/^application\//, "");
  const statusText = f => [...f.statuses.keys()].map(s => (s === 0 ? "ERR" : String(s))).join(",");

  function queuePrint(f, ev) {
    if (!CONFIG.live || !active) return;
    const prev = pending.get(f);
    if (!prev || EVENT_PRIORITY[ev] > EVENT_PRIORITY[prev]) pending.set(f, ev);
    if (!queuePrint.timer) {
      queuePrint.timer = setT(flush, CONFIG.printDelayMs);
    }
  }

  function flush() {
    queuePrint.timer = null;
    const items = [...pending.entries()];
    pending.clear();
    items.sort((a, b) => compareFindings(a[0], b[0]));
    for (const [f, ev] of items) {
      try { printFinding(f, ev); } catch (e) { fail("print", e); }
    }
  }

  let rateWindowStart = 0;
  let rateCount = 0;
  let rateSuppressed = 0;
  let rateTimer = null;

  function allowPrint() {
    const t = Date.now();
    if (t - rateWindowStart >= CONFIG.livePrintWindowMs) { rateWindowStart = t; rateCount = 0; }
    if (rateCount >= CONFIG.livePrintBudget) {
      rateSuppressed++;
      stats.printSuppressed++;
      if (!rateTimer) {
        rateTimer = setT(() => {
          rateTimer = null;
          if (rateSuppressed > 0 && active) {
            styled("[EASYapi] " + rateSuppressed + " findings not printed (output rate limit). Run EASYapi.report() to see everything.", STYLE.dim);
          }
          rateSuppressed = 0;
        }, CONFIG.livePrintWindowMs);
      }
      return false;
    }
    rateCount++;
    return true;
  }

  function line(label, value) {
    nativeConsole.log("  " + label + ":", value);
  }

  function formatGraphQL(g) {
    return g.operations.map(o => o.type + (o.operation ? " " + o.operation : "")).join(", ") + (g.batched ? " (batched)" : "");
  }

  function printFinding(f, ev) {
    if (!store.has(f.key)) return;
    if (!allowPrint()) return;
    f.printed = true;

    if (ev === "STATUS") {
      styled("  + new status " + (f.lastStatus === 0 ? "ERR" : f.lastStatus) + " on " + f.method + " " + f.host + f.normalizedPath, STYLE.dim);
      return;
    }

    const tag = "[" + (f.confidence === "MEDIUM" ? "MED" : f.confidence) + "]";
    const state = f.observed ? "SEEN" : "REF ";
    const note = ev === "UPGRADED" ? " (upgraded)" : ev === "SEEN" ? " (now observed)" : ev === "METHOD" ? " (method resolved)" : "";
    const st = f.statuses.size ? "  -> " + statusText(f) + (f.responseContentType ? " " + shortType(f.responseContentType) : "") : "";
    const header = tag + " " + state + " " + pad(f.method, 9) + clip(f.examples[0] || f.host + f.normalizedPath, 150)
      + st + (f.count > 1 ? "  x" + f.count : "") + (f.thirdParty ? "  [3P]" : "") + note;

    nativeConsole.groupCollapsed("%c%s", STYLE[f.confidence] || "", header);
    try {
      if (f.normalizedPath !== (parseURL(f.examples[0] || "") || {}).pathname) line("Endpoint", f.method + " " + f.host + f.normalizedPath);
      line("Seen via", [...f.sources].join(", "));
      line("Why", [...f.reasons].join(" | "));
      if (f.queryParams.size) line("Query params", [...f.queryParams].join(", "));
      if (f.graphql) line("GraphQL", formatGraphQL(f.graphql));
      if (f.requestContentType) line("Request type", f.requestContentType);
      if (f.requestBody) line("Request body", f.requestBody);
      if (f.statuses.size > 1) line("Status codes", Object.fromEntries(f.statuses));
      if (CONFIG.showResponseBody && f.responseBody) line("Response preview", f.responseBody);
      if (CONFIG.showRequestHeaders && f.requestHeaders && Object.keys(f.requestHeaders).length) line("Request headers", f.requestHeaders);
      if (f.wsSamples.length) line("WebSocket samples", f.wsSamples);
      if (f.examples.length > 1) line("Other URLs", f.examples.slice(1));
    } finally {
      nativeConsole.groupEnd();
    }
  }

  // ---------------------------------------------------------------------
  // Query, report, export
  // ---------------------------------------------------------------------
  function list(opts) {
    const o = opts || {};
    let arr = [...store.values()];
    if (o.min) { const r = CONF_RANK[String(o.min).toUpperCase()] || 0; arr = arr.filter(f => CONF_RANK[f.confidence] >= r); }
    if (o.observed !== undefined) arr = arr.filter(f => f.observed === !!o.observed);
    if (o.thirdParty !== undefined) arr = arr.filter(f => f.thirdParty === !!o.thirdParty);
    if (o.host) arr = arr.filter(f => f.host.includes(String(o.host).toLowerCase()));
    if (o.method) arr = arr.filter(f => f.method === String(o.method).toUpperCase());
    if (o.search) arr = arr.filter(f => (f.host + f.normalizedPath).toLowerCase().includes(String(o.search).toLowerCase()));
    arr.sort(compareFindings);
    return o.limit ? arr.slice(0, o.limit) : arr;
  }

  function serialize(f, includeDetails) {
    const o = {
      confidence: f.confidence,
      state: f.observed ? "seen" : "referenced",
      method: f.method,
      host: f.host,
      path: f.normalizedPath,
      score: f.score,
      thirdParty: f.thirdParty,
      count: f.count,
      statuses: Object.fromEntries(f.statuses),
      sources: [...f.sources],
      reasons: [...f.reasons],
      queryParams: [...f.queryParams],
      graphql: f.graphql,
      examples: f.examples.slice(),
      requestContentType: f.requestContentType,
      responseContentType: f.responseContentType,
      firstSeen: new Date(f.firstSeen).toISOString(),
      lastSeen: new Date(f.lastSeen).toISOString()
    };
    if (includeDetails) {
      o.requestHeaders = f.requestHeaders;
      o.requestBody = f.requestBody;
      o.responseBody = f.responseBody;
      o.wsSamples = f.wsSamples;
    }
    return o;
  }

  function statsSnapshot() {
    return Object.assign({}, stats, { findings: store.size });
  }

  function report(opts) {
    const arr = list(opts);
    if (!arr.length) { styled("[EASYapi] No findings match.", STYLE.dim); return; }
    const rows = arr.map(f => ({
      conf: f.confidence,
      state: f.observed ? "SEEN" : "REF",
      method: f.method,
      host: f.host,
      path: f.normalizedPath,
      status: statusText(f),
      count: f.count,
      score: f.score,
      "3P": f.thirdParty ? "yes" : "",
      via: [...f.sources].join(",")
    }));
    if (nativeConsole.table) nativeConsole.table(rows);
    else nativeConsole.log(JSON.stringify(rows, null, 2));
    styled("[EASYapi] " + arr.length + " of " + store.size + " findings shown. Sorted by confidence, observed first, then score.", STYLE.dim);
  }

  function exportJSON(opts) {
    const o = opts || {};
    const doc = {
      tool: "EASYapi",
      version: VERSION,
      page: redactHref(location.href),
      exportedAt: new Date().toISOString(),
      stats: statsSnapshot(),
      findings: list(o).map(f => serialize(f, !!o.includeDetails))
    };
    return JSON.stringify(doc, null, o.pretty === false ? 0 : 2);
  }

  function download(opts) {
    try {
      const json = exportJSON(opts);
      const blob = new Blob([json], { type: "application/json" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "easyapi-" + String(location.hostname).replace(/[^a-z0-9.-]/gi, "_") + "-" + Date.now() + ".json";
      (document.body || document.documentElement).appendChild(a);
      a.click();
      a.remove();
      setT(() => URL.revokeObjectURL(a.href), 1000);
    } catch (e) {
      fail("download", e);
      styled("[EASYapi] Download failed. Use copy(EASYapi.export()) instead.", STYLE.dim);
    }
  }

  function help() {
    for (const l of [
      "EASYapi commands",
      "  EASYapi.report({ min: 'MEDIUM', observed: true, host: 'api.', method: 'POST' })",
      "  EASYapi.findings(opts)      array of plain objects",
      "  EASYapi.export({ includeDetails: true })   JSON string, e.g. copy(EASYapi.export())",
      "  EASYapi.download()          save the JSON export as a file",
      "  EASYapi.stats / EASYapi.errors",
      "  EASYapi.config              live settings (minConfidence, thirdParty, redactSensitive, live, debug)",
      "  EASYapi.clear() / EASYapi.stop()"
    ]) nativeConsole.log(l);
  }

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
            // Note: attaching a handler marks p as handled for unhandledrejection purposes.
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
    stats.fetch++;
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
    record(meta);
  }

  function onFetchError(ctx) {
    try {
      if (ctx.requestClone && ctx.requestClone.body) { try { ctx.requestClone.body.cancel().catch(() => {}); } catch (_) {} }
      const info = ctx.bodyInfo;
      record({
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
    const send = function send(body) {
      if (active) {
        try {
          const m = meta.get(this);
          if (m) {
            stats.xhr++;
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
    proto.send = send;
    cleanups.push(() => {
      if (proto.open === open) proto.open = origOpen;
      if (proto.setRequestHeader === setRequestHeader) proto.setRequestHeader = origSetHeader;
      if (proto.send === send) proto.send = origSend;
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
          else if (xhr.responseType === "json" && xhr.response !== null) text = JSON.stringify(xhr.response) || "";
        } catch (_) {}
      }
      record({
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
          stats.beacon++;
          const info = describeBody(data);
          record({
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

  function instrumentSocket(ws, finding) {
    const limit = Math.max(1, Math.floor(CONFIG.maxWsSamples / 2));
    let inCount = 0;
    let outCount = 0;
    const push = (dir, data) => {
      if (finding.wsSamples.length < CONFIG.maxWsSamples) finding.wsSamples.push({ dir, data: describeWsData(data) });
    };
    ws.addEventListener("message", ev => {
      if (!active || inCount >= limit) return;
      inCount++;
      try { push("in", ev.data); } catch (e) { fail("ws.message", e); }
    });
    const origSend = ws.send;
    ws.send = function send(data) {
      if (active && outCount < limit) {
        outCount++;
        try { push("out", data); } catch (e) { fail("ws.send", e); }
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
            stats.websocket++;
            const finding = record({ source: "websocket", url: args[0], method: "WEBSOCKET", observed: true });
            if (finding) instrumentSocket(ws, finding);
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
  // Resource Timing: sees requests made before the script was pasted
  // (URL and status only, limited by the browser's timing buffer).
  // ---------------------------------------------------------------------
  const PERF_API_INITIATORS = new Set(["fetch", "xmlhttprequest", "beacon"]);
  const JS_EXT = /\.m?js(?:[?#]|$)/i;

  function handlePerf(entries) {
    for (const e of entries) {
      const name = e && e.name;
      if (typeof name !== "string") continue;
      if (JS_EXT.test(name)) { enqueueScript(name); continue; }
      if (!PERF_API_INITIATORS.has(e.initiatorType)) continue;
      stats.performance++;
      record({
        source: "performance", url: name, method: "?", observed: true,
        status: typeof e.responseStatus === "number" && e.responseStatus > 0 ? e.responseStatus : undefined
      });
    }
  }

  function startPerformanceObserver() {
    if (!CONFIG.usePerformanceEntries || typeof PerformanceObserver === "undefined") return;
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
    for (const url of extractRefs(text)) {
      stats.scriptRefs++;
      record({ source, url, method: "?", observed: false });
    }
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
      if (!res.ok || /html/i.test(res.headers.get("content-type") || "")) { stats.scriptsSkipped++; return; }
      const text = await res.text();
      if (text.length > CONFIG.maxScriptChars) { stats.scriptsSkipped++; return; }
      stats.scripts++;
      await yieldToMain();
      if (active) recordRefs(text, "javascript");
    } catch (_) {
      stats.scriptsSkipped++;
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
          record({ source: "form", url: action, method: form.getAttribute("method") || "GET", observed: false });
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

  function startMutationObserver() {
    if (typeof MutationObserver === "undefined") return;
    let timer = null;
    const obs = new MutationObserver(() => {
      if (timer) clearT(timer);
      timer = setT(scanDOM, 500);
    });
    // childList only. Observing attributes on the whole document is far too noisy.
    obs.observe(document.documentElement, { childList: true, subtree: true });
    cleanups.push(() => { if (timer) clearT(timer); obs.disconnect(); });
    hooks.push("dom");
  }

  // ---------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------
  function stop(opts) {
    if (!active) return;
    active = false;
    for (const fn of cleanups.splice(0)) { try { fn(); } catch (_) {} }
    pending.clear();
    if (queuePrint.timer) { clearT(queuePrint.timer); queuePrint.timer = null; }
    if (!(opts && opts.silent)) {
      styled("[EASYapi] Stopped. " + store.size + " findings kept. Use EASYapi.report() or EASYapi.export().", STYLE.dim);
    }
  }

  function clear() {
    store.clear();
    pathIndex.clear();
    pending.clear();
  }

  const api = {
    version: VERSION,
    config: CONFIG,
    report,
    findings: opts => list(opts).map(f => serialize(f, !!(opts && opts.includeDetails))),
    export: exportJSON,
    download,
    clear,
    stop,
    help,
    get stats() { return statsSnapshot(); },
    get errors() { return errors.slice(); },
    get hooks() { return hooks.slice(); }
  };

  // ---------------------------------------------------------------------
  // Boot. Each step is isolated so one failure cannot disable the rest.
  // ---------------------------------------------------------------------
  for (const [name, fn] of [
    ["fetch", installFetch], ["xhr", installXHR], ["beacon", installBeacon],
    ["websocket", installWebSocket], ["resource-timing", startPerformanceObserver],
    ["dom", startMutationObserver]
  ]) {
    try { fn(); } catch (e) { fail("install " + name, e); }
  }

  try {
    Object.defineProperty(window, "EASYapi", { value: api, configurable: true, writable: true, enumerable: false });
  } catch (_) {
    window.EASYapi = api;
  }

  styled("[EASYapi] v" + VERSION + " LIVE  (hooks: " + hooks.join(", ") + ")", STYLE.ok);
  nativeConsole.log("Browse the application normally. New API findings appear here. EASYapi.help() lists commands.");

  scanDOM();
})();
