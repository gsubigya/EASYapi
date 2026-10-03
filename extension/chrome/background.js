/*
 * EASYapi background worker.
 *
 * Owns the findings store for every captured tab: ingests observations from
 * the page, scores and merges them, persists them for the session, and answers
 * the UI. Works as a service worker (Chrome, Edge) and an event page (Firefox).
 */
"use strict";

const api = globalThis.browser || globalThis.chrome;
const VERSION = "2.0.0";

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------
const DEFAULT_SETTINGS = {
  redactSensitive: true,
  showResponseBody: true,
  scanJavaScript: true,
  scanForms: true,
  usePerformanceEntries: true,
  followNavigation: true,
  includeDetailsInExport: false
};

let settings = Object.assign({}, DEFAULT_SETTINGS);

function sanitizeSettings(s) {
  const out = Object.assign({}, DEFAULT_SETTINGS);
  if (s && typeof s === "object") {
    for (const k of Object.keys(DEFAULT_SETTINGS)) if (typeof s[k] === "boolean") out[k] = s[k];
  }
  return out;
}

function captureConfig() {
  return {
    redactSensitive: settings.redactSensitive,
    showResponseBody: settings.showResponseBody,
    scanJavaScript: settings.scanJavaScript,
    scanForms: settings.scanForms,
    usePerformanceEntries: settings.usePerformanceEntries
  };
}

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------
const MAX_FINDINGS = 1500;
const MAX_EXAMPLES = 5;
const MAX_WS_SAMPLES = 6;
const MAX_ERRORS = 50;
const MAX_STORED_CHARS = 2500000;
const SAVE_DEBOUNCE_MS = 800;
const PUSH_DEBOUNCE_MS = 250;

const CONF_RANK = { IGNORE: 0, LOW: 1, MEDIUM: 2, HIGH: 3 };

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
const tabs = new Map(); // tabId -> TabState
const timers = new Map(); // "save:ID" | "push:ID" -> timer id
let seq = 0;

function newTabState(id) {
  return {
    id,
    enabled: false,
    startedAt: 0,
    pageUrl: "",
    pageHost: "",
    origins: [],
    findings: new Map(),
    pathIndex: new Map(),
    rev: 0,
    loads: 0,
    persistent: true,
    warn: "",
    frames: {},
    errors: [],
    stats: { observations: 0, ignored: 0, skipped: 0, evicted: 0 },
    truncated: false
  };
}

function getState(id) {
  let st = tabs.get(id);
  if (!st) { st = newTabState(id); tabs.set(id, st); }
  return st;
}

function logError(st, where, err) {
  if (st.errors.length >= MAX_ERRORS) st.errors.shift();
  st.errors.push({ where: String(where).slice(0, 80), message: String((err && err.message) || err).slice(0, 300), at: Date.now() });
}

function addUnique(arr, value, cap) {
  if (arr.length < (cap || 1e9) && !arr.includes(value)) arr.push(value);
}

function str(v, max) {
  return typeof v === "string" ? v.slice(0, max) : "";
}

function clampInt(v, lo, hi) {
  const n = Math.floor(Number(v));
  return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : lo;
}

// ---------------------------------------------------------------------------
// URL helpers
// ---------------------------------------------------------------------------
const WEB_PROTOCOLS = new Set(["http:", "https:", "ws:", "wss:"]);

function parseURL(input) {
  try {
    const u = new URL(String(input));
    return WEB_PROTOCOLS.has(u.protocol) ? u : null;
  } catch (_) {
    return null;
  }
}

function parsePageURL(input) {
  try {
    const u = new URL(String(input));
    return u.protocol === "http:" || u.protocol === "https:" ? u : null;
  } catch (_) {
    return null;
  }
}

function decodeBraces(s) {
  return s.replace(/%7B/gi, "{").replace(/%7D/gi, "}");
}

// Page URL for display. Drops userinfo and the query string and fragment.
function safePageUrl(href) {
  const u = parsePageURL(href);
  return u ? u.protocol + "//" + u.host + u.pathname : "";
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

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------
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
  if (hits.length) {
    const uniq = [...new Set(hits)];
    add(Math.min(uniq.length * 6, 24), "resource:" + uniq.slice(0, 4).join(","));
  }

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

function compareFindings(a, b) {
  return (CONF_RANK[b.confidence] - CONF_RANK[a.confidence])
    || ((b.observed ? 1 : 0) - (a.observed ? 1 : 0))
    || (b.score - a.score)
    || (b.count - a.count)
    || a.host.localeCompare(b.host)
    || a.normalizedPath.localeCompare(b.normalizedPath)
    || a.method.localeCompare(b.method);
}

// ---------------------------------------------------------------------------
// Findings store
// ---------------------------------------------------------------------------
function indexAdd(st, pathKey, key) {
  let set = st.pathIndex.get(pathKey);
  if (!set) { set = new Set(); st.pathIndex.set(pathKey, set); }
  set.add(key);
}

function removeFinding(st, key) {
  const f = st.findings.get(key);
  if (!f) return;
  st.findings.delete(key);
  const pk = f.host + "|" + f.normalizedPath;
  const set = st.pathIndex.get(pk);
  if (set) { set.delete(key); if (!set.size) st.pathIndex.delete(pk); }
}

function specificSiblings(st, pathKey) {
  const keys = st.pathIndex.get(pathKey);
  const out = [];
  if (!keys) return out;
  for (const k of keys) {
    if (k.charAt(0) !== "?") { const f = st.findings.get(k); if (f) out.push(f); }
  }
  return out;
}

function enforceCap(st) {
  while (st.findings.size > MAX_FINDINGS) {
    let worst = null;
    for (const f of st.findings.values()) if (!worst || compareFindings(worst, f) < 0) worst = f;
    if (!worst) break;
    removeFinding(st, worst.key);
    st.stats.evicted++;
  }
}

function cleanMethod(m) {
  const s = typeof m === "string" ? m.toUpperCase() : "?";
  return /^[A-Z_?-]{1,16}$/.test(s) ? s : "?";
}

function cleanGraphQL(g) {
  if (!g || typeof g !== "object" || !Array.isArray(g.operations)) return null;
  const operations = g.operations.slice(0, 10).map(o => ({
    type: str(o && o.type, 20) || "query",
    operation: o && typeof o.operation === "string" ? o.operation.slice(0, 80) : null
  }));
  return operations.length ? { operations, batched: !!g.batched } : null;
}

function cleanHeaders(h) {
  if (!h || typeof h !== "object" || Array.isArray(h)) return null;
  const out = {};
  let n = 0;
  for (const k of Object.keys(h)) {
    if (++n > 40) break;
    if (k === "__proto__") continue;
    out[k.slice(0, 80)] = str(String(h[k]), 300);
  }
  return n ? out : null;
}

// Merges one observation into the tab's store. Returns true when anything changed.
function ingest(st, o) {
  if (!o || typeof o !== "object") return false;
  const ts = Date.now();
  const source = str(o.s, 20) || "unknown";
  const u = parseURL(o.u);
  if (!u) { st.stats.skipped++; return false; }

  const method = cleanMethod(o.m);
  const n = clampInt(o.n, 1, 100000);
  const host = u.host.toLowerCase();
  const hostname = u.hostname.toLowerCase();
  const path = decodeBraces(u.pathname);
  const normalizedPath = normalizePath(path);
  const pathKey = host + "|" + normalizedPath;
  st.stats.observations += n;

  if (method === "WS_SAMPLE") {
    const wf = st.findings.get("WEBSOCKET|" + pathKey);
    if (wf && o.w && typeof o.w === "object" && wf.wsSamples.length < MAX_WS_SAMPLES) {
      wf.wsSamples.push({ dir: o.w.dir === "out" ? "out" : "in", data: str(o.w.data, 400) });
      return true;
    }
    return false;
  }

  const thirdParty = !!st.pageHost && siteOf(hostname) !== siteOf(st.pageHost);
  const status = typeof o.st === "number" && o.st >= 0 && o.st < 1000 ? Math.floor(o.st) : undefined;
  const observed = !!o.ob;
  const graphql = cleanGraphQL(o.gq);
  const qb = str(o.qb, 4000);
  const rb = str(o.rb, 4000);
  const qct = str(o.qct, 120);
  const rct = str(o.rct, 120);

  const scored = scoreFinding({
    path, hostname, method, source, status, graphql,
    hasBody: !!qb, requestContentType: qct, responseContentType: rct
  });

  const key = method + "|" + pathKey;

  // Method-less evidence (resource timing, code references) attaches to an
  // existing method-specific finding instead of creating a guessed "GET".
  if (method === "?") {
    const siblings = specificSiblings(st, pathKey);
    if (siblings.length) {
      for (const f of siblings) {
        addUnique(f.sources, source);
        f.lastSeen = ts;
        if (observed && !f.observed) {
          f.observed = true;
          f.confidence = confidenceFrom(f.score, true);
          f.changedAt = ts;
        }
      }
      return true;
    }
  }

  let f = st.findings.get(key);
  let isNew = false;
  let absorbed = null;

  if (!f) {
    if (method !== "?") absorbed = st.findings.get("?|" + pathKey) || null;
    const score = Math.max(scored.score, absorbed ? absorbed.score : 0);
    const obsv = observed || (absorbed ? absorbed.observed : false);
    const conf = confidenceFrom(score, obsv);
    if (conf === "IGNORE") { st.stats.ignored++; return false; }
    f = {
      id: ++seq, key, method, host, hostname, normalizedPath, thirdParty,
      score, confidence: conf, observed: obsv,
      reasons: [], sources: [], examples: [], queryParams: [], statuses: {},
      requestContentType: "", responseContentType: "", requestHeaders: null,
      requestBody: "", responseBody: "", graphql: null, wsSamples: [], lastStatus: null,
      count: 0, firstSeen: ts, lastSeen: ts, changedAt: ts
    };
    if (absorbed) {
      const perfOnly = absorbed.sources.length === 1 && absorbed.sources[0] === "performance";
      removeFinding(st, absorbed.key);
      f.reasons = absorbed.reasons.slice();
      f.sources = absorbed.sources.slice();
      f.examples = absorbed.examples.slice();
      f.queryParams = absorbed.queryParams.slice();
      if (!perfOnly) { f.count = absorbed.count; f.statuses = Object.assign({}, absorbed.statuses); }
      f.firstSeen = absorbed.firstSeen;
      f.requestBody = absorbed.requestBody;
      f.responseBody = absorbed.responseBody;
    }
    st.findings.set(key, f);
    indexAdd(st, pathKey, key);
    isNew = true;
  }

  const before = { conf: f.confidence, observed: f.observed, hadStatus: status !== undefined && f.statuses[status] !== undefined };

  f.count += n;
  f.lastSeen = ts;
  addUnique(f.sources, source);
  for (const r of scored.reasons) addUnique(f.reasons, r);
  if (scored.score > f.score) f.score = scored.score;
  if (observed) f.observed = true;
  addUnique(f.examples, str(o.u, 2048), MAX_EXAMPLES);
  for (const k of u.searchParams.keys()) addUnique(f.queryParams, k.slice(0, 80), 30);
  if (status !== undefined) {
    f.statuses[status] = (f.statuses[status] || 0) + n;
    f.lastStatus = status;
  }
  if (qct && !f.requestContentType) f.requestContentType = qct;
  if (rct) f.responseContentType = rct;
  if (!f.requestHeaders) f.requestHeaders = cleanHeaders(o.qh);
  if (qb && !f.requestBody) f.requestBody = qb;
  if (rb && !f.responseBody) f.responseBody = rb;
  if (graphql && !f.graphql) f.graphql = graphql;
  f.confidence = confidenceFrom(f.score, f.observed);

  if (isNew
    || (!before.observed && f.observed)
    || CONF_RANK[f.confidence] > CONF_RANK[before.conf]
    || (status !== undefined && !before.hadStatus)) {
    f.changedAt = ts;
  }

  enforceCap(st);
  return true;
}

// ---------------------------------------------------------------------------
// Views for the UI
// ---------------------------------------------------------------------------
function gqlLabel(g) {
  if (!g) return "";
  return g.operations.map(o => o.type + (o.operation ? " " + o.operation : "")).join(", ") + (g.batched ? " (batched)" : "");
}

function summarize(f) {
  return {
    id: f.id,
    conf: f.confidence,
    observed: f.observed,
    method: f.method,
    host: f.host,
    path: f.normalizedPath,
    thirdParty: f.thirdParty,
    score: f.score,
    count: f.count,
    statuses: f.statuses,
    sources: f.sources,
    firstSeen: f.firstSeen,
    lastSeen: f.lastSeen,
    changedAt: f.changedAt,
    url: f.examples[0] || "",
    gql: gqlLabel(f.graphql)
  };
}

function serializeFull(f, includeDetails) {
  const o = {
    confidence: f.confidence,
    state: f.observed ? "seen" : "referenced",
    method: f.method,
    host: f.host,
    path: f.normalizedPath,
    score: f.score,
    thirdParty: f.thirdParty,
    count: f.count,
    statuses: f.statuses,
    sources: f.sources,
    reasons: f.reasons,
    queryParams: f.queryParams,
    graphql: f.graphql,
    examples: f.examples,
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

function counts(st) {
  const c = { total: 0, high: 0, medium: 0, low: 0, seen: 0, ref: 0, thirdParty: 0 };
  for (const f of st.findings.values()) {
    c.total++;
    if (f.confidence === "HIGH") c.high++;
    else if (f.confidence === "MEDIUM") c.medium++;
    else c.low++;
    if (f.observed) c.seen++; else c.ref++;
    if (f.thirdParty) c.thirdParty++;
  }
  return c;
}

function queryFindings(st, filters) {
  const f = filters || {};
  let arr = [...st.findings.values()];
  const min = String(f.min || "ALL").toUpperCase();
  if (min === "HIGH") arr = arr.filter(x => x.confidence === "HIGH");
  else if (min === "MEDIUM") arr = arr.filter(x => CONF_RANK[x.confidence] >= 2);
  const state = String(f.state || "ALL").toUpperCase();
  if (state === "SEEN") arr = arr.filter(x => x.observed);
  else if (state === "REF") arr = arr.filter(x => !x.observed);
  if (f.hide3p) arr = arr.filter(x => !x.thirdParty);
  if (f.method) arr = arr.filter(x => x.method === String(f.method).toUpperCase());
  if (f.q) {
    const q = String(f.q).toLowerCase().slice(0, 200);
    arr = arr.filter(x => (x.method + " " + x.host + x.normalizedPath + " " + x.examples.join(" ")).toLowerCase().includes(q));
  }
  const sort = f.sort || "best";
  if (sort === "recent") arr.sort((a, b) => b.lastSeen - a.lastSeen || compareFindings(a, b));
  else if (sort === "hits") arr.sort((a, b) => b.count - a.count || compareFindings(a, b));
  else if (sort === "path") arr.sort((a, b) => a.host.localeCompare(b.host) || a.normalizedPath.localeCompare(b.normalizedPath) || a.method.localeCompare(b.method));
  else arr.sort(compareFindings);
  return arr;
}

// ---------------------------------------------------------------------------
// Persistence (storage.session, so nothing is written to disk)
// ---------------------------------------------------------------------------
function toStored(st) {
  return {
    id: st.id, enabled: st.enabled, startedAt: st.startedAt, pageUrl: st.pageUrl, pageHost: st.pageHost,
    origins: st.origins, rev: st.rev, loads: st.loads, persistent: st.persistent, warn: st.warn,
    frames: st.frames, errors: st.errors, stats: st.stats, truncated: st.truncated, seq,
    findings: [...st.findings.values()]
  };
}

function fromStored(o) {
  const st = newTabState(o.id);
  for (const k of ["enabled", "startedAt", "pageUrl", "pageHost", "origins", "rev", "loads", "persistent", "warn", "frames", "errors", "stats", "truncated"]) {
    if (o[k] !== undefined) st[k] = o[k];
  }
  if (typeof o.seq === "number" && o.seq > seq) seq = o.seq;
  for (const f of o.findings || []) {
    st.findings.set(f.key, f);
    if (f.id > seq) seq = f.id;
    indexAdd(st, f.host + "|" + f.normalizedPath, f.key);
  }
  return st;
}

function shrink(st) {
  // Drop heavy fields from everything except the best findings, then evict the weakest.
  st.truncated = true;
  const sorted = [...st.findings.values()].sort(compareFindings);
  sorted.forEach((f, i) => {
    if (i >= 100) { f.requestBody = ""; f.responseBody = ""; f.requestHeaders = null; f.wsSamples = []; }
  });
  let size = JSON.stringify(toStored(st)).length;
  while (size > MAX_STORED_CHARS && st.findings.size > 50) {
    const drop = sorted.splice(Math.floor(sorted.length * 0.8));
    for (const f of drop) removeFinding(st, f.key);
    size = JSON.stringify(toStored(st)).length;
  }
}

async function saveTab(st) {
  if (!api.storage || !api.storage.session) return;
  try {
    let data = toStored(st);
    if (JSON.stringify(data).length > MAX_STORED_CHARS) { shrink(st); data = toStored(st); }
    await api.storage.session.set({ ["tab:" + st.id]: data });
  } catch (e) {
    logError(st, "persist", e);
  }
}

function debounce(name, ms, fn) {
  if (timers.has(name)) return;
  timers.set(name, setTimeout(() => { timers.delete(name); try { fn(); } catch (_) {} }, ms));
}

function markChanged(st) {
  st.rev++;
  debounce("save:" + st.id, SAVE_DEBOUNCE_MS, () => saveTab(st));
  debounce("push:" + st.id, PUSH_DEBOUNCE_MS, () => { updateBadge(st); broadcast(st); });
}

function swallow(p) {
  if (p && typeof p.catch === "function") p.catch(() => {});
}

function updateBadge(st) {
  if (!api.action) return;
  const n = st.findings.size;
  const text = n === 0 ? (st.enabled ? "0" : "") : n > 999 ? "999+" : String(n);
  try {
    swallow(api.action.setBadgeText({ tabId: st.id, text }));
    swallow(api.action.setBadgeBackgroundColor({ tabId: st.id, color: st.enabled ? "#0f766e" : "#6b7280" }));
  } catch (_) {}
}

function broadcast(st) {
  try { swallow(api.runtime.sendMessage({ t: "changed", tabId: st.id, rev: st.rev })); } catch (_) {}
}

// ---------------------------------------------------------------------------
// Content script registration (early capture on reload and navigation)
// ---------------------------------------------------------------------------
function hashStr(s) {
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) >>> 0;
  return h.toString(36);
}

// Match patterns ignore ports, so one pattern covers every port of a host.
function originToPattern(origin) {
  const u = parsePageURL(origin);
  return u ? u.protocol + "//" + u.hostname + "/*" : null;
}

async function ensureRegistered(origin) {
  const pattern = originToPattern(origin);
  if (!pattern) throw new Error("Unsupported origin");
  const h = hashStr(pattern);
  const ids = ["ea-main-" + h, "ea-bridge-" + h];
  const existing = await api.scripting.getRegisteredContentScripts({ ids });
  if (existing && existing.length === 2) return;
  if (existing && existing.length) await api.scripting.unregisterContentScripts({ ids: existing.map(s => s.id) });
  await api.scripting.registerContentScripts([
    { id: ids[1], matches: [pattern], js: ["bridge.js"], runAt: "document_start", allFrames: true, world: "ISOLATED", persistAcrossSessions: false },
    { id: ids[0], matches: [pattern], js: ["inject.js"], runAt: "document_start", allFrames: true, world: "MAIN", persistAcrossSessions: false }
  ]);
}

async function pruneRegistrations() {
  try {
    const needed = new Set();
    for (const st of tabs.values()) {
      if (!st.enabled) continue;
      for (const o of st.origins) { const p = originToPattern(o); if (p) needed.add(p); }
    }
    const regs = await api.scripting.getRegisteredContentScripts();
    const stale = (regs || [])
      .filter(r => typeof r.id === "string" && r.id.startsWith("ea-") && !(r.matches || []).some(m => needed.has(m)))
      .map(r => r.id);
    if (stale.length) await api.scripting.unregisterContentScripts({ ids: stale });
  } catch (_) {}
}

async function injectInto(tabId, opts) {
  const o = opts || {};
  const target = o.frameIds ? { tabId, frameIds: o.frameIds } : { tabId, allFrames: true };
  await api.scripting.executeScript({ target, files: ["bridge.js"], world: "ISOLATED", injectImmediately: true });
  try { await api.tabs.sendMessage(tabId, { t: "enable", config: captureConfig() }); } catch (_) {}
  await api.scripting.executeScript({ target, files: ["inject.js"], world: "MAIN", injectImmediately: true });
}

// ---------------------------------------------------------------------------
// Capture control
// ---------------------------------------------------------------------------
async function startCapture(tabId) {
  let tab;
  try { tab = await api.tabs.get(tabId); } catch (_) { return { ok: false, error: "notab", message: "That tab no longer exists." }; }
  const u = parsePageURL(tab.url);
  if (!u) {
    return { ok: false, error: "unsupported", message: "EASYapi can only capture regular web pages (http and https). Browser pages, the extension store and some other pages are off limits." };
  }
  const st = getState(tabId);
  const wasEnabled = st.enabled;
  st.enabled = true;
  st.startedAt = st.startedAt || Date.now();
  st.pageUrl = safePageUrl(tab.url);
  st.pageHost = u.hostname;
  st.warn = "";
  if (!st.origins.includes(u.origin)) st.origins.push(u.origin);

  let registered = true;
  try {
    await ensureRegistered(u.origin);
  } catch (e) {
    registered = false;
    logError(st, "register", e);
  }
  st.persistent = registered;

  let injected = true;
  try {
    await injectInto(tabId);
  } catch (e) {
    injected = false;
    logError(st, "inject", e);
  }

  if (!registered && !injected) {
    st.enabled = wasEnabled;
    markChanged(st);
    return { ok: false, error: "inject", message: "EASYapi could not access this page. Check that the extension has site access, then try again." };
  }
  if (!registered) st.warn = "Capture is running for this page load only. Allow site access for this site, then press Start again to keep capturing across reloads.";
  if (!injected) st.warn = "The page could not be hooked yet. Reload the page to start capturing.";
  markChanged(st);
  return { ok: true };
}

async function stopCapture(tabId) {
  const st = tabs.get(tabId);
  if (!st) return { ok: true };
  st.enabled = false;
  try { await api.tabs.sendMessage(tabId, { t: "stop" }); } catch (_) {}
  await pruneRegistrations();
  markChanged(st);
  return { ok: true };
}

async function removeTab(tabId) {
  const st = tabs.get(tabId);
  tabs.delete(tabId);
  for (const k of ["save:" + tabId, "push:" + tabId]) {
    if (timers.has(k)) { clearTimeout(timers.get(k)); timers.delete(k); }
  }
  try { if (api.storage && api.storage.session) await api.storage.session.remove("tab:" + tabId); } catch (_) {}
  if (st && st.enabled) await pruneRegistrations();
}

function pushConfig() {
  for (const st of tabs.values()) {
    if (!st.enabled) continue;
    try { swallow(api.tabs.sendMessage(st.id, { t: "config", config: captureConfig() })); } catch (_) {}
  }
}

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------
async function loadAll() {
  try {
    const local = await api.storage.local.get("settings");
    settings = sanitizeSettings(local && local.settings);
  } catch (_) {}
  try {
    if (api.storage.session) {
      const all = await api.storage.session.get(null);
      for (const k of Object.keys(all || {})) {
        if (!k.startsWith("tab:")) continue;
        try { const st = fromStored(all[k]); tabs.set(st.id, st); } catch (_) {}
      }
    }
  } catch (_) {}
  try {
    const open = await api.tabs.query({});
    const ids = new Set(open.map(t => t.id));
    for (const id of [...tabs.keys()]) if (!ids.has(id)) await removeTab(id);
  } catch (_) {}
  await pruneRegistrations();
}

const ready = loadAll();

// ---------------------------------------------------------------------------
// Message handling
// ---------------------------------------------------------------------------
function isExtensionPage(sender) {
  try {
    return !!sender && typeof sender.url === "string" && sender.url.startsWith(api.runtime.getURL(""));
  } catch (_) {
    return false;
  }
}

function tabIdOf(msg) {
  const id = Number(msg && msg.tabId);
  return Number.isInteger(id) && id >= 0 ? id : null;
}

function stateView(st, extra) {
  const c = st ? counts(st) : { total: 0, high: 0, medium: 0, low: 0, seen: 0, ref: 0, thirdParty: 0 };
  return Object.assign({
    ok: true,
    version: VERSION,
    enabled: !!(st && st.enabled),
    startedAt: st ? st.startedAt : 0,
    pageUrl: st ? st.pageUrl : "",
    pageHost: st ? st.pageHost : "",
    rev: st ? st.rev : 0,
    loads: st ? st.loads : 0,
    persistent: st ? st.persistent : true,
    warn: st ? st.warn : "",
    truncated: st ? st.truncated : false,
    counts: c
  }, extra || {});
}

const handlers = {
  async hello(msg, sender) {
    const tabId = sender && sender.tab ? sender.tab.id : undefined;
    const st = tabId !== undefined ? tabs.get(tabId) : null;
    if (!st || !st.enabled) return { enabled: false };
    if (sender.frameId === 0 && msg.top) {
      st.loads++;
      const u = parsePageURL(msg.href);
      if (u) { st.pageUrl = safePageUrl(msg.href); st.pageHost = u.hostname; }
      markChanged(st);
    }
    return { enabled: true, config: captureConfig() };
  },

  async obs(msg, sender) {
    const tabId = sender && sender.tab ? sender.tab.id : undefined;
    const st = tabId !== undefined ? tabs.get(tabId) : null;
    if (!st || !st.enabled || typeof msg.d !== "string" || msg.d.length > 1500000) return { ok: false };
    let payload;
    try { payload = JSON.parse(msg.d); } catch (_) { return { ok: false }; }
    if (!payload || payload.v !== 1) return { ok: false };
    let changed = false;
    if (Array.isArray(payload.obs)) {
      for (const o of payload.obs.slice(0, 500)) {
        try { if (ingest(st, o)) changed = true; } catch (e) { logError(st, "ingest", e); }
      }
    }
    if (payload.info && typeof payload.info === "object") {
      const origin = str(payload.info.origin, 200) || "unknown";
      if (Object.keys(st.frames).length < 20 || st.frames[origin]) {
        st.frames[origin] = {
          hooks: Array.isArray(payload.info.hooks) ? payload.info.hooks.slice(0, 10).map(h => str(h, 30)) : [],
          top: !!payload.info.top,
          at: Date.now()
        };
        changed = true;
      }
    }
    if (Array.isArray(payload.errs)) {
      for (const e of payload.errs.slice(0, 10)) logError(st, "page:" + str(e && e.where, 60), str(e && e.message, 200));
    }
    if (changed) markChanged(st);
    return { ok: true };
  }
};

const uiHandlers = {
  async state(msg) {
    const tabId = tabIdOf(msg);
    if (tabId === null) return { ok: false, error: "badtab" };
    return stateView(tabs.get(tabId));
  },

  async list(msg) {
    const tabId = tabIdOf(msg);
    const st = tabId === null ? null : tabs.get(tabId);
    if (!st) return { ok: true, rev: 0, total: 0, matched: 0, items: [] };
    const all = queryFindings(st, msg.filters);
    const limit = clampInt(msg.limit || 200, 1, 100000);
    return { ok: true, rev: st.rev, total: st.findings.size, matched: all.length, items: all.slice(0, limit).map(summarize) };
  },

  async detail(msg) {
    const tabId = tabIdOf(msg);
    const st = tabId === null ? null : tabs.get(tabId);
    if (!st) return { ok: false };
    for (const f of st.findings.values()) if (f.id === msg.id) return { ok: true, finding: f };
    return { ok: false };
  },

  async start(msg) {
    const tabId = tabIdOf(msg);
    if (tabId === null) return { ok: false, error: "badtab" };
    return startCapture(tabId);
  },

  async stop(msg) {
    const tabId = tabIdOf(msg);
    if (tabId === null) return { ok: false, error: "badtab" };
    return stopCapture(tabId);
  },

  async clear(msg) {
    const tabId = tabIdOf(msg);
    const st = tabId === null ? null : tabs.get(tabId);
    if (!st) return { ok: true };
    st.findings.clear();
    st.pathIndex.clear();
    st.truncated = false;
    st.errors = [];
    st.stats = { observations: 0, ignored: 0, skipped: 0, evicted: 0 };
    markChanged(st);
    return { ok: true };
  },

  async export(msg) {
    const tabId = tabIdOf(msg);
    const st = tabId === null ? null : tabs.get(tabId);
    if (!st) return { ok: false, error: "nodata" };
    const includeDetails = typeof msg.includeDetails === "boolean" ? msg.includeDetails : settings.includeDetailsInExport;
    const doc = {
      tool: "EASYapi",
      version: VERSION,
      page: st.pageUrl,
      exportedAt: new Date().toISOString(),
      redaction: settings.redactSensitive,
      stats: Object.assign({}, st.stats, { findings: st.findings.size }),
      findings: queryFindings(st, msg.filters).map(f => serializeFull(f, includeDetails))
    };
    return { ok: true, json: JSON.stringify(doc, null, 2), host: st.pageHost };
  },

  async settings(msg) {
    if (msg.set && typeof msg.set === "object") {
      settings = sanitizeSettings(Object.assign({}, settings, msg.set));
      try { await api.storage.local.set({ settings }); } catch (_) {}
      pushConfig();
    }
    return { ok: true, settings };
  },

  async diag(msg) {
    const tabId = tabIdOf(msg);
    const st = tabId === null ? null : tabs.get(tabId);
    let registered = 0;
    try {
      const regs = await api.scripting.getRegisteredContentScripts();
      registered = (regs || []).filter(r => typeof r.id === "string" && r.id.startsWith("ea-")).length;
    } catch (_) {}
    return {
      ok: true,
      version: VERSION,
      registeredScripts: registered,
      state: st ? {
        enabled: st.enabled, startedAt: st.startedAt, loads: st.loads, persistent: st.persistent,
        origins: st.origins, frames: st.frames, stats: st.stats, truncated: st.truncated, counts: counts(st)
      } : null,
      errors: st ? st.errors.slice(-20) : []
    };
  },

  async tabs() {
    const out = [];
    for (const st of tabs.values()) {
      if (!st.enabled && !st.findings.size) continue;
      let title = "";
      try { const t = await api.tabs.get(st.id); title = t.title || ""; } catch (_) {}
      out.push({ id: st.id, title, host: st.pageHost, enabled: st.enabled, count: st.findings.size });
    }
    return { ok: true, tabs: out };
  }
};

api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || typeof msg !== "object" || typeof msg.t !== "string") return false;
  let fn = null;
  if (msg.t === "hello" || msg.t === "obs") {
    if (sender && sender.tab) fn = handlers[msg.t];
  } else if (Object.prototype.hasOwnProperty.call(uiHandlers, msg.t) && isExtensionPage(sender)) {
    fn = uiHandlers[msg.t];
  }
  if (!fn) return false;
  (async () => {
    await ready;
    return fn(msg, sender);
  })().then(sendResponse, err => sendResponse({ ok: false, error: String((err && err.message) || err) }));
  return true;
});

// ---------------------------------------------------------------------------
// Browser events
// ---------------------------------------------------------------------------
api.tabs.onRemoved.addListener(tabId => {
  ready.then(() => removeTab(tabId)).catch(() => {});
});

if (api.webNavigation && api.webNavigation.onCommitted) {
  api.webNavigation.onCommitted.addListener(async details => {
    if (details.frameId !== 0) return;
    await ready;
    const st = tabs.get(details.tabId);
    if (!st || !st.enabled) return;
    const u = parsePageURL(details.url);
    if (!u) return;
    st.pageUrl = safePageUrl(details.url);
    st.pageHost = u.hostname;
    if (st.origins.includes(u.origin) || !settings.followNavigation) return;
    st.origins.push(u.origin);
    try { await ensureRegistered(u.origin); } catch (e) { logError(st, "register", e); }
    try { await injectInto(details.tabId, { frameIds: [0] }); } catch (e) { logError(st, "inject", e); }
    markChanged(st);
  });
}

if (api.runtime.onInstalled) {
  api.runtime.onInstalled.addListener(() => {
    ready.then(() => pruneRegistrations()).catch(() => {});
  });
}
