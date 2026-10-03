/*
 * EASYapi UI. One page used as the toolbar popup and as a full-tab view.
 * All data is rendered with textContent, never innerHTML, because the strings
 * come from web pages.
 */
(() => {
  "use strict";

  const api = globalThis.browser || globalThis.chrome;
  const params = new URLSearchParams(location.search);
  const FULL = params.has("full");
  document.documentElement.classList.add(FULL ? "full" : "popup");

  const $ = id => document.getElementById(id);

  const S = {
    tabId: params.has("tab") ? Number(params.get("tab")) : null,
    tabUrl: "",
    st: null,
    list: null,
    settings: null,
    view: "endpoints",
    filters: { q: "", min: "ALL", state: "ALL", hide3p: false, sort: "best" },
    limit: 200,
    lastRev: -1,
    refreshing: false,
    again: false,
    rows: new Map(),
    dismissedReload: false,
    clearArmed: false,
    toastTimer: null,
    searchTimer: null,
    lastPush: 0,
    pushTimer: null,
    firstRender: true
  };

  // -------------------------------------------------------------------
  // Small helpers
  // -------------------------------------------------------------------
  function h(tag, props, ...kids) {
    const e = document.createElement(tag);
    if (props) {
      for (const k of Object.keys(props)) {
        const v = props[k];
        if (v === undefined || v === null || v === false) continue;
        if (k === "class") e.className = v;
        else if (k === "text") e.textContent = v;
        else if (k.slice(0, 2) === "on") e.addEventListener(k.slice(2), v);
        else e.setAttribute(k, v === true ? "" : String(v));
      }
    }
    for (const kid of kids) {
      if (kid === null || kid === undefined || kid === false) continue;
      e.appendChild(typeof kid === "string" ? document.createTextNode(kid) : kid);
    }
    return e;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  async function send(msg) {
    try {
      const r = await api.runtime.sendMessage(msg);
      return r === undefined ? { ok: false, error: "No response from the background worker." } : r;
    } catch (e) {
      return { ok: false, error: String((e && e.message) || e) };
    }
  }

  function toast(text) {
    const el = $("toast");
    el.textContent = text;
    el.hidden = false;
    if (S.toastTimer) clearTimeout(S.toastTimer);
    S.toastTimer = setTimeout(() => { el.hidden = true; }, 2600);
  }

  function ago(ts) {
    if (!ts) return "";
    const s = Math.max(0, Math.round((Date.now() - ts) / 1000));
    if (s < 5) return "just now";
    if (s < 60) return s + "s ago";
    if (s < 3600) return Math.floor(s / 60) + "m ago";
    if (s < 86400) return Math.floor(s / 3600) + "h ago";
    return Math.floor(s / 86400) + "d ago";
  }

  function pretty(text) {
    if (!text) return "";
    try { return JSON.stringify(JSON.parse(text), null, 2); } catch (_) { return text; }
  }

  async function copyText(text, label) {
    try {
      await navigator.clipboard.writeText(text);
      toast((label || "Text") + " copied");
      return;
    } catch (_) {}
    try {
      const ta = h("textarea", { style: "position:fixed;left:-9999px;top:0" });
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand("copy");
      document.body.removeChild(ta);
      toast(ok ? (label || "Text") + " copied" : "Copy failed");
    } catch (_) {
      toast("Copy failed");
    }
  }

  function saveFile(name, mime, text) {
    try {
      const url = URL.createObjectURL(new Blob([text], { type: mime }));
      const a = h("a", { href: url, download: name });
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 2000);
      toast("Saved " + name);
    } catch (e) {
      toast("Download failed");
    }
  }

  const SOURCE_NAMES = {
    fetch: "Fetch", xhr: "XHR", beacon: "Beacon", websocket: "WebSocket",
    performance: "Resource timing", javascript: "Code reference", form: "Form action"
  };
  const CONF_NAMES = { HIGH: "High", MEDIUM: "Medium", LOW: "Low" };

  function statusClass(code) {
    const n = Number(code);
    if (n === 0) return "s0";
    return "s" + Math.floor(n / 100);
  }

  function statusLabel(code) {
    return Number(code) === 0 ? "ERR" : String(code);
  }

  function sortedStatuses(obj) {
    return Object.keys(obj || {}).map(Number).sort((a, b) => a - b);
  }

  function prefsLoad() {
    try {
      const raw = localStorage.getItem("easyapi.filters");
      if (raw) {
        const p = JSON.parse(raw);
        for (const k of ["min", "state", "sort"]) if (typeof p[k] === "string") S.filters[k] = p[k];
        if (typeof p.hide3p === "boolean") S.filters.hide3p = p.hide3p;
      }
    } catch (_) {}
  }

  function prefsSave() {
    try {
      const f = S.filters;
      localStorage.setItem("easyapi.filters", JSON.stringify({ min: f.min, state: f.state, sort: f.sort, hide3p: f.hide3p }));
    } catch (_) {}
  }

  function tabPattern() {
    try {
      const u = new URL(S.tabUrl);
      if (u.protocol !== "http:" && u.protocol !== "https:") return null;
      return u.protocol + "//" + u.hostname + "/*";
    } catch (_) {
      return null;
    }
  }

  function isSupportedUrl() {
    if (!S.tabUrl) return true; // unknown, let the background decide
    return tabPattern() !== null;
  }

  // -------------------------------------------------------------------
  // Data
  // -------------------------------------------------------------------
  async function resolveTab() {
    try {
      let tab = null;
      if (S.tabId !== null && Number.isInteger(S.tabId)) {
        tab = await api.tabs.get(S.tabId);
      } else {
        const found = await api.tabs.query({ active: true, currentWindow: true });
        tab = found && found[0];
        if (tab) S.tabId = tab.id;
      }
      S.tabUrl = (tab && tab.url) || "";
      return tab;
    } catch (_) {
      return null;
    }
  }

  async function refresh(force) {
    if (S.refreshing) { S.again = true; return; }
    S.refreshing = true;
    try {
      if (S.tabId === null || !Number.isInteger(S.tabId)) await resolveTab();
      if (S.tabId === null) { renderAll(); return; }
      const st = await send({ t: "state", tabId: S.tabId });
      if (!st || st.ok === false) { S.st = null; renderAll(); return; }
      const needList = force || st.rev !== S.lastRev || !S.list;
      S.st = st;
      if (needList) {
        const list = await send({ t: "list", tabId: S.tabId, filters: S.filters, limit: S.limit });
        if (list && list.ok !== false) { S.list = list; S.lastRev = st.rev; }
      }
      if (S.view === "diag") S.diag = await send({ t: "diag", tabId: S.tabId });
      renderAll();
    } finally {
      S.refreshing = false;
      if (S.again) { S.again = false; refresh(false); }
    }
  }

  // -------------------------------------------------------------------
  // Rendering: header, target card, banners
  // -------------------------------------------------------------------
  function renderHeader() {
    const st = S.st;
    const on = !!(st && st.enabled);
    const btn = $("toggle");
    btn.textContent = on ? "Stop capture" : "Start capture";
    btn.className = "btn btn-primary" + (on ? " is-running" : "");
    btn.disabled = !isSupportedUrl();

    const pill = $("pill");
    let label = "Off";
    let cls = "pill pill-off";
    if (on) { label = "Capturing"; cls = "pill pill-on"; if (st.warn) { label = "Limited"; cls = "pill pill-warn"; } }
    else if (st && st.counts.total) { label = "Stopped"; }
    pill.textContent = label;
    pill.className = cls;

    let host = (st && st.pageHost) || "";
    let url = (st && st.pageUrl) || "";
    if (!host && S.tabUrl) {
      try { const u = new URL(S.tabUrl); host = u.hostname; url = u.protocol + "//" + u.host + u.pathname; } catch (_) {}
    }
    $("host").textContent = host || "No page selected";
    $("url").textContent = url;
    $("avatar").textContent = (host.replace(/^www\./, "")[0] || "E");
    $("tabCount").hidden = !(st && st.counts.total);
    $("tabCount").textContent = st ? String(st.counts.total) : "";
  }

  function renderStats() {
    const c = (S.st && S.st.counts) || { total: 0, high: 0, medium: 0, low: 0, seen: 0, ref: 0 };
    const tiles = [
      ["Endpoints", c.total], ["High", c.high], ["Medium", c.medium],
      ["Low", c.low], ["Seen", c.seen], ["Referenced", c.ref]
    ];
    const box = $("stats");
    clear(box);
    for (const [label, value] of tiles) {
      box.appendChild(h("div", { class: "stat" },
        h("div", { class: "stat-value", text: String(value) }),
        h("div", { class: "stat-label", text: label })));
    }
  }

  function renderBanners() {
    const box = $("banners");
    clear(box);
    const st = S.st;
    if (!isSupportedUrl()) {
      box.appendChild(h("div", { class: "banner banner-warn" },
        h("div", { class: "banner-text", text: "EASYapi can only capture regular web pages (http and https). Open the site you want to test, then click the EASYapi icon." })));
      return;
    }
    if (st && st.enabled && st.warn) {
      box.appendChild(h("div", { class: "banner banner-warn" }, h("div", { class: "banner-text", text: st.warn })));
    }
    if (st && st.enabled && st.loads <= 1 && !S.dismissedReload) {
      box.appendChild(h("div", { class: "banner banner-info" },
        h("div", { class: "banner-text", text: "Capture is on. Reload the page to catch requests made during page load." }),
        h("div", { class: "banner-actions" },
          h("button", { class: "btn", type: "button", text: "Reload", onclick: onReload }),
          h("button", { class: "btn btn-ghost", type: "button", text: "Dismiss", onclick: () => { S.dismissedReload = true; renderBanners(); } }))));
    }
    if (st && st.truncated) {
      box.appendChild(h("div", { class: "banner banner-info" },
        h("div", { class: "banner-text", text: "This tab collected a lot of data. Older bodies and some low ranked findings were trimmed to stay within browser storage limits." })));
    }
  }

  // -------------------------------------------------------------------
  // Rendering: filters
  // -------------------------------------------------------------------
  function buildSegment(containerId, options, key) {
    const box = $(containerId);
    clear(box);
    for (const [value, label] of options) {
      box.appendChild(h("button", {
        type: "button", "data-value": value, "aria-pressed": S.filters[key] === value ? "true" : "false", text: label,
        onclick: () => {
          S.filters[key] = value;
          prefsSave();
          buildSegment(containerId, options, key);
          S.limit = 200;
          refresh(true);
        }
      }));
    }
  }

  function buildFilters() {
    buildSegment("segMin", [["ALL", "All"], ["MEDIUM", "Medium+"], ["HIGH", "High"]], "min");
    buildSegment("segState", [["ALL", "Any"], ["SEEN", "Seen"], ["REF", "Referenced"]], "state");
    $("sort").value = S.filters.sort;
    $("hide3p").checked = S.filters.hide3p;
  }

  // -------------------------------------------------------------------
  // Rendering: endpoint list
  // -------------------------------------------------------------------
  function methodClass(m) {
    return "method m-" + String(m).toLowerCase().replace(/[^a-z]/g, "");
  }

  function makeRow(item) {
    const main = h("button", { class: "ep-main", type: "button", "aria-expanded": "false" });
    const detail = h("div", { class: "ep-detail", hidden: true });
    const li = h("li", { class: "card ep" }, main, detail);
    const row = { id: item.id, li, main, detail, item: null, sig: "", expanded: false, detailSeen: 0, loading: false };
    main.addEventListener("click", () => toggleRow(row));
    return row;
  }

  function updateRow(row, item, isFresh) {
    row.item = item;
    const sig = [item.conf, item.observed, item.method, item.path, item.host, item.count, item.thirdParty, JSON.stringify(item.statuses)].join("|");
    if (sig === row.sig) return;
    row.sig = sig;
    const m = row.main;
    clear(m);

    const statuses = sortedStatuses(item.statuses);
    const shown = statuses.slice(0, 2).map(code => h("span", { class: "status " + statusClass(code), text: statusLabel(code) }));
    if (statuses.length > 2) shown.push(h("span", { class: "hits", text: "+" + (statuses.length - 2) }));

    const side = h("span", { class: "ep-side" },
      h("span", { class: "tag tag-" + item.conf.toLowerCase(), text: CONF_NAMES[item.conf] || item.conf }),
      h("span", { class: "tag " + (item.observed ? "tag-seen" : "tag-ref"), text: item.observed ? "Seen" : "Referenced" }),
      item.thirdParty ? h("span", { class: "tag tag-ref", text: "3P" }) : null,
      item.gql ? h("span", { class: "tag tag-ref", text: "GraphQL" }) : null);

    m.appendChild(h("span", { class: methodClass(item.method), text: item.method === "?" ? "ANY" : item.method }));
    m.appendChild(h("span", { class: "ep-text" },
      h("span", { class: "ep-path", text: item.path, title: item.path }),
      h("span", { class: "ep-host", text: item.host })));
    m.appendChild(side);
    m.appendChild(h("span", { class: "ep-meta" }, ...shown,
      h("span", { class: "hits", text: item.count + (item.count === 1 ? " hit" : " hits") })));
    m.appendChild(h("span", { class: "chev", "aria-hidden": "true" }));

    if (isFresh && !S.firstRender && Date.now() - item.changedAt < 4000) {
      row.li.classList.add("is-new");
      setTimeout(() => row.li.classList.remove("is-new"), 2600);
    }
    if (row.expanded && item.lastSeen !== row.detailSeen) loadDetail(row);
  }

  async function toggleRow(row) {
    row.expanded = !row.expanded;
    row.main.setAttribute("aria-expanded", row.expanded ? "true" : "false");
    row.detail.hidden = !row.expanded;
    if (row.expanded) await loadDetail(row);
  }

  async function loadDetail(row) {
    if (row.loading) return;
    row.loading = true;
    try {
      const r = await send({ t: "detail", tabId: S.tabId, id: row.id });
      if (r && r.ok && r.finding) {
        row.detailSeen = r.finding.lastSeen;
        renderDetail(row, r.finding);
      } else {
        clear(row.detail);
        row.detail.appendChild(h("p", { class: "muted", text: "Details are no longer available for this endpoint." }));
      }
    } finally {
      row.loading = false;
    }
  }

  function kvRow(label, content) {
    return h("div", { class: "kv-row" }, h("dt", { text: label }), h("dd", null, content));
  }

  function chips(values, mono) {
    return h("div", { class: "chips" }, ...values.map(v => h("span", { class: "chip" + (mono ? " chip-mono" : ""), text: v })));
  }

  function renderDetail(row, f) {
    const d = row.detail;
    clear(d);
    const dl = h("dl", { class: "kv" });

    const urls = h("div", null, ...f.examples.map(u => h("div", { class: "url-line" },
      h("span", { class: "mono", text: u }),
      h("button", { class: "btn btn-ghost", type: "button", text: "Copy", onclick: () => copyText(u, "URL") }))));
    dl.appendChild(kvRow(f.examples.length > 1 ? "URLs" : "URL", urls));
    dl.appendChild(kvRow("Endpoint", h("span", { class: "mono", text: f.method + " " + f.host + f.normalizedPath })));
    dl.appendChild(kvRow("Seen via", chips(f.sources.map(s => SOURCE_NAMES[s] || s))));
    if (f.reasons.length) dl.appendChild(kvRow("Why flagged", chips(f.reasons)));
    if (f.queryParams.length) dl.appendChild(kvRow("Query params", chips(f.queryParams, true)));
    if (f.graphql) {
      dl.appendChild(kvRow("GraphQL", chips(f.graphql.operations.map(o => o.type + (o.operation ? " " + o.operation : "")).concat(f.graphql.batched ? ["batched"] : []))));
    }
    const codes = sortedStatuses(f.statuses);
    if (codes.length) {
      dl.appendChild(kvRow("Status codes", h("div", { class: "chips" }, ...codes.map(c =>
        h("span", { class: "chip" }, h("span", { class: "status " + statusClass(c), text: statusLabel(c) }), " x" + f.statuses[c])))));
    }
    if (f.requestContentType) dl.appendChild(kvRow("Request type", h("span", { class: "mono", text: f.requestContentType })));
    if (f.responseContentType) dl.appendChild(kvRow("Response type", h("span", { class: "mono", text: f.responseContentType })));
    if (f.requestHeaders && Object.keys(f.requestHeaders).length) {
      dl.appendChild(kvRow("Request headers", h("pre", { text: Object.keys(f.requestHeaders).map(k => k + ": " + f.requestHeaders[k]).join("\n") })));
    }
    if (f.requestBody) dl.appendChild(kvRow("Request body", h("pre", { text: pretty(f.requestBody) })));
    if (f.responseBody) dl.appendChild(kvRow("Response preview", h("pre", { text: pretty(f.responseBody) })));
    if (f.wsSamples && f.wsSamples.length) {
      dl.appendChild(kvRow("WebSocket", h("pre", { text: f.wsSamples.map(s => (s.dir === "out" ? "sent: " : "received: ") + s.data).join("\n") })));
    }
    dl.appendChild(kvRow("First seen", h("span", { text: ago(f.firstSeen) })));
    dl.appendChild(kvRow("Last seen", h("span", { text: ago(f.lastSeen) })));
    d.appendChild(dl);

    d.appendChild(h("div", { class: "detail-actions" },
      h("button", { class: "btn", type: "button", text: "Copy URL", onclick: () => copyText(f.examples[0] || "", "URL") }),
      h("button", { class: "btn", type: "button", text: "Copy endpoint", onclick: () => copyText(f.method + " " + f.host + f.normalizedPath, "Endpoint") }),
      h("button", { class: "btn", type: "button", text: "Copy as JSON", onclick: () => copyText(JSON.stringify(f, null, 2), "Finding") })));
  }

  function renderEmpty() {
    const box = $("empty");
    const st = S.st;
    const list = S.list;
    const on = !!(st && st.enabled);
    const total = st ? st.counts.total : 0;
    const matched = list ? list.matched : 0;
    clear(box);

    if (!isSupportedUrl()) { box.hidden = true; return; }
    if (matched > 0) { box.hidden = true; return; }
    box.hidden = false;

    if (total > 0) {
      box.appendChild(h("div", { class: "empty-title", text: "No findings match these filters" }));
      box.appendChild(h("button", { class: "btn", type: "button", text: "Reset filters", onclick: resetFilters }));
    } else if (on) {
      box.appendChild(h("div", { class: "empty-title", text: "Waiting for API activity" }));
      box.appendChild(h("div", { text: "Use the site normally, or reload the page. New endpoints appear here as they are found." }));
    } else {
      box.appendChild(h("div", { class: "empty-title", text: "Capture is off for this tab" }));
      box.appendChild(h("div", { text: "EASYapi watches the API traffic of the current page. It only runs when you start it." }));
      box.appendChild(h("ol", { class: "empty-steps" },
        h("li", { text: "Press Start capture." }),
        h("li", { text: "Reload the page to include requests made during page load." }),
        h("li", { text: "Browse the site. Endpoints are ranked as they appear." })));
    }
  }

  function renderList() {
    const items = (S.list && S.list.items) || [];
    const listEl = $("list");
    const seen = new Set();
    const ordered = [];
    for (const item of items) {
      let row = S.rows.get(item.id);
      const fresh = !row;
      if (!row) { row = makeRow(item); S.rows.set(item.id, row); }
      updateRow(row, item, fresh);
      seen.add(item.id);
      ordered.push(row);
    }
    for (const [id, row] of [...S.rows]) {
      if (!seen.has(id)) { if (row.li.parentNode) listEl.removeChild(row.li); S.rows.delete(id); }
    }
    let ref = listEl.firstChild;
    for (const row of ordered) {
      if (ref === row.li) ref = ref.nextSibling;
      else listEl.insertBefore(row.li, ref);
    }
    const matched = S.list ? S.list.matched : 0;
    $("more").hidden = !(matched > items.length);
    if (!$("more").hidden) $("more").textContent = "Show more (" + (matched - items.length) + " remaining)";
    const hasData = !!(S.st && S.st.counts.total);
    $("actions").hidden = !hasData;
  }

  // -------------------------------------------------------------------
  // Rendering: settings and diagnostics
  // -------------------------------------------------------------------
  const SETTING_DEFS = [
    ["redactSensitive", "Redact sensitive values", "Masks passwords, tokens, API keys, cookies and similar values before anything is stored or shown. Recommended."],
    ["showResponseBody", "Capture response previews", "Keeps the first part of text and JSON responses so you can see what an endpoint returns."],
    ["scanJavaScript", "Scan JavaScript for API paths", "Re-reads the page's own script files, normally from the browser cache, to find endpoints that were not called yet."],
    ["scanForms", "Scan form actions", "Lists the targets of forms on the page."],
    ["usePerformanceEntries", "Use resource timing", "Picks up API requests made before capture started. URL and status only."],
    ["followNavigation", "Follow navigation to other sites", "Keep capturing when this tab moves to a different site."],
    ["includeDetailsInExport", "Include headers and bodies in exports", "Exports then contain redacted request headers, request bodies and response previews. Review before sharing."]
  ];

  function renderSettings() {
    const box = $("settingsList");
    clear(box);
    const s = S.settings || {};
    for (const [key, title, help] of SETTING_DEFS) {
      const input = h("input", { type: "checkbox", "aria-label": title });
      input.checked = !!s[key];
      input.addEventListener("change", async () => {
        const r = await send({ t: "settings", set: { [key]: input.checked } });
        if (r && r.settings) S.settings = r.settings;
        toast("Setting saved");
      });
      box.appendChild(h("div", { class: "setting" },
        h("div", null,
          h("div", { class: "setting-title", text: title }),
          h("div", { class: "setting-help", text: help })),
        h("label", { class: "switch" }, input, h("span"))));
    }
  }

  async function renderAccess() {
    const text = $("accessText");
    const btn = $("grant");
    const pattern = tabPattern();
    if (!pattern) {
      text.textContent = "Open a regular web page to manage site access.";
      btn.hidden = true;
      return;
    }
    let granted = true;
    try {
      if (api.permissions && api.permissions.contains) granted = await api.permissions.contains({ origins: [pattern] });
    } catch (_) {}
    let host = "";
    try { host = new URL(S.tabUrl).hostname; } catch (_) {}
    text.textContent = granted
      ? "EASYapi has access to " + host + ". Capture keeps running across reloads and navigation."
      : "EASYapi does not have access to " + host + " yet. Without it, capture cannot start on page load.";
    btn.hidden = granted;
  }

  function renderDiag() {
    const d = S.diag;
    const status = $("diagStatus");
    clear(status);
    const st = d && d.state;
    const rows = [
      ["Version", d ? d.version : "Unknown"],
      ["Capture", st ? (st.enabled ? "On" : "Off") : "Never started on this tab"],
      ["Early capture", st ? (st.persistent ? "Registered for this site" : "Not registered (this page load only)") : "Not applicable"],
      ["Page loads seen", st ? String(st.loads) : "0"],
      ["Observations", st ? String(st.stats.observations) : "0"],
      ["Ignored as noise", st ? String(st.stats.ignored) : "0"],
      ["Skipped", st ? String(st.stats.skipped) : "0"],
      ["Evicted", st ? String(st.stats.evicted) : "0"],
      ["Registered scripts", d ? String(d.registeredScripts) : "0"]
    ];
    for (const [k, v] of rows) status.appendChild(kvRow(k, h("span", { text: v })));

    const frames = $("diagFrames");
    clear(frames);
    const list = st ? Object.keys(st.frames) : [];
    if (!list.length) frames.textContent = "No frames reported yet.";
    for (const origin of list) {
      const fr = st.frames[origin];
      frames.appendChild(h("div", { class: "frame-item" },
        h("div", { class: "mono", text: origin + (fr.top ? " (top frame)" : "") }),
        h("div", { class: "muted", text: "Hooks: " + (fr.hooks.join(", ") || "none") })));
    }

    const errs = $("diagErrors");
    clear(errs);
    const errors = (d && d.errors) || [];
    if (!errors.length) errs.textContent = "No errors.";
    for (const e of errors) {
      errs.appendChild(h("div", { class: "error-item" },
        h("div", { class: "error-where", text: e.where }),
        h("div", { class: "muted", text: e.message })));
    }
  }

  async function renderTabSelect() {
    const sel = $("tabSelect");
    if (!FULL) { sel.hidden = true; return; }
    const r = await send({ t: "tabs" });
    const tabs = (r && r.tabs) || [];
    if (tabs.length < 2) { sel.hidden = true; return; }
    clear(sel);
    for (const t of tabs) {
      const opt = h("option", { value: String(t.id), text: (t.title || t.host || "Tab " + t.id) + " (" + t.count + ")" });
      if (t.id === S.tabId) opt.selected = true;
      sel.appendChild(opt);
    }
    sel.value = String(S.tabId);
    sel.hidden = false;
  }

  // -------------------------------------------------------------------
  // View switching and render
  // -------------------------------------------------------------------
  function setView(name) {
    S.view = name;
    for (const v of ["endpoints", "settings", "diag"]) {
      $("view-" + v).hidden = v !== name;
      $("tab-" + v).setAttribute("aria-selected", v === name ? "true" : "false");
    }
    if (name === "settings") { renderSettings(); renderAccess(); }
    if (name === "diag") refresh(false);
  }

  function renderAll() {
    renderHeader();
    renderStats();
    renderBanners();
    renderEmpty();
    renderList();
    if (S.view === "diag") renderDiag();
    S.firstRender = false;
  }

  // -------------------------------------------------------------------
  // Actions
  // -------------------------------------------------------------------
  function resetFilters() {
    S.filters = { q: "", min: "ALL", state: "ALL", hide3p: false, sort: "best" };
    $("search").value = "";
    buildFilters();
    prefsSave();
    refresh(true);
  }

  async function onToggle() {
    if (S.tabId === null) await resolveTab();
    if (S.tabId === null) { toast("No tab selected"); return; }
    if (S.st && S.st.enabled) {
      await send({ t: "stop", tabId: S.tabId });
      toast("Capture stopped");
      await refresh(true);
      return;
    }
    // Ask for site access first, directly inside the click, so the browser accepts the gesture.
    const pattern = tabPattern();
    if (pattern && api.permissions && api.permissions.request) {
      let granted = true;
      try { granted = await api.permissions.request({ origins: [pattern] }); } catch (_) { granted = true; }
      if (!granted) { toast("Site access was not granted"); return; }
    }
    const r = await send({ t: "start", tabId: S.tabId });
    if (!r || r.ok === false) {
      toast((r && r.message) || "Could not start capture");
    } else {
      S.dismissedReload = false;
      toast("Capture started");
    }
    await refresh(true);
  }

  async function onReload() {
    try { await api.tabs.reload(S.tabId); toast("Reloading the page"); } catch (_) { toast("Could not reload the tab"); }
  }

  function onOpenTab() {
    if (S.tabId === null) return;
    try {
      api.tabs.create({ url: api.runtime.getURL("ui.html?full=1&tab=" + S.tabId) });
      if (!FULL) window.close();
    } catch (_) {
      toast("Could not open a new tab");
    }
  }

  async function onClear() {
    if (!S.clearArmed) {
      S.clearArmed = true;
      $("clear").textContent = "Click again to confirm";
      setTimeout(() => { S.clearArmed = false; $("clear").textContent = "Clear"; }, 3000);
      return;
    }
    S.clearArmed = false;
    $("clear").textContent = "Clear";
    await send({ t: "clear", tabId: S.tabId });
    for (const row of S.rows.values()) if (row.li.parentNode) row.li.parentNode.removeChild(row.li);
    S.rows.clear();
    toast("Findings cleared");
    await refresh(true);
  }

  async function exportJson() {
    const r = await send({ t: "export", tabId: S.tabId, filters: S.filters });
    if (!r || !r.ok) { toast("Nothing to export"); return null; }
    return r;
  }

  async function onExportJson() {
    const r = await exportJson();
    if (r) saveFile("easyapi-" + (r.host || "export") + "-" + Date.now() + ".json", "application/json", r.json);
  }

  async function onCopyJson() {
    const r = await exportJson();
    if (r) await copyText(r.json, "JSON");
  }

  function csvCell(v) {
    let s = String(v === undefined || v === null ? "" : v);
    // Guard against spreadsheet formula injection.
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  }

  async function onExportCsv() {
    const r = await send({ t: "list", tabId: S.tabId, filters: S.filters, limit: 100000 });
    const items = (r && r.items) || [];
    if (!items.length) { toast("Nothing to export"); return; }
    const head = ["confidence", "state", "method", "host", "path", "statuses", "hits", "score", "third_party", "sources", "example_url", "first_seen", "last_seen"];
    const lines = [head.join(",")];
    for (const i of items) {
      lines.push([
        i.conf, i.observed ? "seen" : "referenced", i.method, i.host, i.path,
        sortedStatuses(i.statuses).map(statusLabel).join(" "), i.count, i.score, i.thirdParty ? "yes" : "no",
        i.sources.join(" "), i.url, new Date(i.firstSeen).toISOString(), new Date(i.lastSeen).toISOString()
      ].map(csvCell).join(","));
    }
    saveFile("easyapi-" + ((S.st && S.st.pageHost) || "export") + "-" + Date.now() + ".csv", "text/csv", lines.join("\n") + "\n");
  }

  async function onGrant() {
    const pattern = tabPattern();
    if (!pattern) return;
    let granted = false;
    try { granted = await api.permissions.request({ origins: [pattern] }); } catch (_) {}
    toast(granted ? "Site access granted" : "Site access was not granted");
    renderAccess();
  }

  // Throttled refresh with a trailing call, so the last change in a burst is never dropped.
  function scheduleRefresh() {
    if (S.pushTimer) return;
    const wait = Math.max(0, 300 - (Date.now() - S.lastPush));
    S.pushTimer = setTimeout(() => {
      S.pushTimer = null;
      S.lastPush = Date.now();
      refresh(false);
    }, wait);
  }

  // -------------------------------------------------------------------
  // Boot
  // -------------------------------------------------------------------
  async function init() {
    prefsLoad();
    buildFilters();

    $("toggle").addEventListener("click", onToggle);
    $("openTab").addEventListener("click", onOpenTab);
    $("exportJson").addEventListener("click", onExportJson);
    $("copyJson").addEventListener("click", onCopyJson);
    $("exportCsv").addEventListener("click", onExportCsv);
    $("clear").addEventListener("click", onClear);
    $("grant").addEventListener("click", onGrant);
    $("more").addEventListener("click", () => { S.limit += 200; refresh(true); });
    for (const v of ["endpoints", "settings", "diag"]) $("tab-" + v).addEventListener("click", () => setView(v));

    $("search").addEventListener("input", () => {
      if (S.searchTimer) clearTimeout(S.searchTimer);
      S.searchTimer = setTimeout(() => { S.filters.q = $("search").value.trim(); S.limit = 200; refresh(true); }, 200);
    });
    $("sort").addEventListener("change", () => { S.filters.sort = $("sort").value; prefsSave(); refresh(true); });
    $("hide3p").addEventListener("change", () => { S.filters.hide3p = $("hide3p").checked; prefsSave(); refresh(true); });
    $("tabSelect").addEventListener("change", () => {
      S.tabId = Number($("tabSelect").value);
      S.lastRev = -1;
      S.list = null;
      for (const row of S.rows.values()) if (row.li.parentNode) row.li.parentNode.removeChild(row.li);
      S.rows.clear();
      resolveTab().then(() => refresh(true));
    });

    document.addEventListener("keydown", e => {
      if (e.key === "/" && document.activeElement && document.activeElement.tagName !== "INPUT") { e.preventDefault(); $("search").focus(); }
    });

    api.runtime.onMessage.addListener(msg => {
      // Only react to change notices. Never answer other messages, the background does that.
      if (msg && msg.t === "changed" && msg.tabId === S.tabId) scheduleRefresh();
      return false;
    });

    document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(false); });
    setInterval(() => { if (!document.hidden) refresh(false); }, 1500);

    const r = await send({ t: "settings" });
    if (r && r.settings) S.settings = r.settings;
    await resolveTab();
    await refresh(true);
    renderTabSelect();
  }

  init();
})();
