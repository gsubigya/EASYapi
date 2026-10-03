/*
 * EASYapi bridge. Runs in the extension's isolated content-script world.
 *
 * It relays redacted observations from the page capture script to the
 * background worker, and relays commands back. It never reads page data itself.
 */
(() => {
  "use strict";

  const api = globalThis.browser || globalThis.chrome;
  if (!api || !api.runtime || !api.runtime.sendMessage) return;
  if (window.__EASYAPI_BRIDGE__) return;
  window.__EASYAPI_BRIDGE__ = true;

  const EVT_OUT = "__easyapi_out__";
  const EVT_IN = "__easyapi_in__";
  const MAX_DETAIL = 1500000;

  let enabled = null; // null = not known yet
  let config = null;
  let dead = false;
  let helloBusy = false;
  let helloTries = 0;

  function toPage(cmd) {
    try {
      window.dispatchEvent(new CustomEvent(EVT_IN, { detail: JSON.stringify(cmd) }));
    } catch (_) {}
  }

  function shutdown() {
    dead = true;
    window.removeEventListener(EVT_OUT, onPageEvent, true);
  }

  function onSendError(err) {
    const msg = String((err && err.message) || err);
    // The extension was reloaded or removed while this page stayed open.
    if (/context invalidated|Extension context/i.test(msg)) shutdown();
  }

  function applyState() {
    if (enabled === true) toPage({ cmd: "config", config });
    else if (enabled === false) toPage({ cmd: "stop" });
  }

  async function hello() {
    if (helloBusy || dead) return;
    helloBusy = true;
    try {
      const r = await api.runtime.sendMessage({ t: "hello", href: location.href, top: window === window.top });
      if (r && typeof r === "object") {
        enabled = !!r.enabled;
        config = r.config || null;
      }
    } catch (e) {
      onSendError(e);
    } finally {
      helloBusy = false;
    }
    if (enabled === null && !dead && helloTries++ < 5) setTimeout(hello, 800);
    else applyState();
  }

  function onPageEvent(ev) {
    if (dead) return;
    const d = ev && ev.detail;
    if (typeof d !== "string" || d.length > MAX_DETAIL) return;
    // Handshake requests from the page script are tiny and carry no observations.
    if (d.length < 40 && d.indexOf('"hello"') !== -1) {
      if (enabled !== null) applyState();
      return;
    }
    if (enabled !== true) return;
    try {
      const p = api.runtime.sendMessage({ t: "obs", d });
      if (p && typeof p.catch === "function") p.catch(onSendError);
    } catch (e) {
      onSendError(e);
    }
  }

  window.addEventListener(EVT_OUT, onPageEvent, true);

  try {
    api.runtime.onMessage.addListener(msg => {
      if (!msg || typeof msg !== "object") return;
      if (msg.t === "enable") {
        enabled = true;
        config = msg.config || config;
      } else if (msg.t === "config") {
        config = msg.config || config;
        if (enabled === true) toPage({ cmd: "config", config });
      } else if (msg.t === "stop") {
        enabled = false;
        toPage({ cmd: "stop" });
      }
      // No response is sent. Returning nothing keeps other listeners free to answer.
    });
  } catch (_) {}

  hello();
})();
