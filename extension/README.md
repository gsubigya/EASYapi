# EASYapi Extension

EASYapi is a browser extension that shows you which APIs a web application is using. Start it on a tab, browse the site, and it lists every API endpoint the page calls, ranked by how likely each one is to be a real API.

It is built for authorized web security testing and reconnaissance. It also works for developers who want to see exactly what their own frontend exposes.

## Install

This package contains two folders. Use the one that matches your browser.

### Chrome, Edge, Brave, Opera (version 112 or newer)

1. Open `chrome://extensions` (or `edge://extensions`).
2. Turn on Developer mode.
3. Click Load unpacked and select the `chrome` folder.
4. Pin the EASYapi icon from the extensions menu.

### Firefox (version 128 or newer)

1. Open `about:debugging#/runtime/this-firefox`.
2. Click Load Temporary Add-on and select `manifest.json` inside the `firefox` folder.
3. Firefox removes temporary add-ons when it restarts. For a permanent install, sign the extension through addons.mozilla.org, or use Firefox Developer Edition, Nightly or ESR with `xpinstall.signatures.required` set to false.
4. Firefox does not grant site access automatically. EASYapi asks for it when you press Start capture on a site. You can also grant it in the add-on permissions.

## Use

1. Open the site you are authorized to test.
2. Click the EASYapi icon and press Start capture.
3. Reload the page to include requests made during page load, then browse the site normally.
4. Use the arrow button in the popup to open the same view in a full tab.

Capture is per tab. It keeps running across reloads and navigation until you press Stop capture or close the tab.

## Reading the results

Each card is one endpoint. Numeric IDs, UUIDs and long hashes in paths are normalized, so `/users/101` and `/users/202` become one finding, `/users/{id}`.

| Label | Meaning |
| --- | --- |
| Seen | The page actually called the endpoint while capture was on. |
| Referenced | Found only as a string in code or resource data. Treat it as a lead. Referenced findings never rise above Medium. |
| High, Medium, Low | How likely the endpoint is a real API, based on path, method, content types, status codes, GraphQL and WebSocket signals. |
| 3P | A different site than the page, such as analytics. |

Expand a card to see the full URL, why it was flagged, query parameter names, every status code seen, GraphQL operation names, request headers, request body, a response preview and WebSocket samples. Comparing status codes across endpoints is a quick way to spot authorization differences.

Results are sorted by confidence, then observed before referenced, then score and hit count. You can also sort by most recent, most hits, or host and path, filter by confidence and state, search, and hide third party traffic.

Export the current view as JSON or CSV, or copy the JSON to the clipboard. Exports leave out headers and bodies unless you turn on Include headers and bodies in Settings.

## What it captures

- Calls made with `fetch`, `XMLHttpRequest` and `sendBeacon`, including method, URL, headers, body, status and a response preview
- GraphQL operation types and names, including batched requests
- WebSocket connections and a few sample messages
- Requests made before capture started, from the browser's Resource Timing data (URL and status only)
- API paths referenced inside loaded and inline JavaScript
- Form actions
- Same-site frames, including frames that load later

## Privacy and safety

- Everything stays in your browser. EASYapi has no server and sends nothing anywhere.
- Findings are kept in session storage, which the browser clears when it closes, and each tab's data is deleted when the tab closes.
- Sensitive values are redacted before they leave the page script: passwords, tokens, API keys, authorization values, cookies and similar keys in headers, JSON bodies, form bodies, URL query strings and fragments, plus JWTs, bearer tokens and several common key formats. Credentials in URLs are dropped. Redaction is pattern based, so review exports before sharing them.
- The page script is designed not to affect the site. It calls the original `fetch`, `XMLHttpRequest`, `sendBeacon` and `WebSocket` exactly once with the original arguments, reads bodies from clones in the background with a size cap and a timeout, and catches its own errors.
- It never sends requests to API endpoints and never fuzzes anything. The one active step is optional: it re-reads the page's own script files, normally from the browser cache, to find API paths. Turn this off in Settings.

## Permissions

| Permission | Why |
| --- | --- |
| Site access (all sites) | Lets EASYapi attach to the tab you start capture on, and re-attach early on reload and navigation. It does nothing on a tab until you press Start capture. |
| scripting | Injects the capture script into the tab. |
| webNavigation | Re-attaches capture when a captured tab navigates to another site. |
| storage | Saves your settings and the session's findings. |
| activeTab | Lets the popup act on the tab you opened it from. |

## Limits

- Pages the browser protects cannot be captured: browser pages, extension stores, and some others. Chrome also needs "Allow access to file URLs" for local files.
- Frames from other sites are only hooked if they exist when you press Start capture.
- Web workers and service workers are not hooked.
- Requests made before capture started appear only through Resource Timing, so you get the URL and status but no method or body, and the browser's timing buffer is limited.
- The third party tag uses a simple domain heuristic. An API on a separate domain you own may be tagged 3P.
- EASYapi is a discovery tool, not a vulnerability scanner. It tells you what exists. Testing for broken authorization, IDOR and similar issues is up to you.

## Responsible use

Only run EASYapi on applications you own or have explicit permission to test. Follow the scope and rules of any program or engagement you are part of.

## Version

EASYapi v2.0.0
