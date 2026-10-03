# EASYapi

EASYapi is a browser console script that shows you which APIs a web application is using. Paste it into DevTools, browse the site normally, and it logs every API request the app makes, ranked by how likely each one is to be a real API endpoint.

It is built for authorized web security testing and reconnaissance. It also works for developers who want to see exactly what their own frontend exposes.

## How it works

EASYapi watches the traffic your browser already generates. It never sends requests to API endpoints, never brute-forces paths, and never fuzzes anything.

It does one active thing: it re-reads the JavaScript files the page has loaded, normally from the browser cache, and looks for API paths inside them. Turn that off with `EASYapi.config.scanJavaScript = false`.

The script is designed not to affect the page. It calls the original `fetch`, `XMLHttpRequest`, `sendBeacon`, and `WebSocket` exactly once with the original arguments, reads bodies from clones in the background, and catches its own errors.

## What it captures

- All HTTP methods through `fetch`, `XMLHttpRequest`, and `sendBeacon`
- GraphQL operations (type and name), including batched requests
- WebSocket connections and a few sample messages
- Requests made before you pasted the script (URL and status only, from Resource Timing)
- API paths referenced inside loaded and inline JavaScript
- Form actions

For each endpoint it records the method, URL, request headers and body, response status, content type, a short response preview, the query parameter names, every status code seen, and the reasons it was flagged.

## Usage

1. Open a website you are authorized to test.
2. Press `F12` and go to the **Console** tab.
3. Copy the contents of `console.js`, paste it into the console, and press Enter.
4. Wait for the line `[EASYapi] v2.0.0 LIVE`.
5. Use the site like a normal user. Log in, search, open profiles, change settings, submit forms, upload files.

Some browsers block pasting into the console until you confirm. Firefox, for example, asks you to type `allow pasting`. Only paste code you have read.

## Reading the output

Each new endpoint prints one line:

```
[HIGH] SEEN POST      https://example.com/api/v1/login  -> 200 json
[MED]  REF  ?         https://example.com/api/v1/admin/export
```

- `HIGH`, `MED`, `LOW` is how likely the endpoint is a real API.
- `SEEN` means the browser actually called it. `REF` means it was only found as a string in code or resource data, so treat it as a lead. REF findings are capped at MED.
- `?` as the method means the method is unknown. It resolves automatically when the endpoint is called.
- `[3P]` marks a different site than the page, such as analytics.

Click a line to expand it. The details show the request body, headers, response preview, query parameters, status codes, GraphQL operations, and the reasons for the score.

Repeated calls to the same endpoint are merged. Numeric IDs, UUIDs, and long hashes in paths are normalized, so `/users/101` and `/users/202` become one finding, `/users/{id}`. A line prints again only when something new appears: the endpoint is first observed, its confidence rises, or a new status code shows up (useful for spotting differences in authorization). If output floods, it rate-limits itself and tells you.

## Commands

You do not need any of these, but they help once you have browsed for a while.

```
EASYapi.report({ min: "MEDIUM", observed: true })   sorted table of findings
EASYapi.findings({ host: "api." })                  array of plain objects
EASYapi.export({ includeDetails: true })            JSON string, use copy(EASYapi.export())
EASYapi.download()                                  save the JSON as a file
EASYapi.stats                                       counters
EASYapi.errors                                      internal errors, if any
EASYapi.config                                      live settings
EASYapi.clear()                                     reset findings
EASYapi.stop()                                      unhook everything
```

Filters accepted by `report`, `findings`, and `export`: `min`, `observed`, `thirdParty`, `host`, `method`, `search`, `limit`.

Useful settings: `minConfidence`, `thirdParty` (`"tag"` or `"hide"`), `showResponseBody`, `redactSensitive`, `live`, `debug`.

## Redaction

Sensitive values are redacted before anything is stored or printed: password, token, secret, API key, authorization, cookie, and similar keys in headers, JSON bodies, form bodies, and URL query strings and fragments, plus JWTs, bearer tokens, and several common key formats wherever they appear. Credentials in URLs are dropped.

Redaction is pattern-based. It will not catch a secret stored under an unusual key name with no recognizable format, so review exports before sharing them. Exports leave out headers and bodies unless you pass `includeDetails: true`.

## Limitations

- It only sees what the page's own scripts do. Requests from iframes, web workers, and service workers are not hooked.
- Requests made before you pasted it show up only through Resource Timing, so you get the URL and status but no method or body, and the browser's timing buffer is limited.
- Reloading the page stops it. Paste it again after a reload.
- Endpoints never called and never referenced will not appear.
- The third-party tag uses a simple domain heuristic. An API on a separate domain you own may be tagged `[3P]`.
- It is a discovery tool, not a vulnerability scanner. It tells you what exists. Testing for broken authorization, IDOR, and similar issues is up to you.

## Responsible use

Only run EASYapi on applications you own or have explicit permission to test. Follow the scope and rules of any program or engagement you are part of.

## Version

EASYapi v2
