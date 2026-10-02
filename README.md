# EASYapi

EASYapi is a browser console script that shows you which APIs a web application is using. You paste it into DevTools, browse the site normally, and it logs every API request the app makes.

It is built for authorized web security testing and reconnaissance. It also works for developers who want to see exactly what their own frontend exposes.

## How it works

EASYapi is passive. It watches the traffic your browser already generates and the references already present in the loaded page. It does not send its own requests, brute-force paths, or fuzz anything.

For each API request it detects, it shows:

- HTTP method
- Full URL, path, and query string
- Request headers and body
- Request content type
- Response status and content type
- A preview of the response body
- The GraphQL operation, if there is one
- The reason the request was flagged as an API

Passwords, tokens, API keys, and authorization values are redacted automatically.

## What it detects

- All HTTP methods (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`, and others)
- `fetch()` and `XMLHttpRequest` calls
- `sendBeacon()` calls
- GraphQL requests
- WebSocket connections
- API URLs referenced inside JavaScript files
- Other API-related browser resources

## Usage

1. Open a website you are authorized to test.
2. Press `F12` and go to the **Console** tab.
3. Copy the contents of `console.js` from this repo, paste it into the console, and press Enter.
4. Wait for this message:

```
[SmartAPI] ● LIVE
Waiting for API activity...
```

5. Use the site like a normal user. Log in, search, open profiles, change settings, submit forms, upload files. Every API request shows up in the console as it happens.

Some browsers block pasting into the console by default. If yours does, follow the prompt it gives you (Firefox, for example, asks you to type `allow pasting` first). Only paste code you have read and understand.

## Example output

```
[HIGH] POST  https://example.com/api/v1/login
         → BODY: {"email":"test@example.com","password":"[REDACTED]"}
         → 200 application/json

[HIGH] GET  https://example.com/api/v1/users/123
         → 200 application/json
```

## Limitations

- It only finds what the browser calls or what appears in the resources it scans. An endpoint that is never triggered and never referenced will not show up.
- It runs inside the page, so reloading the page stops it. Paste it again after a reload.
- It cannot see requests made before you pasted it.
- It is a discovery tool, not a vulnerability scanner. It tells you what exists. Testing for broken authorization, IDOR, and similar issues is still up to you.

For deeper enumeration, you will need other authorized testing techniques alongside this.

## Responsible use

Only run EASYapi on applications you own or have explicit permission to test. Follow the scope and rules of any program or engagement you are part of.

## Version

EASYapi v1
