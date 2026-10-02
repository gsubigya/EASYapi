# EASYapu

Smart API Discovery (EASYapi) is a browser-console tool for discovering APIs used by a web application.

It passively watches the browser and identifies API requests made by the application. It shows useful information such as the HTTP method, URL, request body, response status, and content type.

The main goal is to make API discovery easier during authorized web security testing and reconnaissance.

## What It Detects

The tool can monitor:

- `GET`
- `POST`
- `PUT`
- `PATCH`
- `DELETE`
- Other HTTP methods
- GraphQL requests
- WebSockets
- `fetch()`
- `XMLHttpRequest`
- `sendBeacon()`
- API URLs referenced inside JavaScript
- API-related browser resources

For detected requests, it can show:

- HTTP method
- Full URL
- Path and query string
- Request headers
- Request body
- Request content type
- Response status
- Response content type
- Response body preview
- GraphQL operation
- Why the endpoint was identified as an API

Sensitive values such as passwords, tokens, API keys, and authorization values are automatically redacted.

## How to Use

### 1. Open the target website

Use a website or application that you are authorized to test.

### 2. Open Developer Tools

Press `F12` and open the **Console** tab.

### 3. Paste the script

Copy the Smart API Discovery JavaScript into the console and press Enter.

You should see:

    [SmartAPI] ● LIVE
    Waiting for API activity...

### 4. Browse the application

You do not need to enter any additional commands.

Simply use the website normally:

- Log in
- Search
- Open profiles
- View products
- Submit forms
- Change settings
- Upload files
- Navigate through different pages

When the browser makes an API request, the tool will automatically display it.

Example:

    [HIGH] POST  https://example.com/api/v1/login
             → BODY: {"email":"test@example.com","password":"[REDACTED]"}
             → 200 application/json

Another example:

    [HIGH] GET  https://example.com/api/v1/users/123
             → 200 application/json

## Important

Smart API Discovery is **passive**. It observes requests made by the browser and references found in the loaded application.

It does **not** automatically brute-force or fuzz random API endpoints.

It is intended for authorized security testing, learning, and reconnaissance.

## Limitations

The tool cannot discover every API that exists on a server.

If an endpoint is never called by the browser and is not exposed in the resources scanned by the tool, it may not be discovered.

For deeper API enumeration, additional authorized testing techniques may be required.

## Version

**EASYapi v1**

A lightweight browser-console API discovery tool for web security research.
