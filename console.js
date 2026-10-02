(() => {
  "use strict";

  /*
   * ============================================================
   * EASYapi v1
   * Passive browser-side API discovery
   *
   * Paste once.
   * No commands required afterwards.
   * ============================================================
   */

  // ------------------------------------------------------------
  // CLEAN UP PREVIOUS INSTANCE
  // ------------------------------------------------------------

  if (window.__SMART_API_DISCOVERY_CLEANUP__) {
    try {
      window.__SMART_API_DISCOVERY_CLEANUP__();
    } catch {}
  }

  const VERSION = "4.0";

  const CONFIG = {
    maxRequestBody: 3000,
    maxResponseBody: 2500,
    maxScriptSize: 2000000,
    maxScripts: 50,

    scanJavaScript: true,
    scanPerformance: true,

    showRequestHeaders: true,
    showResponseBody: true,

    redactSensitive: true
  };

  const findings = new Map();

  const stats = {
    total: 0,
    fetch: 0,
    xhr: 0,
    beacon: 0,
    websocket: 0,
    javascript: 0,
    performance: 0,
    graphql: 0
  };

  const cleanups = [];

  // ------------------------------------------------------------
  // BANNER
  // ------------------------------------------------------------

  console.log("");
  console.log(
    "%c╔══════════════════════════════════════════════╗",
    "font-weight:bold"
  );

  console.log(
    `%c║        SMART API DISCOVERY v${VERSION}             ║`,
    "font-weight:bold"
  );

  console.log(
    "%c║                 ● LIVE                       ║",
    "font-weight:bold"
  );

  console.log(
    "%c╚══════════════════════════════════════════════╝",
    "font-weight:bold"
  );

  console.log(
    "%cPassive API monitoring started.",
    "font-weight:bold"
  );

  console.log(
    "Browse the application normally. API findings will appear automatically."
  );

  console.log(
    "Sensitive values are automatically redacted."
  );

  console.log("");

  // ------------------------------------------------------------
  // SENSITIVE DATA
  // ------------------------------------------------------------

  const SENSITIVE = [
    "password",
    "passwd",
    "pass",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "api_key",
    "apikey",
    "authorization",
    "auth",
    "secret",
    "signature",
    "sig",
    "cookie",
    "session",
    "sessionid",
    "client_secret",
    "private_key",
    "otp",
    "verification_code"
  ];

  function sensitiveKey(key) {
    const k = String(key).toLowerCase();

    return SENSITIVE.some(
      x =>
        k === x ||
        k.includes(x)
    );
  }

  function redactText(value) {

    if (!CONFIG.redactSensitive) {
      return String(value ?? "");
    }

    let text =
      String(value ?? "");

    // Authorization headers
    text = text.replace(
      /Bearer\s+[A-Za-z0-9._~+/=-]+/gi,
      "Bearer [REDACTED]"
    );

    // JSON / key=value style secrets
    for (const key of SENSITIVE) {

      const regex = new RegExp(
        `(["']?${key}["']?\\s*[:=]\\s*)(["'][^"']*["']|[^,;&\\s}\\]]+)`,
        "gi"
      );

      text = text.replace(
        regex,
        "$1[REDACTED]"
      );
    }

    return text;
  }

  function truncate(value, max) {

    let text;

    try {

      if (
        typeof value === "object" &&
        value !== null
      ) {
        text =
          JSON.stringify(
            value,
            null,
            2
          );
      } else {
        text =
          String(value ?? "");
      }

    } catch {
      text =
        String(value ?? "");
    }

    text =
      redactText(text);

    if (text.length > max) {

      return (
        text.slice(0, max) +
        ` ... [truncated]`
      );
    }

    return text;
  }

  // ------------------------------------------------------------
  // HEADERS
  // ------------------------------------------------------------

  function headersToObject(headers) {

    const output = {};

    if (!headers) {
      return output;
    }

    try {

      if (
        typeof Headers !== "undefined" &&
        headers instanceof Headers
      ) {

        headers.forEach(
          (value, key) => {

            output[key] =
              sensitiveKey(key)
                ? "[REDACTED]"
                : value;

          }
        );

      } else if (
        Array.isArray(headers)
      ) {

        for (
          const [key, value]
          of headers
        ) {

          output[key] =
            sensitiveKey(key)
              ? "[REDACTED]"
              : value;
        }

      } else {

        for (
          const [key, value]
          of Object.entries(headers)
        ) {

          output[key] =
            sensitiveKey(key)
              ? "[REDACTED]"
              : value;
        }
      }

    } catch {}

    return output;
  }

  // ------------------------------------------------------------
  // BODY
  // ------------------------------------------------------------

  function bodyToText(body) {

    if (
      body === undefined ||
      body === null
    ) {
      return "";
    }

    if (
      typeof body === "string"
    ) {

      try {

        const json =
          JSON.parse(body);

        return truncate(
          json,
          CONFIG.maxRequestBody
        );

      } catch {

        return truncate(
          body,
          CONFIG.maxRequestBody
        );
      }
    }

    if (
      typeof URLSearchParams !== "undefined" &&
      body instanceof URLSearchParams
    ) {

      const obj = {};

      for (
        const [key, value]
        of body.entries()
      ) {

        obj[key] =
          sensitiveKey(key)
            ? "[REDACTED]"
            : value;
      }

      return truncate(
        obj,
        CONFIG.maxRequestBody
      );
    }

    if (
      typeof FormData !== "undefined" &&
      body instanceof FormData
    ) {

      const obj = {};

      for (
        const [key, value]
        of body.entries()
      ) {

        if (
          typeof File !== "undefined" &&
          value instanceof File
        ) {

          obj[key] =
            `[File: ${value.name}, ${value.size} bytes]`;

        } else {

          obj[key] =
            sensitiveKey(key)
              ? "[REDACTED]"
              : String(value);
        }
      }

      return truncate(
        obj,
        CONFIG.maxRequestBody
      );
    }

    if (
      typeof Blob !== "undefined" &&
      body instanceof Blob
    ) {

      return `[Blob: ${body.type || "unknown"}, ${body.size} bytes]`;
    }

    if (
      typeof ArrayBuffer !== "undefined" &&
      body instanceof ArrayBuffer
    ) {

      return `[ArrayBuffer: ${body.byteLength} bytes]`;
    }

    return truncate(
      body,
      CONFIG.maxRequestBody
    );
  }

  // ------------------------------------------------------------
  // URL PARSING
  // ------------------------------------------------------------

  function parseURL(input) {

    try {

      const u =
        new URL(
          String(input),
          location.href
        );

      return {

        url: u.href,

        host:
          u.host,

        path:
          u.pathname,

        query:
          u.search

      };

    } catch {

      return {

        url:
          String(input),

        host:
          "",

        path:
          "",

        query:
          ""
      };
    }
  }

  // ------------------------------------------------------------
  // GRAPHQL
  // ------------------------------------------------------------

  function detectGraphQL(url, body) {

    const text =
      `${url} ${body || ""}`;

    if (
      /\/graphql(?:\/|$|\?)/i.test(url) ||
      /\/gql(?:\/|$|\?)/i.test(url)
    ) {

      const match =
        String(body || "").match(
          /\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)/
        );

      return {

        detected: true,

        type:
          match?.[1] || "unknown",

        operation:
          match?.[2] || null
      };
    }

    if (
      /\b(query|mutation|subscription)\s+[A-Za-z_]/i.test(text)
    ) {

      const match =
        text.match(
          /\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)/i
        );

      return {

        detected: true,

        type:
          match?.[1] || "unknown",

        operation:
          match?.[2] || null
      };
    }

    return null;
  }

  // ------------------------------------------------------------
  // API SCORING
  // ------------------------------------------------------------

  function scoreAPI(info) {

    let score = 0;

    const reasons = [];

    const full =
      `${info.url} ${info.path} ${info.host}`.toLowerCase();

    const path =
      info.path.toLowerCase();

    // Strong API paths

    if (
      /\/(api|graphql|gql|rest|rpc|jsonrpc|odata)(\/|$)/i.test(
        path
      )
    ) {

      score += 35;

      reasons.push(
        "API path"
      );
    }

    // Common API frameworks/specifications

    if (
      /\/(swagger|openapi|wp-json|admin-ajax\.php)(\/|$|\?)/i.test(
        path
      )
    ) {

      score += 40;

      reasons.push(
        "API framework/spec"
      );
    }

    // Version

    if (
      /\/v[0-9]+(?:\/|$)/i.test(
        path
      )
    ) {

      score += 18;

      reasons.push(
        "versioned API"
      );
    }

    // API-like hostname

    if (
      /(^|[.-])(api|backend|service|services)([.-]|$)/i.test(
        info.host
      )
    ) {

      score += 25;

      reasons.push(
        "API-like hostname"
      );
    }

    // API vocabulary

    const apiWords = [
      "api",
      "graphql",
      "gql",
      "rest",
      "rpc",
      "jsonrpc",
      "odata",
      "swagger",
      "openapi",
      "wp-json"
    ];

    for (
      const word
      of apiWords
    ) {

      if (
        new RegExp(
          `(^|[\\/_?.-])${word}([\\/_?.-]|$)`,
          "i"
        ).test(full)
      ) {

        score += 8;

        reasons.push(
          `keyword:${word}`
        );
      }
    }

    // Resources

    const resources = [
      "users",
      "user",
      "accounts",
      "account",
      "profiles",
      "profile",
      "auth",
      "login",
      "logout",
      "register",
      "session",
      "token",
      "customers",
      "customer",
      "products",
      "product",
      "orders",
      "order",
      "payments",
      "payment",
      "invoices",
      "invoice",
      "bookings",
      "booking",
      "files",
      "file",
      "upload",
      "download",
      "messages",
      "message",
      "notifications",
      "notification",
      "settings",
      "config",
      "configuration",
      "admin",
      "search",
      "reports",
      "report",
      "analytics",
      "health",
      "status"
    ];

    const resourceHits =
      resources.filter(
        word =>
          new RegExp(
            `(^|[\\/_?.-])${word}([\\/_?.-]|$)`,
            "i"
          ).test(full)
      );

    if (
      resourceHits.length
    ) {

      score +=
        Math.min(
          resourceHits.length * 6,
          24
        );

      reasons.push(
        "resource:" +
        resourceHits
          .slice(0, 4)
          .join(",")
      );
    }

    // HTTP methods

    if (
      ["POST", "PUT", "PATCH", "DELETE"]
        .includes(info.method)
    ) {

      score += 15;

      reasons.push(
        info.method
      );
    }

    // Body

    if (
      info.body
    ) {

      score += 8;

      reasons.push(
        "request body"
      );
    }

    // Structured content

    if (
      /json|graphql|xml|form/i.test(
        info.requestContentType ||
        ""
      )
    ) {

      score += 10;

      reasons.push(
        "structured request"
      );
    }

    if (
      /json|graphql|xml/i.test(
        info.responseContentType ||
        ""
      )
    ) {

      score += 15;

      reasons.push(
        "structured response"
      );
    }

    // GraphQL

    if (
      info.graphql
    ) {

      score += 35;

      reasons.push(
        "GraphQL"
      );
    }

    // Runtime evidence

    if (
      [
        "fetch",
        "xhr",
        "beacon"
      ].includes(info.source)
    ) {

      score += 12;

      reasons.push(
        "runtime request"
      );
    }

    // Status

    if (
      [401, 403, 405, 429]
        .includes(info.status)
    ) {

      score += 12;

      reasons.push(
        `HTTP ${info.status}`
      );
    }

    if (
      info.status >= 200 &&
      info.status < 300 &&
      /json|graphql/i.test(
        info.responseContentType ||
        ""
      )
    ) {

      score += 20;

      reasons.push(
        "successful API response"
      );
    }

    // Static JS evidence

    if (
      info.source === "javascript"
    ) {

      score += 8;

      reasons.push(
        "JavaScript reference"
      );
    }

    // Performance evidence

    if (
      info.source === "performance"
    ) {

      score += 5;

      reasons.push(
        "browser resource"
      );
    }

    // Static assets penalty

    if (
      /\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|map)(\?|$)/i.test(
        path
      )
    ) {

      score -= 30;
    }

    return {

      score:
        Math.max(
          0,
          score
        ),

      reasons:
        [...new Set(reasons)]
    };
  }

  function confidence(score) {

    if (score >= 75)
      return "HIGH";

    if (score >= 45)
      return "MEDIUM";

    if (score >= 22)
      return "LOW";

    return "IGNORE";
  }

  // ------------------------------------------------------------
  // PRINT
  // ------------------------------------------------------------

  function printFinding(f, update = false) {

    if (
      f.confidence === "IGNORE"
    ) {
      return;
    }

    const label =
      f.confidence === "HIGH"
        ? "[HIGH]"
        : f.confidence === "MEDIUM"
          ? "[MED]"
          : "[LOW]";

    const method =
      String(
        f.method
      ).padEnd(
        8
      );

    console.log(
      `%c${label} ${method} ${f.url}`,
      "font-weight:bold"
    );

    // Response line

    if (
      f.status !== undefined &&
      f.status !== null
    ) {

      console.log(
        `         → ${f.status} ${f.responseContentType || ""}`
      );
    }

    // Request body

    if (
      f.body
    ) {

      console.log(
        "         → BODY:",
        f.body
      );
    }

    // GraphQL

    if (
      f.graphql
    ) {

      console.log(
        `         → GraphQL: ${f.graphql.type}${f.graphql.operation ? " " + f.graphql.operation : ""}`
      );
    }

    // Request type

    if (
      f.requestContentType
    ) {

      console.log(
        `         → Request-Type: ${f.requestContentType}`
      );
    }

    // Response body

    if (
      CONFIG.showResponseBody &&
      f.responseBody
    ) {

      console.log(
        "         → RESPONSE:",
        f.responseBody
      );
    }

    // Reasons

    console.log(
      `         → ${f.reasons.join(" | ")}`
    );

    // Headers

    if (
      CONFIG.showRequestHeaders &&
      Object.keys(
        f.requestHeaders || {}
      ).length
    ) {

      console.log(
        "         → Headers:",
        f.requestHeaders
      );
    }

    console.log("");
  }

  // ------------------------------------------------------------
  // RECORD
  // ------------------------------------------------------------

  function record(raw) {

    if (
      !raw ||
      !raw.url
    ) {
      return;
    }

    const parsed =
      parseURL(
        raw.url
      );

    const info = {

      ...raw,

      ...parsed,

      method:
        String(
          raw.method ||
          "GET"
        ).toUpperCase()
    };

    info.graphql =
      raw.graphql ||
      detectGraphQL(
        info.url,
        info.body
      );

    if (
      info.graphql
    ) {

      stats.graphql++;
    }

    const scoring =
      scoreAPI(
        info
      );

    info.score =
      scoring.score;

    info.reasons =
      scoring.reasons;

    info.confidence =
      confidence(
        info.score
      );

    if (
      info.confidence === "IGNORE"
    ) {
      return;
    }

    /*
     * Normalize IDs so:
     *
     * /users/123
     * /users/456
     *
     * can be recognized as the same endpoint.
     */

    const normalizedPath =
      info.path
        .replace(
          /\/[0-9]{2,}(?=\/|$)/g,
          "/{id}"
        )
        .replace(
          /\/[0-9a-f]{8}-[0-9a-f-]{27,36}(?=\/|$)/gi,
          "/{uuid}"
        );

    const key =
      `${info.method}|${info.host}|${normalizedPath}`;

    const existing =
      findings.get(
        key
      );

    if (
      existing
    ) {

      existing.count++;

      existing.lastSeen =
        new Date().toISOString();

      existing.score =
        Math.max(
          existing.score,
          info.score
        );

      existing.confidence =
        confidence(
          existing.score
        );

      existing.reasons =
        [
          ...new Set(
            [
              ...existing.reasons,
              ...info.reasons
            ]
          )
        ];

      if (
        info.status
      ) {

        existing.status =
          info.status;
      }

      if (
        info.responseBody
      ) {

        existing.responseBody =
          info.responseBody;
      }

      if (
        info.responseContentType
      ) {

        existing.responseContentType =
          info.responseContentType;
      }

      return;
    }

    const finding = {

      url:
        info.url,

      method:
        info.method,

      host:
        info.host,

      path:
        info.path,

      query:
        info.query,

      normalizedPath,

      score:
        info.score,

      confidence:
        info.confidence,

      reasons:
        info.reasons,

      source:
        info.source,

      sources:
        [info.source],

      requestHeaders:
        info.requestHeaders ||
        {},

      requestContentType:
        info.requestContentType ||
        "",

      body:
        info.body ||
        "",

      status:
        info.status,

      statusText:
        info.statusText ||
        "",

      responseContentType:
        info.responseContentType ||
        "",

      responseBody:
        info.responseBody ||
        "",

      graphql:
        info.graphql ||
        null,

      count:
        1,

      firstSeen:
        new Date().toISOString(),

      lastSeen:
        new Date().toISOString()
    };

    findings.set(
      key,
      finding
    );

    stats.total++;

    printFinding(
      finding,
      false
    );
  }

  // ------------------------------------------------------------
  // FETCH HOOK
  // ------------------------------------------------------------

  const originalFetch =
    window.fetch;

  window.fetch =
    async function(
      input,
      init
    ) {

      let url =
        "";

      let method =
        "GET";

      let headers =
        {};

      let body =
        "";

      try {

        if (
          input instanceof Request
        ) {

          url =
            input.url;

          method =
            input.method ||
            "GET";

          headers =
            headersToObject(
              input.headers
            );

          if (
            input.body
          ) {

            try {

              const clone =
                input.clone();

              body =
                bodyToText(
                  await clone.text()
                );

            } catch {}
          }

        } else {

          url =
            String(
              input
            );

          method =
            init?.method ||
            "GET";

          headers =
            headersToObject(
              init?.headers
            );

          body =
            bodyToText(
              init?.body
            );
        }

      } catch {}

      stats.fetch++;

      let response;

      try {

        response =
          await originalFetch.apply(
            this,
            arguments
          );

      } catch (error) {

        record({

          source:
            "fetch",

          url,

          method,

          requestHeaders:
            headers,

          requestContentType:
            headers["content-type"] ||
            "",

          body,

          status:
            0,

          statusText:
            "NETWORK ERROR"
        });

        throw error;
      }

      try {

        const responseHeaders =
          headersToObject(
            response.headers
          );

        const responseContentType =
          response.headers.get(
            "content-type"
          ) || "";

        let responseBody =
          "";

        if (
          CONFIG.showResponseBody &&
          /json|graphql|text|xml/i.test(
            responseContentType
          )
        ) {

          try {

            const clone =
              response.clone();

            responseBody =
              truncate(
                await clone.text(),
                CONFIG.maxResponseBody
              );

          } catch {}
        }

        record({

          source:
            "fetch",

          url,

          method,

          requestHeaders:
            headers,

          requestContentType:
            headers["content-type"] ||
            headers["Content-Type"] ||
            "",

          body,

          status:
            response.status,

          statusText:
            response.statusText,

          responseHeaders,

          responseContentType,

          responseBody
        });

      } catch {}

      return response;
    };

  cleanups.push(
    () => {
      window.fetch =
        originalFetch;
    }
  );

  // ------------------------------------------------------------
  // XHR HOOK
  // ------------------------------------------------------------

  const originalOpen =
    XMLHttpRequest.prototype.open;

  const originalSend =
    XMLHttpRequest.prototype.send;

  const originalSetHeader =
    XMLHttpRequest.prototype.setRequestHeader;

  XMLHttpRequest.prototype.open =
    function(
      method,
      url,
      ...rest
    ) {

      this.__smartAPI =
        {

          method:
            String(
              method ||
              "GET"
            ).toUpperCase(),

          url:
            new URL(
              url,
              location.href
            ).href,

          headers:
            {}
        };

      return originalOpen.call(
        this,
        method,
        url,
        ...rest
      );
    };

  XMLHttpRequest.prototype.setRequestHeader =
    function(
      name,
      value
    ) {

      if (
        !this.__smartAPI
      ) {

        this.__smartAPI =
          {
            method:
              "GET",

            url:
              "",

            headers:
              {}
          };
      }

      this.__smartAPI.headers[name] =
        sensitiveKey(name)
          ? "[REDACTED]"
          : value;

      return originalSetHeader.call(
        this,
        name,
        value
      );
    };

  XMLHttpRequest.prototype.send =
    function(body) {

      const xhr =
        this;

      const meta =
        xhr.__smartAPI ||
        {};

      stats.xhr++;

      const requestBody =
        bodyToText(
          body
        );

      xhr.addEventListener(
        "loadend",
        function() {

          try {

            const contentType =
              xhr.getResponseHeader(
                "content-type"
              ) || "";

            let responseBody =
              "";

            if (
              CONFIG.showResponseBody &&
              /json|graphql|text|xml/i.test(
                contentType
              )
            ) {

              responseBody =
                truncate(
                  xhr.responseText,
                  CONFIG.maxResponseBody
                );
            }

            record({

              source:
                "xhr",

              url:
                meta.url ||
                xhr.responseURL,

              method:
                meta.method ||
                "GET",

              requestHeaders:
                meta.headers ||
                {},

              requestContentType:
                meta.headers?.["Content-Type"] ||
                meta.headers?.["content-type"] ||
                "",

              body:
                requestBody,

              status:
                xhr.status,

              statusText:
                xhr.statusText,

              responseContentType:
                contentType,

              responseBody
            });

          } catch {}

        },
        {
          once:
            true
        }
      );

      return originalSend.call(
        this,
        body
      );
    };

  cleanups.push(
    () => {

      XMLHttpRequest.prototype.open =
        originalOpen;

      XMLHttpRequest.prototype.send =
        originalSend;

      XMLHttpRequest.prototype.setRequestHeader =
        originalSetHeader;
    }
  );

  // ------------------------------------------------------------
  // BEACON
  // ------------------------------------------------------------

  if (
    navigator.sendBeacon
  ) {

    const originalBeacon =
      navigator.sendBeacon.bind(
        navigator
      );

    try {

      navigator.sendBeacon =
        function(
          url,
          data
        ) {

          stats.beacon++;

          record({

            source:
              "beacon",

            url:
              new URL(
                url,
                location.href
              ).href,

            method:
              "POST",

            body:
              bodyToText(
                data
              ),

            requestContentType:
              data?.type ||
              ""
          });

          return originalBeacon(
            url,
            data
          );
        };

      cleanups.push(
        () => {

          try {

            navigator.sendBeacon =
              originalBeacon;

          } catch {}
        }
      );

    } catch {}
  }

  // ------------------------------------------------------------
  // WEBSOCKET
  // ------------------------------------------------------------

  const OriginalWebSocket =
    window.WebSocket;

  try {

    window.WebSocket =
      new Proxy(
        OriginalWebSocket,
        {

          construct(
            Target,
            args
          ) {

            const url =
              String(
                args[0]
              );

            stats.websocket++;

            record({

              source:
                "websocket",

              url,

              method:
                "WEBSOCKET"
            });

            const socket =
              Reflect.construct(
                Target,
                args
              );

            socket.addEventListener(
              "message",
              event => {

                record({

                  source:
                    "websocket",

                  url,

                  method:
                    "MESSAGE",

                  responseBody:
                    truncate(
                      event.data,
                      CONFIG.maxResponseBody
                    )
                });
              }
            );

            return socket;
          }
        }
      );

    cleanups.push(
      () => {

        window.WebSocket =
          OriginalWebSocket;
      }
    );

  } catch {}

  // ------------------------------------------------------------
  // PERFORMANCE SCANNER
  // ------------------------------------------------------------

  function scanPerformance() {

    if (
      !CONFIG.scanPerformance
    ) {
      return;
    }

    try {

      const entries =
        performance.getEntriesByType(
          "resource"
        );

      for (
        const entry
        of entries
      ) {

        if (
          !entry.name
        ) {
          continue;
        }

        stats.performance++;

        record({

          source:
            "performance",

          url:
            entry.name,

          method:
            "GET"
        });
      }

    } catch {}
  }

  // ------------------------------------------------------------
  // JAVASCRIPT URL EXTRACTION
  // ------------------------------------------------------------

  function extractURLs(
    text,
    base
  ) {

    const results =
      new Set();

    const patterns = [

      /https?:\/\/[^\s"'`<>\\]+/gi,

      /["'`](\/(?:api|graphql|gql|rest|rpc|jsonrpc|odata|v\d+|wp-json)[^"'`<>\\]*)["'`]/gi,

      /["'`](\/[^"'`<>\\]*(?:users?|accounts?|profiles?|auth|login|orders?|products?|payments?|bookings?|files?|upload|download|messages?|notifications?|settings?|config|search|admin)[^"'`<>\\]*)["'`]/gi

    ];

    for (
      const regex
      of patterns
    ) {

      let match;

      while (
        (match =
          regex.exec(text)) !==
        null
      ) {

        let candidate =
          match[1] ||
          match[0];

        candidate =
          candidate
            .replace(
              /^["'`]/
            , "")
            .replace(
              /["'`]$/
            , "")
            .replace(
              /[),;]+$/,
              ""
            );

        try {

          const absolute =
            new URL(
              candidate,
              base
            ).href;

          results.add(
            absolute
          );

        } catch {}
      }
    }

    return [
      ...results
    ];
  }

  async function scanJavaScript() {

    if (
      !CONFIG.scanJavaScript
    ) {
      return;
    }

    const scripts =
      [
        ...document.scripts
      ]
        .map(
          s => s.src
        )
        .filter(
          Boolean
        )
        .filter(
          src =>
            src.startsWith(
              location.origin
            )
        )
        .slice(
          0,
          CONFIG.maxScripts
        );

    for (
      const src
      of scripts
    ) {

      try {

        const response =
          await originalFetch(
            src,
            {
              credentials:
                "include",

              cache:
                "force-cache"
            }
          );

        if (
          !response.ok
        ) {
          continue;
        }

        const text =
          await response.text();

        if (
          text.length >
          CONFIG.maxScriptSize
        ) {
          continue;
        }

        const urls =
          extractURLs(
            text,
            src
          );

        stats.javascript +=
          urls.length;

        for (
          const url
          of urls
        ) {

          record({

            source:
              "javascript",

            url,

            method:
              "GET"
          });
        }

      } catch {}
    }
  }

  // ------------------------------------------------------------
  // INLINE SCRIPTS
  // ------------------------------------------------------------

  function scanInlineScripts() {

    document
      .querySelectorAll(
        "script:not([src])"
      )
      .forEach(
        script => {

          const text =
            script.textContent ||
            "";

          if (
            !text.trim()
          ) {
            return;
          }

          const urls =
            extractURLs(
              text,
              location.href
            );

          stats.javascript +=
            urls.length;

          for (
            const url
            of urls
          ) {

            record({

              source:
                "javascript",

              url,

              method:
                "GET"
            });
          }
        }
      );
  }

  // ------------------------------------------------------------
  // DOM SCANNER
  // ------------------------------------------------------------

  function scanDOM() {

    document
      .querySelectorAll(
        "form[action]"
      )
      .forEach(
        form => {

          try {

            record({

              source:
                "form",

              url:
                form.action,

              method:
                (
                  form.method ||
                  "GET"
                ).toUpperCase()
            });

          } catch {}
        }
      );

    document
      .querySelectorAll(
        "script[src]"
      )
      .forEach(
        script => {

          try {

            record({

              source:
                "javascript",

              url:
                script.src,

              method:
                "GET"
            });

          } catch {}
        }
      );
  }

  // ------------------------------------------------------------
  // PERFORMANCE OBSERVER
  // ------------------------------------------------------------

  try {

    const performanceObserver =
      new PerformanceObserver(
        list => {

          for (
            const entry
            of list.getEntries()
          ) {

            if (
              !entry.name
            ) {
              continue;
            }

            record({

              source:
                "performance",

              url:
                entry.name,

              method:
                "GET"
            });
          }
        }
      );

    performanceObserver.observe(
      {
        entryTypes:
          ["resource"]
      }
    );

    cleanups.push(
      () =>
        performanceObserver.disconnect()
    );

  } catch {}

  // ------------------------------------------------------------
  // MUTATION OBSERVER
  // ------------------------------------------------------------

  try {

    let timer;

    const mutationObserver =
      new MutationObserver(
        () => {

          clearTimeout(
            timer
          );

          timer =
            setTimeout(
              () => {

                scanDOM();

              },
              400
            );
        }
      );

    mutationObserver.observe(
      document.documentElement,
      {
        subtree:
          true,

        childList:
          true,

        attributes:
          true
      }
    );

    cleanups.push(
      () =>
        mutationObserver.disconnect()
    );

  } catch {}

  // ------------------------------------------------------------
  // INITIAL SCAN
  // ------------------------------------------------------------

  scanDOM();

  scanInlineScripts();

  scanPerformance();

  scanJavaScript();

  // ------------------------------------------------------------
  // CLEANUP FUNCTION
  // ------------------------------------------------------------

  window.__SMART_API_DISCOVERY_CLEANUP__ =
    function() {

      for (
        const cleanup
        of cleanups
      ) {

        try {
          cleanup();
        } catch {}
      }

      console.log(
        "[SmartAPI] Previous instance stopped."
      );
    };

  // ------------------------------------------------------------
  // FINAL STATUS
  // ------------------------------------------------------------

  console.log(
    "%c[SmartAPI] ● LIVE",
    "font-weight:bold"
  );

  console.log(
    "Waiting for API activity..."
  );

})();
