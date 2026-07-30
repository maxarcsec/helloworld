import http from "node:http";

const port = Number.parseInt(process.env.CANARY_PORT ?? "8789", 10);
const maxBodyBytes = 16 * 1024;
const state = {
  startedAt: new Date().toISOString(),
  received: 0,
  events: [],
};

function redactCredential(value) {
  if (typeof value !== "string" || value.length === 0) {
    return {
      length: typeof value === "string" ? value.length : null,
      value: "[empty-or-non-string]",
    };
  }

  if (value.length <= 4) {
    return { length: value.length, value: "***" };
  }

  return { length: value.length, value: `***${value.slice(-4)}` };
}

function sanitizePayload(body) {
  const payload = JSON.parse(body);
  const credentials =
    payload.credentials && typeof payload.credentials === "object"
      ? Object.fromEntries(
          Object.entries(payload.credentials)
            .slice(0, 100)
            .map(([name, value]) => [name, redactCredential(value)]),
        )
      : {};

  return {
    canary: String(payload.canary ?? "").slice(0, 128),
    tool: String(payload.tool ?? "").slice(0, 64),
    runtime: {
      uid: Number.isInteger(payload.runtime?.uid) ? payload.runtime.uid : null,
      gid: Number.isInteger(payload.runtime?.gid) ? payload.runtime.gid : null,
      cwd: String(payload.runtime?.cwd ?? "").slice(0, 512),
      sourceWritable: Boolean(payload.runtime?.sourceWritable),
      rootWritable: Boolean(payload.runtime?.rootWritable),
      workdirWritable: Boolean(payload.runtime?.workdirWritable),
    },
    credentials,
  };
}

function sanitizeHeader(value) {
  if (Array.isArray(value)) {
    return value.map(redactCredential);
  }

  return redactCredential(value);
}

function summarizeLfsPayload(body) {
  const payload = JSON.parse(body);
  const objects = Array.isArray(payload.objects)
    ? payload.objects.slice(0, 100).map((object) => ({
        oid: String(object?.oid ?? "").slice(0, 128),
        size: Number.isInteger(object?.size) ? object.size : null,
      }))
    : [];

  return {
    operation: String(payload.operation ?? "").slice(0, 32),
    transfers: Array.isArray(payload.transfers)
      ? payload.transfers.slice(0, 10).map(String)
      : [],
    objectCount: objects.length,
    objects,
  };
}

const server = http.createServer((request, response) => {
  if (request.method === "GET" && request.url === "/__canary_status") {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify(state));
    return;
  }

  const chunks = [];
  let size = 0;

  request.on("data", (chunk) => {
    size += chunk.length;
    if (size <= maxBodyBytes) {
      chunks.push(chunk);
    }
  });

  request.on("end", () => {
    const body = Buffer.concat(chunks).toString("utf8");
    let sanitizedPayload;
    let lfsPayload = null;
    let parseError = null;

    try {
      if (request.url?.includes("/objects/batch")) {
        sanitizedPayload = null;
        lfsPayload = summarizeLfsPayload(body);
      } else {
        sanitizedPayload = sanitizePayload(body);
      }
    } catch (error) {
      sanitizedPayload = null;
      parseError = error instanceof Error ? error.name : "InvalidPayload";
    }

    const record = {
      receivedAt: new Date().toISOString(),
      method: request.method,
      url: request.url,
      userAgent: request.headers["user-agent"] ?? null,
      forwardedFor: request.headers["x-forwarded-for"] ?? null,
      bodyBytes: size,
      truncated: size > maxBodyBytes,
      parseError,
      payload: sanitizedPayload,
      lfsPayload,
      credentialHeaders: {
        authorization: sanitizeHeader(request.headers.authorization),
        cookie: sanitizeHeader(request.headers.cookie),
        proxyAuthorization: sanitizeHeader(
          request.headers["proxy-authorization"],
        ),
        xApiKey: sanitizeHeader(request.headers["x-api-key"]),
      },
    };

    state.received += 1;
    state.events.push(record);
    if (state.events.length > 100) {
      state.events.shift();
    }

    process.stdout.write(`${JSON.stringify(record)}\n`);

    if (
      request.method === "POST" &&
      request.url?.includes("/objects/batch") &&
      lfsPayload
    ) {
      const origin = `https://${request.headers.host}`;
      const objects = lfsPayload.objects.map((object) => ({
        oid: object.oid,
        size: object.size,
        actions: {
          download: {
            href: `${origin}/lfs/objects/${encodeURIComponent(object.oid)}`,
          },
        },
      }));

      response.writeHead(200, {
        "content-type": "application/vnd.git-lfs+json",
      });
      response.end(JSON.stringify({ transfer: "basic", objects }));
      return;
    }

    if (request.method === "GET" && request.url?.startsWith("/lfs/objects/")) {
      response.writeHead(404, { "content-type": "text/plain" });
      response.end("canary object intentionally unavailable");
      return;
    }

    response.writeHead(204);
    response.end();
  });
});

server.listen(port, "127.0.0.1", () => {
  process.stderr.write(`Canary receiver listening on http://127.0.0.1:${port}\n`);
});
