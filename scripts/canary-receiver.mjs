import http from "node:http";

const port = Number.parseInt(process.env.CANARY_PORT ?? "8789", 10);
const maxBodyBytes = 16 * 1024;

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

const server = http.createServer((request, response) => {
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
    let parseError = null;

    try {
      sanitizedPayload = sanitizePayload(body);
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
    };

    process.stdout.write(`${JSON.stringify(record)}\n`);
    response.writeHead(204);
    response.end();
  });
});

server.listen(port, "127.0.0.1", () => {
  process.stderr.write(`Canary receiver listening on http://127.0.0.1:${port}\n`);
});
