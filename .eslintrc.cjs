const { runtimeEvidence } = require("./codacy_eslint_canary.cjs");

module.exports = {
  root: true,
  env: {
    es2021: true,
    node: true,
  },
  parserOptions: {
    ecmaVersion: 2021,
    sourceType: "module",
  },
  rules: {
    "no-console": "error",
    "no-restricted-syntax": [
      "error",
      {
        selector: "CallExpression[callee.object.name='console']",
        message: runtimeEvidence,
      },
    ],
  },
};
