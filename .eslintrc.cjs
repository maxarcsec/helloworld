require("./codacy_eslint_canary.cjs");

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
};
