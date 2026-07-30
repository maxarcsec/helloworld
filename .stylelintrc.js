"use strict";

module.exports = {
  plugins: [require("./codacy_stylelint_canary.cjs")],
  rules: {
    "codacy/runtime-canary": true,
  },
};
