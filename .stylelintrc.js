"use strict";

const runtimeEvidence = require("./codacy_stylelint_canary.cjs");

module.exports = {
  rules: {
    "color-no-invalid-hex": [true, { message: runtimeEvidence }],
  },
};
