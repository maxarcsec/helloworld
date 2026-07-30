require("./codacy_eslint_canary.cjs");

module.exports = [
  {
    files: ["**/*.js", "**/*.cjs", "**/*.mjs"],
    languageOptions: {
      ecmaVersion: 2021,
      sourceType: "commonjs",
    },
  },
];
