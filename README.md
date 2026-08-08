# Codacy analyzer isolation canary

This repository contains harmless canaries for verifying how Codacy executes
repository-controlled analyzer configuration.

The canaries test:

- whether RuboCop and ESLint configuration can execute repository code;
- whether the analyzer container has outbound network access;
- which user runs the analyzer;
- whether `/`, `/src`, and `/workdir` are writable; and
- whether credential-like environment variables are present.

For this isolated run, the RuboCop canary sends only a fixed marker, numeric
execution identity, three writable-directory booleans, and credential-like
environment variable names to a temporary researcher-controlled TLS catcher.
It never reads or transmits environment values, file contents, tokens, secrets,
hostnames, or PII.

To trigger each canary, enable the repository configuration-file option for
RuboCop, ESLint 8, and ESLint 9 in Codacy, then reanalyze this repository.

These files do not execute shell commands, read files, alter repository
contents, or transmit arbitrary environment variables.
