# Codacy analyzer isolation canary

This repository contains harmless canaries for verifying how Codacy executes
repository-controlled analyzer configuration.

The canaries test:

- whether RuboCop and ESLint configuration can execute repository code;
- whether the analyzer container has outbound network access;
- which user runs the analyzer;
- whether `/`, `/src`, and `/workdir` are writable; and
- whether credential-like environment variables are present.

Credential-like values are sent only to the temporary, researcher-controlled
TLS catcher. The catcher prints only the variable name, value length, and the
last four characters. Values four characters or shorter are fully masked.

To trigger each canary, enable the repository configuration-file option for
RuboCop, ESLint 8, and ESLint 9 in Codacy, then reanalyze this repository.

These files do not execute shell commands, read files, alter repository
contents, or transmit arbitrary environment variables.

Runloop Reflex gateway-path canary: 2026-08-29-M.
Runloop Reflex IMDSv2 token canary: 2026-08-29-N.
Runloop Reflex IPv6 root control: 2026-08-29-O.
