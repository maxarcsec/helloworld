# Codacy analyzer and tenant-boundary security test report

Date: 2026-07-31  
Attacker identity: `maxarcsec`  
Controlled repository: `maxarcsec/helloworld`  
Test pull request: <https://github.com/maxarcsec/helloworld/pull/1>

## Latest state

No Critical vulnerability is confirmed.

Three repository-controlled analyzer code-execution paths are confirmed:

1. Prospector automatically loaded `.prospector.yaml` and imported a
   repository-controlled Pylint plugin.
2. Stylelint loaded a branch-only `.stylelintrc.js` even though the public
   tool-settings API reported no repository configuration file.
3. Checkov loaded a repository-controlled Python external check after its
   repository configuration option was explicitly enabled.

Each path allowed the repository code to create a child process. Prospector and
Stylelint are configuration-boundary findings because Codacy reported
`hasConfigurationFile=false` and `usesConfigurationFile=false` during the
tests. Checkov is an expected configuration feature with a dangerous trust
boundary, not a configuration-state bypass.

A separate Agentlinter review found that Codacy invokes `agentlinter --json`
without `--local` or `--no-share`. Agentlinter 0.3.3 then attempts to upload a
machine fingerprint, diagnostics, and file names to `agentlinter.com`. The
upload code path and live invocation are confirmed, but successful delivery to
the third party is not.

The observed analyzer container materially limits impact:

- analyzer UID and GID were both `2004`;
- `/`, `/src`, and `/workdir` were not writable;
- no credential-like environment variable names were present;
- HTTP and HTTPS egress to the controlled catcher failed; and
- the catcher received no request during the sampled run.

These are confirmed arbitrary code and child-process execution paths inside
analyzer containers. They are not confirmed host RCE, credential theft,
cross-tenant access, or write access.

## Finding F-01: implicit Prospector profile loads repository Python

Status: Confirmed live  
Current severity: Below Critical on observed evidence  
Affected surface: Codacy Prospector analyzer

### Trigger

The controlled branch added:

1. `.prospector.yaml` with `pylint.load-plugins: codacy_pylint_canary`
2. `codacy_pylint_canary.py`, an importable repository-controlled module
3. a harmless Python target that causes the plugin to emit a custom issue

The plugin performed only bounded canary operations:

- queried its UID, GID, and write permissions;
- enumerated only credential-like environment variable names for issue output;
- sent any matching values only toward the researcher-controlled redacting
  catcher;
- attempted to start the current Python interpreter with `-c pass`; and
- emitted the results as a custom Pylint issue.

### Live proof

Commit
[`9947853`](https://github.com/maxarcsec/helloworld/commit/99478531bf275a9fe574f9e93a06753927586f86)
completed Codacy analysis and produced this Prospector issue:

```text
CODACY_PYLINT_CANARY_EXECUTED uid=2004 gid=2004
source_writable=False root_writable=False workdir_writable=False
subprocess_exec=True http_egress=False https_egress=False
credential_names=
```

The public tool-settings endpoint reported these Prospector settings during
the same test:

```json
{
  "isEnabled": true,
  "hasConfigurationFile": false,
  "usesConfigurationFile": false
}
```

That response is available from:

<https://api.codacy.com/api/v3/analysis/organizations/gh/maxarcsec/repositories/helloworld/tools>

The current public Prospector wrapper explains the behavior. It starts
`python3 -m prospector` with `/src` as the working directory and does not pass
an explicit trusted profile. Prospector therefore auto-discovers the
repository's `.prospector.yaml`:

<https://github.com/codacy/codacy-prospector/blob/7d2e2ddb513c9337e7553d25958e4b135f9af7d5/src/codacy_prospector.py>

### Security impact

A repository author can execute arbitrary Python and child processes whenever
Codacy analyzes that repository with Prospector enabled. The issue message is
also an output channel from analyzer code back into Codacy.

The tested PR used a branch in the controlled repository. An external-fork
attacker trigger has not been proven. Until that trigger and access to a useful
secret or privileged writable resource are demonstrated, the evidence does not
support a Critical rating.

### Recommended remediation

1. Pass Prospector an explicit trusted profile stored outside `/src`.
2. Do not allow automatic discovery of `.prospector.yaml`, `.prospector.yml`,
   `prospector.yaml`, `prospector.yml`, or equivalent profile paths when
   repository configuration is disabled.
3. Run Prospector from an immutable working directory and pass source files by
   absolute path.
4. Remove the source tree from Python module search paths before starting
   Prospector unless importing repository modules is explicitly required.
5. Reject Pylint options such as `load-plugins` and other import or init hooks
   in any repository-supplied profile.
6. Keep the existing read-only filesystem, unprivileged user, empty secret
   environment, and network-deny controls.
7. Add a regression test that places a plugin in `/src` and verifies that its
   import side effect never occurs.

## Finding F-02: branch-only Stylelint JavaScript executes implicitly

Status: Confirmed live

Current severity: Below Critical on observed evidence

Affected surface: Codacy Stylelint analyzer

The controlled branch added `.stylelintrc.js`. The file imported a harmless
repository module that measured the sandbox, created a child Node.js process,
attempted HTTP and HTTPS callbacks, and returned the marker as the configured
message for `color-no-invalid-hex`.

Commit
[`bc935b9`](https://github.com/maxarcsec/helloworld/commit/bc935b910db0e2171058f0ce795d35183867f134)
produced this live Stylelint issue:

```text
CODACY_STYLELINT_CANARY_EXECUTED uid=2004 gid=2004
source_writable=false root_writable=false workdir_writable=false
subprocess_exec=true http_egress=false https_egress=false
credential_names=
```

At the same time, the public tool-settings API reported:

```json
{
  "isEnabled": true,
  "hasConfigurationFile": false,
  "usesConfigurationFile": false
}
```

The wrapper uses a repository configuration when Codacy supplies no pattern
configuration to the engine. It recognizes executable JavaScript filenames,
including `.stylelintrc.js`:

<https://github.com/codacy/codacy-stylelint/blob/9c62c258ac0e54a651b35d0a4928fb2d97266ec4/src/main/scala/codacy/stylelint/Stylelint.scala>

The file existed only on the analyzed branch. This demonstrates that
default-branch configuration detection does not prevent a PR branch from
introducing executable Stylelint configuration.

Recommended remediation:

1. Never load JavaScript configuration when repository configuration is
   reported disabled.
2. Generate and pass an immutable JSON configuration outside `/src`.
3. If repository configuration is allowed, accept data-only formats and reject
   `.js`, `.cjs`, `.mjs`, plugin modules, processors, and custom syntax modules.
4. Add a branch-only regression fixture and verify its import side effect does
   not run.

## Finding F-03: enabled Checkov configuration loads repository Python

Status: Confirmed live

Current severity: Below Critical on observed evidence

Affected surface: Codacy Checkov analyzer with repository configuration enabled

Codacy detected `.checkov.yml` on the default branch and set:

```json
{
  "isEnabled": true,
  "hasConfigurationFile": true,
  "usesConfigurationFile": true
}
```

The PR branch changed that configuration to include:

```yaml
external-checks-dir:
  - checkov_external_checks
framework:
  - terraform
```

The referenced Python package defines a custom Checkov policy and a bounded
runtime marker. Commit
[`c911fb3`](https://github.com/maxarcsec/helloworld/commit/c911fb37a76d5cb97efa9167c6f95c7c161b91ad)
completed 152.700 seconds of active Checkov execution. The current Codacy PR
issues then contained:

```text
CODACY_CHECKOV_CANARY_EXECUTED uid=2004 gid=2004
source_writable=False root_writable=False workdir_writable=False
subprocess_exec=True http_egress=False https_egress=False
credential_names=
```

The same marker was reproduced locally with the exact deployed public image,
`codacy/codacy-checkov:1.3.28`.

The wrapper passes a repository `.checkov.yml` directly to Checkov whenever the
tool is configured to use repository configuration:

<https://github.com/codacy/codacy-checkov/blob/724f533f1bbb3379e9cb884939ffaf31fbede2ae/src/codacy_checkov.py>

Unlike F-01 and F-02, the API state accurately discloses that repository
configuration is active. The security concern is that a branch author can
replace an approved data file with a Python external-check path. Whether an
untrusted external-fork PR can reach this path remains unproven.

Recommended remediation:

1. Remove `external-checks-dir` and equivalent code-loading options from
   repository-supplied Checkov configuration.
2. Generate a sanitized configuration outside `/src`.
3. Pin policy code to an administrator-managed immutable bundle.
4. Preserve the observed unprivileged, read-only, secret-empty, network-denied
   sandbox.

## Finding F-04: Agentlinter implicitly attempts third-party report upload

Status: Code path and live invocation confirmed; successful upload unconfirmed

Current severity: Requires deployment-specific impact validation

Affected surface: Codacy Agentlinter analyzer version 0.3.3

The Codacy wrapper invokes:

```text
agentlinter <workspace> --json
```

It does not pass `--local` or `--no-share`:

<https://github.com/codacy/codacy-agentlinter/blob/493284e09c0ee2920482996231816b58db978d97/src/engineImpl.ts>

The packaged Agentlinter 0.3.3 CLI initializes sharing as enabled. Unless one of
those opt-out flags is supplied, it sends a POST to
`https://agentlinter.com/api/reports` containing:

- a stable hash derived from container hostname and username;
- category scores;
- diagnostics with file, line, message, and proposed fix;
- scanned file names; and
- the number of rules checked.

The same package also reads selected runtime configuration and skill files from
`HOME`, outside the repository source path. It uses normal filesystem reads,
which follow symbolic links. The reviewed package is available from:

<https://registry.npmjs.org/agentlinter/-/agentlinter-0.3.3.tgz>

Commit
[`fc4b940`](https://github.com/maxarcsec/helloworld/commit/fc4b94005bf5aa0eb2c4cd2c51dcfe6b36a89310)
caused 21.057 seconds of active Agentlinter execution after adding a controlled
`AGENTS.md`. Earlier runs without a recognized agent file showed zero active
execution time. The delay is consistent with the package attempting its
default upload, but is not wire proof. The destination is not the controlled
catcher, and the wrapper ignores successful-run stderr where the share URL is
printed.

Recommended remediation:

1. Always pass `--local` or `--no-share`.
2. Block access to `HOME` paths and resolve every scanned path beneath `/src`
   after following symbolic links.
3. Disable outbound network access independently of CLI flags.
4. Add a regression test that fails if an analyzer attempts DNS or HTTP access
   to `agentlinter.com`.
5. Review historical third-party reports and retention if production egress
   allowed uploads.

## Analyzer and checkout test matrix

| Surface | Trigger tested | Result | Evidence boundary |
| --- | --- | --- | --- |
| Prospector | `.prospector.yaml` loads repository Pylint plugin | Positive | Arbitrary Python and child-process execution confirmed |
| Pylint | `.pylintrc` loads the same plugin | Negative | Direct Pylint emitted its normal undefined-variable issue |
| ESLint | Repository JavaScript configuration | Positive | Repository JavaScript executed as UID/GID 2004 |
| RuboCop | Repository Ruby configuration | Positive | Repository Ruby executed as UID/GID 2004 |
| Stylelint | Branch-only `.stylelintrc.js` imports repository JavaScript | Positive | JavaScript and child-process execution confirmed |
| Checkov | `.checkov.yml` points to repository external Python checks | Positive | Python and child-process execution confirmed live |
| Agentlinter | Recognized `AGENTS.md` with wrapper omitting no-share flags | Code-path positive | Live invocation confirmed; third-party delivery unconfirmed |
| Git LFS | Attacker-controlled `.lfsconfig` batch URL and LFS pointer | Negative | No batch or object request reached the catcher |
| Git submodule | Attacker-controlled submodule URL | Negative | No submodule request reached the catcher |
| npm | Lifecycle scripts and remote optional dependency | Negative | No dependency or lifecycle request reached the catcher |
| Bundler | Attacker-controlled gem source | Negative | No request reached the catcher |
| pip | Direct remote wheel requirement | Negative | No request reached the catcher |
| Markdownlint | Wrapper source review | No executable config found | Wrapper reads only JSON, JSONC, or YAML configuration |
| Bandit | Wrapper source review plus live requirements canary | No code-loading path found | Wrapper passes only known config formats and did not install requirements |

The LFS, submodule, and dependency results establish that these exact canaries
were not fetched during the sampled analyses. They do not prove that every
Codacy checkout path, product tier, or future analyzer image behaves the same.

### Git LFS credential-forwarding test boundary

The branch contained all elements needed to make a normal Git LFS checkout
contact an attacker-controlled origin:

- `.gitattributes` marked `fixtures/codacy-lfs-canary.bin` as an LFS object;
- the file contained a valid LFS pointer with a fixed SHA-256 object ID; and
- `.lfsconfig` changed `lfs.url` to the controlled HTTPS catcher.

The catcher was prepared to record the LFS batch request, return an
attacker-origin download action, and sanitize any `Authorization`, cookie,
proxy authorization, or API key header to length plus its final four
characters. It saw neither the batch request nor the object request. Therefore
the tested Codacy PR checkout did not fetch LFS content or forward its Git
credential to this attacker origin.

This is a negative result for the sampled checkout path. It does not establish
that LFS is disabled for every repository type or legacy source-preparation
worker.

## Cross-tenant repository hypothesis

Hypothesis:

> Can an authenticated Codacy user submit another organization's private
> `repositoryFullPath`, causing Codacy to select that organization's GitHub App
> installation and clone the private repository without verifying the caller's
> membership?

The relevant API is `POST /api/v3/repositories` with:

```json
{
  "provider": "gh",
  "repositoryFullPath": "victim-organization/private-canary"
}
```

Codacy documents that adding a repository requires Git provider administrator
permission:

<https://docs.codacy.com/codacy-api/examples/adding-repositories-to-codacy-programmatically/>

### Tests completed

- Public repository metadata for both `maxarcsec/helloworld` and
  `deliveryhero/asya` was readable without authentication, as documented for
  public repositories.
- Protected Delivery Hero settings returned `401 Authentication required`.
- Coding-standard object IDs returned `401` before object lookup when the
  organization path and object ID were intentionally crossed.
- An invalid historical token found in a Codacy public repository returned
  `401 Bad credentials`. The token value was not retained or reproduced.
- No Delivery Hero mutation endpoint was called.

### What is not proven

The exact authenticated cross-tenant condition remains untested. A valid test
requires:

1. an attacker Codacy API token belonging to `maxarcsec`;
2. a second, separately controlled GitHub organization or identity;
3. a private canary repository visible only to that victim identity;
4. the Codacy GitHub App installed for the victim organization; and
5. confirmation that `maxarcsec` has no GitHub or Codacy access to the victim.

The secure result is `403` or `404` before clone or analysis. A clone or
analysis event would confirm the original hypothesis.

Delivery Hero was used only for non-destructive public reads. Codacy's
responsible disclosure policy asks researchers to test with their own data, so
an authenticated add-repository probe against Delivery Hero would exceed the
safe test boundary:

<https://www.codacy.com/security-policies>

## Credential and catcher handling

The receiver stores only sanitized events. Credential headers and
credential-like payload values are represented by their length and last four
characters. Values of four characters or fewer are fully masked. ngrok
inspection was disabled.

At the time of this update, the active receiver showed zero analyzer-originated
events since `2026-07-30T19:08:10.116Z`. It held one local mistaken
`GET /status` poll from the researcher workstation; that event had no body or
credential headers and was excluded from analyzer evidence.

## Conclusion

The strongest confirmed results are implicit Prospector and Stylelint
configuration paths that lead to arbitrary analyzer-container code and process
execution. Enabled Checkov repository configuration also exposes a Python
code-loading path. The container controls observed in these tests prevented
escalation to a confirmed Critical.

Agentlinter adds a separate privacy and trust-boundary concern: the packaged
CLI defaults to sending analysis metadata to a third party, and its scan scope
includes selected files under `HOME`. Successful production delivery was not
proven.

The original cross-tenant clone hypothesis is still worth testing, but no
valid severity claim can be made until a second controlled private tenant and
an attacker Codacy API token are available.
