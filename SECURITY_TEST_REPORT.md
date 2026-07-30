# Codacy analyzer and tenant-boundary security test report

Date: 2026-07-31  
Attacker identity: `maxarcsec`  
Controlled repository: `maxarcsec/helloworld`  
Test pull request: <https://github.com/maxarcsec/helloworld/pull/1>

## Latest state

No Critical vulnerability is confirmed.

One previously undocumented code-execution surface is confirmed live:
Prospector automatically loaded `.prospector.yaml`, imported a
repository-controlled Pylint plugin, and allowed that plugin to create a child
process. Codacy's public tool-settings API simultaneously reported that
Prospector did not have and was not using a repository configuration file.

The observed analyzer container materially limits impact:

- analyzer UID and GID were both `2004`;
- `/`, `/src`, and `/workdir` were not writable;
- no credential-like environment variable names were present;
- HTTPS egress to the controlled catcher failed; and
- the catcher received no request during the sampled run.

This is confirmed arbitrary code and child-process execution inside the
Prospector analyzer container. It is not confirmed host RCE, credential theft,
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

## Analyzer and checkout test matrix

| Surface | Trigger tested | Result | Evidence boundary |
| --- | --- | --- | --- |
| Prospector | `.prospector.yaml` loads repository Pylint plugin | Positive | Arbitrary Python and child-process execution confirmed |
| Pylint | `.pylintrc` loads the same plugin | Negative | Direct Pylint emitted its normal undefined-variable issue |
| ESLint | Repository JavaScript configuration | Positive | Repository JavaScript executed as UID/GID 2004 |
| RuboCop | Repository Ruby configuration | Positive | Repository Ruby executed as UID/GID 2004 |
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

At the time of this report, the active receiver snapshot showed zero events
since `2026-07-30T19:08:10.116Z`.

## Conclusion

The strongest confirmed result is an implicit Prospector configuration bypass
that leads to arbitrary analyzer-container code and process execution. The
container controls observed in this test prevented escalation to a confirmed
Critical.

The original cross-tenant clone hypothesis is still worth testing, but no
valid severity claim can be made until a second controlled private tenant and
an attacker Codacy API token are available.
