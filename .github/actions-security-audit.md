# GitHub Actions security audit

Audited on 2026-04-30.

## Findings addressed

- All third-party and first-party `uses:` references in `.github/workflows/*.yml`
  are pinned to immutable 40-character commit SHAs. The original tag or branch is
  retained in a YAML comment to keep reviews and Dependabot updates readable.
- Workflows now declare default `permissions: contents: read`, reducing the
  default `GITHUB_TOKEN` scope for jobs that do not need write access.
- Jobs that require elevated permissions keep job-scoped grants:
  - `ci.yml` `deploy-docs`: `pages: write`, `id-token: write`
  - `release.yml` `release-notes`: `contents: write`
- Dependabot is configured for the `github-actions` ecosystem so pinned action
  SHAs can be reviewed and updated regularly.

## Residual risks to track

- `e2e.yml` installs the Aptos CLI with `curl | python3` from
  `https://aptos.dev/scripts/install_cli.py`. Prefer a checksum-verified release
  artifact or another version-pinned installer when available.
- Several jobs install cargo subcommands from crates.io at runtime
  (`cargo-audit`, `cargo-deny`, `cargo-tarpaulin`). Prefer `cargo install
  --locked --version <version>` or a prebuilt, verified tool image for
  reproducible CI.
- Hosted runner labels such as `ubuntu-latest`, `macos-latest`, and
  `windows-latest` move over time. Pin OS image versions where reproducibility is
  more important than automatically receiving hosted runner updates.
- `security.yml` keeps `cargo deny check` as `continue-on-error` until policy is
  configured; dependency policy violations will not fail CI yet.
