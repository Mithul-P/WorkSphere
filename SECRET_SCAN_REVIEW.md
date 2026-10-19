# Secret scan review

Reviewed on 19 October 2026 using Gitleaks 8.24.2 over the complete Git history.

The four findings in import commit `18b857b1198f5a3ae2d57029e373be564b2155bb` were the public hexadecimal test/demo TOTP key in `apps/api/tests/setup.ts`, `scripts/local.ts`, and `.github/workflows/ci.yml`, plus the unfilled replacement instruction in `.env.example`. These values were synthetic development fixtures or a placeholder, not identified production credentials. The local launcher creates a disposable database, and the CI database is recreated for every run.

The test setup, local launcher and CI now generate fresh random keys. CI shares its ephemeral keys across migration, seeding, API and browser-test processes. The example environment file leaves the TOTP key empty and requires the operator to generate it as described in the README. Persistent installations must retain their existing encryption keys; replacing one invalidates encrypted authenticator secrets.

`.gitleaksignore` records only the four exact historical commit/file/rule/line fingerprints. No scanning rules or file paths are disabled. Gitleaks remains a required, independent CI job and scans the full committed history with redacted diagnostics. Docker Compose's explicitly documented local-demo defaults remain development-only; production requires independently configured secrets.
