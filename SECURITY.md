# Security reporting

Do not publish credentials, private databases, unredacted network inventories or exploit details in an ordinary public issue. If GitHub private vulnerability reporting is enabled for this repository, use its **Security → Report a vulnerability** flow. Otherwise ask the maintainer for a private reporting channel without disclosing sensitive details in the issue.

Include the affected version, impact, minimal reproduction and whether the problem affects discovery boundaries, database handling, startup or report output. Use controlled test data and authorized systems.

Version 3.0.0 is an unsigned development release. A matching SHA-256 manifest confirms byte equality; it does not provide a trusted code-signing identity. Native Windows acceptance status is documented in `docs/VALIDATION.md`.
