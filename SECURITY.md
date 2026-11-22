# Security policy

Spoor is experimental. Please include the commit you reviewed in any report.

## Report a vulnerability privately

While the repository is private, contact the maintainers through the private
channel you used to get access. Once Spoor is public and GitHub's private
vulnerability reporting is enabled, use **Security and quality → Advisories →
Report a vulnerability**.

Include the affected commit, the setup needed to observe the issue, and the
potential impact. Use synthetic data and redact credentials, customer data,
and contents of audit trails. Keep vulnerability details out of public issues.

## Handling audit data

Spoor's broker listens on loopback by default and assumes a trusted client.
The policy and detection rules are intended for controlled environments.

The broker records command arguments in its trail. The optional model proxy
can record prompt and reasoning content. Parent command redaction covers common
credential patterns. Use restricted permissions for audit files and any
forwarded copies.
