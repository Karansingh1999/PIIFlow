# Security Policy

## Supported Versions

Security reports are accepted for the `0.3.x` line.

## Reporting A Vulnerability

Do not include real personal data, credentials, private keys, proprietary source
code, or exploit details in a public issue.

If GitHub private vulnerability reporting is enabled for the repository, use that
feature. If it is not enabled, open a minimal public issue that says you need a
private channel for a security report, without sensitive details.

No private security email address has been verified for this repository, so this
document does not invent one.

## What Counts As A Security Issue

Examples:

- PIIFlow unexpectedly executes scanned target code.
- A crafted repository causes unsafe file writes outside the intended output path.
- Packaged code includes credentials or private keys.
- CLI error handling exposes sensitive local details beyond normal paths and
  diagnostics.

## Analyzer Limitations

False positives and false negatives in static analysis are usually analyzer
limitations rather than security vulnerabilities in PIIFlow itself. They are
still valuable reports, especially when accompanied by a minimal synthetic
reproduction.

## Privacy Notes

PIIFlow scans source code locally and does not execute the target program. It
does not call LLM providers, inspect production data, or guarantee legal,
regulatory, contractual, or organizational compliance.
