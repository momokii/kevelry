# Security Policy

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| `main`  | :white_check_mark: |

Only the current `main` branch (and the container image built from it) is
supported. The CVE intelligence data shown by a deployment is a
last-known-good snapshot governed by upstream feed terms, not by this file.

## Reporting a vulnerability

**Do not open a public issue for a suspected vulnerability.**

- Use GitHub's **private vulnerability reporting** (Security tab →
  Report a vulnerability) on this repository, or contact the maintainer
  privately if you have a direct channel.
- Include: affected route or file, steps to reproduce, the impact you see,
  and anything you already tried. Logs and screenshots help; never include
  secrets, credentials, or personal data.
- You will get an acknowledgment and a remediation plan or timeline. If a
  fix needs a coordinated data refresh or redeploy, that will be stated.

## Scope notes for reporters

- The public surface is intentionally a **read-only, anonymous** website
  and API: no accounts, sessions, uploads, or user data stores. Reports
  about the absence of authentication are out of scope by design.
- Upstream feed content (CVE descriptions, references) is **untrusted
  third-party data**; output-encoding issues in how it is rendered are in
  scope, the upstream content itself is not.
- The project whitespaces no secrets into the repo or image; a report
  should demonstrate exposure, not just the presence of a placeholder.

## No bounty

There is no paid bug bounty. Valid reports are credited in the release
notes unless you ask to stay anonymous.
