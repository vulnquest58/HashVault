# Security Policy

HashVault is a dual-use security tool. We take security reports seriously and
ask researchers to act in good faith.

## Supported versions

| Version | Supported |
| --- | --- |
| 2.0.x | Yes |
| 1.x | No |
| 0.x | No |

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting:

<https://github.com/vulnquest58/HashVault/security/advisories/new>

If that is unavailable, contact the maintainer through the GitHub profile at
<https://github.com/vulnquest58> and request a private channel. Do not open a
public issue with exploit details, secrets, or customer data.

Include:

- affected version or commit,
- a minimal reproduction,
- the security impact and affected component,
- whether the issue requires local access, a crafted input, or a malicious
  configuration,
- any suggested fix or mitigation.

## Scope

In scope:

- command injection or argument injection,
- path traversal or unsafe file handling,
- binary planting or unsafe helper resolution,
- decompression bombs or resource exhaustion,
- certificate/evidence signature bypass or plaintext leakage,
- secret exposure in logs, reports, or generated artifacts,
- dependency vulnerabilities with a practical impact.

Out of scope:

- using HashVault against systems without authorization,
- weak passwords or hashes present in test corpora,
- reports that require a compromised local account without a privilege boundary,
- social engineering or physical attacks,
- issues in optional third-party engines (report those upstream).

## Safe harbor

We will not pursue action against researchers who:

- make a good-faith effort to avoid privacy violations, data loss, and service
  disruption,
- use only test data or data they are authorized to access,
- give us reasonable time to investigate and remediate before disclosure,
- do not exploit the issue beyond what is needed to demonstrate it.

## Response process

We aim to acknowledge a report within 5 business days and provide a status
update within 10 business days. Timelines depend on severity and complexity.
We will credit reporters who want attribution after a fix is available.

## Handling secrets

Never include tokens, private keys, plaintext passwords, customer hashes, or
engagement material in a report. If a secret was exposed, rotate it immediately
and tell us what was exposed without repeating the value.

## Release security

Release artifacts are built from a clean checkout, tested, and published with a
changelog and tag. See [docs/RELEASE.md](docs/RELEASE.md). Security fixes may be
released without prior public detail.
