# TLSAuditHub

[![CI](https://github.com/trizzosk/TLSAuditHub/actions/workflows/ci.yml/badge.svg)](https://github.com/trizzosk/TLSAuditHub/actions/workflows/ci.yml)
[![Latest Release](https://img.shields.io/badge/release-0.6-blue)](https://github.com/trizzosk/TLSAuditHub/releases)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)
[![Python](https://img.shields.io/badge/python-3.12-blue)](https://www.python.org/downloads/release/python-3120/)

<img src="ui/logo.svg" alt="TLSAuditHub logo" style="max-width: 33%; width: 100%; height: auto; justify-content: center;">

## Objective
TLSAuditHub is a lightweight platform for auditing SSL/TLS posture across services. It focuses on scheduled scans, change tracking, and an operator-friendly workflow.

The core TLS scanning engine is [`sslyze`](https://github.com/nabla-c0d3/sslyze).

## Functions
- local/OIDC/LDAP authentication
- target inventory and on-demand scans
- scheduled scanning with job history
- TLS results and diff tracking
- DNS posture data (SPF/DMARC/DKIM/WHOIS/NS/MX)
- built-in reports for TLS and mail-security posture
- SMTP CSV export of report findings
- admin controls for users/auth/proxy/scheduler/SMTP/DKIM

## Quick Start
1. `docker compose up`
2. Open `http://localhost:5173`
3. Log in with default admin account:
   - Username: `Adm$n`
   - Password: `Cr!mson$Nebula_7#Qx`

Change the default password immediately after first login.

## Documentation
- [Deployment](/Users/trizzo/Development/TLSAuditHub/docs/deployment.md)
- [DNS And DKIM](/Users/trizzo/Development/TLSAuditHub/docs/dns-and-dkim.md)
- [Authentication](/Users/trizzo/Development/TLSAuditHub/docs/authentication.md)
- [Reports And SMTP](/Users/trizzo/Development/TLSAuditHub/docs/reports-and-smtp.md)

## Notes
- UI source is in `ui/`.
- The login form is shown until authenticated.
- DNS data is collected in the background when targets are added.

## Disclaimer
TLSAuditHub is provided "as is", without warranties of any kind, express or implied, including (without limitation) warranties of merchantability, fitness for a particular purpose, and non-infringement.

The authors and contributors make no guarantee that scan results are complete, accurate, or suitable for operational, legal, compliance, or security decisions. Findings may include false positives and false negatives.

By using this software, you accept full responsibility for validating all outputs before acting on them and for any changes made in your environment.

To the maximum extent permitted by applicable law, the authors and contributors are not liable for any direct, indirect, incidental, special, consequential, or punitive damages, including but not limited to service interruption, data loss, security incidents, compliance failures, financial loss, or other damages arising from the use of, or inability to use, this tool.

## Acknowledgments
- Kudos to the SSLyze maintainers for building and maintaining a robust TLS analysis tool that this project relies on.
