# TLSAuditHub

[![CI](https://github.com/trizzosk/TLSAuditHub/actions/workflows/ci.yml/badge.svg)](https://github.com/trizzosk/TLSAuditHub/actions/workflows/ci.yml)
[![Latest Release](https://img.shields.io/badge/release-0.7-blue)](https://github.com/trizzosk/TLSAuditHub/releases)
[![Vibe Coding](https://img.shields.io/badge/vibe%20coding-on-ff69b4)](https://img.shields.io/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)
[![Python](https://img.shields.io/badge/python-3.12-blue)](https://www.python.org/downloads/release/python-3120/)

<img src="ui/logo.svg" alt="TLSAuditHub logo" style="max-width: 33%; width: 100%; height: auto; justify-content: center;">

## Objective
TLSAuditHub is a lightweight platform for auditing SSL/TLS posture across services. It focuses on scheduled scans, change tracking, and an operator-friendly workflow.

The core TLS scanning engine is [`sslyze`](https://github.com/nabla-c0d3/sslyze).

## Vibe-Coded Project Note
This tool is vibe coded and community-driven. It is practical and fast-moving by design, and improvements are expected over time.

## Requirements And Deployment (Simple)
### Requirements
- Docker Engine
- Docker Compose
- Open ports `5173` (UI) and `8000` (API)

### Quick Start In 60 Seconds
1. Start services:
   - `docker compose up`
2. Open UI:
   - `http://localhost:5173`
3. Log in with default admin account:
   - Username: `Adm$n`
   - Password: `Cr!mson$Nebula_7#Qx`

### Security Notice
- Change the default admin password immediately after first login.
- Do not expose the stack publicly before changing credentials and hardening access.

## Usage (Simple)
1. Add domains/hosts in `Domains / Hosts`.
2. Trigger scans (`Run Scan`) or wait for scheduler runs.
3. Review findings in `Results`, `Certificates`, and `Reports`.
4. Use Admin pages for auth/proxy/scheduler/SMTP/DKIM/check policies.

## Troubleshooting
- UI looks stale after update:
  - hard refresh (`Cmd+Shift+R` on macOS, `Ctrl+Shift+R` on Windows/Linux).
- Services not healthy:
  - `docker compose ps`
  - `docker compose logs ui api worker scheduler --tail=200`
- Scan data missing:
  - verify target has TLS checks enabled.
  - verify worker is up.
- DNS/M365 details missing:
  - trigger DNS refresh (or wait for background collection).
  - check resolver/proxy/network reachability.
- Certificates list/details missing:
  - verify target has TLS checks enabled.
  - verify at least one completed TLS scan exists for that target.

## Geeks-Nerds Section
Advanced topics and deployment variants live in dedicated docs pages:

- [Deployment](docs/deployment.md)
- [Authentication](docs/authentication.md)
- [DNS And DKIM](docs/dns-and-dkim.md)
- [Certificates](docs/certificates.md)
- [Reports And SMTP](docs/reports-and-smtp.md)

Recommended DKIM selector lists:
- `docs/dkim-selectors-recommended.txt`
- `docs/dkim-selectors-recommended.csv`

## Disclaimer
TLSAuditHub is provided "as is", without warranties of any kind, express or implied, including (without limitation) warranties of merchantability, fitness for a particular purpose, and non-infringement.

The authors and contributors make no guarantee that scan results are complete, accurate, or suitable for operational, legal, compliance, or security decisions. Findings may include false positives and false negatives.

By using this software, you accept full responsibility for validating all outputs before acting on them and for any changes made in your environment.

To the maximum extent permitted by applicable law, the authors and contributors are not liable for any direct, indirect, incidental, special, consequential, or punitive damages, including but not limited to service interruption, data loss, security incidents, compliance failures, financial loss, or other damages arising from the use of, or inability to use, this tool.

## Acknowledgments
- Kudos to the SSLyze maintainers for building and maintaining a robust TLS analysis tool that this project relies on.
