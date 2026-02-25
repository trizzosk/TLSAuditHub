# TLSAuditHub

## Objective
TLSAuditHub is a lightweight platform for auditing SSL/TLS posture across services. It focuses on scheduled scans, change tracking, and a clean operator workflow.

## Functions
- Authentication via `/auth/token`.
- Targets inventory with add/delete operations via `/targets`.
- On-demand scan triggering per target.
- Jobs view to track scan status and history.
- Results view for job output details.
- Spoofable report view to highlight domains with weak SPF/DMARC posture.
- DNS data collection per target (WHOIS, NS, MX, SPF, DMARC) used by reports.
- Admin proxy configuration for outbound scan traffic.
- UI prototype for exercising the API and dashboards.

## Deployment
The repo ships as a multi-service Docker Compose stack (API, worker, scheduler, Postgres, Redis, UI).

### Run everything (API + workers + UI)
1. `docker compose up`
2. Open `http://localhost:5173`

### Run backend only and host the UI locally
1. `docker compose up api worker scheduler postgres redis`
2. In another terminal:
   - `cd ui-prototype`
   - `python3 -m http.server 5173`
3. Open `http://localhost:5173`

## Notes
- The UI prototype is in `ui-prototype/` and intended for workflow validation.
- The UI presents only the login form until authenticated.
- The Spoofable report uses stored DNS data (SPF/DMARC) per target to classify spoofing risk.
- DNS data is collected in the background when a target is added.
