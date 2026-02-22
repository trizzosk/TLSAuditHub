# TLSAuditHub
Simple platform for SSL/TLS audits of services. Provides periodical scans with dashboards. More features will follow.

## UI Prototype
This repo now includes a lightweight frontend prototype in `ui-prototype/` to quickly test dashboard flows against the API.

### Run
1. Start all services (including UI): `docker compose up`.
2. Open `http://localhost:5173`.

Alternative (no UI container):
1. Start backend only: `docker compose up api worker scheduler postgres redis`
2. In another terminal:
   - `cd ui-prototype`
   - `python3 -m http.server 5173`
3. Open `http://localhost:5173`.

### What it includes
- Health check panel
- Login form (`/auth/token`)
- Add target form (`/targets`)
- Targets table (`/targets`)
- Diff history viewer (`/targets/{target_id}/diffs`)
