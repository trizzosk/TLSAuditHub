# TLSAuditHub

[![CI](https://github.com/trizzosk/TLSAuditHub/actions/workflows/ci.yml/badge.svg)](https://github.com/trizzosk/TLSAuditHub/actions/workflows/ci.yml)
[![Latest Release](https://img.shields.io/badge/release-0.6-blue)](https://github.com/trizzosk/TLSAuditHub/releases)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)
[![Python](https://img.shields.io/badge/python-3.12-blue)](https://www.python.org/downloads/release/python-3120/)

<img src="ui/logo.svg" alt="TLSAuditHub logo" style="max-width: 33%; width: 100%; height: auto; justify-content: center;">

## Objective
TLSAuditHub is a lightweight platform for auditing SSL/TLS posture across services. It focuses on scheduled scans, change tracking, and a clean operator workflow.
The core TLS scanning engine in this project is [`sslyze`](https://github.com/nabla-c0d3/sslyze), which powers the certificate and protocol analysis.

## Functions
- Authentication via `/auth/token`.
- Optional OpenID Connect login with local username mapping (user must exist in app).
- Targets inventory with add/delete operations via `/targets`.
- On-demand scan triggering per target.
- Jobs view to track scan status and history.
- Results view for job output details.
- Spoofable report view to highlight domains with weak SPF/DMARC posture.
- DNS data collection per target (WHOIS, NS, MX, SPF, DMARC) used by reports.
- Admin proxy configuration for outbound scan traffic.
- Web UI for exercising the API and dashboards.

## Deployment
The repo ships as a multi-service Docker Compose stack (API, worker, scheduler, Postgres, Redis, UI).

### Corporate proxy support
If your network requires an outbound HTTP proxy, set the standard proxy environment variables before running Docker Compose. The containers will pass these through for `pip install` during startup.

1. Add these to `.env` (or export them in your shell):
   - `HTTP_PROXY=http://proxy.company.local:8080`
   - `HTTPS_PROXY=http://proxy.company.local:8080`
   - `NO_PROXY=localhost,127.0.0.1,postgres,redis`
2. Run `docker compose up`.

#### Proxy variable details
- `HTTP_PROXY`: proxy URL used for outbound plain HTTP connections.
- `HTTPS_PROXY`: proxy URL used for outbound HTTPS/TLS connections.
- `NO_PROXY`: comma-separated hosts/domains/IP ranges that must bypass the proxy.

Recommended `NO_PROXY` entries for this stack:
- `localhost,127.0.0.1,postgres,redis,api,worker,scheduler`

If your organization uses uppercase-only or lowercase-only variables, keep both forms aligned when possible (`HTTP_PROXY` + `http_proxy`, `HTTPS_PROXY` + `https_proxy`, `NO_PROXY` + `no_proxy`) to avoid runtime differences across tools.

### Corporate DNS tuning (internal + forwarded resolution)
If your environment uses internal DNS with forwarding to external resolvers, you can tune DNS lookup behavior for the worker:

- `DNS_NAMESERVERS` comma-separated resolvers to force (example: `10.10.1.53,10.10.1.54`)
- `DNS_PRIVATE_NAMESERVERS` resolvers used when target `dns_scope=private`
- `DNS_PUBLIC_NAMESERVERS` resolvers used when target `dns_scope=public`
- `DNS_LIFETIME_SECONDS` total resolver lifetime per query (default `8`)
- `DNS_TIMEOUT_SECONDS` per-attempt timeout (default `3`)
- `DNS_ATTEMPTS` max attempts per record query (default `2`)
- `DNS_USE_SEARCH` enable resolver search behavior (`true`/`false`, default `true`)
- `WHOIS_SKIP_SUFFIXES` comma-separated suffixes to skip WHOIS for internal/private domains  
  (default: `.internal,.local,.corp,.lan,.home,localhost`)

Example `.env`:

```env
DNS_NAMESERVERS=10.10.1.53,10.10.1.54
DNS_PRIVATE_NAMESERVERS=10.10.1.53,10.10.1.54
DNS_PUBLIC_NAMESERVERS=1.1.1.1,8.8.8.8
DNS_LIFETIME_SECONDS=10
DNS_TIMEOUT_SECONDS=4
DNS_ATTEMPTS=3
DNS_USE_SEARCH=true
WHOIS_SKIP_SUFFIXES=.internal,.local,.corp,.lan,.home,localhost
```

### Split-brain DNS support (per target)
Targets support `dns_scope` with values:

- `system` (default): use host/system resolver behavior.
- `private`: use `DNS_PRIVATE_NAMESERVERS` (or fallback to `DNS_NAMESERVERS`).
- `public`: use `DNS_PUBLIC_NAMESERVERS` (or fallback to `DNS_NAMESERVERS`).

You can set this when adding/editing targets in UI. DNS scope is used for DNS lookup jobs and scan address resolution.

Resolver selection order:
- Target `dns_scope=private`: `DNS_PRIVATE_NAMESERVERS` -> `DNS_NAMESERVERS` -> system resolver.
- Target `dns_scope=public`: `DNS_PUBLIC_NAMESERVERS` -> `DNS_NAMESERVERS` -> system resolver.
- Target `dns_scope=system`: system resolver only.

Practical setup example:
- Set `DNS_PRIVATE_NAMESERVERS` to your internal DNS (for split-horizon internal answers).
- Set `DNS_PUBLIC_NAMESERVERS` to public resolvers (for internet-facing answers).
- Choose scope per target in **Hosts / Targets** UI.

### Authentication providers (Local / OIDC / LDAP)
Authentication is configured in **Admin -> Authentication**.

- Only one provider can be active at a time (`local`, `oidc`, or `ldap`).
- External users are never auto-provisioned.
- Username must match an existing active local app user (`users.username`).
- No role/group claim mapping is used.
- Admin access still depends on local `users.is_admin`.

#### OpenID Connect
- Uses Authorization Code flow with PKCE.
- `oidc_username_claim` is mapped directly to local username.

#### LDAP / LDAPS
- Supports plain LDAP and LDAPS (`ldap_use_ssl`).
- Certificate verification can be enabled/disabled (`ldap_validate_cert`).
- User lookup uses configured base DN + filter (filter must include `{username}`).
- Login binds with user DN and provided password after lookup.

Environment variables can still be used as initial defaults for auth config on first startup:
- `OIDC_*` (`OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`, etc.)
- `LDAP_*` (`LDAP_HOST`, `LDAP_PORT`, `LDAP_USE_SSL`, `LDAP_VALIDATE_CERT`, etc.)

### Report export via SMTP
TLSAuditHub can export report findings directly by email (CSV attachment) using an internal SMTP relay.

- Supports anonymous SMTP and authenticated SMTP.
- SMTP settings are managed in **Admin -> SMTP**.
- Required fields:
  - `From Address`
  - `Recipient`
  - `Reply-To`
- Subject is template-based and customizable. Default template:
  - `{finding_name}`

Supported subject placeholders:
- `{finding_name}`
- `{report_id}`
- `{row_count}`

Usage flow:
1. Configure SMTP in **Admin -> SMTP** and save.
2. Open **Reports**, pick report type, click **Refresh**.
3. Click **Send Email**.
4. Optionally set a one-time subject override (or leave empty to use template).

### Run everything (API + workers + UI)
1. `docker compose up`
2. Open `http://localhost:5173`

#### UI API base URL behavior
- When UI runs on `localhost:5173` or `127.0.0.1:5173`, it targets API on the same host at port `8000`.
- For non-dev hostnames, UI defaults to same-origin `/api`.
- Optional browser override:
  - `localStorage.setItem("tlsaudithub_api_base_url", "http://your-host:8000")`

#### CORS defaults
- API allows these origins by default:
  - `http://localhost:5173`
  - `http://127.0.0.1:5173`
  - `http://[::1]:5173`
- Override with env var:
  - `CORS_ALLOW_ORIGINS=http://host1:5173,http://host2:5173`

### Run behind reverse proxy with SSL offload (single exposed port)
Use this model when clients cannot reach backend port `8000` directly (for example, VLAN/firewall restrictions).

- Expose only `443` externally on the reverse proxy.
- Route UI requests (`/`) to the UI service.
- Route API requests (`/api/...`) to the API service.
- Keep backend port `8000` private/internal only.

#### 1) Make UI call API through same origin path
Set UI API base URL to `"/api"` (instead of `http://localhost:8000`) so browsers call the reverse proxy path and not local loopback.

#### 2) Bind container ports locally on the host
Prefer loopback bindings in Compose when reverse proxy is on the same host:

- UI: `127.0.0.1:5173:5173`
- API: `127.0.0.1:8000:8000`

#### 3) Nginx example (SSL offload + path routing)
```nginx
server {
    listen 443 ssl http2;
    server_name tlsaudithub.example.com;

    ssl_certificate     /etc/ssl/certs/tlsaudithub.crt;
    ssl_certificate_key /etc/ssl/private/tlsaudithub.key;

    # API under /api/*
    location /api/ {
        proxy_pass http://127.0.0.1:8000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # UI under /
    location / {
        proxy_pass http://127.0.0.1:5173/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

#### 4) Apache2 example (SSL offload + path routing)
Enable required modules:

- `a2enmod ssl proxy proxy_http headers`

VirtualHost example:

```apache
<VirtualHost *:443>
    ServerName tlsaudithub.example.com

    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/tlsaudithub.crt
    SSLCertificateKeyFile /etc/ssl/private/tlsaudithub.key

    ProxyPreserveHost On
    RequestHeader set X-Forwarded-Proto "https"

    # API under /api/*
    ProxyPass        /api/ http://127.0.0.1:8000/
    ProxyPassReverse /api/ http://127.0.0.1:8000/

    # UI under /
    ProxyPass        / http://127.0.0.1:5173/
    ProxyPassReverse / http://127.0.0.1:5173/
</VirtualHost>
```

#### 5) Result
Clients use only:

- `https://tlsaudithub.example.com/` for UI
- `https://tlsaudithub.example.com/api/...` for API

No direct client access to `:8000` is required.

### Default admin account (initial run)
- Username: `Adm$n`
- Password: `Cr!mson$Nebula_7#Qx`

Change this password immediately after first login.

### Run backend only and host the UI locally
1. `docker compose up api worker scheduler postgres redis`
2. In another terminal:
   - `cd ui`
   - `python3 -m http.server 5173`
3. Open `http://localhost:5173`

## OpenShift Deployment
This repo includes OpenShift assets under `deploy/openshift/`:

- `template.yaml`: app stack (`api`, `ui`, `worker`, `scheduler`) with Routes/Services/Secrets/ConfigMaps.
- `db-init-job.yaml`: one-time schema bootstrap job using `db/init.sql`.
- Dockerfiles for image builds:
  - `docker/api.Dockerfile`
  - `docker/worker.Dockerfile`
  - `docker/ui.Dockerfile`

### 1) Build and push images
Example with Podman:

```bash
podman build -f docker/api.Dockerfile -t <registry>/tlsaudithub-api:<tag> .
podman build -f docker/worker.Dockerfile -t <registry>/tlsaudithub-worker:<tag> .
podman build -f docker/ui.Dockerfile -t <registry>/tlsaudithub-ui:<tag> .
podman push <registry>/tlsaudithub-api:<tag>
podman push <registry>/tlsaudithub-worker:<tag>
podman push <registry>/tlsaudithub-ui:<tag>
```

### 2) Provision PostgreSQL and Redis in OpenShift
Use your preferred operator-managed services and expose them as DNS names reachable from the namespace.

Expected defaults in the template:
- PostgreSQL DSN: `postgresql://sslyze:sslyze@postgresql:5432/sslyze`
- Redis URL: `redis://redis:6379/0`

### 3) Deploy the app stack
Set `API_BASE_URL` to your public API Route URL (used by UI runtime config).

```bash
oc process -f deploy/openshift/template.yaml \
  -p API_IMAGE=<registry>/tlsaudithub-api:<tag> \
  -p WORKER_IMAGE=<registry>/tlsaudithub-worker:<tag> \
  -p UI_IMAGE=<registry>/tlsaudithub-ui:<tag> \
  -p API_BASE_URL=https://tlsaudithub-api-<project>.<apps-domain> \
  -p DNS_PRIVATE_NAMESERVERS=10.10.1.53,10.10.1.54 \
  -p DNS_PUBLIC_NAMESERVERS=1.1.1.1,8.8.8.8 \
  -p CORS_ALLOW_ORIGINS=http://localhost:5173,http://127.0.0.1:5173,http://[::1]:5173,https://tlsaudithub-ui-<project>.<apps-domain> \
  | oc apply -f -
```

### 4) Initialize database schema (first deployment only)
Create a ConfigMap from `db/init.sql`, then run the init Job:

```bash
oc create configmap tlsaudithub-db-init-sql --from-file=init.sql=db/init.sql
oc apply -f deploy/openshift/db-init-job.yaml
oc logs -f job/tlsaudithub-db-init
```

### 5) Access the app
Get the UI and API Routes:

```bash
oc get route tlsaudithub-ui tlsaudithub-api
```

Open the UI Route URL and log in.

## Notes
- The web UI is in `ui/`.
- The UI presents only the login form until authenticated.
- The Spoofable report uses stored DNS data (SPF/DMARC) per target to classify spoofing risk.
- DNS data is collected in the background when a target is added.

## Disclaimer
TLSAuditHub is provided "as is", without warranties of any kind, express or implied, including (without limitation) warranties of merchantability, fitness for a particular purpose, and non-infringement.

The authors and contributors make no guarantee that scan results are complete, accurate, or suitable for operational, legal, compliance, or security decisions. Findings may include false positives and false negatives.

By using this software, you accept full responsibility for validating all outputs before acting on them and for any changes made in your environment.

To the maximum extent permitted by applicable law, the authors and contributors are not liable for any direct, indirect, incidental, special, consequential, or punitive damages, including but not limited to service interruption, data loss, security incidents, compliance failures, financial loss, or other damages arising from the use of, or inability to use, this tool.

## Acknowledgments
- Kudos to the SSLyze maintainers for building and maintaining a robust TLS analysis tool that this project relies on.
