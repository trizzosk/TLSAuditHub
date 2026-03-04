# Deployment

## Run everything (API + workers + UI)
1. `docker compose up`
2. Open `http://localhost:5173`

### UI API base URL behavior
- When UI runs on `localhost:5173` or `127.0.0.1:5173`, it targets API on the same host at port `8000`.
- For non-dev hostnames, UI defaults to same-origin `/api`.
- Optional browser override:
  - `localStorage.setItem("tlsaudithub_api_base_url", "http://your-host:8000")`

### CORS defaults
- API allows these origins by default:
  - `http://localhost:5173`
  - `http://127.0.0.1:5173`
  - `http://[::1]:5173`
- Override with env var:
  - `CORS_ALLOW_ORIGINS=http://host1:5173,http://host2:5173`

## Corporate proxy support
If your network requires an outbound HTTP proxy, set standard proxy environment variables before running Docker Compose.

1. Add to `.env` (or export in shell):
   - `HTTP_PROXY=http://proxy.company.local:8080`
   - `HTTPS_PROXY=http://proxy.company.local:8080`
   - `NO_PROXY=localhost,127.0.0.1,postgres,redis`
2. Run `docker compose up`.

### Proxy variable details
- `HTTP_PROXY`: proxy URL used for outbound plain HTTP connections.
- `HTTPS_PROXY`: proxy URL used for outbound HTTPS/TLS connections.
- `NO_PROXY`: comma-separated hosts/domains/IP ranges that must bypass proxy.

Recommended `NO_PROXY` entries:
- `localhost,127.0.0.1,postgres,redis,api,worker,scheduler`

If your organization uses uppercase-only or lowercase-only variables, keep both forms aligned (`HTTP_PROXY` + `http_proxy`, `HTTPS_PROXY` + `https_proxy`, `NO_PROXY` + `no_proxy`).

## Run behind reverse proxy with SSL offload
Use this model when clients cannot reach backend port `8000` directly.

- Expose only `443` externally on reverse proxy.
- Route UI (`/`) to UI service.
- Route API (`/api/...`) to API service.
- Keep backend port `8000` private/internal.

### 1) Make UI call API through same-origin path
Set UI API base URL to `"/api"` (instead of `http://localhost:8000`).

### 2) Bind container ports locally on host
Prefer loopback bindings in Compose when reverse proxy is on same host:
- UI: `127.0.0.1:5173:5173`
- API: `127.0.0.1:8000:8000`

### 3) Nginx example
```nginx
server {
    listen 443 ssl http2;
    server_name tlsaudithub.example.com;

    ssl_certificate     /etc/ssl/certs/tlsaudithub.crt;
    ssl_certificate_key /etc/ssl/private/tlsaudithub.key;

    location /api/ {
        proxy_pass http://127.0.0.1:8000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location / {
        proxy_pass http://127.0.0.1:5173/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 4) Apache2 example
Enable modules:
- `a2enmod ssl proxy proxy_http headers`

```apache
<VirtualHost *:443>
    ServerName tlsaudithub.example.com

    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/tlsaudithub.crt
    SSLCertificateKeyFile /etc/ssl/private/tlsaudithub.key

    ProxyPreserveHost On
    RequestHeader set X-Forwarded-Proto "https"

    ProxyPass        /api/ http://127.0.0.1:8000/
    ProxyPassReverse /api/ http://127.0.0.1:8000/

    ProxyPass        / http://127.0.0.1:5173/
    ProxyPassReverse / http://127.0.0.1:5173/
</VirtualHost>
```

### 5) Result
Clients use:
- `https://tlsaudithub.example.com/` for UI
- `https://tlsaudithub.example.com/api/...` for API

No direct client access to `:8000` is required.

## Run backend only and host UI locally
1. `docker compose up api worker scheduler postgres redis`
2. In another terminal:
   - `cd ui`
   - `python3 -m http.server 5173`
3. Open `http://localhost:5173`

## OpenShift Deployment
OpenShift assets are under `deploy/openshift/`:
- `template.yaml`: app stack (`api`, `ui`, `worker`, `scheduler`) with Routes/Services/Secrets/ConfigMaps
- `db-init-job.yaml`: one-time schema bootstrap job using `db/init.sql`
- image builds:
  - `docker/api.Dockerfile`
  - `docker/worker.Dockerfile`
  - `docker/ui.Dockerfile`

### 1) Build and push images
```bash
podman build -f docker/api.Dockerfile -t <registry>/tlsaudithub-api:<tag> .
podman build -f docker/worker.Dockerfile -t <registry>/tlsaudithub-worker:<tag> .
podman build -f docker/ui.Dockerfile -t <registry>/tlsaudithub-ui:<tag> .
podman push <registry>/tlsaudithub-api:<tag>
podman push <registry>/tlsaudithub-worker:<tag>
podman push <registry>/tlsaudithub-ui:<tag>
```

### 2) Provision PostgreSQL and Redis in OpenShift
Use operator-managed services reachable from namespace.

Expected defaults:
- PostgreSQL: `postgresql://sslyze:sslyze@postgresql:5432/sslyze`
- Redis: `redis://redis:6379/0`

### 3) Deploy app stack
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
```bash
oc create configmap tlsaudithub-db-init-sql --from-file=init.sql=db/init.sql
oc apply -f deploy/openshift/db-init-job.yaml
oc logs -f job/tlsaudithub-db-init
```

### 5) Access app
```bash
oc get route tlsaudithub-ui tlsaudithub-api
```

Open the UI Route URL and log in.
