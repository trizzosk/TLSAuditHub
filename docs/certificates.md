# Certificates

## Objective
The **Certificates** section provides a consolidated certificate inventory per enabled TLS target so operators can quickly review issuer and validity posture without opening each raw scan result.

## What the list shows
Each row in the main Certificates list includes:
- target host and port
- leaf certificate issuer
- certificate CN
- certificate SAN values
- validity window (`Not Before` / `Not After`)
- latest scan timestamp

## Show details action
Each row has a **Show** button that opens full certificate details for the latest available scan of that target.

Details combine:
- SSLyze `certificate_info` output
- live probe metadata collected at request time (OpenSSL-like handshake/certificate context)

This gives both persisted scan evidence and current live certificate context in one view.

## API endpoints
- `GET /certificates`
  - paginated inventory across enabled targets with TLS checks enabled
- `GET /certificates/{scan_id}/details`
  - full details for a specific scan, including `certificate_info` and `live_probe`

## Troubleshooting
- Empty Certificates list:
  - confirm targets are enabled and `tls_checks_enabled=true`
  - confirm completed scans exist (`completed`/`done`)
- Details not available for a row:
  - scan may not include `certificate_info` plugin output yet
  - rerun scan and retry
