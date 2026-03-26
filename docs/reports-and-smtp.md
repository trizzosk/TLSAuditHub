# Reports And SMTP Export

## Available report IDs
- `no_tls13`
- `pqc_non_compliant`
- `legacy_ssl_enabled`
- `spf_not_strict`
- `missing_hsts`
- `missing_dmarc_policy`
- `weak_dkim_keys`
- `hosted_in_m365`
- `spoofable_domains_hosts`
- `authoritative_dns_health`
- `reputation_blacklist`
- `ct_revocation_gaps`
- `ca_issuers_used`
- `wildcard_certs_in_use`
- `https_posture_issues`
- `cipher_hygiene_risk`

## SMTP report export
TLSAuditHub can export report findings by email (CSV attachment) via internal SMTP relay.

Supports:
- anonymous SMTP
- authenticated SMTP

Managed in **Admin -> SMTP**.

Required fields:
- `From Address`
- `Recipient`
- `Reply-To`

Default subject template:
- `{finding_name}`

Supported placeholders:
- `{finding_name}`
- `{report_id}`
- `{row_count}`

Usage flow:
1. Configure SMTP in **Admin -> SMTP** and save.
2. Open **Reports**, choose report type, click **Refresh**.
3. Click **Send Email**.
4. Optionally set one-time subject override.
