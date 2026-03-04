# DNS And DKIM

## Corporate DNS tuning (internal + forwarded resolution)
If your environment uses internal DNS with forwarding to external resolvers, tune worker lookup behavior:

- `DNS_NAMESERVERS` comma-separated resolvers to force (example: `10.10.1.53,10.10.1.54`)
- `DNS_PRIVATE_NAMESERVERS` resolvers used when target `dns_scope=private`
- `DNS_PUBLIC_NAMESERVERS` resolvers used when target `dns_scope=public`
- `DNS_LIFETIME_SECONDS` total resolver lifetime per query (default `8`)
- `DNS_TIMEOUT_SECONDS` per-attempt timeout (default `3`)
- `DNS_ATTEMPTS` max attempts per record query (default `2`)
- `DNS_USE_SEARCH` enable resolver search behavior (`true`/`false`, default `true`)
- `WHOIS_SKIP_SUFFIXES` suffixes to skip WHOIS for internal/private domains
  (default: `.internal,.local,.corp,.lan,.home,localhost`)

## Split-brain DNS support (per target)
Targets support `dns_scope`:
- `system` (default): use host/system resolver behavior
- `private`: use `DNS_PRIVATE_NAMESERVERS` (fallback to `DNS_NAMESERVERS`)
- `public`: use `DNS_PUBLIC_NAMESERVERS` (fallback to `DNS_NAMESERVERS`)

Set this in add/edit target UI. DNS scope is used for DNS lookup jobs and scan address resolution.

Resolver selection order:
- `private`: `DNS_PRIVATE_NAMESERVERS` -> `DNS_NAMESERVERS` -> system resolver
- `public`: `DNS_PUBLIC_NAMESERVERS` -> `DNS_NAMESERVERS` -> system resolver
- `system`: system resolver only

Practical setup:
- set `DNS_PRIVATE_NAMESERVERS` to internal DNS
- set `DNS_PUBLIC_NAMESERVERS` to public resolvers
- choose scope per target

## DKIM discovery model (no external selector API dependency)
DKIM selector lookup does not rely on public selector APIs.

Worker DNS collection:
- builds candidate mail domains from target hostname and MX hostnames
- tests configured selectors + optional fallback selectors
- runs bounded TXT lookups on `<selector>._domainkey.<candidate-domain>`

This is intended to work better in mixed/regional environments (including `cz`, `sk`, `eu`, `hu`) where public selector APIs are incomplete.

## DKIM selector management in Admin UI
Use **Admin -> DKIM** and provide one selector per line.

- selectors are stored in DB config (`dkim_config`)
- stored selectors are used by worker DNS lookups
- `DKIM_SELECTORS` env is initial/default fallback only

## DKIM tuning environment variables
- `DKIM_SELECTORS` comma-separated selectors (initial/default fallback)
- `DKIM_EXTRA_SELECTORS` extra selectors appended after configured list
- `DKIM_INCLUDE_DEFAULT_SELECTORS` include built-in fallback selector list (`true`/`false`, default `true`)
- `DKIM_MAX_QUERIES` hard limit for DKIM TXT queries per host (default `48`)
- `DKIM_MAX_PARALLEL` max concurrent DKIM TXT checks per batch (default `8`)
- `DKIM_EARLY_STOP_RECORDS` stop per candidate domain after N records (default `3`)
- `DKIM_FULL_SCAN` disable early-stop and probe until budget is exhausted (`true`/`false`, default `false`)

Example:

```env
DNS_NAMESERVERS=10.10.1.53,10.10.1.54
DNS_PRIVATE_NAMESERVERS=10.10.1.53,10.10.1.54
DNS_PUBLIC_NAMESERVERS=1.1.1.1,8.8.8.8
DNS_LIFETIME_SECONDS=10
DNS_TIMEOUT_SECONDS=4
DNS_ATTEMPTS=3
DNS_USE_SEARCH=true
WHOIS_SKIP_SUFFIXES=.internal,.local,.corp,.lan,.home,localhost
DKIM_SELECTORS=selector1,selector2,s1,s2
DKIM_EXTRA_SELECTORS=default,mail,mx
DKIM_INCLUDE_DEFAULT_SELECTORS=true
DKIM_MAX_QUERIES=48
DKIM_MAX_PARALLEL=8
DKIM_EARLY_STOP_RECORDS=3
DKIM_FULL_SCAN=false
```
