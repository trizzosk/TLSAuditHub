# TLSAuditHub - Feature TODO

This backlog captures candidate checks/functionality to add on top of current SSL/TLS + SPF/DMARC coverage.

## High Priority

- [x] **DKIM checks**
  - [x] Discover selectors with configurable selector list + fallback heuristics.
  - [x] Validate DKIM TXT syntax (`v=DKIM1`, `k=`, `p=` fields).
  - [x] Validate key strength/algorithm (flag weak RSA key sizes).

- [ ] **MTA-STS checks**
  - [ ] Validate `_mta-sts.<domain>` TXT record.
  - [ ] Fetch and parse `https://mta-sts.<domain>/.well-known/mta-sts.txt`.
  - [ ] Validate policy fields (`version`, `mode`, `max_age`, `mx`).

- [ ] **TLS-RPT checks**
  - [ ] Validate `_smtp._tls.<domain>` TXT record.
  - [ ] Parse and validate report URI(s) (`rua=`).

- [ ] **CAA record analysis**
  - [ ] Check for CAA presence.
  - [ ] Validate `issue`/`issuewild`/`iodef` content.
  - [ ] Flag risky/missing CAA on critical domains.

- [ ] **DNSSEC validation**
  - [ ] Validate DS/DNSKEY/RRSIG chain.
  - [ ] Detect expired/invalid signatures.

## Medium Priority

- [ ] **BIMI checks**
  - [ ] Validate `default._bimi.<domain>` TXT record.
  - [ ] Verify logo URL availability and SVG format.
  - [ ] Validate optional VMC reference.

- [ ] **Mail transport posture checks**
  - [ ] Test STARTTLS support across all MX hosts.
  - [ ] Verify consistency of TLS support/policy across MX set.

- [x] **Certificate transparency + revocation checks**
  - [x] OCSP stapling presence/quality.
  - [x] OCSP/CRL endpoint reachability.
  - [x] Basic revocation status checks.

- [x] **HTTPS posture checks**
  - [x] HTTP -> HTTPS redirect checks.
  - [x] HSTS posture checks (presence, max-age baseline, preload flag).
  - [x] Certificate expiry checks (expired / near expiry).
  - [x] Cert SAN/CN mismatch and wildcard risk flags.

- [x] **Cipher hygiene scoring**
  - [x] Risk scoring based on protocol/cipher findings.
  - [x] Forward secrecy coverage checks.

## Lower Priority / Extended Scope

- [ ] **DNS zone hygiene**
  - [ ] Dangling CNAME / subdomain takeover indicators.
  - [ ] Expired domains in NS/MX/CNAME chains.

- [x] **Authoritative DNS health**
  - [x] NS consistency checks.
  - [x] Lame delegation detection.

- [x] **Reputation/blacklist integrations (optional)**
  - [x] Domain/IP blocklist checks.
  - [x] ASN/country exposure summaries.

- [ ] **Host dependency posture**
  - [ ] HTTP security headers checks.
  - [ ] Basic server stack obsolescence flags.

## Reporting / Operational Enhancements

- [x] **Domains / Hosts**
  - [x] Add `Generate Report` button in Domains / Hosts section.
  - [x] Prompt user to select report format: HTML or PDF.
  - [x] Include all collected domain/host information in the report.
  - [x] Keep report structure aligned with UI sections (basic data, DNS data, certificate data, spoofing check, etc.).

- [ ] **Expiry and rotation intelligence**
  - [ ] Cert expiry forecasting and blast-radius mapping.
  - [ ] DKIM key age/rotation reminders.
  - [ ] SPF include-chain depth/lookup-limit warnings.

- [x] **Configurability**
  - [x] Admin-configurable selector lists (DKIM), thresholds, and severities.
  - [x] Per-check enable/disable toggles.
  - [x] Environment + UI config support for new checks.

- [x] **UI/UX**
  - [x] Add dedicated Mail Security dashboard section.
  - [x] Add check-specific drilldown views and remediation hints.
  - [-] Add trend views for posture change over time.

- [x] **Reporting**
  - [x] Add the report of CA's used (Issued by)
  - [x] Report of wildcard certs in use including hosts/targets
