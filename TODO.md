# TLSAuditHub - Feature TODO

This backlog captures candidate checks/functionality to add on top of current SSL/TLS + SPF/DMARC coverage.

## High Priority

- [ ] **DKIM checks**
  - [x] Discover selectors with configurable selector list + fallback heuristics.
  - [x] Validate DKIM TXT syntax (`v=DKIM1`, `k=`, `p=` fields).
  - [ ] Validate key strength/algorithm (flag weak RSA key sizes).

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

- [ ] **Certificate transparency + revocation checks**
  - [ ] OCSP stapling presence/quality.
  - [ ] OCSP/CRL endpoint reachability.
  - [ ] Basic revocation status checks.

- [x] **HTTPS posture checks**
  - [x] HTTP -> HTTPS redirect checks.
  - [x] HSTS posture checks (presence, max-age baseline, preload flag).
  - [x] Certificate expiry checks (expired / near expiry).
  - [ ] Cert SAN/CN mismatch and wildcard risk flags.

- [x] **Cipher hygiene scoring**
  - [x] Risk scoring based on protocol/cipher findings.
  - [x] Forward secrecy coverage checks.

## Lower Priority / Extended Scope

- [ ] **DNS zone hygiene**
  - [ ] Dangling CNAME / subdomain takeover indicators.
  - [ ] Expired domains in NS/MX/CNAME chains.

- [ ] **Authoritative DNS health**
  - [ ] NS consistency checks.
  - [ ] Lame delegation detection.

- [ ] **Reputation/blacklist integrations (optional)**
  - [ ] Domain/IP blocklist checks.
  - [ ] ASN/country exposure summaries.

- [ ] **Host dependency posture**
  - [ ] HTTP security headers checks.
  - [ ] Basic server stack obsolescence flags.

## Reporting / Operational Enhancements

- [ ] **Expiry and rotation intelligence**
  - [ ] Cert expiry forecasting and blast-radius mapping.
  - [ ] DKIM key age/rotation reminders.
  - [ ] SPF include-chain depth/lookup-limit warnings.

- [ ] **Configurability**
  - [ ] Admin-configurable selector lists (DKIM), thresholds, and severities.
  - [ ] Per-check enable/disable toggles.
  - [ ] Environment + UI config support for new checks.

- [ ] **UI/UX**
  - [ ] Add dedicated Mail Security dashboard section.
  - [ ] Add check-specific drilldown views and remediation hints.
  - [ ] Add trend views for posture change over time.
