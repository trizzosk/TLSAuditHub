# Authentication

Authentication is configured in **Admin -> Authentication**.

## Providers
Only one provider can be active at a time:
- `local`
- `oidc`
- `ldap`

Rules:
- External users are never auto-provisioned.
- Username must match an existing active local app user (`users.username`).
- No role/group claim mapping is used.
- Admin access depends on local `users.is_admin`.

## OpenID Connect
- Authorization Code flow with PKCE.
- `oidc_username_claim` maps directly to local username.

## LDAP / LDAPS
- Supports LDAP and LDAPS (`ldap_use_ssl`).
- Certificate verification toggle: `ldap_validate_cert`.
- User lookup uses configured base DN + filter (must include `{username}`).
- Login binds with user DN and provided password after lookup.

## Environment defaults for first startup
These can seed initial values:
- `OIDC_*` (`OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`, etc.)
- `LDAP_*` (`LDAP_HOST`, `LDAP_PORT`, `LDAP_USE_SSL`, `LDAP_VALIDATE_CERT`, etc.)
