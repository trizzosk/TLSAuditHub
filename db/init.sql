CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE targets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    hostname TEXT NOT NULL,
    port INT NOT NULL DEFAULT 443,
    dns_scope TEXT NOT NULL DEFAULT 'system'
        CHECK (dns_scope IN ('system', 'private', 'public')),
    enabled BOOLEAN DEFAULT TRUE,
    scan_interval_minutes INT DEFAULT 1440
);

CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target_id UUID REFERENCES targets(id),
    started_at TIMESTAMP,
    finished_at TIMESTAMP,
    status TEXT,
    error_message TEXT
);

CREATE TABLE scan_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scans(id),
    plugin TEXT,
    result JSONB
);

CREATE TABLE target_dns (
    target_id UUID PRIMARY KEY REFERENCES targets(id),
    data JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    is_admin BOOLEAN DEFAULT FALSE,
    name TEXT NOT NULL DEFAULT '',
    surname TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL DEFAULT ''
);

CREATE TABLE scan_diffs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target_id UUID REFERENCES targets(id),
    old_scan_id UUID REFERENCES scans(id),
    new_scan_id UUID REFERENCES scans(id),
    created_at TIMESTAMP DEFAULT now(),
    diff JSONB
);

CREATE TABLE IF NOT EXISTS event_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    username TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'ui',
    level TEXT NOT NULL DEFAULT 'info'
        CHECK (level IN ('debug', 'info', 'warn', 'error')),
    message TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_event_logs_created_at
ON event_logs (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_event_logs_level_created_at
ON event_logs (level, created_at DESC);

CREATE TABLE IF NOT EXISTS proxy_config (
    id INT PRIMARY KEY DEFAULT 1,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    host TEXT NOT NULL DEFAULT '',
    port INT NOT NULL DEFAULT 8080,
    username TEXT NOT NULL DEFAULT '',
    password TEXT NOT NULL DEFAULT '',
    no_proxy_patterns TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMP NOT NULL DEFAULT now(),
    CONSTRAINT proxy_config_singleton CHECK (id = 1)
);

INSERT INTO proxy_config
(id, enabled, host, port, username, password, no_proxy_patterns)
VALUES (1, FALSE, '', 8080, '', '', '')
ON CONFLICT (id)
DO NOTHING;

CREATE TABLE IF NOT EXISTS scheduler_config (
    id INT PRIMARY KEY DEFAULT 1,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    frequency TEXT NOT NULL DEFAULT 'daily',
    day_of_week INT NOT NULL DEFAULT 1,
    hour INT NOT NULL DEFAULT 2,
    minute INT NOT NULL DEFAULT 0,
    interval_minutes INT NOT NULL DEFAULT 1440,
    last_run_at TIMESTAMP NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT now(),
    CONSTRAINT scheduler_config_singleton CHECK (id = 1),
    CONSTRAINT scheduler_frequency_valid CHECK (
        frequency IN ('hourly', 'daily', 'weekly', 'interval')
    ),
    CONSTRAINT scheduler_day_valid CHECK (day_of_week BETWEEN 0 AND 6),
    CONSTRAINT scheduler_hour_valid CHECK (hour BETWEEN 0 AND 23),
    CONSTRAINT scheduler_minute_valid CHECK (minute BETWEEN 0 AND 59),
    CONSTRAINT scheduler_interval_valid CHECK (interval_minutes BETWEEN 1 AND 10080)
);

INSERT INTO scheduler_config
(id, enabled, frequency, day_of_week, hour, minute, interval_minutes)
VALUES (1, TRUE, 'daily', 1, 2, 0, 1440)
ON CONFLICT (id)
DO NOTHING;

CREATE TABLE IF NOT EXISTS smtp_config (
    id INT PRIMARY KEY DEFAULT 1,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    host TEXT NOT NULL DEFAULT '',
    port INT NOT NULL DEFAULT 25,
    use_starttls BOOLEAN NOT NULL DEFAULT FALSE,
    use_auth BOOLEAN NOT NULL DEFAULT FALSE,
    username TEXT NOT NULL DEFAULT '',
    password TEXT NOT NULL DEFAULT '',
    from_address TEXT NOT NULL DEFAULT '',
    recipient TEXT NOT NULL DEFAULT '',
    reply_to TEXT NOT NULL DEFAULT '',
    subject_template TEXT NOT NULL DEFAULT '{finding_name}',
    timeout_seconds INT NOT NULL DEFAULT 15,
    updated_at TIMESTAMP NOT NULL DEFAULT now(),
    CONSTRAINT smtp_config_singleton CHECK (id = 1)
);

INSERT INTO smtp_config
(
    id, enabled, host, port, use_starttls, use_auth, username, password,
    from_address, recipient, reply_to, subject_template, timeout_seconds
)
VALUES
(
    1, FALSE, '', 25, FALSE, FALSE, '', '',
    '', '', '', '{finding_name}', 15
)
ON CONFLICT (id)
DO NOTHING;

CREATE TABLE IF NOT EXISTS auth_config (
    id INT PRIMARY KEY DEFAULT 1,
    active_method TEXT NOT NULL DEFAULT 'local',
    oidc_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    oidc_issuer_url TEXT NOT NULL DEFAULT '',
    oidc_client_id TEXT NOT NULL DEFAULT '',
    oidc_client_secret TEXT NOT NULL DEFAULT '',
    oidc_redirect_uri TEXT NOT NULL DEFAULT 'http://localhost:8000/auth/oidc/callback',
    oidc_ui_redirect_uri TEXT NOT NULL DEFAULT 'http://localhost:5173/',
    oidc_scopes TEXT NOT NULL DEFAULT 'openid profile email',
    oidc_username_claim TEXT NOT NULL DEFAULT 'preferred_username',
    ldap_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ldap_host TEXT NOT NULL DEFAULT '',
    ldap_port INT NOT NULL DEFAULT 636,
    ldap_use_ssl BOOLEAN NOT NULL DEFAULT TRUE,
    ldap_validate_cert BOOLEAN NOT NULL DEFAULT TRUE,
    ldap_bind_dn TEXT NOT NULL DEFAULT '',
    ldap_bind_password TEXT NOT NULL DEFAULT '',
    ldap_user_base_dn TEXT NOT NULL DEFAULT '',
    ldap_user_filter TEXT NOT NULL DEFAULT '(uid={username})',
    updated_at TIMESTAMP NOT NULL DEFAULT now(),
    CONSTRAINT auth_config_singleton CHECK (id = 1),
    CONSTRAINT auth_method_valid CHECK (
        active_method IN ('local', 'oidc', 'ldap')
    )
);

INSERT INTO auth_config (
    id, active_method,
    oidc_enabled, oidc_issuer_url, oidc_client_id, oidc_client_secret,
    oidc_redirect_uri, oidc_ui_redirect_uri, oidc_scopes, oidc_username_claim,
    ldap_enabled, ldap_host, ldap_port, ldap_use_ssl, ldap_validate_cert,
    ldap_bind_dn, ldap_bind_password, ldap_user_base_dn, ldap_user_filter
)
VALUES (
    1, 'local',
    FALSE, '', '', '',
    'http://localhost:8000/auth/oidc/callback', 'http://localhost:5173/', 'openid profile email', 'preferred_username',
    FALSE, '', 636, TRUE, TRUE,
    '', '', '', '(uid={username})'
)
ON CONFLICT (id)
DO NOTHING;

INSERT INTO users (username, password_hash, is_active, is_admin)
VALUES (
    'Adm$n',
    '$pbkdf2-sha256$29000$N4YQQmit1boXIiQkJMR4Lw$IaSMW5l8kslxxsLXQeQsTcoixpAgvnLq.aB3zx/9RW4',
    TRUE,
    TRUE
)
ON CONFLICT (username)
DO UPDATE SET
    password_hash = EXCLUDED.password_hash,
    is_active = TRUE,
    is_admin = TRUE;
