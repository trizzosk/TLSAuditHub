CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE targets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    hostname TEXT NOT NULL,
    port INT NOT NULL DEFAULT 443,
    enabled BOOLEAN DEFAULT TRUE,
    scan_interval_minutes INT DEFAULT 1440
);

CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target_id UUID REFERENCES targets(id),
    started_at TIMESTAMP,
    finished_at TIMESTAMP,
    status TEXT
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
    level TEXT NOT NULL DEFAULT 'info',
    message TEXT NOT NULL
);

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

INSERT INTO users (username, password_hash, is_active)
VALUES (
    'trizzo',
    '$pbkdf2-sha256$29000$BqD0HuOcM4ZQijGGUKo1Jg$G79aYyJO4xeZXrb28Wfe28g9rTcbSJzM1/HYCF4nG64',
    TRUE
)
ON CONFLICT (username)
DO UPDATE SET
    password_hash = EXCLUDED.password_hash,
    is_active = TRUE;
