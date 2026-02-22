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

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE
);

CREATE TABLE scan_diffs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target_id UUID REFERENCES targets(id),
    old_scan_id UUID REFERENCES scans(id),
    new_scan_id UUID REFERENCES scans(id),
    created_at TIMESTAMP DEFAULT now(),
    diff JSONB
);

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
