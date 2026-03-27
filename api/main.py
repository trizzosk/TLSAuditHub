from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from sqlalchemy import text
from celery import Celery
from shared.database import SessionLocal
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from jose import JWTError, jwt
from auth import verify_password, create_access_token, hash_password
from deps import get_current_admin, get_current_user
import csv
import ipaddress
import os
import secrets
import socket
import ssl
import smtplib
import time
import re
import urllib.parse
import urllib.request
import hashlib
import base64
import json
import tempfile
from datetime import datetime, timezone
from uuid import UUID
from io import StringIO
from email.message import EmailMessage

app = FastAPI(title="SSLyze Scanner API")
celery_client = Celery(
    "api",
    broker=os.environ.get("CELERY_BROKER_URL", "redis://redis:6379/0"),
)


def _env_bool(name: str, default: bool = False) -> bool:
    raw = (os.environ.get(name) or "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


FAILED_LOGINS = {}
LOGIN_WINDOW_SECONDS = 300
LOGIN_MAX_ATTEMPTS = 10
EVENT_LOG_LEVELS = ("debug", "info", "warn", "error")
EVENT_LOG_DEFAULT_LIMIT = 15
EVENT_LOG_RETENTION_DAYS = 90
OIDC_STATE_TTL_SECONDS = 300
AUTH_METHODS = ("local", "oidc", "ldap")
DNS_SCOPE_VALUES = ("system", "private", "public")
DEFAULT_AUTH_METHOD = "local"
CHECK_SEVERITY_VALUES = ("low", "medium", "high")
CHECK_THRESHOLD_KEYS = (
    "dkim_min_rsa_bits",
    "cert_expiry_days",
    "hsts_min_max_age",
)

OIDC_ISSUER_URL_DEFAULT = (os.environ.get("OIDC_ISSUER_URL") or "").strip()
OIDC_CLIENT_ID_DEFAULT = (os.environ.get("OIDC_CLIENT_ID") or "").strip()
OIDC_CLIENT_SECRET_DEFAULT = (os.environ.get("OIDC_CLIENT_SECRET") or "").strip()
OIDC_REDIRECT_URI_DEFAULT = (
    os.environ.get("OIDC_REDIRECT_URI")
    or "http://localhost:8000/auth/oidc/callback"
).strip()
OIDC_UI_REDIRECT_URI_DEFAULT = (
    os.environ.get("OIDC_UI_REDIRECT_URI") or "http://localhost:5173/"
).strip()
OIDC_SCOPES_DEFAULT = (
    os.environ.get("OIDC_SCOPES") or "openid profile email"
).strip()
OIDC_USERNAME_CLAIM_DEFAULT = (
    os.environ.get("OIDC_USERNAME_CLAIM") or "preferred_username"
).strip()
OIDC_ENABLED_DEFAULT = _env_bool("OIDC_ENABLED", False)

LDAP_HOST_DEFAULT = (os.environ.get("LDAP_HOST") or "").strip()
LDAP_PORT_DEFAULT = int((os.environ.get("LDAP_PORT") or "636").strip() or 636)
LDAP_USE_SSL_DEFAULT = _env_bool("LDAP_USE_SSL", True)
LDAP_VALIDATE_CERT_DEFAULT = _env_bool("LDAP_VALIDATE_CERT", True)
LDAP_BIND_DN_DEFAULT = (os.environ.get("LDAP_BIND_DN") or "").strip()
LDAP_BIND_PASSWORD_DEFAULT = (os.environ.get("LDAP_BIND_PASSWORD") or "").strip()
LDAP_USER_BASE_DN_DEFAULT = (os.environ.get("LDAP_USER_BASE_DN") or "").strip()
LDAP_USER_FILTER_DEFAULT = (
    os.environ.get("LDAP_USER_FILTER") or "(uid={username})"
).strip()
LDAP_ENABLED_DEFAULT = _env_bool("LDAP_ENABLED", False)

OIDC_DISCOVERY_CACHE = {"expires_at": 0.0, "data": None}
OIDC_JWKS_CACHE = {"expires_at": 0.0, "keys": []}
OIDC_PENDING_STATES = {}


class ProxyConfigUpdate(BaseModel):
    enabled: bool = False
    host: str = ""
    port: int = 8080
    username: str = ""
    password: str = ""
    no_proxy_patterns: str = ""


class SchedulerConfigUpdate(BaseModel):
    enabled: bool = True
    frequency: str = "daily"
    day_of_week: int = 1
    hour: int = 2
    minute: int = 0
    interval_minutes: int = 1440


class UserCreate(BaseModel):
    username: str
    password: str
    name: str = ""
    surname: str = ""
    email: str = ""
    is_active: bool = True
    is_admin: bool = False


class UserUpdate(BaseModel):
    name: str = ""
    surname: str = ""
    email: str = ""
    is_active: bool = True
    is_admin: bool = False


class EventLogCreate(BaseModel):
    message: str
    source: str = "ui"
    level: str = "info"


class SmtpConfigUpdate(BaseModel):
    enabled: bool = False
    host: str = ""
    port: int = 25
    use_starttls: bool = False
    use_auth: bool = False
    username: str = ""
    password: str = ""
    from_address: str = ""
    recipient: str = ""
    reply_to: str = ""
    subject_template: str = "{finding_name}"
    timeout_seconds: int = 15


class DkimConfigUpdate(BaseModel):
    selectors_text: str = ""


class ReportEmailRequest(BaseModel):
    report_id: str
    subject: str = ""
    selected_target_ids: list[str] = Field(default_factory=list)


class TargetUpdate(BaseModel):
    hostname: str
    port: int = 443
    dns_scope: str = "system"
    dns_checks_enabled: bool = True
    tls_checks_enabled: bool = True


class AuthConfigUpdate(BaseModel):
    active_method: str = DEFAULT_AUTH_METHOD
    oidc_enabled: bool = False
    oidc_issuer_url: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_redirect_uri: str = "http://localhost:8000/auth/oidc/callback"
    oidc_ui_redirect_uri: str = "http://localhost:5173/"
    oidc_scopes: str = "openid profile email"
    oidc_username_claim: str = "preferred_username"
    ldap_enabled: bool = False
    ldap_host: str = ""
    ldap_port: int = 636
    ldap_use_ssl: bool = True
    ldap_validate_cert: bool = True
    ldap_bind_dn: str = ""
    ldap_bind_password: str = ""
    ldap_user_base_dn: str = ""
    ldap_user_filter: str = "(uid={username})"


class ChecksConfigUpdate(BaseModel):
    enabled_reports: dict[str, bool] = Field(default_factory=dict)
    severity_overrides: dict[str, str] = Field(default_factory=dict)
    thresholds: dict[str, int] = Field(default_factory=dict)


REPORT_DEFINITIONS = {
    "no_tls13": {
        "id": "no_tls13",
        "finding_id": "NO_TLS13",
        "title": "Hosts Not Supporting TLS 1.3",
        "description": (
            "Targets where the latest completed scan reports "
            "tls_1_3_cipher_suites.is_protocol_supported = false."
        ),
        "severity": "medium",
    },
    "pqc_non_compliant": {
        "id": "pqc_non_compliant",
        "finding_id": "PQC_NON_COMPLIANT",
        "title": "Hosts Not Compliant With PQC",
        "description": (
            "Targets where latest completed TLS scans do not support TLS 1.3 "
            "or do not report PQC-capable key exchange groups "
            "(for example ML-KEM/Kyber hybrids)."
        ),
        "severity": "high",
    },
    "legacy_ssl_enabled": {
        "id": "legacy_ssl_enabled",
        "finding_id": "SSLV2_OR_SSLV3_ENABLED",
        "title": "Hosts Supporting SSLv2 Or SSLv3",
        "description": (
            "Targets where the latest completed scan reports SSLv2 and/or SSLv3 "
            "as supported."
        ),
        "severity": "high",
    },
    "spf_not_strict": {
        "id": "spf_not_strict",
        "finding_id": "SPF_NOT_STRICT",
        "title": "Hosts With SPF Not Set To -all",
        "description": (
            "Targets where DNS SPF is missing or does not end with -all."
        ),
        "severity": "medium",
    },
    "missing_hsts": {
        "id": "missing_hsts",
        "finding_id": "MISSING_HSTS",
        "title": "Hosts Missing HSTS Header",
        "description": (
            "Targets where the latest completed scan does not include a "
            "Strict-Transport-Security header."
        ),
        "severity": "medium",
    },
    "missing_dmarc_policy": {
        "id": "missing_dmarc_policy",
        "finding_id": "MISSING_OR_WEAK_DMARC_POLICY",
        "title": "Hosts Missing DMARC Policy",
        "description": (
            "Targets where DMARC is missing from DNS or DMARC policy is p=none."
        ),
        "severity": "high",
    },
    "weak_dkim_keys": {
        "id": "weak_dkim_keys",
        "finding_id": "WEAK_DKIM_RSA_KEY",
        "title": "Hosts With Weak DKIM RSA Keys",
        "description": (
            "Targets where discovered DKIM records contain RSA public keys "
            "with estimated size below 2048 bits."
        ),
        "severity": "high",
    },
    "hosted_in_m365": {
        "id": "hosted_in_m365",
        "finding_id": "HOSTED_IN_M365",
        "title": "Hosts Detected As Microsoft 365-Hosted",
        "description": (
            "Targets with DNS signals indicating an assigned Microsoft 365 tenant "
            "and active M365 mail service usage (for example Exchange Online MX, "
            "M365 SPF includes, and Outlook autodiscover CNAME)."
        ),
        "severity": "low",
    },
    "spoofable_domains_hosts": {
        "id": "spoofable_domains_hosts",
        "finding_id": "SPOOFABLE_DOMAIN_OR_HOST",
        "title": "Spoofable Domains/Hosts",
        "description": (
            "Domains/hosts where SPF is not strict (-all) and DMARC policy is "
            "missing or p=none, with active mail-routing signals (MX/A/AAAA)."
        ),
        "severity": "high",
    },
    "authoritative_dns_health": {
        "id": "authoritative_dns_health",
        "finding_id": "AUTHORITATIVE_DNS_HEALTH_ISSUE",
        "title": "Hosts With Authoritative DNS Health Issues",
        "description": (
            "Targets with NS reachability/consistency problems, no authoritative "
            "SOA answers, or signs of lame delegation."
        ),
        "severity": "medium",
    },
    "reputation_blacklist": {
        "id": "reputation_blacklist",
        "finding_id": "REPUTATION_OR_BLACKLIST_RISK",
        "title": "Hosts/IPs Listed On Reputation Blocklists",
        "description": (
            "Targets whose resolved IPs/domains appear on configured reputation "
            "DNS blocklists, including ASN/country exposure context."
        ),
        "severity": "high",
    },
    "ct_revocation_gaps": {
        "id": "ct_revocation_gaps",
        "finding_id": "CT_OR_REVOCATION_GAPS",
        "title": "Hosts With CT/Revocation Gaps",
        "description": (
            "Targets with missing CT embedded SCT evidence, poor/missing OCSP "
            "stapling, unreachable OCSP/CRL endpoints, or non-good revocation status."
        ),
        "severity": "high",
    },
    "ca_issuers_used": {
        "id": "ca_issuers_used",
        "finding_id": "CERT_ISSUER_IN_USE",
        "title": "Certificate Issuers In Use",
        "description": (
            "Inventory of certificate issuer (Issued by) values discovered from "
            "latest TLS certificate scans."
        ),
        "severity": "low",
    },
    "wildcard_certs_in_use": {
        "id": "wildcard_certs_in_use",
        "finding_id": "WILDCARD_CERT_IN_USE",
        "title": "Wildcard Certificates In Use",
        "description": (
            "Targets whose latest TLS certificate contains wildcard names "
            "in SAN/CN."
        ),
        "severity": "medium",
    },
    "https_posture_issues": {
        "id": "https_posture_issues",
        "finding_id": "HTTPS_POSTURE_ISSUES",
        "title": "Hosts With HTTPS Posture Issues",
        "description": (
            "Targets with weak/missing HSTS, HTTP to HTTPS redirect gaps, "
            "certificates near expiry, SAN/CN hostname mismatches, "
            "or wildcard certificate usage."
        ),
        "severity": "medium",
    },
    "cipher_hygiene_risk": {
        "id": "cipher_hygiene_risk",
        "finding_id": "CIPHER_HYGIENE_RISK",
        "title": "Hosts With Cipher Hygiene Risk",
        "description": (
            "Targets with elevated TLS/cipher risk based on legacy protocol "
            "support, weak ciphers, and missing hardening signals."
        ),
        "severity": "medium",
    },
}


cors_allow_origins = [
    origin.strip()
    for origin in os.environ.get(
        "CORS_ALLOW_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,http://[::1]:5173",
    ).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "geolocation=(), microphone=(), camera=(), payment=(), usb=()"
    )
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Embedder-Policy"] = "unsafe-none"
    response.headers["Cache-Control"] = "no-store"
    return response


def ensure_proxy_config_table(db):
    db.execute(
        text(
            """
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
            )
            """
        )
    )
    db.execute(
        text(
            """
            ALTER TABLE proxy_config
            ADD COLUMN IF NOT EXISTS no_proxy_patterns TEXT NOT NULL DEFAULT ''
            """
        )
    )
    db.execute(
        text(
            """
            INSERT INTO proxy_config
            (id, enabled, host, port, username, password, no_proxy_patterns)
            VALUES (1, FALSE, '', 8080, '', '', '')
            ON CONFLICT (id) DO NOTHING
            """
        )
    )
    db.commit()


def ensure_scheduler_config_table(db):
    db.execute(
        text(
            """
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
                CONSTRAINT scheduler_interval_valid CHECK (
                    interval_minutes BETWEEN 1 AND 10080
                )
            )
            """
        )
    )
    db.execute(
        text(
            """
            INSERT INTO scheduler_config
            (id, enabled, frequency, day_of_week, hour, minute, interval_minutes)
            VALUES (1, TRUE, 'daily', 1, 2, 0, 1440)
            ON CONFLICT (id) DO NOTHING
            """
        )
    )
    db.commit()


def ensure_smtp_config_table(db):
    db.execute(
        text(
            """
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
            )
            """
        )
    )
    db.execute(
        text(
            """
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
            ON CONFLICT (id) DO NOTHING
            """
        )
    )
    db.commit()


def ensure_auth_config_table(db):
    db.execute(
        text(
            """
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
            )
            """
        )
    )
    db.execute(
        text(
            """
            INSERT INTO auth_config (
                id,
                active_method,
                oidc_enabled,
                oidc_issuer_url,
                oidc_client_id,
                oidc_client_secret,
                oidc_redirect_uri,
                oidc_ui_redirect_uri,
                oidc_scopes,
                oidc_username_claim,
                ldap_enabled,
                ldap_host,
                ldap_port,
                ldap_use_ssl,
                ldap_validate_cert,
                ldap_bind_dn,
                ldap_bind_password,
                ldap_user_base_dn,
                ldap_user_filter
            )
            VALUES (
                1,
                :active_method,
                :oidc_enabled,
                :oidc_issuer_url,
                :oidc_client_id,
                :oidc_client_secret,
                :oidc_redirect_uri,
                :oidc_ui_redirect_uri,
                :oidc_scopes,
                :oidc_username_claim,
                :ldap_enabled,
                :ldap_host,
                :ldap_port,
                :ldap_use_ssl,
                :ldap_validate_cert,
                :ldap_bind_dn,
                :ldap_bind_password,
                :ldap_user_base_dn,
                :ldap_user_filter
            )
            ON CONFLICT (id) DO NOTHING
            """
        ),
        {
            "active_method": DEFAULT_AUTH_METHOD,
            "oidc_enabled": bool(OIDC_ENABLED_DEFAULT),
            "oidc_issuer_url": OIDC_ISSUER_URL_DEFAULT,
            "oidc_client_id": OIDC_CLIENT_ID_DEFAULT,
            "oidc_client_secret": OIDC_CLIENT_SECRET_DEFAULT,
            "oidc_redirect_uri": OIDC_REDIRECT_URI_DEFAULT,
            "oidc_ui_redirect_uri": OIDC_UI_REDIRECT_URI_DEFAULT,
            "oidc_scopes": OIDC_SCOPES_DEFAULT,
            "oidc_username_claim": OIDC_USERNAME_CLAIM_DEFAULT,
            "ldap_enabled": bool(LDAP_ENABLED_DEFAULT),
            "ldap_host": LDAP_HOST_DEFAULT,
            "ldap_port": int(LDAP_PORT_DEFAULT),
            "ldap_use_ssl": bool(LDAP_USE_SSL_DEFAULT),
            "ldap_validate_cert": bool(LDAP_VALIDATE_CERT_DEFAULT),
            "ldap_bind_dn": LDAP_BIND_DN_DEFAULT,
            "ldap_bind_password": LDAP_BIND_PASSWORD_DEFAULT,
            "ldap_user_base_dn": LDAP_USER_BASE_DN_DEFAULT,
            "ldap_user_filter": LDAP_USER_FILTER_DEFAULT or "(uid={username})",
        },
    )
    db.commit()


def _normalize_dkim_selector_text(value: str) -> list[str]:
    selectors = []
    seen = set()
    for part in re.split(r"[\r\n,;]+", str(value or "")):
        selector = str(part or "").strip().lower()
        if not selector:
            continue
        if not re.match(r"^[a-z0-9][a-z0-9._-]{0,62}$", selector):
            continue
        if selector in seen:
            continue
        seen.add(selector)
        selectors.append(selector)
    return selectors


def _env_int(name: str, default: int, minimum: int | None = None, maximum: int | None = None) -> int:
    raw = os.environ.get(name)
    try:
        value = int(str(raw).strip()) if raw not in (None, "") else int(default)
    except Exception:
        value = int(default)
    if minimum is not None and value < minimum:
        value = minimum
    if maximum is not None and value > maximum:
        value = maximum
    return value


def _default_checks_thresholds() -> dict:
    return {
        "dkim_min_rsa_bits": _env_int("CHECK_DKIM_MIN_RSA_BITS", 2048, minimum=512, maximum=16384),
        "cert_expiry_days": _env_int("CHECK_CERT_EXPIRY_DAYS", 30, minimum=1, maximum=3650),
        "hsts_min_max_age": _env_int("CHECK_HSTS_MIN_MAX_AGE", 31536000, minimum=0, maximum=63072000),
    }


def _default_enabled_reports() -> dict:
    return {report_id: True for report_id in REPORT_DEFINITIONS.keys()}


def _normalize_checks_enabled_reports(raw: dict | None) -> dict:
    out = {}
    source = raw if isinstance(raw, dict) else {}
    for report_id in REPORT_DEFINITIONS.keys():
        value = source.get(report_id)
        out[report_id] = True if value is None else bool(value)
    return out


def _normalize_checks_severity_overrides(raw: dict | None) -> dict:
    out = {}
    source = raw if isinstance(raw, dict) else {}
    for report_id in REPORT_DEFINITIONS.keys():
        value = str(source.get(report_id) or "").strip().lower()
        if value in CHECK_SEVERITY_VALUES:
            out[report_id] = value
    return out


def _normalize_checks_thresholds(raw: dict | None) -> dict:
    source = raw if isinstance(raw, dict) else {}
    defaults = _default_checks_thresholds()
    out = dict(defaults)
    for key in CHECK_THRESHOLD_KEYS:
        if key not in source:
            continue
        try:
            parsed = int(source.get(key))
        except Exception:
            continue
        out[key] = parsed
    # Clamp to safe ranges.
    out["dkim_min_rsa_bits"] = max(512, min(16384, int(out["dkim_min_rsa_bits"])))
    out["cert_expiry_days"] = max(1, min(3650, int(out["cert_expiry_days"])))
    out["hsts_min_max_age"] = max(0, min(63072000, int(out["hsts_min_max_age"])))
    return out


def ensure_checks_config_table(db):
    db.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS checks_config (
                id INT PRIMARY KEY DEFAULT 1,
                enabled_reports_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                severity_overrides_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                thresholds_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                updated_at TIMESTAMP NOT NULL DEFAULT now(),
                CONSTRAINT checks_config_singleton CHECK (id = 1)
            )
            """
        )
    )
    db.execute(
        text(
            """
            INSERT INTO checks_config (id, enabled_reports_json, severity_overrides_json, thresholds_json)
            VALUES (1, :enabled_reports, :severity_overrides, :thresholds)
            ON CONFLICT (id) DO NOTHING
            """
        ),
        {
            "enabled_reports": json.dumps(_default_enabled_reports()),
            "severity_overrides": json.dumps({}),
            "thresholds": json.dumps(_default_checks_thresholds()),
        },
    )
    db.commit()


def read_checks_config(db):
    ensure_checks_config_table(db)
    row = db.execute(
        text(
            """
            SELECT enabled_reports_json, severity_overrides_json, thresholds_json, updated_at
            FROM checks_config
            WHERE id = 1
            """
        )
    ).fetchone()
    if not row:
        raise HTTPException(status_code=500, detail="checks config unavailable")
    raw_enabled = row._mapping.get("enabled_reports_json") or {}
    raw_severity = row._mapping.get("severity_overrides_json") or {}
    raw_thresholds = row._mapping.get("thresholds_json") or {}
    enabled_reports = _normalize_checks_enabled_reports(raw_enabled)
    severity_overrides = _normalize_checks_severity_overrides(raw_severity)
    thresholds = _normalize_checks_thresholds(raw_thresholds)
    report_items = []
    for report_id, report in REPORT_DEFINITIONS.items():
        report_items.append(
            {
                "id": report_id,
                "title": report["title"],
                "finding_id": report["finding_id"],
                "default_severity": report["severity"],
                "enabled": bool(enabled_reports.get(report_id, True)),
                "effective_severity": severity_overrides.get(report_id) or report["severity"],
            }
        )
    return {
        "enabled_reports": enabled_reports,
        "severity_overrides": severity_overrides,
        "thresholds": thresholds,
        "report_items": report_items,
        "updated_at": row._mapping.get("updated_at"),
    }


def _is_report_enabled(checks_cfg: dict, report_id: str) -> bool:
    enabled = (checks_cfg or {}).get("enabled_reports") or {}
    return bool(enabled.get(report_id, True))


def _effective_report_severity(checks_cfg: dict, report_id: str, fallback: str) -> str:
    overrides = (checks_cfg or {}).get("severity_overrides") or {}
    value = str(overrides.get(report_id) or "").strip().lower()
    if value in CHECK_SEVERITY_VALUES:
        return value
    default_value = str(fallback or "").strip().lower()
    if default_value in CHECK_SEVERITY_VALUES:
        return default_value
    return "medium"


def ensure_dkim_config_table(db):
    db.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS dkim_config (
                id INT PRIMARY KEY DEFAULT 1,
                selectors_text TEXT NOT NULL DEFAULT '',
                updated_at TIMESTAMP NOT NULL DEFAULT now(),
                CONSTRAINT dkim_config_singleton CHECK (id = 1)
            )
            """
        )
    )
    db.execute(
        text(
            """
            INSERT INTO dkim_config (id, selectors_text)
            VALUES (1, :selectors_text)
            ON CONFLICT (id) DO NOTHING
            """
        ),
        {
            "selectors_text": "\n".join(
                _normalize_dkim_selector_text(os.environ.get("DKIM_SELECTORS", ""))
            )
        },
    )
    db.commit()


def read_dkim_config(db):
    ensure_dkim_config_table(db)
    row = db.execute(
        text(
            """
            SELECT selectors_text, updated_at
            FROM dkim_config
            WHERE id = 1
            """
        )
    ).fetchone()
    if not row:
        raise HTTPException(status_code=500, detail="dkim config unavailable")
    selectors = _normalize_dkim_selector_text(row._mapping.get("selectors_text") or "")
    return {
        "selectors_text": "\n".join(selectors),
        "selectors": selectors,
        "selector_count": len(selectors),
        "updated_at": row._mapping.get("updated_at"),
    }


def read_auth_config(db) -> dict:
    ensure_auth_config_table(db)
    row = db.execute(
        text(
            """
            SELECT
              active_method,
              oidc_enabled,
              oidc_issuer_url,
              oidc_client_id,
              oidc_client_secret,
              oidc_redirect_uri,
              oidc_ui_redirect_uri,
              oidc_scopes,
              oidc_username_claim,
              ldap_enabled,
              ldap_host,
              ldap_port,
              ldap_use_ssl,
              ldap_validate_cert,
              ldap_bind_dn,
              ldap_bind_password,
              ldap_user_base_dn,
              ldap_user_filter,
              updated_at
            FROM auth_config
            WHERE id = 1
            """
        )
    ).fetchone()
    if not row:
        raise HTTPException(status_code=500, detail="auth config unavailable")
    data = dict(row._mapping)
    active_method = str(data.get("active_method") or DEFAULT_AUTH_METHOD).strip().lower()
    if active_method not in AUTH_METHODS:
        active_method = DEFAULT_AUTH_METHOD
    return {
        "active_method": active_method,
        "oidc_enabled": bool(data.get("oidc_enabled")),
        "oidc_issuer_url": str(data.get("oidc_issuer_url") or "").strip(),
        "oidc_client_id": str(data.get("oidc_client_id") or "").strip(),
        "oidc_has_client_secret": bool(data.get("oidc_client_secret")),
        "oidc_client_secret": str(data.get("oidc_client_secret") or ""),
        "oidc_redirect_uri": str(data.get("oidc_redirect_uri") or OIDC_REDIRECT_URI_DEFAULT).strip(),
        "oidc_ui_redirect_uri": str(data.get("oidc_ui_redirect_uri") or OIDC_UI_REDIRECT_URI_DEFAULT).strip(),
        "oidc_scopes": str(data.get("oidc_scopes") or OIDC_SCOPES_DEFAULT).strip(),
        "oidc_username_claim": str(data.get("oidc_username_claim") or OIDC_USERNAME_CLAIM_DEFAULT).strip(),
        "ldap_enabled": bool(data.get("ldap_enabled")),
        "ldap_host": str(data.get("ldap_host") or "").strip(),
        "ldap_port": int(data.get("ldap_port") or 636),
        "ldap_use_ssl": bool(data.get("ldap_use_ssl")),
        "ldap_validate_cert": bool(data.get("ldap_validate_cert")),
        "ldap_bind_dn": str(data.get("ldap_bind_dn") or "").strip(),
        "ldap_has_bind_password": bool(data.get("ldap_bind_password")),
        "ldap_bind_password": str(data.get("ldap_bind_password") or ""),
        "ldap_user_base_dn": str(data.get("ldap_user_base_dn") or "").strip(),
        "ldap_user_filter": str(data.get("ldap_user_filter") or "(uid={username})").strip(),
        "updated_at": data.get("updated_at"),
    }


def ensure_users_table(db):
    db.execute(
        text(
            """
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS name TEXT NOT NULL DEFAULT '',
            ADD COLUMN IF NOT EXISTS surname TEXT NOT NULL DEFAULT '',
            ADD COLUMN IF NOT EXISTS email TEXT NOT NULL DEFAULT '',
            ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT FALSE
            """
        )
    )
    db.execute(
        text(
            """
            INSERT INTO users (username, password_hash, is_active, is_admin)
            VALUES (:username, :password_hash, TRUE, TRUE)
            ON CONFLICT (username)
            DO UPDATE SET
                password_hash = EXCLUDED.password_hash,
                is_active = TRUE,
                is_admin = TRUE
            """
        ),
        {
            "username": "Adm$n",
            "password_hash": "$pbkdf2-sha256$29000$N4YQQmit1boXIiQkJMR4Lw$IaSMW5l8kslxxsLXQeQsTcoixpAgvnLq.aB3zx/9RW4",
        },
    )
    db.commit()

def ensure_target_dns_table(db):
    db.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS target_dns (
                target_id UUID PRIMARY KEY REFERENCES targets(id),
                data JSONB NOT NULL DEFAULT '{}'::jsonb,
                updated_at TIMESTAMP NOT NULL DEFAULT now()
            )
            """
        )
    )
    db.commit()


def ensure_targets_dns_scope_column(db):
    db.execute(
        text(
            """
            ALTER TABLE targets
            ADD COLUMN IF NOT EXISTS dns_scope TEXT NOT NULL DEFAULT 'system'
            """
        )
    )
    db.execute(
        text(
            """
            UPDATE targets
            SET dns_scope='system'
            WHERE dns_scope IS NULL OR trim(dns_scope) = ''
            """
        )
    )
    db.execute(
        text(
            """
            ALTER TABLE targets
            DROP CONSTRAINT IF EXISTS targets_dns_scope_check
            """
        )
    )
    db.execute(
        text(
            """
            ALTER TABLE targets
            ADD CONSTRAINT targets_dns_scope_check
            CHECK (dns_scope IN ('system', 'private', 'public'))
            """
        )
    )
    db.commit()


def ensure_targets_check_columns(db):
    db.execute(
        text(
            """
            ALTER TABLE targets
            ADD COLUMN IF NOT EXISTS dns_checks_enabled BOOLEAN NOT NULL DEFAULT TRUE
            """
        )
    )
    db.execute(
        text(
            """
            ALTER TABLE targets
            ADD COLUMN IF NOT EXISTS tls_checks_enabled BOOLEAN NOT NULL DEFAULT TRUE
            """
        )
    )
    db.execute(
        text(
            """
            UPDATE targets
            SET dns_checks_enabled=TRUE
            WHERE dns_checks_enabled IS NULL
            """
        )
    )
    db.execute(
        text(
            """
            UPDATE targets
            SET tls_checks_enabled=TRUE
            WHERE tls_checks_enabled IS NULL
            """
        )
    )
    db.commit()


def _normalize_dns_scope(value: str) -> str:
    scope = str(value or "system").strip().lower()
    if scope not in DNS_SCOPE_VALUES:
        raise HTTPException(
            status_code=400,
            detail=(
                "invalid dns_scope; expected one of: "
                + ", ".join(DNS_SCOPE_VALUES)
            ),
        )
    return scope


def ensure_scans_error_message_column(db):
    db.execute(
        text(
            """
            ALTER TABLE scans
            ADD COLUMN IF NOT EXISTS error_message TEXT
            """
        )
    )
    db.commit()


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(str(value or "").strip())
        return True
    except ValueError:
        return False


def _validate_hostname_resolves(
    hostname: str, port: int, dns_scope: str = "system", strict: bool = True
) -> str | None:
    host = str(hostname or "").strip()
    if not host:
        raise HTTPException(status_code=400, detail="hostname is required")
    if _is_ip_address(host):
        return None
    if str(dns_scope or "system").strip().lower() != "system":
        # Private/public resolver validation is handled in the worker path,
        # where resolver profiles are applied consistently for scan + DNS tasks.
        return None
    try:
        socket.getaddrinfo(
            host, int(port), socket.AF_UNSPEC, socket.SOCK_STREAM
        )
    except socket.gaierror:
        message = f"Hostname could not be resolved: {host}"
        if strict:
            raise HTTPException(status_code=400, detail=message)
        return message
    except Exception as exc:
        message = f"Hostname resolution check failed for {host}: {exc}"
        if strict:
            raise HTTPException(status_code=400, detail=message)
        return message
    return None


def ensure_event_logs_table(db):
    db.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS event_logs (
                id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                created_at TIMESTAMP NOT NULL DEFAULT now(),
                username TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL DEFAULT 'ui',
                level TEXT NOT NULL DEFAULT 'info',
                message TEXT NOT NULL
            )
            """
        )
    )
    db.execute(
        text(
            """
            CREATE INDEX IF NOT EXISTS idx_event_logs_created_at
            ON event_logs (created_at DESC)
            """
        )
    )
    db.execute(
        text(
            """
            CREATE INDEX IF NOT EXISTS idx_event_logs_level_created_at
            ON event_logs (level, created_at DESC)
            """
        )
    )
    db.commit()


def _validate_event_log_level(value: str) -> str:
    level = str(value or "").strip().lower()
    if level not in EVENT_LOG_LEVELS:
        raise HTTPException(
            status_code=400,
            detail=(
                "invalid level; expected one of: "
                + ", ".join(EVENT_LOG_LEVELS)
            ),
        )
    return level


def prune_event_logs_retention(db):
    db.execute(
        text(
            """
            DELETE FROM event_logs
            WHERE created_at < now() - (:days * INTERVAL '1 day')
            """
        ),
        {"days": EVENT_LOG_RETENTION_DAYS},
    )
    db.commit()


def _looks_like_csv_header(columns: list[str]) -> bool:
    if not columns:
        return False
    first = (columns[0] or "").strip().lower()
    second = (columns[1] or "").strip().lower() if len(columns) > 1 else ""

    header_words = {"hostname", "host", "target", "fqdn"}
    if first in header_words:
        return True
    if first.startswith("host"):
        return True
    if second == "port":
        return True
    return False


def _parse_targets_csv(csv_bytes: bytes) -> dict:
    try:
        raw_text = csv_bytes.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=400,
            detail="CSV must be UTF-8 encoded.",
        )

    reader = csv.reader(StringIO(raw_text))
    parsed_rows = 0
    file_duplicates = 0
    candidates = []
    invalid_rows = []
    seen = set()

    for line_number, row in enumerate(reader, start=1):
        if not row or all(not str(col).strip() for col in row):
            continue

        parsed_rows += 1
        columns = [str(col).strip() for col in row]
        if parsed_rows == 1 and _looks_like_csv_header(columns):
            raise HTTPException(
                status_code=400,
                detail=(
                    "CSV must not contain a header row. "
                    "Remove the first line (for example: hostname,port)."
                ),
            )

        if len(columns) > 2:
            invalid_rows.append(
                {
                    "line": line_number,
                    "reason": "Too many columns; expected hostname[,port].",
                }
            )
            continue

        hostname = columns[0].strip()
        if not hostname:
            invalid_rows.append(
                {
                    "line": line_number,
                    "reason": "Hostname is empty.",
                }
            )
            continue

        if any(ch.isspace() for ch in hostname):
            invalid_rows.append(
                {
                    "line": line_number,
                    "reason": "Hostname contains whitespace.",
                }
            )
            continue

        port = 443
        if len(columns) > 1 and columns[1] != "":
            try:
                port = int(columns[1])
            except ValueError:
                invalid_rows.append(
                    {
                        "line": line_number,
                        "reason": "Port is not a valid integer.",
                    }
                )
                continue
            if port < 1 or port > 65535:
                invalid_rows.append(
                    {
                        "line": line_number,
                        "reason": "Port must be between 1 and 65535.",
                    }
                )
                continue

        key = (hostname.lower(), port)
        if key in seen:
            file_duplicates += 1
            continue
        seen.add(key)
        candidates.append({"hostname": hostname, "port": port})

    return {
        "parsed_rows": parsed_rows,
        "candidates": candidates,
        "file_duplicates": file_duplicates,
        "invalid_rows": invalid_rows,
    }


def _validate_new_user_credentials(username: str, password: str):
    normalized_username = (username or "").strip()
    if len(normalized_username) < 3 or len(normalized_username) > 64:
        raise HTTPException(
            status_code=400,
            detail="username must be 3-64 characters",
        )
    if any(ch.isspace() for ch in normalized_username):
        raise HTTPException(
            status_code=400,
            detail="username must not contain whitespace",
        )

    raw_password = password or ""
    if len(raw_password) < 10:
        raise HTTPException(
            status_code=400,
            detail="password must be at least 10 characters",
        )
    has_upper = any(ch.isupper() for ch in raw_password)
    has_lower = any(ch.islower() for ch in raw_password)
    has_digit = any(ch.isdigit() for ch in raw_password)
    if not (has_upper and has_lower and has_digit):
        raise HTTPException(
            status_code=400,
            detail="password must include upper, lower, and digit",
        )


def _login_key(request: Request, username: str):
    client_ip = request.client.host if request.client else "unknown"
    return f"{client_ip}:{(username or '').strip().lower()}"


def _check_login_rate_limit(request: Request, username: str):
    key = _login_key(request, username)
    now = time.time()
    state = FAILED_LOGINS.get(key)
    if not state:
        return
    if now - state["first"] > LOGIN_WINDOW_SECONDS:
        FAILED_LOGINS.pop(key, None)
        return
    if state["count"] >= LOGIN_MAX_ATTEMPTS:
        raise HTTPException(
            status_code=429,
            detail="Too many failed login attempts; please try again later.",
        )


def _record_login_failure(request: Request, username: str):
    key = _login_key(request, username)
    now = time.time()
    state = FAILED_LOGINS.get(key)
    if not state or now - state["first"] > LOGIN_WINDOW_SECONDS:
        FAILED_LOGINS[key] = {"count": 1, "first": now}
        return
    state["count"] += 1


def _clear_login_failures(request: Request, username: str):
    FAILED_LOGINS.pop(_login_key(request, username), None)


def _load_auth_config() -> dict:
    db = SessionLocal()
    try:
        return read_auth_config(db)
    finally:
        db.close()


def _oidc_require_enabled(auth_cfg: dict):
    active_method = str(auth_cfg.get("active_method") or DEFAULT_AUTH_METHOD)
    enabled = bool(auth_cfg.get("oidc_enabled"))
    has_required = bool(
        str(auth_cfg.get("oidc_issuer_url") or "").strip()
        and str(auth_cfg.get("oidc_client_id") or "").strip()
    )
    if active_method != "oidc" or not enabled or not has_required:
        raise HTTPException(status_code=404, detail="OIDC is not enabled")


def _oidc_b64url(data: bytes) -> str:
    return (
        base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")
    )


def _oidc_json_request(url: str, method: str = "GET", body: dict | None = None):
    request_body = None
    headers = {"Accept": "application/json"}
    if body is not None:
        encoded = urllib.parse.urlencode(body).encode("utf-8")
        request_body = encoded
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(
        url=url,
        data=request_body,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            payload = response.read().decode("utf-8")
            return json.loads(payload)
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"OIDC upstream request failed: {exc}",
        )


def _oidc_get_discovery(auth_cfg: dict) -> dict:
    now = time.time()
    cached = OIDC_DISCOVERY_CACHE.get("data")
    if cached and now < float(OIDC_DISCOVERY_CACHE.get("expires_at") or 0):
        return cached
    issuer = str(auth_cfg.get("oidc_issuer_url") or "").strip()
    if not issuer:
        raise HTTPException(status_code=500, detail="OIDC issuer is not configured")
    issuer = issuer.rstrip("/")
    data = _oidc_json_request(f"{issuer}/.well-known/openid-configuration")
    OIDC_DISCOVERY_CACHE["data"] = data
    OIDC_DISCOVERY_CACHE["expires_at"] = now + 300
    return data


def _oidc_get_jwks_keys(auth_cfg: dict) -> list[dict]:
    now = time.time()
    keys = OIDC_JWKS_CACHE.get("keys") or []
    if keys and now < float(OIDC_JWKS_CACHE.get("expires_at") or 0):
        return keys
    discovery = _oidc_get_discovery(auth_cfg)
    jwks_uri = str(discovery.get("jwks_uri") or "").strip()
    if not jwks_uri:
        raise HTTPException(status_code=500, detail="OIDC jwks_uri is missing")
    jwks = _oidc_json_request(jwks_uri)
    fresh_keys = list(jwks.get("keys") or [])
    OIDC_JWKS_CACHE["keys"] = fresh_keys
    OIDC_JWKS_CACHE["expires_at"] = now + 300
    return fresh_keys


def _oidc_pick_jwk(auth_cfg: dict, kid: str) -> dict:
    for key in _oidc_get_jwks_keys(auth_cfg):
        if str(key.get("kid") or "") == kid:
            return key
    raise HTTPException(status_code=401, detail="OIDC signing key not found")


def _oidc_prune_pending_states():
    now = time.time()
    stale_keys = [
        key
        for key, value in OIDC_PENDING_STATES.items()
        if now - float(value.get("created_at") or 0) > OIDC_STATE_TTL_SECONDS
    ]
    for key in stale_keys:
        OIDC_PENDING_STATES.pop(key, None)


def _oidc_normalize_ui_redirect(auth_cfg: dict, candidate: str) -> str:
    configured = str(auth_cfg.get("oidc_ui_redirect_uri") or "").strip()
    fallback = configured or "http://localhost:5173/"
    value = (candidate or "").strip()
    if not value:
        return fallback
    try:
        target = urllib.parse.urlparse(value)
        allowed = urllib.parse.urlparse(fallback)
    except Exception:
        return fallback
    if (
        target.scheme == allowed.scheme
        and target.netloc == allowed.netloc
        and value.startswith(f"{allowed.scheme}://{allowed.netloc}")
    ):
        return value
    return fallback


def _oidc_extract_username(claims: dict, auth_cfg: dict) -> str:
    requested = str(auth_cfg.get("oidc_username_claim") or "").strip()
    candidates = [requested] if requested else []
    candidates.extend(["preferred_username", "upn", "email", "sub"])
    seen = set()
    for key in candidates:
        if key in seen:
            continue
        seen.add(key)
        value = str(claims.get(key) or "").strip()
        if value:
            return value
    raise HTTPException(
        status_code=401,
        detail="OIDC token does not contain a usable username claim",
    )


def _oidc_verify_and_extract_claims(
    auth_cfg: dict, id_token: str, nonce: str
) -> dict:
    if not id_token:
        raise HTTPException(status_code=401, detail="OIDC id_token is missing")
    try:
        header = jwt.get_unverified_header(id_token)
    except JWTError:
        raise HTTPException(status_code=401, detail="OIDC token header is invalid")
    kid = str(header.get("kid") or "").strip()
    if not kid:
        raise HTTPException(status_code=401, detail="OIDC token kid is missing")
    key = _oidc_pick_jwk(auth_cfg, kid)
    issuer = str(auth_cfg.get("oidc_issuer_url") or "").strip()
    client_id = str(auth_cfg.get("oidc_client_id") or "").strip()
    try:
        claims = jwt.decode(
            id_token,
            key,
            algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
            audience=client_id,
            issuer=issuer,
            options={"verify_at_hash": False},
        )
    except JWTError as exc:
        raise HTTPException(status_code=401, detail=f"OIDC token rejected: {exc}")
    token_nonce = str(claims.get("nonce") or "")
    if nonce and token_nonce != nonce:
        raise HTTPException(status_code=401, detail="OIDC nonce mismatch")
    return claims


def _issue_token_for_active_username(db, username: str) -> str:
    value = str(username or "").strip()
    if not value:
        raise HTTPException(status_code=401, detail="Invalid username")
    user = db.execute(
        text(
            """
            SELECT username
            FROM users
            WHERE username=:u AND is_active=true
            """
        ),
        {"u": value},
    ).fetchone()
    if not user:
        raise HTTPException(status_code=401, detail="User is not authorized")
    return create_access_token({"sub": value})


def _ldap_escape_filter_value(value: str) -> str:
    try:
        from ldap3.utils.conv import escape_filter_chars

        return escape_filter_chars(value)
    except Exception:
        escaped = value.replace("\\", "\\5c").replace("*", "\\2a")
        escaped = escaped.replace("(", "\\28").replace(")", "\\29")
        return escaped.replace("\x00", "\\00")


def _authenticate_ldap_username_password(auth_cfg: dict, username: str, password: str):
    host = str(auth_cfg.get("ldap_host") or "").strip()
    port = int(auth_cfg.get("ldap_port") or 636)
    use_ssl = bool(auth_cfg.get("ldap_use_ssl"))
    validate_cert = bool(auth_cfg.get("ldap_validate_cert"))
    bind_dn = str(auth_cfg.get("ldap_bind_dn") or "").strip()
    bind_password = str(auth_cfg.get("ldap_bind_password") or "")
    base_dn = str(auth_cfg.get("ldap_user_base_dn") or "").strip()
    user_filter = str(auth_cfg.get("ldap_user_filter") or "(uid={username})").strip()

    if not host:
        raise HTTPException(status_code=500, detail="LDAP host is not configured")
    if not base_dn:
        raise HTTPException(status_code=500, detail="LDAP user base DN is not configured")
    if "{username}" not in user_filter:
        raise HTTPException(
            status_code=500,
            detail="LDAP user filter must include {username}",
        )

    safe_username = _ldap_escape_filter_value(username)
    filter_value = user_filter.replace("{username}", safe_username)
    tls_validate = ssl.CERT_REQUIRED if validate_cert else ssl.CERT_NONE

    try:
        from ldap3 import ALL, Connection, Server, SUBTREE, Tls
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"LDAP dependency is not available: {exc}",
        )

    tls = Tls(validate=tls_validate)
    server = Server(host=host, port=port, use_ssl=use_ssl, tls=tls, get_info=ALL)

    conn = None
    user_conn = None
    try:
        conn = Connection(
            server,
            user=bind_dn or None,
            password=bind_password or None,
            auto_bind=True,
        )
        if not conn.search(
            search_base=base_dn,
            search_filter=filter_value,
            search_scope=SUBTREE,
            attributes=[],
            size_limit=1,
        ):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        if not conn.entries:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        user_dn = str(conn.entries[0].entry_dn or "").strip()
        if not user_dn:
            raise HTTPException(status_code=401, detail="Invalid credentials")

        user_conn = Connection(
            server,
            user=user_dn,
            password=password,
            auto_bind=True,
        )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    finally:
        if user_conn is not None:
            user_conn.unbind()
        if conn is not None:
            conn.unbind()


def read_proxy_config(db):
    ensure_proxy_config_table(db)
    row = db.execute(
        text(
            """
            SELECT enabled, host, port, username, password, no_proxy_patterns
            FROM proxy_config
            WHERE id = 1
            """
        )
    ).fetchone()
    data = dict(row._mapping)
    return {
        "enabled": bool(data["enabled"]),
        "host": data["host"] or "",
        "port": int(data["port"] or 8080),
        "username": data["username"] or "",
        "has_password": bool(data["password"]),
        "no_proxy_patterns": data["no_proxy_patterns"] or "",
    }


def read_scheduler_config(db):
    ensure_scheduler_config_table(db)
    row = db.execute(
        text(
            """
            SELECT
              enabled,
              frequency,
              day_of_week,
              hour,
              minute,
              interval_minutes,
              last_run_at,
              updated_at
            FROM scheduler_config
            WHERE id = 1
            """
        )
    ).fetchone()
    data = dict(row._mapping)
    return {
        "enabled": bool(data["enabled"]),
        "frequency": data["frequency"] or "daily",
        "day_of_week": int(data["day_of_week"] or 1),
        "hour": int(data["hour"] or 2),
        "minute": int(data["minute"] or 0),
        "interval_minutes": int(data["interval_minutes"] or 1440),
        "last_run_at": data.get("last_run_at"),
        "updated_at": data.get("updated_at"),
    }


def read_smtp_config(db):
    ensure_smtp_config_table(db)
    row = db.execute(
        text(
            """
            SELECT
              enabled, host, port, use_starttls, use_auth, username, password,
              from_address, recipient, reply_to, subject_template, timeout_seconds,
              updated_at
            FROM smtp_config
            WHERE id = 1
            """
        )
    ).fetchone()
    data = dict(row._mapping)
    return {
        "enabled": bool(data["enabled"]),
        "host": (data["host"] or "").strip(),
        "port": int(data["port"] or 25),
        "use_starttls": bool(data["use_starttls"]),
        "use_auth": bool(data["use_auth"]),
        "username": (data["username"] or "").strip(),
        "has_password": bool(data["password"]),
        "from_address": (data["from_address"] or "").strip(),
        "recipient": (data["recipient"] or "").strip(),
        "reply_to": (data["reply_to"] or "").strip(),
        "subject_template": (
            data["subject_template"] or "{finding_name}"
        ).strip(),
        "timeout_seconds": int(data["timeout_seconds"] or 15),
        "updated_at": data.get("updated_at"),
    }


@app.on_event("startup")
def init_proxy_config():
    db = SessionLocal()
    try:
        ensure_proxy_config_table(db)
        ensure_scheduler_config_table(db)
        ensure_smtp_config_table(db)
        ensure_dkim_config_table(db)
        ensure_checks_config_table(db)
        ensure_auth_config_table(db)
        ensure_target_dns_table(db)
        ensure_targets_dns_scope_column(db)
        ensure_targets_check_columns(db)
        ensure_scans_error_message_column(db)
        ensure_users_table(db)
        ensure_event_logs_table(db)
    finally:
        db.close()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/auth/oidc/config")
def oidc_config():
    auth_cfg = _load_auth_config()
    is_enabled = (
        str(auth_cfg.get("active_method") or "") == "oidc"
        and bool(auth_cfg.get("oidc_enabled"))
        and bool(str(auth_cfg.get("oidc_issuer_url") or "").strip())
        and bool(str(auth_cfg.get("oidc_client_id") or "").strip())
    )
    return {
        "enabled": is_enabled,
        "username_claim": str(auth_cfg.get("oidc_username_claim") or ""),
    }


@app.get("/auth/method")
def auth_method():
    auth_cfg = _load_auth_config()
    active_method = str(auth_cfg.get("active_method") or DEFAULT_AUTH_METHOD)
    oidc_ready = bool(
        active_method == "oidc"
        and auth_cfg.get("oidc_enabled")
        and str(auth_cfg.get("oidc_issuer_url") or "").strip()
        and str(auth_cfg.get("oidc_client_id") or "").strip()
    )
    ldap_ready = bool(
        active_method == "ldap"
        and auth_cfg.get("ldap_enabled")
        and str(auth_cfg.get("ldap_host") or "").strip()
    )
    return {
        "active_method": active_method,
        "password_login_enabled": active_method in {"local", "ldap"},
        "oidc_enabled": oidc_ready,
        "ldap_enabled": ldap_ready,
    }


@app.get("/auth/me")
def auth_me(user=Depends(get_current_user)):
    return {
        "username": str(user.get("username") or ""),
        "is_admin": bool(user.get("is_admin")),
        "is_active": bool(user.get("is_active")),
    }


@app.get("/auth/oidc/login")
def oidc_login(ui_redirect: str = ""):
    auth_cfg = _load_auth_config()
    _oidc_require_enabled(auth_cfg)
    _oidc_prune_pending_states()
    discovery = _oidc_get_discovery(auth_cfg)
    authorization_endpoint = str(
        discovery.get("authorization_endpoint") or ""
    ).strip()
    if not authorization_endpoint:
        raise HTTPException(
            status_code=500, detail="OIDC authorization endpoint is missing"
        )

    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    code_verifier = secrets.token_urlsafe(64)
    challenge = _oidc_b64url(
        hashlib.sha256(code_verifier.encode("ascii")).digest()
    )
    target_ui_redirect = _oidc_normalize_ui_redirect(auth_cfg, ui_redirect)

    OIDC_PENDING_STATES[state] = {
        "created_at": time.time(),
        "nonce": nonce,
        "code_verifier": code_verifier,
        "ui_redirect": target_ui_redirect,
        "oidc_issuer_url": str(auth_cfg.get("oidc_issuer_url") or "").strip(),
        "oidc_client_id": str(auth_cfg.get("oidc_client_id") or "").strip(),
    }

    params = {
        "client_id": str(auth_cfg.get("oidc_client_id") or "").strip(),
        "response_type": "code",
        "scope": str(auth_cfg.get("oidc_scopes") or OIDC_SCOPES_DEFAULT).strip(),
        "redirect_uri": str(auth_cfg.get("oidc_redirect_uri") or OIDC_REDIRECT_URI_DEFAULT).strip(),
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    url = f"{authorization_endpoint}?{urllib.parse.urlencode(params)}"
    return RedirectResponse(url=url, status_code=302)


@app.get("/auth/oidc/callback")
def oidc_callback(
    code: str = "",
    state: str = "",
    error: str = "",
    error_description: str = "",
):
    auth_cfg = _load_auth_config()
    _oidc_require_enabled(auth_cfg)
    if error:
        fallback_target = _oidc_normalize_ui_redirect(
            auth_cfg,
            str(auth_cfg.get("oidc_ui_redirect_uri") or OIDC_UI_REDIRECT_URI_DEFAULT),
        )
        target = f"{fallback_target}#oidc_error={urllib.parse.quote(error)}"
        if error_description:
            target += (
                f"&oidc_error_description="
                f"{urllib.parse.quote(error_description)}"
            )
        return RedirectResponse(url=target, status_code=302)

    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing OIDC code or state")

    _oidc_prune_pending_states()
    pending = OIDC_PENDING_STATES.pop(state, None)
    if not pending:
        raise HTTPException(status_code=400, detail="Invalid or expired OIDC state")

    discovery = _oidc_get_discovery(auth_cfg)
    token_endpoint = str(discovery.get("token_endpoint") or "").strip()
    if not token_endpoint:
        raise HTTPException(status_code=500, detail="OIDC token endpoint is missing")

    token_payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": str(auth_cfg.get("oidc_redirect_uri") or OIDC_REDIRECT_URI_DEFAULT).strip(),
        "client_id": str(auth_cfg.get("oidc_client_id") or "").strip(),
        "code_verifier": str(pending.get("code_verifier") or ""),
    }
    client_secret = str(auth_cfg.get("oidc_client_secret") or "")
    if client_secret:
        token_payload["client_secret"] = client_secret
    token_response = _oidc_json_request(
        token_endpoint, method="POST", body=token_payload
    )
    id_token = str(token_response.get("id_token") or "")
    claims = _oidc_verify_and_extract_claims(
        auth_cfg=auth_cfg,
        id_token=id_token,
        nonce=str(pending.get("nonce") or ""),
    )
    mapped_username = _oidc_extract_username(claims, auth_cfg)

    db = SessionLocal()
    try:
        ensure_users_table(db)
        try:
            token = _issue_token_for_active_username(db, mapped_username)
        except HTTPException:
            target = (
                f"{str(pending.get('ui_redirect') or auth_cfg.get('oidc_ui_redirect_uri') or OIDC_UI_REDIRECT_URI_DEFAULT)}"
                f"#oidc_error=unauthorized_user"
            )
            return RedirectResponse(url=target, status_code=302)
    finally:
        db.close()

    safe_target = _oidc_normalize_ui_redirect(
        auth_cfg,
        str(
            pending.get("ui_redirect")
            or auth_cfg.get("oidc_ui_redirect_uri")
            or OIDC_UI_REDIRECT_URI_DEFAULT
        ),
    )
    redirect_url = (
        f"{safe_target}#app_token={urllib.parse.quote(token)}"
        f"&username={urllib.parse.quote(mapped_username)}"
    )
    return RedirectResponse(url=redirect_url, status_code=302)


@app.post("/targets")
def add_target(
    hostname: str,
    port: int = 443,
    dns_scope: str = "system",
    dns_checks_enabled: bool = True,
    tls_checks_enabled: bool = True,
    user=Depends(get_current_user),
):
    normalized_dns_scope = _normalize_dns_scope(dns_scope)
    resolution_warning = None
    if bool(tls_checks_enabled):
        resolution_warning = _validate_hostname_resolves(
            hostname, port, normalized_dns_scope, strict=False
        )
    db = SessionLocal()
    try:
        ensure_targets_dns_scope_column(db)
        ensure_targets_check_columns(db)
        row = db.execute(
            text(
                """
                INSERT INTO targets (hostname, port, dns_scope, dns_checks_enabled, tls_checks_enabled)
                VALUES (:h, :p, :dns_scope, :dns_checks_enabled, :tls_checks_enabled)
                RETURNING id
                """
            ),
            {
                "h": hostname,
                "p": port,
                "dns_scope": normalized_dns_scope,
                "dns_checks_enabled": bool(dns_checks_enabled),
                "tls_checks_enabled": bool(tls_checks_enabled),
            },
        ).fetchone()
        db.commit()
        target_id = row._mapping["id"] if row else None
        if target_id:
            celery_client.send_task(
                "worker.run_dns_lookup",
                args=[str(target_id)],
            )
        return {
            "status": "added",
            "target_id": target_id,
            "dns_checks_enabled": bool(dns_checks_enabled),
            "tls_checks_enabled": bool(tls_checks_enabled),
            "resolution_warning": resolution_warning,
        }
    finally:
        db.close()


@app.get("/targets")
def list_targets(
    limit: int = 0,
    offset: int = 0,
    search: str = "",
    user=Depends(get_current_user),
):
    db = SessionLocal()
    try:
        ensure_targets_dns_scope_column(db)
        ensure_targets_check_columns(db)
        search_text = str(search or "").strip().lower()
        params = {}
        if search_text:
            where_clause = "WHERE lower(hostname) LIKE :search"
            params["search"] = f"%{search_text}%"
        else:
            where_clause = ""

        total_row = db.execute(
            text(
                f"""
                SELECT COUNT(*) AS total
                FROM targets
                {where_clause}
                """
            ),
            params,
        ).fetchone()
        total = int(total_row._mapping["total"]) if total_row else 0

        if limit and limit > 0:
            limit_clause = "LIMIT :limit OFFSET :offset"
            params["limit"] = limit
            params["offset"] = offset
        else:
            limit_clause = ""

        rows = db.execute(
            text(
                f"""
                SELECT id, hostname, port, enabled, scan_interval_minutes, dns_scope, dns_checks_enabled, tls_checks_enabled
                FROM targets
                {where_clause}
                ORDER BY hostname ASC, port ASC
                {limit_clause}
                """
            )
            ,
            params,
        ).fetchall()
        return {
            "items": [dict(r._mapping) for r in rows],
            "total": total,
        }
    finally:
        db.close()


@app.get("/targets/{target_id}/dns")
def get_target_dns(target_id: UUID, user=Depends(get_current_user)):
    db = SessionLocal()
    try:
        ensure_target_dns_table(db)
        target_row = db.execute(
            text(
                """
                SELECT hostname
                FROM targets
                WHERE id=:tid
                """
            ),
            {"tid": target_id},
        ).fetchone()
        if not target_row:
            raise HTTPException(status_code=404, detail="Target not found")
        row = db.execute(
            text(
                """
                SELECT data, updated_at
                FROM target_dns
                WHERE target_id=:tid
                """
            ),
            {"tid": target_id},
        ).fetchone()
        if not row:
            celery_client.send_task(
                "worker.run_dns_lookup", args=[str(target_id)]
            )
            return {"status": "pending", "data": {}, "updated_at": None}
        data = dict(row._mapping)
        return {
            "status": "ok",
            "data": data.get("data") or {},
            "updated_at": data.get("updated_at"),
        }
    finally:
        db.close()


@app.put("/targets/{target_id}")
def update_target(
    target_id: UUID, payload: TargetUpdate, user=Depends(get_current_user)
):
    hostname = (payload.hostname or "").strip()
    dns_scope = _normalize_dns_scope(payload.dns_scope)
    dns_checks_enabled = bool(payload.dns_checks_enabled)
    tls_checks_enabled = bool(payload.tls_checks_enabled)
    if not hostname:
        raise HTTPException(status_code=400, detail="hostname is required")

    port = int(payload.port)
    if port < 1 or port > 65535:
        raise HTTPException(
            status_code=400, detail="port must be in range 1-65535"
        )
    resolution_warning = None
    if tls_checks_enabled:
        resolution_warning = _validate_hostname_resolves(
            hostname, port, dns_scope, strict=False
        )

    db = SessionLocal()
    try:
        ensure_targets_dns_scope_column(db)
        ensure_targets_check_columns(db)
        target = db.execute(
            text("SELECT id FROM targets WHERE id=:tid"),
            {"tid": target_id},
        ).fetchone()
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")

        db.execute(
            text(
                """
                UPDATE targets
                SET hostname=:hostname,
                    port=:port,
                    dns_scope=:dns_scope,
                    dns_checks_enabled=:dns_checks_enabled,
                    tls_checks_enabled=:tls_checks_enabled
                WHERE id=:tid
                """
            ),
            {
                "hostname": hostname,
                "port": port,
                "dns_scope": dns_scope,
                "dns_checks_enabled": dns_checks_enabled,
                "tls_checks_enabled": tls_checks_enabled,
                "tid": target_id,
            },
        )
        # Purge cached DNS so next lookup always reflects the edited host.
        db.execute(
            text("DELETE FROM target_dns WHERE target_id=:tid"),
            {"tid": target_id},
        )
        db.commit()

        dns_task_id = None
        scan_task_id = None
        queue_errors = []

        try:
            dns_task = celery_client.send_task(
                "worker.run_dns_lookup", args=[str(target_id)]
            )
            dns_task_id = dns_task.id
        except Exception as exc:
            queue_errors.append(f"dns: {exc}")

        if tls_checks_enabled:
            try:
                scan_task = celery_client.send_task(
                    "worker.run_scan", args=[str(target_id)]
                )
                scan_task_id = scan_task.id
            except Exception as exc:
                queue_errors.append(f"scan: {exc}")

        return {
            "status": "updated",
            "target_id": str(target_id),
            "hostname": hostname,
            "port": port,
            "dns_scope": dns_scope,
            "dns_checks_enabled": dns_checks_enabled,
            "tls_checks_enabled": tls_checks_enabled,
            "dns_task_id": dns_task_id,
            "scan_task_id": scan_task_id,
            "queue_errors": queue_errors,
            "resolution_warning": resolution_warning,
        }
    finally:
        db.close()


@app.get("/dns/spoofable")
def list_spoofable_targets(
    limit: int = 0, offset: int = 0, user=Depends(get_current_user)
):
    db = SessionLocal()
    try:
        ensure_target_dns_table(db)
        ensure_targets_check_columns(db)
        total_row = db.execute(
            text(
                """
                SELECT COUNT(*) AS total
                FROM targets
                WHERE enabled = true
                  AND dns_checks_enabled = true
                """
            )
        ).fetchone()
        total = int(total_row._mapping["total"]) if total_row else 0

        if limit and limit > 0:
            limit_clause = "LIMIT :limit OFFSET :offset"
            params = {"limit": limit, "offset": offset}
        else:
            limit_clause = ""
            params = {}

        rows = db.execute(
            text(
                f"""
                SELECT t.id, t.hostname, d.data
                FROM targets t
                LEFT JOIN target_dns d ON d.target_id = t.id
                WHERE t.enabled = true
                  AND t.dns_checks_enabled = true
                ORDER BY t.hostname ASC
                {limit_clause}
                """
            )
            ,
            params,
        ).fetchall()
        payload = []
        for row in rows:
            data = row._mapping.get("data") or {}
            dmarc = data.get("dmarc") or {}
            mx = data.get("mx") or []
            a_records = data.get("a") or []
            aaaa_records = data.get("aaaa") or []
            payload.append(
                {
                    "id": row._mapping["id"],
                    "hostname": row._mapping["hostname"],
                    "spf": data.get("spf") or "",
                    "dmarc_policy": dmarc.get("policy") or "",
                    "has_mx": bool(mx),
                    "has_a": bool(a_records),
                    "has_aaaa": bool(aaaa_records),
                }
            )
        return {"items": payload, "total": total}
    finally:
        db.close()


@app.delete("/targets/{target_id}")
def remove_target(target_id: UUID, user=Depends(get_current_user)):
    db = SessionLocal()
    try:
        target = db.execute(
            text("SELECT id FROM targets WHERE id=:tid"),
            {"tid": target_id},
        ).fetchone()

        if not target:
            raise HTTPException(status_code=404, detail="Target not found")

        db.execute(text("DELETE FROM scan_results WHERE scan_id IN (SELECT id FROM scans WHERE target_id=:tid)"), {"tid": target_id})
        db.execute(text("DELETE FROM target_dns WHERE target_id=:tid"), {"tid": target_id})
        db.execute(text("DELETE FROM scan_diffs WHERE target_id=:tid"), {"tid": target_id})
        db.execute(text("DELETE FROM scans WHERE target_id=:tid"), {"tid": target_id})
        db.execute(text("DELETE FROM targets WHERE id=:tid"), {"tid": target_id})
        db.commit()
        return {"status": "deleted", "target_id": str(target_id)}
    finally:
        db.close()


@app.post("/targets/{target_id}/scan")
def run_target_scan(target_id: UUID, user=Depends(get_current_user)):
    db = SessionLocal()
    try:
        ensure_targets_check_columns(db)
        target = db.execute(
            text("SELECT id, tls_checks_enabled FROM targets WHERE id=:tid"),
            {"tid": target_id},
        ).fetchone()

        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        if not bool(target._mapping.get("tls_checks_enabled")):
            raise HTTPException(
                status_code=400,
                detail="TLS checks are disabled for this target.",
            )

        task = celery_client.send_task("worker.run_scan", args=[str(target_id)])
        return {
            "status": "queued",
            "target_id": str(target_id),
            "task_id": task.id,
        }
    finally:
        db.close()


@app.post("/auth/token")
def login(
    request: Request, form_data: OAuth2PasswordRequestForm = Depends()
):
    username = (form_data.username or "").strip()
    password = form_data.password or ""
    if not username or not password:
        raise HTTPException(status_code=400, detail="username and password are required")

    db = SessionLocal()
    try:
        ensure_auth_config_table(db)
        auth_cfg = read_auth_config(db)
        active_method = str(auth_cfg.get("active_method") or DEFAULT_AUTH_METHOD)

        _check_login_rate_limit(request, username)
        if active_method == "oidc":
            _record_login_failure(request, username)
            raise HTTPException(
                status_code=400,
                detail="Password login is disabled. Use OpenID login.",
            )

        if active_method == "local":
            user = db.execute(
                text("SELECT * FROM users WHERE username=:u"),
                {"u": username},
            ).fetchone()
            if not user or not verify_password(password, user.password_hash):
                _record_login_failure(request, username)
                raise HTTPException(status_code=401, detail="Invalid credentials")
            token = _issue_token_for_active_username(db, username)
        elif active_method == "ldap":
            if not bool(auth_cfg.get("ldap_enabled")):
                _record_login_failure(request, username)
                raise HTTPException(status_code=400, detail="LDAP login is disabled")
            _authenticate_ldap_username_password(auth_cfg, username, password)
            token = _issue_token_for_active_username(db, username)
        else:
            _record_login_failure(request, username)
            raise HTTPException(status_code=500, detail="Unsupported auth method")

        _clear_login_failures(request, username)
        return {"access_token": token, "token_type": "bearer"}
    finally:
        db.close()


@app.get("/admin/users")
def list_users(user=Depends(get_current_admin)):
    db = SessionLocal()
    try:
        ensure_users_table(db)
        rows = db.execute(
            text(
                """
                SELECT id, username, name, surname, email, is_active, is_admin
                FROM users
                ORDER BY username ASC
                """
            )
        ).fetchall()
        return [dict(r._mapping) for r in rows]
    finally:
        db.close()


@app.get("/admin/event-logs")
def list_event_logs(
    limit: int = EVENT_LOG_DEFAULT_LIMIT,
    offset: int = 0,
    level: str = "",
    user=Depends(get_current_admin),
):
    db = SessionLocal()
    try:
        prune_event_logs_retention(db)
        safe_limit = max(1, min(int(limit or EVENT_LOG_DEFAULT_LIMIT), 500))
        safe_offset = max(0, int(offset or 0))
        level_value = str(level or "").strip().lower()
        level_filter = None
        if level_value not in ("", "all"):
            level_filter = _validate_event_log_level(level_value)

        if level_filter is None:
            total_row = db.execute(
                text(
                    """
                    SELECT COUNT(*) AS total
                    FROM event_logs
                    """
                )
            ).fetchone()
            rows = db.execute(
                text(
                    """
                    SELECT id, created_at, username, source, level, message
                    FROM event_logs
                    ORDER BY created_at DESC
                    LIMIT :limit OFFSET :offset
                    """
                ),
                {
                    "limit": safe_limit,
                    "offset": safe_offset,
                },
            ).fetchall()
        else:
            total_row = db.execute(
                text(
                    """
                    SELECT COUNT(*) AS total
                    FROM event_logs
                    WHERE level = :level
                    """
                ),
                {"level": level_filter},
            ).fetchone()
            rows = db.execute(
                text(
                    """
                    SELECT id, created_at, username, source, level, message
                    FROM event_logs
                    WHERE level = :level
                    ORDER BY created_at DESC
                    LIMIT :limit OFFSET :offset
                    """
                ),
                {
                    "level": level_filter,
                    "limit": safe_limit,
                    "offset": safe_offset,
                },
            ).fetchall()
        total = int(total_row._mapping["total"]) if total_row else 0
        return {"items": [dict(r._mapping) for r in rows], "total": total}
    finally:
        db.close()


@app.post("/admin/event-logs")
def create_event_log(payload: EventLogCreate, user=Depends(get_current_admin)):
    message = (payload.message or "").strip()
    if not message:
        raise HTTPException(status_code=400, detail="message is required")

    db = SessionLocal()
    try:
        db.execute(
            text(
                """
                INSERT INTO event_logs (username, source, level, message)
                VALUES (:u, :s, :l, :m)
                """
            ),
            {
                "u": str(user.get("username") or ""),
                "s": str(payload.source or "ui").strip()[:50],
                "l": _validate_event_log_level(payload.level or "info"),
                "m": message[:4000],
            },
        )
        db.commit()
        return {"status": "created"}
    finally:
        db.close()


@app.post("/admin/users")
def create_user(payload: UserCreate, user=Depends(get_current_admin)):
    db = SessionLocal()
    try:
        ensure_users_table(db)
        username = (payload.username or "").strip()
        _validate_new_user_credentials(username, payload.password)
        existing = db.execute(
            text("SELECT id FROM users WHERE username=:u"),
            {"u": username},
        ).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail="User already exists")

        db.execute(
            text(
                """
                INSERT INTO users
                (username, password_hash, is_active, is_admin, name, surname, email)
                VALUES (:u, :p, :a, :admin, :n, :s, :e)
                """
            ),
            {
                "u": username,
                "p": hash_password(payload.password),
                "a": bool(payload.is_active),
                "admin": bool(payload.is_admin),
                "n": payload.name.strip(),
                "s": payload.surname.strip(),
                "e": payload.email.strip(),
            },
        )
        db.commit()
        return {"status": "created"}
    finally:
        db.close()


@app.put("/admin/users/{user_id}")
def update_user(
    user_id: UUID, payload: UserUpdate, user=Depends(get_current_admin)
):
    db = SessionLocal()
    try:
        ensure_users_table(db)
        row = db.execute(
            text("SELECT id, username, is_admin FROM users WHERE id=:id"),
            {"id": user_id},
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        target_username = str(row._mapping.get("username") or "")
        target_is_admin = bool(row._mapping.get("is_admin"))
        requested_is_admin = bool(payload.is_admin)
        if (
            target_username == str(user.get("username") or "")
            and target_is_admin
            and not requested_is_admin
        ):
            raise HTTPException(
                status_code=400,
                detail="Cannot remove your own admin role",
            )

        db.execute(
            text(
                """
                UPDATE users
                SET name=:n,
                    surname=:s,
                    email=:e,
                    is_active=:a,
                    is_admin=:admin
                WHERE id=:id
                """
            ),
            {
                "id": user_id,
                "n": payload.name.strip(),
                "s": payload.surname.strip(),
                "e": payload.email.strip(),
                "a": bool(payload.is_active),
                "admin": requested_is_admin,
            },
        )
        db.commit()
        return {"status": "updated", "user_id": str(user_id)}
    finally:
        db.close()


@app.post("/admin/targets/import-csv")
async def import_targets_csv(
    file: UploadFile = File(...), user=Depends(get_current_admin)
):
    csv_bytes = await file.read()
    if not csv_bytes:
        raise HTTPException(status_code=400, detail="CSV file is empty.")

    parsed = _parse_targets_csv(csv_bytes)
    parsed_rows = parsed["parsed_rows"]
    candidates = parsed["candidates"]
    file_duplicates = parsed["file_duplicates"]
    invalid_rows = parsed["invalid_rows"]

    if parsed_rows == 0:
        raise HTTPException(
            status_code=400,
            detail="CSV file is empty. Add rows like hostname,port (no header).",
        )

    db = SessionLocal()
    try:
        ensure_targets_check_columns(db)
        existing_rows = db.execute(
            text("SELECT hostname, port FROM targets")
        ).fetchall()
        existing_keys = {
            (
                str(r._mapping["hostname"] or "").strip().lower(),
                int(r._mapping["port"]),
            )
            for r in existing_rows
        }

        to_insert = []
        already_in_db = 0
        for item in candidates:
            key = (item["hostname"].lower(), int(item["port"]))
            if key in existing_keys:
                already_in_db += 1
                continue
            to_insert.append(item)
            existing_keys.add(key)

        inserted_target_ids = []
        for item in to_insert:
            row = db.execute(
                text(
                    """
                    INSERT INTO targets (hostname, port, dns_checks_enabled, tls_checks_enabled)
                    VALUES (:h, :p, TRUE, TRUE)
                    RETURNING id
                    """
                ),
                {"h": item["hostname"], "p": item["port"]},
            ).fetchone()
            if row:
                inserted_target_ids.append(str(row._mapping["id"]))

        db.commit()

        for target_id in inserted_target_ids:
            celery_client.send_task("worker.run_dns_lookup", args=[target_id])

        return {
            "status": "ok",
            "parsed_rows": parsed_rows,
            "added": len(inserted_target_ids),
            "already_in_db": already_in_db,
            "duplicates_in_file": file_duplicates,
            "invalid_rows_count": len(invalid_rows),
            "invalid_rows": invalid_rows[:20],
            "note": "CSV must not contain a header row.",
        }
    finally:
        db.close()


@app.delete("/admin/users/{user_id}")
def delete_user(user_id: UUID, user=Depends(get_current_admin)):
    db = SessionLocal()
    try:
        ensure_users_table(db)
        row = db.execute(
            text("SELECT id, username FROM users WHERE id=:id"),
            {"id": user_id},
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")

        username = str(row._mapping["username"] or "")
        current_username = str(user.get("username") or "")
        if username == current_username:
            raise HTTPException(
                status_code=400,
                detail="Cannot delete currently logged-in user",
            )

        db.execute(
            text("DELETE FROM users WHERE id=:id"),
            {"id": user_id},
        )
        db.commit()
        return {"status": "deleted", "user_id": str(user_id)}
    finally:
        db.close()


@app.get("/dashboard/summary")
def dashboard_summary(user=Depends(get_current_user)):
    db = SessionLocal()
    try:
        ensure_targets_check_columns(db)
        counts = db.execute(
            text(
                """
                WITH mail AS (
                  SELECT
                    t.id,
                    COALESCE(d.data, '{}'::jsonb) AS data
                  FROM targets t
                  LEFT JOIN target_dns d ON d.target_id = t.id
                  WHERE t.enabled = true
                    AND t.dns_checks_enabled = true
                ),
                mail_norm AS (
                  SELECT
                    id,
                    lower(trim(COALESCE(data->>'spf', ''))) AS spf,
                    lower(trim(COALESCE(data->'dmarc'->>'policy', ''))) AS dmarc_policy,
                    COALESCE(jsonb_array_length(COALESCE(data->'dkim'->'records', '[]'::jsonb)), 0) AS dkim_records_count,
                    COALESCE(jsonb_array_length(COALESCE(data->'mx', '[]'::jsonb)), 0) > 0 AS has_mx,
                    COALESCE(jsonb_array_length(COALESCE(data->'a', '[]'::jsonb)), 0) > 0 AS has_a,
                    COALESCE(jsonb_array_length(COALESCE(data->'aaaa', '[]'::jsonb)), 0) > 0 AS has_aaaa
                  FROM mail
                )
                SELECT
                  (SELECT COUNT(*) FROM targets) AS targets_total,
                  (SELECT COUNT(*) FROM targets WHERE enabled=true) AS targets_enabled,
                  (SELECT COUNT(*) FROM scans) AS scans_total,
                  (SELECT COUNT(*) FROM scans WHERE status='running') AS scans_running,
                  (SELECT COUNT(*) FROM scan_results) AS results_total,
                  (SELECT COUNT(*) FROM scan_diffs) AS diffs_total,
                  (SELECT MAX(finished_at) FROM scans) AS last_scan_finished_at,
                  (SELECT COUNT(*) FROM mail_norm) AS mail_targets_total,
                  (SELECT COUNT(*) FROM mail_norm WHERE spf LIKE '%-all') AS mail_spf_strict,
                  (SELECT COUNT(*) FROM mail_norm WHERE dmarc_policy IN ('reject', 'quarantine')) AS mail_dmarc_enforced,
                  (SELECT COUNT(*) FROM mail_norm WHERE dkim_records_count > 0) AS mail_dkim_present,
                  (
                    SELECT COUNT(*)
                    FROM mail_norm
                    WHERE (NOT (spf LIKE '%-all'))
                      AND dmarc_policy IN ('', 'none')
                      AND (has_mx OR has_a OR has_aaaa)
                  ) AS mail_spoofable
                """
            )
        ).fetchone()
        return dict(counts._mapping)
    finally:
        db.close()


@app.get("/config/proxy")
def get_proxy_config(user=Depends(get_current_admin)):
    db = SessionLocal()
    try:
        return read_proxy_config(db)
    finally:
        db.close()


@app.put("/config/proxy")
def update_proxy_config(
    payload: ProxyConfigUpdate, user=Depends(get_current_admin)
):
    db = SessionLocal()
    try:
        ensure_proxy_config_table(db)
        current = db.execute(
            text(
                """
                SELECT password FROM proxy_config
                WHERE id = 1
                """
            )
        ).fetchone()
        current_password = current._mapping["password"] if current else ""
        new_password = (
            payload.password
            if payload.password not in (None, "")
            else current_password
        )

        db.execute(
            text(
                """
                UPDATE proxy_config
                SET enabled=:enabled,
                    host=:host,
                    port=:port,
                    username=:username,
                    password=:password,
                    no_proxy_patterns=:no_proxy_patterns,
                    updated_at=now()
                WHERE id = 1
                """
            ),
            {
                "enabled": payload.enabled,
                "host": payload.host.strip(),
                "port": payload.port,
                "username": payload.username.strip(),
                "password": new_password,
                "no_proxy_patterns": payload.no_proxy_patterns.strip(),
            },
        )
        db.commit()
        return read_proxy_config(db)
    finally:
        db.close()


@app.get("/config/scheduler")
def get_scheduler_config(user=Depends(get_current_admin)):
    db = SessionLocal()
    try:
        return read_scheduler_config(db)
    finally:
        db.close()


@app.put("/config/scheduler")
def update_scheduler_config(
    payload: SchedulerConfigUpdate, user=Depends(get_current_admin)
):
    allowed_frequencies = {"hourly", "daily", "weekly", "interval"}
    frequency = (payload.frequency or "").strip().lower()
    if frequency not in allowed_frequencies:
        raise HTTPException(
            status_code=400,
            detail="frequency must be one of: hourly, daily, weekly, interval",
        )

    if payload.day_of_week < 0 or payload.day_of_week > 6:
        raise HTTPException(status_code=400, detail="day_of_week must be 0-6")
    if payload.hour < 0 or payload.hour > 23:
        raise HTTPException(status_code=400, detail="hour must be 0-23")
    if payload.minute < 0 or payload.minute > 59:
        raise HTTPException(status_code=400, detail="minute must be 0-59")
    if payload.interval_minutes < 1 or payload.interval_minutes > 10080:
        raise HTTPException(
            status_code=400,
            detail="interval_minutes must be between 1 and 10080",
        )

    db = SessionLocal()
    try:
        ensure_scheduler_config_table(db)
        db.execute(
            text(
                """
                UPDATE scheduler_config
                SET enabled=:enabled,
                    frequency=:frequency,
                    day_of_week=:day_of_week,
                    hour=:hour,
                    minute=:minute,
                    interval_minutes=:interval_minutes,
                    updated_at=now()
                WHERE id = 1
                """
            ),
            {
                "enabled": bool(payload.enabled),
                "frequency": frequency,
                "day_of_week": int(payload.day_of_week),
                "hour": int(payload.hour),
                "minute": int(payload.minute),
                "interval_minutes": int(payload.interval_minutes),
            },
        )
        db.commit()
        return read_scheduler_config(db)
    finally:
        db.close()


@app.get("/config/auth")
def get_auth_config(user=Depends(get_current_admin)):
    db = SessionLocal()
    try:
        data = read_auth_config(db)
        return {
            "active_method": data["active_method"],
            "oidc_enabled": data["oidc_enabled"],
            "oidc_issuer_url": data["oidc_issuer_url"],
            "oidc_client_id": data["oidc_client_id"],
            "oidc_has_client_secret": data["oidc_has_client_secret"],
            "oidc_redirect_uri": data["oidc_redirect_uri"],
            "oidc_ui_redirect_uri": data["oidc_ui_redirect_uri"],
            "oidc_scopes": data["oidc_scopes"],
            "oidc_username_claim": data["oidc_username_claim"],
            "ldap_enabled": data["ldap_enabled"],
            "ldap_host": data["ldap_host"],
            "ldap_port": data["ldap_port"],
            "ldap_use_ssl": data["ldap_use_ssl"],
            "ldap_validate_cert": data["ldap_validate_cert"],
            "ldap_bind_dn": data["ldap_bind_dn"],
            "ldap_has_bind_password": data["ldap_has_bind_password"],
            "ldap_user_base_dn": data["ldap_user_base_dn"],
            "ldap_user_filter": data["ldap_user_filter"],
            "updated_at": data.get("updated_at"),
        }
    finally:
        db.close()


@app.put("/config/auth")
def update_auth_config(payload: AuthConfigUpdate, user=Depends(get_current_admin)):
    active_method = str(payload.active_method or DEFAULT_AUTH_METHOD).strip().lower()
    if active_method not in AUTH_METHODS:
        raise HTTPException(
            status_code=400,
            detail="active_method must be one of: local, oidc, ldap",
        )

    oidc_issuer_url = str(payload.oidc_issuer_url or "").strip()
    oidc_client_id = str(payload.oidc_client_id or "").strip()
    oidc_redirect_uri = str(
        payload.oidc_redirect_uri or OIDC_REDIRECT_URI_DEFAULT
    ).strip()
    oidc_ui_redirect_uri = str(
        payload.oidc_ui_redirect_uri or OIDC_UI_REDIRECT_URI_DEFAULT
    ).strip()
    oidc_scopes = str(payload.oidc_scopes or OIDC_SCOPES_DEFAULT).strip()
    oidc_username_claim = str(
        payload.oidc_username_claim or OIDC_USERNAME_CLAIM_DEFAULT
    ).strip()

    ldap_host = str(payload.ldap_host or "").strip()
    ldap_bind_dn = str(payload.ldap_bind_dn or "").strip()
    ldap_user_base_dn = str(payload.ldap_user_base_dn or "").strip()
    ldap_user_filter = str(payload.ldap_user_filter or "(uid={username})").strip()
    ldap_port = int(payload.ldap_port or 636)
    ldap_enabled = bool(payload.ldap_enabled)
    oidc_enabled = bool(payload.oidc_enabled)

    if ldap_port < 1 or ldap_port > 65535:
        raise HTTPException(status_code=400, detail="ldap_port must be 1-65535")
    if "{username}" not in ldap_user_filter:
        raise HTTPException(
            status_code=400,
            detail="ldap_user_filter must include {username}",
        )
    if active_method == "oidc":
        if not oidc_enabled:
            raise HTTPException(
                status_code=400,
                detail="oidc_enabled must be true when active_method=oidc",
            )
        if not oidc_issuer_url or not oidc_client_id:
            raise HTTPException(
                status_code=400,
                detail="oidc_issuer_url and oidc_client_id are required for OIDC",
            )
    if active_method == "ldap":
        if not ldap_enabled:
            raise HTTPException(
                status_code=400,
                detail="ldap_enabled must be true when active_method=ldap",
            )
        if not ldap_host or not ldap_user_base_dn:
            raise HTTPException(
                status_code=400,
                detail="ldap_host and ldap_user_base_dn are required for LDAP",
            )

    db = SessionLocal()
    try:
        ensure_auth_config_table(db)
        current = read_auth_config(db)

        oidc_client_secret = (
            str(payload.oidc_client_secret or "")
            if payload.oidc_client_secret not in (None, "")
            else str(current.get("oidc_client_secret") or "")
        )
        ldap_bind_password = (
            str(payload.ldap_bind_password or "")
            if payload.ldap_bind_password not in (None, "")
            else str(current.get("ldap_bind_password") or "")
        )

        db.execute(
            text(
                """
                UPDATE auth_config
                SET active_method=:active_method,
                    oidc_enabled=:oidc_enabled,
                    oidc_issuer_url=:oidc_issuer_url,
                    oidc_client_id=:oidc_client_id,
                    oidc_client_secret=:oidc_client_secret,
                    oidc_redirect_uri=:oidc_redirect_uri,
                    oidc_ui_redirect_uri=:oidc_ui_redirect_uri,
                    oidc_scopes=:oidc_scopes,
                    oidc_username_claim=:oidc_username_claim,
                    ldap_enabled=:ldap_enabled,
                    ldap_host=:ldap_host,
                    ldap_port=:ldap_port,
                    ldap_use_ssl=:ldap_use_ssl,
                    ldap_validate_cert=:ldap_validate_cert,
                    ldap_bind_dn=:ldap_bind_dn,
                    ldap_bind_password=:ldap_bind_password,
                    ldap_user_base_dn=:ldap_user_base_dn,
                    ldap_user_filter=:ldap_user_filter,
                    updated_at=now()
                WHERE id=1
                """
            ),
            {
                "active_method": active_method,
                "oidc_enabled": oidc_enabled,
                "oidc_issuer_url": oidc_issuer_url,
                "oidc_client_id": oidc_client_id,
                "oidc_client_secret": oidc_client_secret,
                "oidc_redirect_uri": oidc_redirect_uri,
                "oidc_ui_redirect_uri": oidc_ui_redirect_uri,
                "oidc_scopes": oidc_scopes,
                "oidc_username_claim": oidc_username_claim,
                "ldap_enabled": ldap_enabled,
                "ldap_host": ldap_host,
                "ldap_port": ldap_port,
                "ldap_use_ssl": bool(payload.ldap_use_ssl),
                "ldap_validate_cert": bool(payload.ldap_validate_cert),
                "ldap_bind_dn": ldap_bind_dn,
                "ldap_bind_password": ldap_bind_password,
                "ldap_user_base_dn": ldap_user_base_dn,
                "ldap_user_filter": ldap_user_filter,
            },
        )
        db.commit()
        OIDC_DISCOVERY_CACHE["data"] = None
        OIDC_DISCOVERY_CACHE["expires_at"] = 0.0
        OIDC_JWKS_CACHE["keys"] = []
        OIDC_JWKS_CACHE["expires_at"] = 0.0
        return get_auth_config(user)
    finally:
        db.close()


def _looks_like_email(value: str) -> bool:
    text_value = (value or "").strip()
    return "@" in text_value and "." in text_value.split("@", 1)[-1]


@app.get("/config/smtp")
def get_smtp_config(user=Depends(get_current_admin)):
    db = SessionLocal()
    try:
        return read_smtp_config(db)
    finally:
        db.close()


@app.put("/config/smtp")
def update_smtp_config(payload: SmtpConfigUpdate, user=Depends(get_current_admin)):
    host = (payload.host or "").strip()
    from_address = (payload.from_address or "").strip()
    recipient = (payload.recipient or "").strip()
    reply_to = (payload.reply_to or "").strip()
    subject_template = (payload.subject_template or "").strip() or "{finding_name}"

    if payload.port < 1 or payload.port > 65535:
        raise HTTPException(status_code=400, detail="port must be 1-65535")
    if payload.timeout_seconds < 3 or payload.timeout_seconds > 120:
        raise HTTPException(
            status_code=400, detail="timeout_seconds must be 3-120"
        )
    if not host:
        raise HTTPException(status_code=400, detail="host is required")
    if not from_address or not recipient or not reply_to:
        raise HTTPException(
            status_code=400,
            detail="from_address, recipient, and reply_to are required",
        )
    if not _looks_like_email(from_address):
        raise HTTPException(status_code=400, detail="from_address is invalid")
    if not _looks_like_email(recipient):
        raise HTTPException(status_code=400, detail="recipient is invalid")
    if not _looks_like_email(reply_to):
        raise HTTPException(status_code=400, detail="reply_to is invalid")

    db = SessionLocal()
    try:
        ensure_smtp_config_table(db)
        current = db.execute(
            text(
                """
                SELECT password FROM smtp_config
                WHERE id = 1
                """
            )
        ).fetchone()
        current_password = current._mapping["password"] if current else ""
        new_password = (
            payload.password
            if payload.password not in (None, "")
            else current_password
        )

        if payload.use_auth and not (payload.username or "").strip():
            raise HTTPException(
                status_code=400, detail="username is required when use_auth=true"
            )
        if payload.use_auth and not new_password:
            raise HTTPException(
                status_code=400, detail="password is required when use_auth=true"
            )

        db.execute(
            text(
                """
                UPDATE smtp_config
                SET enabled=:enabled,
                    host=:host,
                    port=:port,
                    use_starttls=:use_starttls,
                    use_auth=:use_auth,
                    username=:username,
                    password=:password,
                    from_address=:from_address,
                    recipient=:recipient,
                    reply_to=:reply_to,
                    subject_template=:subject_template,
                    timeout_seconds=:timeout_seconds,
                    updated_at=now()
                WHERE id = 1
                """
            ),
            {
                "enabled": bool(payload.enabled),
                "host": host,
                "port": int(payload.port),
                "use_starttls": bool(payload.use_starttls),
                "use_auth": bool(payload.use_auth),
                "username": (payload.username or "").strip(),
                "password": new_password,
                "from_address": from_address,
                "recipient": recipient,
                "reply_to": reply_to,
                "subject_template": subject_template,
                "timeout_seconds": int(payload.timeout_seconds),
            },
        )
        db.commit()
        return read_smtp_config(db)
    finally:
        db.close()


@app.get("/config/dkim")
def get_dkim_config(user=Depends(get_current_admin)):
    db = SessionLocal()
    try:
        return read_dkim_config(db)
    finally:
        db.close()


@app.put("/config/dkim")
def update_dkim_config(
    payload: DkimConfigUpdate, user=Depends(get_current_admin)
):
    selectors = _normalize_dkim_selector_text(payload.selectors_text or "")
    db = SessionLocal()
    try:
        ensure_dkim_config_table(db)
        db.execute(
            text(
                """
                UPDATE dkim_config
                SET selectors_text=:selectors_text,
                    updated_at=now()
                WHERE id = 1
                """
            ),
            {"selectors_text": "\n".join(selectors)},
        )
        db.commit()
        return read_dkim_config(db)
    finally:
        db.close()


@app.get("/config/checks")
def get_checks_config(user=Depends(get_current_admin)):
    db = SessionLocal()
    try:
        return read_checks_config(db)
    finally:
        db.close()


@app.put("/config/checks")
def update_checks_config(
    payload: ChecksConfigUpdate, user=Depends(get_current_admin)
):
    enabled_reports = _normalize_checks_enabled_reports(payload.enabled_reports)
    severity_overrides = _normalize_checks_severity_overrides(payload.severity_overrides)
    thresholds = _normalize_checks_thresholds(payload.thresholds)
    db = SessionLocal()
    try:
        ensure_checks_config_table(db)
        db.execute(
            text(
                """
                UPDATE checks_config
                SET enabled_reports_json=:enabled_reports_json,
                    severity_overrides_json=:severity_overrides_json,
                    thresholds_json=:thresholds_json,
                    updated_at=now()
                WHERE id = 1
                """
            ),
            {
                "enabled_reports_json": json.dumps(enabled_reports),
                "severity_overrides_json": json.dumps(severity_overrides),
                "thresholds_json": json.dumps(thresholds),
            },
        )
        db.commit()
        return read_checks_config(db)
    finally:
        db.close()


def _purge_jobs_data(db):
    results_row = db.execute(
        text("SELECT COUNT(*) AS c FROM scan_results")
    ).fetchone()
    diffs_row = db.execute(
        text("SELECT COUNT(*) AS c FROM scan_diffs")
    ).fetchone()
    scans_row = db.execute(
        text("SELECT COUNT(*) AS c FROM scans")
    ).fetchone()

    deleted_results = int(results_row._mapping["c"]) if results_row else 0
    deleted_diffs = int(diffs_row._mapping["c"]) if diffs_row else 0
    deleted_scans = int(scans_row._mapping["c"]) if scans_row else 0

    db.execute(text("DELETE FROM scan_results"))
    db.execute(text("DELETE FROM scan_diffs"))
    db.execute(text("DELETE FROM scans"))
    db.commit()

    return {
        "deleted_scans": deleted_scans,
        "deleted_results": deleted_results,
        "deleted_diffs": deleted_diffs,
    }


def _latest_completed_scans(db):
    rows = db.execute(
        text(
            """
            SELECT DISTINCT ON (s.target_id)
              s.id AS scan_id,
              s.target_id,
              t.hostname,
              t.port,
              COALESCE(s.finished_at, s.started_at) AS scan_timestamp_utc
            FROM scans s
            JOIN targets t ON t.id = s.target_id
            WHERE s.status IN ('completed', 'done')
              AND t.enabled = true
              AND t.tls_checks_enabled = true
            ORDER BY
              s.target_id,
              s.finished_at DESC NULLS LAST,
              s.started_at DESC NULLS LAST
            """
        )
    ).fetchall()
    return [dict(r._mapping) for r in rows]


def _load_results_for_scans(db, scan_ids: list[str], plugins: list[str]):
    if not scan_ids:
        return {}

    rows = db.execute(
        text(
            """
            SELECT scan_id, plugin, result
            FROM scan_results
            WHERE scan_id = ANY(CAST(:scan_ids AS uuid[]))
              AND plugin = ANY(:plugins)
            """
        ),
        {"scan_ids": scan_ids, "plugins": plugins},
    ).fetchall()

    grouped = {}
    for row in rows:
        data = dict(row._mapping)
        scan_id = str(data["scan_id"])
        grouped.setdefault(scan_id, {})
        grouped[scan_id][data["plugin"]] = data["result"] or {}
    return grouped


def _coerce_support_flag(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes", "y"}:
            return True
        if lowered in {"false", "0", "no", "n", ""}:
            return False
    return False


def _extract_hsts_issues(headers: dict, min_max_age: int = 31536000) -> list[str]:
    issues = []
    hsts = (headers or {}).get("strict_transport_security") or {}
    if not hsts:
        return ["hsts missing"]
    max_age = int(hsts.get("max_age") or 0)
    if max_age < int(min_max_age):
        issues.append(f"hsts max-age too low ({max_age}; expected>={int(min_max_age)})")
    if not bool(hsts.get("include_subdomains")):
        issues.append("hsts includeSubDomains missing")
    if not bool(hsts.get("preload")):
        issues.append("hsts preload missing")
    return issues


def _probe_http_to_https_redirect(hostname: str, timeout_seconds: float = 4.0):
    host = str(hostname or "").strip()
    if not host:
        return False, "empty hostname"
    if _is_ip_address(host):
        return False, "ip target (redirect check skipped)"
    url = f"http://{host}/"
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "TLSAuditHub/1.0"},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
            final_url = str(response.geturl() or "")
            if final_url.lower().startswith("https://"):
                return True, f"redirects to {final_url}"
            return False, f"final_url={final_url or url}"
    except Exception as exc:
        return False, f"redirect probe failed: {exc.__class__.__name__}"


def _parse_iso_utc(value):
    text_value = str(value or "").strip()
    if not text_value:
        return None
    try:
        parsed = datetime.fromisoformat(text_value)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return None


def _extract_cert_near_expiry_issue(cert_info: dict, days: int = 30) -> str:
    certs = (cert_info or {}).get("certificate_chain") or []
    if not certs:
        return "certificate info missing"
    leaf = certs[0] or {}
    not_after = _parse_iso_utc(leaf.get("not_after"))
    if not not_after:
        return "certificate not_after unavailable"
    now = datetime.now(timezone.utc)
    remaining = (not_after - now).total_seconds()
    if remaining < 0:
        return f"certificate expired ({leaf.get('not_after')})"
    remaining_days = int(remaining // 86400)
    if remaining_days <= days:
        return f"certificate expires soon ({remaining_days} days)"
    return ""


def _normalize_dns_name(value: str) -> str:
    return str(value or "").strip().lower().rstrip(".")


def _extract_leaf_cn(cert_info: dict) -> str:
    certs = (cert_info or {}).get("certificate_chain") or []
    if not certs:
        return ""
    subject = str((certs[0] or {}).get("subject") or "")
    if not subject:
        return ""
    match = re.search(r"(?:^|,)CN=([^,]+)", subject, flags=re.IGNORECASE)
    if not match:
        return ""
    return _normalize_dns_name(match.group(1))


def _extract_leaf_san_dns(cert_info: dict) -> list[str]:
    certs = (cert_info or {}).get("certificate_chain") or []
    if not certs:
        return []
    sans = (certs[0] or {}).get("subject_alternative_name") or []
    if not isinstance(sans, list):
        return []
    out = []
    seen = set()
    for item in sans:
        name = _normalize_dns_name(str(item or ""))
        if not name or name in seen:
            continue
        seen.add(name)
        out.append(name)
    return out


def _dns_name_matches_host(pattern: str, hostname: str) -> bool:
    pat = _normalize_dns_name(pattern)
    host = _normalize_dns_name(hostname)
    if not pat or not host:
        return False
    if "*" not in pat:
        return pat == host
    # RFC-style wildcard: only single wildcard label at left-most position.
    if not pat.startswith("*.") or pat.count("*") != 1:
        return False
    suffix = pat[2:]
    if not suffix or not host.endswith("." + suffix):
        return False
    host_labels = host.split(".")
    suffix_labels = suffix.split(".")
    return len(host_labels) == len(suffix_labels) + 1


def _extract_cert_name_issues(hostname: str, cert_info: dict) -> list[str]:
    host = _normalize_dns_name(hostname)
    if not host:
        return ["certificate hostname validation unavailable (empty hostname)"]
    try:
        ipaddress.ip_address(host)
        # Current certificate payload stores DNS SAN only; skip IP match checks.
        return []
    except ValueError:
        pass

    san_names = _extract_leaf_san_dns(cert_info)
    cn_name = _extract_leaf_cn(cert_info)
    candidate_names = san_names if san_names else ([cn_name] if cn_name else [])
    issues = []
    if not candidate_names:
        issues.append("certificate SAN/CN unavailable for hostname validation")
        return issues
    if not any(_dns_name_matches_host(name, host) for name in candidate_names):
        shown = ", ".join(candidate_names[:5]) if candidate_names else "(none)"
        if len(candidate_names) > 5:
            shown += f", ... +{len(candidate_names) - 5} more"
        issues.append(
            f"certificate SAN/CN mismatch for {host} (present: {shown})"
        )

    wildcard_names = [name for name in candidate_names if "*" in name]
    if wildcard_names:
        shown = ", ".join(wildcard_names[:5])
        if len(wildcard_names) > 5:
            shown += f", ... +{len(wildcard_names) - 5} more"
        issues.append(f"wildcard certificate in use ({shown})")
    return issues


def _looks_weak_cipher_name(cipher_name: str) -> bool:
    value = str(cipher_name or "").upper()
    weak_tokens = [
        "RC4",
        "3DES",
        "DES",
        "NULL",
        "MD5",
        "EXPORT",
        "ANON",
        "IDEA",
        "SEED",
        "PSK",
    ]
    return any(token in value for token in weak_tokens)


def _has_forward_secrecy(cipher_names: list[str]) -> bool:
    for cipher in cipher_names:
        upper = str(cipher or "").upper()
        if "ECDHE" in upper or ("DHE" in upper and "PSK" not in upper):
            return True
    return False


def _is_pqc_group_name(group_name: str) -> bool:
    value = str(group_name or "").upper()
    if not value:
        return False
    tokens = (
        "MLKEM",
        "KYBER",
        "FRODOKEM",
        "BIKE",
        "HQC",
        "NTRU",
    )
    return any(token in value for token in tokens)


def _build_no_tls13_items(db):
    latest = _latest_completed_scans(db)
    by_scan = _load_results_for_scans(
        db,
        [str(item["scan_id"]) for item in latest],
        ["tls_1_3_cipher_suites"],
    )
    report = REPORT_DEFINITIONS["no_tls13"]
    items = []
    for row in latest:
        scan_id = str(row["scan_id"])
        tls13 = (by_scan.get(scan_id) or {}).get("tls_1_3_cipher_suites") or {}
        is_supported = _coerce_support_flag(
            tls13.get("is_protocol_supported", tls13.get("is_tls_version_supported"))
        )
        if is_supported:
            continue
        accepted = tls13.get("accepted_cipher_suites") or []
        proof = (
            f"tls_1_3_cipher_suites.is_protocol_supported={is_supported}; "
            f"accepted_cipher_suites={len(accepted)}"
        )
        items.append(
            {
                "target_id": str(row["target_id"]),
                "host_target": f'{row["hostname"]}:{row["port"]}',
                "finding_id": report["finding_id"],
                "severity": report["severity"],
                "finding_proof": proof,
                "scan_timestamp_utc": row["scan_timestamp_utc"],
            }
        )
    return items


def _build_legacy_ssl_items(db):
    latest = _latest_completed_scans(db)
    by_scan = _load_results_for_scans(
        db,
        [str(item["scan_id"]) for item in latest],
        ["ssl_2_0_cipher_suites", "ssl_3_0_cipher_suites"],
    )
    report = REPORT_DEFINITIONS["legacy_ssl_enabled"]
    items = []
    for row in latest:
        scan_id = str(row["scan_id"])
        scan_results = by_scan.get(scan_id) or {}
        ssl2 = scan_results.get("ssl_2_0_cipher_suites") or {}
        ssl3 = scan_results.get("ssl_3_0_cipher_suites") or {}
        ssl2_supported = bool(ssl2.get("is_protocol_supported"))
        ssl3_supported = bool(ssl3.get("is_protocol_supported"))
        if not ssl2_supported and not ssl3_supported:
            continue
        ssl2_count = len(ssl2.get("accepted_cipher_suites") or [])
        ssl3_count = len(ssl3.get("accepted_cipher_suites") or [])
        proof = (
            f"ssl2_supported={ssl2_supported} (accepted={ssl2_count}); "
            f"ssl3_supported={ssl3_supported} (accepted={ssl3_count})"
        )
        items.append(
            {
                "target_id": str(row["target_id"]),
                "host_target": f'{row["hostname"]}:{row["port"]}',
                "finding_id": report["finding_id"],
                "severity": report["severity"],
                "finding_proof": proof,
                "scan_timestamp_utc": row["scan_timestamp_utc"],
            }
        )
    return items


def _build_pqc_non_compliant_items(db):
    latest = _latest_completed_scans(db)
    by_scan = _load_results_for_scans(
        db,
        [str(item["scan_id"]) for item in latest],
        ["elliptic_curves", "tls_1_3_cipher_suites"],
    )
    report = REPORT_DEFINITIONS["pqc_non_compliant"]
    items = []
    for row in latest:
        scan_id = str(row["scan_id"])
        scan_results = by_scan.get(scan_id) or {}
        group_scan = scan_results.get("elliptic_curves") or {}
        tls13_scan = scan_results.get("tls_1_3_cipher_suites") or {}

        raw_groups = []
        for key in (
            "supported_groups",
            "accepted_groups",
            "supported_curves",
            "accepted_curves",
            "curves",
        ):
            values = group_scan.get(key) or []
            if isinstance(values, list):
                raw_groups.extend(values)

        groups = []
        seen = set()
        for value in raw_groups:
            name = str(value or "").strip()
            if not name:
                continue
            key = name.lower()
            if key in seen:
                continue
            seen.add(key)
            groups.append(name)

        has_pqc_group = any(_is_pqc_group_name(name) for name in groups)
        if has_pqc_group:
            continue

        tls13_supported = _coerce_support_flag(
            tls13_scan.get(
                "is_protocol_supported",
                tls13_scan.get("is_tls_version_supported"),
            )
        )
        if not tls13_supported:
            reason = "TLS 1.3 is not supported"
        elif not groups:
            reason = "TLS 1.3 supported but key exchange group data is unavailable"
        else:
            reason = "no PQC-capable key exchange groups detected"
        if not groups and not tls13_supported:
            reason = "TLS 1.3 is not supported and key exchange group data is unavailable"
        groups_preview = ", ".join(groups[:8]) if groups else "(none)"
        if len(groups) > 8:
            groups_preview += f", ... +{len(groups) - 8} more"
        proof = (
            f"{reason}; tls13_supported={tls13_supported}; "
            f"supported_groups={groups_preview}"
        )
        items.append(
            {
                "target_id": str(row["target_id"]),
                "host_target": f'{row["hostname"]}:{row["port"]}',
                "finding_id": report["finding_id"],
                "severity": report["severity"],
                "finding_proof": proof,
                "scan_timestamp_utc": row["scan_timestamp_utc"],
            }
        )
    return items


def _build_spf_not_strict_items(db):
    rows = db.execute(
        text(
            """
            SELECT
              t.id AS target_id,
              t.hostname,
              t.port,
              d.data AS dns_data,
              latest.scan_timestamp_utc
            FROM targets t
            LEFT JOIN target_dns d ON d.target_id = t.id
            LEFT JOIN LATERAL (
              SELECT COALESCE(s.finished_at, s.started_at) AS scan_timestamp_utc
              FROM scans s
              WHERE s.target_id = t.id
                AND s.status IN ('completed', 'done')
              ORDER BY s.finished_at DESC NULLS LAST, s.started_at DESC NULLS LAST
              LIMIT 1
            ) latest ON TRUE
            WHERE t.enabled = true
              AND t.dns_checks_enabled = true
            ORDER BY t.hostname ASC, t.port ASC
            """
        )
    ).fetchall()
    report = REPORT_DEFINITIONS["spf_not_strict"]
    items = []
    for row in rows:
        data = dict(row._mapping)
        dns_data = data.get("dns_data") or {}
        spf = str(dns_data.get("spf") or "").strip()
        if spf and spf.lower().endswith("-all"):
            continue
        reason = (
            "spf missing"
            if not spf
            else "spf does not end with -all"
        )
        proof = f"{reason}; spf_record={spf or '(missing)'}"
        items.append(
            {
                "target_id": str(data["target_id"]),
                "host_target": f'{data["hostname"]}:{data["port"]}',
                "finding_id": report["finding_id"],
                "severity": report["severity"],
                "finding_proof": proof,
                "scan_timestamp_utc": data.get("scan_timestamp_utc"),
            }
        )
    return items


def _build_missing_hsts_items(db):
    latest = _latest_completed_scans(db)
    by_scan = _load_results_for_scans(
        db,
        [str(item["scan_id"]) for item in latest],
        ["http_headers"],
    )
    report = REPORT_DEFINITIONS["missing_hsts"]
    items = []
    for row in latest:
        scan_id = str(row["scan_id"])
        headers = (by_scan.get(scan_id) or {}).get("http_headers") or {}
        hsts = headers.get("strict_transport_security")
        if hsts:
            continue
        proof = (
            "http_headers.strict_transport_security is missing; "
            f"http_status_code={headers.get('http_status_code')}"
        )
        items.append(
            {
                "target_id": str(row["target_id"]),
                "host_target": f'{row["hostname"]}:{row["port"]}',
                "finding_id": report["finding_id"],
                "severity": report["severity"],
                "finding_proof": proof,
                "scan_timestamp_utc": row["scan_timestamp_utc"],
            }
        )
    return items


def _build_missing_dmarc_policy_items(db):
    rows = db.execute(
        text(
            """
            SELECT
              t.id AS target_id,
              t.hostname,
              t.port,
              d.data AS dns_data,
              latest.scan_timestamp_utc
            FROM targets t
            LEFT JOIN target_dns d ON d.target_id = t.id
            LEFT JOIN LATERAL (
              SELECT COALESCE(s.finished_at, s.started_at) AS scan_timestamp_utc
              FROM scans s
              WHERE s.target_id = t.id
                AND s.status IN ('completed', 'done')
              ORDER BY s.finished_at DESC NULLS LAST, s.started_at DESC NULLS LAST
              LIMIT 1
            ) latest ON TRUE
            WHERE t.enabled = true
              AND t.dns_checks_enabled = true
            ORDER BY t.hostname ASC, t.port ASC
            """
        )
    ).fetchall()
    report = REPORT_DEFINITIONS["missing_dmarc_policy"]
    items = []
    for row in rows:
        data = dict(row._mapping)
        dns_data = data.get("dns_data") or {}
        dmarc = dns_data.get("dmarc") or {}
        dmarc_record = str(dmarc.get("record") or "").strip()
        dmarc_policy = str(dmarc.get("policy") or "").strip().lower()
        missing_record = not dmarc_record
        weak_policy = dmarc_policy in {"", "none"}
        if not (missing_record or weak_policy):
            continue
        reason = "dmarc record missing" if missing_record else "dmarc policy is p=none"
        proof = (
            f"{reason}; dmarc_record={dmarc_record or '(missing)'}; "
            f"dmarc_policy={dmarc_policy or '(missing)'}"
        )
        items.append(
            {
                "target_id": str(data["target_id"]),
                "host_target": f'{data["hostname"]}:{data["port"]}',
                "finding_id": report["finding_id"],
                "severity": report["severity"],
                "finding_proof": proof,
                "scan_timestamp_utc": data.get("scan_timestamp_utc"),
            }
        )
    return items


def _build_weak_dkim_keys_items(db, checks_cfg=None):
    rows = db.execute(
        text(
            """
            SELECT
              t.id AS target_id,
              t.hostname,
              t.port,
              d.data AS dns_data,
              latest.scan_timestamp_utc
            FROM targets t
            LEFT JOIN target_dns d ON d.target_id = t.id
            LEFT JOIN LATERAL (
              SELECT COALESCE(s.finished_at, s.started_at) AS scan_timestamp_utc
              FROM scans s
              WHERE s.target_id = t.id
                AND s.status IN ('completed', 'done')
              ORDER BY s.finished_at DESC NULLS LAST, s.started_at DESC NULLS LAST
              LIMIT 1
            ) latest ON TRUE
            WHERE t.enabled = true
              AND t.dns_checks_enabled = true
            ORDER BY t.hostname ASC, t.port ASC
            """
        )
    ).fetchall()
    report = REPORT_DEFINITIONS["weak_dkim_keys"]
    thresholds = (checks_cfg or {}).get("thresholds") or {}
    min_bits = int(thresholds.get("dkim_min_rsa_bits") or 2048)
    items = []
    for row in rows:
        data = dict(row._mapping)
        dns_data = data.get("dns_data") or {}
        dkim = dns_data.get("dkim") or {}
        dkim_records = dkim.get("records") or []
        if not isinstance(dkim_records, list):
            continue
        weak_entries = []
        for entry in dkim_records:
            if not isinstance(entry, dict):
                continue
            key_type = str(entry.get("key_type") or "rsa").strip().lower()
            try:
                key_bits = int(entry.get("public_key_size_hint_bits") or 0)
            except Exception:
                key_bits = 0
            weak_hint = bool(entry.get("weak_key_hint"))
            if key_type != "rsa":
                continue
            if not weak_hint and key_bits >= min_bits:
                continue
            if key_bits <= 0:
                continue
            weak_entries.append(
                f"{entry.get('fqdn') or '-'} ({key_type},{key_bits}b)"
            )
        if not weak_entries:
            continue
        proof = (
            f"weak DKIM RSA keys detected (<{min_bits} bits): "
            + "; ".join(weak_entries[:8])
        )
        if len(weak_entries) > 8:
            proof += f"; ... +{len(weak_entries) - 8} more"
        items.append(
            {
                "target_id": str(data["target_id"]),
                "host_target": f'{data["hostname"]}:{data["port"]}',
                "finding_id": report["finding_id"],
                "severity": report["severity"],
                "finding_proof": proof,
                "scan_timestamp_utc": data.get("scan_timestamp_utc"),
            }
        )
    return items


def _build_hosted_in_m365_items(db):
    rows = db.execute(
        text(
            """
            SELECT
              t.id AS target_id,
              t.hostname,
              t.port,
              d.data AS dns_data,
              latest.scan_timestamp_utc
            FROM targets t
            LEFT JOIN target_dns d ON d.target_id = t.id
            LEFT JOIN LATERAL (
              SELECT COALESCE(s.finished_at, s.started_at) AS scan_timestamp_utc
              FROM scans s
              WHERE s.target_id = t.id
                AND s.status IN ('completed', 'done')
              ORDER BY s.finished_at DESC NULLS LAST, s.started_at DESC NULLS LAST
              LIMIT 1
            ) latest ON TRUE
            WHERE t.enabled = true
              AND t.dns_checks_enabled = true
            ORDER BY t.hostname ASC, t.port ASC
            """
        )
    ).fetchall()
    report = REPORT_DEFINITIONS["hosted_in_m365"]
    items = []
    for row in rows:
        data = dict(row._mapping)
        dns_data = data.get("dns_data") or {}
        m365 = dns_data.get("m365") or {}
        hosted = bool(m365.get("hosted"))
        if not hosted:
            continue
        tenant_assigned = bool(m365.get("tenant_assigned"))
        service_usage = bool(m365.get("service_usage"))
        confidence = str(m365.get("confidence") or "unknown")
        score = int(m365.get("score") or 0)
        signals = m365.get("signals") or []
        tenant_hints = m365.get("tenant_hints") or []
        ms_tokens = m365.get("ms_verification_tokens") or []
        identity = m365.get("identity") or {}
        identity_tenant_id = str(identity.get("tenant_id") or "").strip()
        identity_namespace_type = str(identity.get("namespace_type") or "").strip()
        identity_domain_checked = str(identity.get("domain_checked") or "").strip()
        identity_cloud_instance = str(identity.get("cloud_instance_name") or "").strip()
        identity_tenant_region = str(identity.get("tenant_region_scope") or "").strip()
        identity_federation_brand = str(identity.get("federation_brand_name") or "").strip()
        proof_parts = [
            "m365_hosted=true",
            f"tenant_assigned={tenant_assigned}",
            f"service_usage={service_usage}",
            f"confidence={confidence}",
            f"score={score}",
        ]
        if tenant_hints:
            proof_parts.append("tenant_hints=" + ",".join(str(v) for v in tenant_hints[:5]))
        if ms_tokens:
            proof_parts.append(
                "ms_verification="
                + ",".join(f"MS={str(v)}" for v in ms_tokens[:5])
            )
        if identity_tenant_id:
            proof_parts.append(f"tenant_id={identity_tenant_id}")
        if identity_namespace_type:
            proof_parts.append(f"namespace_type={identity_namespace_type}")
        if identity_domain_checked:
            proof_parts.append(f"identity_domain={identity_domain_checked}")
        if identity_cloud_instance:
            proof_parts.append(f"cloud_instance={identity_cloud_instance}")
        if identity_tenant_region:
            proof_parts.append(f"tenant_region={identity_tenant_region}")
        if identity_federation_brand:
            proof_parts.append(f"federation_brand={identity_federation_brand}")
        if signals:
            proof_parts.append("signals=" + "; ".join(str(v) for v in signals[:3]))
        items.append(
            {
                "target_id": str(data["target_id"]),
                "host_target": f'{data["hostname"]}:{data["port"]}',
                "finding_id": report["finding_id"],
                "severity": report["severity"],
                "finding_proof": "; ".join(proof_parts),
                "scan_timestamp_utc": data.get("scan_timestamp_utc"),
            }
        )
    return items


def _build_spoofable_domains_hosts_items(db):
    rows = db.execute(
        text(
            """
            SELECT
              t.id AS target_id,
              t.hostname,
              t.port,
              d.data AS dns_data,
              latest.scan_timestamp_utc
            FROM targets t
            LEFT JOIN target_dns d ON d.target_id = t.id
            LEFT JOIN LATERAL (
              SELECT COALESCE(s.finished_at, s.started_at) AS scan_timestamp_utc
              FROM scans s
              WHERE s.target_id = t.id
                AND s.status IN ('completed', 'done')
              ORDER BY s.finished_at DESC NULLS LAST, s.started_at DESC NULLS LAST
              LIMIT 1
            ) latest ON TRUE
            WHERE t.enabled = true
              AND t.dns_checks_enabled = true
            ORDER BY t.hostname ASC, t.port ASC
            """
        )
    ).fetchall()
    report = REPORT_DEFINITIONS["spoofable_domains_hosts"]
    items = []
    for row in rows:
        data = dict(row._mapping)
        dns_data = data.get("dns_data") or {}
        spf = str(dns_data.get("spf") or "").strip()
        dmarc = dns_data.get("dmarc") or {}
        dmarc_policy = str(dmarc.get("policy") or "").strip().lower()
        has_mx = bool(dns_data.get("mx") or [])
        has_a = bool(dns_data.get("a") or [])
        has_aaaa = bool(dns_data.get("aaaa") or [])
        has_mail_route = bool(has_mx or has_a or has_aaaa)

        spf_strict = spf.lower().endswith("-all")
        dmarc_none = dmarc_policy in {"", "none"}
        if not has_mail_route:
            continue
        if spf_strict or not dmarc_none:
            continue

        proof = (
            f"spf={spf or '(missing)'}; dmarc_policy={dmarc_policy or '(missing)'}; "
            f"has_mx={has_mx}; has_a={has_a}; has_aaaa={has_aaaa}"
        )
        items.append(
            {
                "target_id": str(data["target_id"]),
                "host_target": f'{data["hostname"]}:{data["port"]}',
                "finding_id": report["finding_id"],
                "severity": report["severity"],
                "finding_proof": proof,
                "scan_timestamp_utc": data.get("scan_timestamp_utc"),
            }
        )
    return items


def _build_authoritative_dns_health_items(db):
    rows = db.execute(
        text(
            """
            SELECT
              t.id AS target_id,
              t.hostname,
              t.port,
              d.data AS dns_data,
              latest.scan_timestamp_utc
            FROM targets t
            LEFT JOIN target_dns d ON d.target_id = t.id
            LEFT JOIN LATERAL (
              SELECT COALESCE(s.finished_at, s.started_at) AS scan_timestamp_utc
              FROM scans s
              WHERE s.target_id = t.id
                AND s.status IN ('completed', 'done')
              ORDER BY s.finished_at DESC NULLS LAST, s.started_at DESC NULLS LAST
              LIMIT 1
            ) latest ON TRUE
            WHERE t.enabled = true
              AND t.dns_checks_enabled = true
            ORDER BY t.hostname ASC, t.port ASC
            """
        )
    ).fetchall()
    report = REPORT_DEFINITIONS["authoritative_dns_health"]
    items = []
    for row in rows:
        data = dict(row._mapping)
        dns_data = data.get("dns_data") or {}
        health = dns_data.get("dns_authority") or {}
        status = str(health.get("status") or "").strip().lower()
        issues = health.get("issues") or []
        if not isinstance(issues, list):
            issues = []
        if status in {"", "good"} and not issues:
            continue

        nameserver_count = int(health.get("nameserver_count") or 0)
        nameservers_reachable = int(health.get("nameservers_reachable") or 0)
        authoritative_answer_count = int(health.get("authoritative_answer_count") or 0)
        lame = bool(health.get("lame_delegation_detected"))
        ns_consistent = bool(health.get("ns_consistent", True))
        serials = health.get("serials") or []
        if not isinstance(serials, list):
            serials = []
        severity = "medium"
        if lame or authoritative_answer_count == 0 or nameserver_count == 0:
            severity = "high"
        elif not ns_consistent or nameservers_reachable < nameserver_count:
            severity = "medium"
        else:
            severity = "low"

        proof_parts = [
            f"status={status or 'unknown'}",
            f"zone={str(health.get('zone_checked') or '(unknown)')}",
            f"reachable_ns={nameservers_reachable}/{nameserver_count}",
            f"authoritative_soa_answers={authoritative_answer_count}",
            f"lame_delegation={lame}",
            f"ns_consistent={ns_consistent}",
        ]
        if serials:
            proof_parts.append("serials=" + ",".join(str(v) for v in serials[:6]))
        if issues:
            proof_parts.append("issues=" + ",".join(str(v) for v in issues[:6]))

        items.append(
            {
                "target_id": str(data["target_id"]),
                "host_target": f'{data["hostname"]}:{data["port"]}',
                "finding_id": report["finding_id"],
                "severity": severity,
                "finding_proof": "; ".join(proof_parts),
                "scan_timestamp_utc": data.get("scan_timestamp_utc"),
            }
        )
    return items


def _build_reputation_blacklist_items(db):
    rows = db.execute(
        text(
            """
            SELECT
              t.id AS target_id,
              t.hostname,
              t.port,
              d.data AS dns_data,
              latest.scan_timestamp_utc
            FROM targets t
            LEFT JOIN target_dns d ON d.target_id = t.id
            LEFT JOIN LATERAL (
              SELECT COALESCE(s.finished_at, s.started_at) AS scan_timestamp_utc
              FROM scans s
              WHERE s.target_id = t.id
                AND s.status IN ('completed', 'done')
              ORDER BY s.finished_at DESC NULLS LAST, s.started_at DESC NULLS LAST
              LIMIT 1
            ) latest ON TRUE
            WHERE t.enabled = true
              AND t.dns_checks_enabled = true
            ORDER BY t.hostname ASC, t.port ASC
            """
        )
    ).fetchall()
    report = REPORT_DEFINITIONS["reputation_blacklist"]
    items = []
    for row in rows:
        data = dict(row._mapping)
        dns_data = data.get("dns_data") or {}
        reputation = dns_data.get("reputation") or {}
        enabled = bool(reputation.get("enabled"))
        listed_count = int(reputation.get("listed_count") or 0)
        if not enabled or listed_count <= 0:
            continue

        ip_checks = reputation.get("ip_checks") or []
        if not isinstance(ip_checks, list):
            ip_checks = []
        domain_checks = reputation.get("domain_checks") or []
        if not isinstance(domain_checks, list):
            domain_checks = []
        exposure = reputation.get("asn_country_exposure") or {}
        asns = exposure.get("asns") or []
        if not isinstance(asns, list):
            asns = []
        countries = exposure.get("countries") or []
        if not isinstance(countries, list):
            countries = []

        listed_entries = []
        for entry in ip_checks:
            if not isinstance(entry, dict):
                continue
            ip_value = str(entry.get("ip") or "").strip()
            zones = entry.get("zones") or []
            if not isinstance(zones, list):
                zones = []
            listed_zones = [
                f"{str(zone.get('zone') or '')}={str(zone.get('response') or 'listed')}"
                for zone in zones
                if isinstance(zone, dict) and bool(zone.get("listed"))
            ]
            if ip_value and listed_zones:
                listed_entries.append(f"{ip_value}[{','.join(listed_zones[:4])}]")
        for entry in domain_checks:
            if not isinstance(entry, dict):
                continue
            if not bool(entry.get("listed")):
                continue
            listed_entries.append(
                f"{str(entry.get('query_name') or '')}[{str(entry.get('response') or 'listed')}]"
            )

        proof_parts = [
            f"listed_count={listed_count}",
            f"status={str(reputation.get('status') or 'listed')}",
        ]
        if listed_entries:
            proof_parts.append("listed_entries=" + "; ".join(listed_entries[:6]))
        if asns:
            proof_parts.append("asns=" + ",".join(str(v) for v in asns[:6]))
        if countries:
            proof_parts.append("countries=" + ",".join(str(v) for v in countries[:6]))

        items.append(
            {
                "target_id": str(data["target_id"]),
                "host_target": f'{data["hostname"]}:{data["port"]}',
                "finding_id": report["finding_id"],
                "severity": report["severity"],
                "finding_proof": "; ".join(proof_parts),
                "scan_timestamp_utc": data.get("scan_timestamp_utc"),
            }
        )
    return items


def _build_ct_revocation_gap_items(db):
    latest = _latest_completed_scans(db)
    by_scan = _load_results_for_scans(
        db,
        [str(item["scan_id"]) for item in latest],
        ["certificate_info"],
    )
    report = REPORT_DEFINITIONS["ct_revocation_gaps"]
    items = []
    for row in latest:
        scan_id = str(row["scan_id"])
        cert_info = (by_scan.get(scan_id) or {}).get("certificate_info") or {}
        ct = cert_info.get("certificate_transparency") or {}
        rev = cert_info.get("revocation") or {}
        stapling = rev.get("ocsp_stapling") or {}
        ocsp_urls = rev.get("ocsp_urls") or []
        crl_urls = rev.get("crl_urls") or []
        ocsp_reach = rev.get("ocsp_reachability") or []
        crl_reach = rev.get("crl_reachability") or []

        issues = []
        has_scts = bool(ct.get("has_embedded_scts"))
        sct_count = int(ct.get("embedded_scts_count") or 0)
        if not has_scts:
            issues.append(f"certificate transparency SCT missing (embedded_scts={sct_count})")

        stapling_present = bool(stapling.get("present"))
        stapling_quality = str(stapling.get("quality") or "missing").lower()
        if not stapling_present:
            issues.append("OCSP stapling missing")
        elif stapling_quality not in {"good"}:
            status = str(stapling.get("cert_status") or stapling.get("response_status") or "unknown")
            issues.append(f"OCSP stapling not good (quality={stapling_quality}, status={status})")

        basic_status = str(rev.get("basic_status") or "unknown").lower()
        if basic_status in {"revoked", "unknown"}:
            issues.append(f"basic revocation status={basic_status}")

        if not ocsp_urls and not crl_urls:
            issues.append("revocation endpoints missing (no OCSP/CRL URLs)")
        else:
            ocsp_reachable = any(bool(x.get("reachable")) for x in ocsp_reach if isinstance(x, dict))
            crl_reachable = any(bool(x.get("reachable")) for x in crl_reach if isinstance(x, dict))
            if ocsp_urls and not ocsp_reachable:
                issues.append("OCSP endpoints unreachable")
            if crl_urls and not crl_reachable:
                issues.append("CRL endpoints unreachable")

        if not issues:
            continue

        severity = (
            "high"
            if any("revocation status=revoked" in issue for issue in issues)
            else "medium"
        )
        proof = "; ".join(issues)
        items.append(
            {
                "target_id": str(row["target_id"]),
                "host_target": f'{row["hostname"]}:{row["port"]}',
                "finding_id": report["finding_id"],
                "severity": severity,
                "finding_proof": proof,
                "scan_timestamp_utc": row["scan_timestamp_utc"],
            }
        )
    return items


def _build_ca_issuers_used_items(db):
    latest = _latest_completed_scans(db)
    by_scan = _load_results_for_scans(
        db,
        [str(item["scan_id"]) for item in latest],
        ["certificate_info"],
    )
    report = REPORT_DEFINITIONS["ca_issuers_used"]
    items = []
    for row in latest:
        scan_id = str(row["scan_id"])
        cert_info = (by_scan.get(scan_id) or {}).get("certificate_info") or {}
        certs = cert_info.get("certificate_chain") or []
        leaf = certs[0] if isinstance(certs, list) and certs else {}
        issuer = str((leaf or {}).get("issuer") or "").strip()
        subject = str((leaf or {}).get("subject") or "").strip()
        proof = (
            f"issuer={issuer or '(unavailable)'}; "
            f"subject={subject or '(unavailable)'}"
        )
        items.append(
            {
                "target_id": str(row["target_id"]),
                "host_target": f'{row["hostname"]}:{row["port"]}',
                "finding_id": report["finding_id"],
                "severity": report["severity"],
                "finding_proof": proof,
                "scan_timestamp_utc": row["scan_timestamp_utc"],
            }
        )
    return items


def _build_wildcard_certs_in_use_items(db):
    latest = _latest_completed_scans(db)
    by_scan = _load_results_for_scans(
        db,
        [str(item["scan_id"]) for item in latest],
        ["certificate_info"],
    )
    report = REPORT_DEFINITIONS["wildcard_certs_in_use"]
    items = []
    for row in latest:
        scan_id = str(row["scan_id"])
        cert_info = (by_scan.get(scan_id) or {}).get("certificate_info") or {}
        san_names = _extract_leaf_san_dns(cert_info)
        cn_name = _extract_leaf_cn(cert_info)
        wildcard_names = [name for name in san_names if "*" in str(name or "")]
        if cn_name and "*" in cn_name and cn_name not in wildcard_names:
            wildcard_names.append(cn_name)
        if not wildcard_names:
            continue
        proof = "wildcard_names=" + ", ".join(wildcard_names[:8])
        if len(wildcard_names) > 8:
            proof += f", ... +{len(wildcard_names) - 8} more"
        items.append(
            {
                "target_id": str(row["target_id"]),
                "host_target": f'{row["hostname"]}:{row["port"]}',
                "finding_id": report["finding_id"],
                "severity": report["severity"],
                "finding_proof": proof,
                "scan_timestamp_utc": row["scan_timestamp_utc"],
            }
        )
    return items


def _build_https_posture_issue_items(db, checks_cfg=None):
    latest = _latest_completed_scans(db)
    by_scan = _load_results_for_scans(
        db,
        [str(item["scan_id"]) for item in latest],
        ["http_headers", "certificate_info"],
    )
    report = REPORT_DEFINITIONS["https_posture_issues"]
    thresholds = (checks_cfg or {}).get("thresholds") or {}
    cert_expiry_days = int(thresholds.get("cert_expiry_days") or 30)
    hsts_min_max_age = int(thresholds.get("hsts_min_max_age") or 31536000)
    items = []
    for row in latest:
        scan_id = str(row["scan_id"])
        results = by_scan.get(scan_id) or {}
        headers = results.get("http_headers") or {}
        cert_info = results.get("certificate_info") or {}
        issues = []
        issues.extend(_extract_hsts_issues(headers, min_max_age=hsts_min_max_age))
        redirect_ok, redirect_info = _probe_http_to_https_redirect(str(row["hostname"]))
        if not redirect_ok:
            issues.append(f"http->https redirect not confirmed ({redirect_info})")
        cert_issue = _extract_cert_near_expiry_issue(cert_info, days=cert_expiry_days)
        if cert_issue:
            issues.append(cert_issue)
        issues.extend(_extract_cert_name_issues(str(row["hostname"]), cert_info))
        if not issues:
            continue
        severity = (
            "high"
            if any(
                ("expired" in i) or ("SAN/CN mismatch" in i)
                for i in issues
            )
            else "medium"
        )
        proof = "; ".join(issues)
        items.append(
            {
                "target_id": str(row["target_id"]),
                "host_target": f'{row["hostname"]}:{row["port"]}',
                "finding_id": report["finding_id"],
                "severity": severity,
                "finding_proof": proof,
                "scan_timestamp_utc": row["scan_timestamp_utc"],
            }
        )
    return items


def _build_cipher_hygiene_risk_items(db):
    latest = _latest_completed_scans(db)
    plugins = [
        "ssl_2_0_cipher_suites",
        "ssl_3_0_cipher_suites",
        "tls_1_0_cipher_suites",
        "tls_1_1_cipher_suites",
        "tls_1_2_cipher_suites",
        "tls_1_3_cipher_suites",
        "tls_compression",
        "tls_fallback_scsv",
    ]
    by_scan = _load_results_for_scans(
        db,
        [str(item["scan_id"]) for item in latest],
        plugins,
    )
    report = REPORT_DEFINITIONS["cipher_hygiene_risk"]
    items = []
    for row in latest:
        scan_id = str(row["scan_id"])
        results = by_scan.get(scan_id) or {}

        penalties = []
        penalty_points = 0

        def add_penalty(points: int, reason: str):
            nonlocal penalty_points
            penalty_points += points
            penalties.append(f"-{points} {reason}")

        if _coerce_support_flag((results.get("ssl_2_0_cipher_suites") or {}).get("is_protocol_supported")):
            add_penalty(40, "SSLv2 supported")
        if _coerce_support_flag((results.get("ssl_3_0_cipher_suites") or {}).get("is_protocol_supported")):
            add_penalty(35, "SSLv3 supported")
        if _coerce_support_flag((results.get("tls_1_0_cipher_suites") or {}).get("is_protocol_supported")):
            add_penalty(25, "TLS 1.0 supported")
        if _coerce_support_flag((results.get("tls_1_1_cipher_suites") or {}).get("is_protocol_supported")):
            add_penalty(20, "TLS 1.1 supported")

        tls13_supported = _coerce_support_flag((results.get("tls_1_3_cipher_suites") or {}).get("is_protocol_supported"))
        if not tls13_supported:
            add_penalty(10, "TLS 1.3 not supported")

        accepted_cipher_names = []
        for plugin in ("tls_1_2_cipher_suites", "tls_1_3_cipher_suites"):
            accepted_cipher_names.extend((results.get(plugin) or {}).get("accepted_cipher_suites") or [])
        weak_cipher_count = sum(1 for name in accepted_cipher_names if _looks_weak_cipher_name(name))
        if weak_cipher_count > 0:
            add_penalty(20, f"weak cipher patterns detected ({weak_cipher_count})")
        if accepted_cipher_names and not _has_forward_secrecy(accepted_cipher_names):
            add_penalty(20, "no forward secrecy cipher negotiated")

        if bool((results.get("tls_compression") or {}).get("supports_compression")):
            add_penalty(10, "TLS compression enabled")
        fallback_support = (results.get("tls_fallback_scsv") or {}).get("supports_fallback_scsv")
        if fallback_support is False:
            add_penalty(5, "TLS fallback SCSV not supported")

        score = max(0, 100 - penalty_points)
        if score >= 90:
            continue
        severity = "high" if score < 60 else "medium" if score < 80 else "low"
        proof = f"score={score}; penalties={', '.join(penalties) if penalties else 'none'}"
        items.append(
            {
                "target_id": str(row["target_id"]),
                "host_target": f'{row["hostname"]}:{row["port"]}',
                "finding_id": report["finding_id"],
                "severity": severity,
                "finding_proof": proof,
                "scan_timestamp_utc": row["scan_timestamp_utc"],
            }
        )
    return items


def _build_report_items(db, report_id: str):
    checks_cfg = read_checks_config(db)
    if not _is_report_enabled(checks_cfg, report_id):
        return []

    if report_id == "no_tls13":
        rows = _build_no_tls13_items(db)
    elif report_id == "pqc_non_compliant":
        rows = _build_pqc_non_compliant_items(db)
    elif report_id == "legacy_ssl_enabled":
        rows = _build_legacy_ssl_items(db)
    elif report_id == "spf_not_strict":
        rows = _build_spf_not_strict_items(db)
    elif report_id == "missing_hsts":
        rows = _build_missing_hsts_items(db)
    elif report_id == "missing_dmarc_policy":
        rows = _build_missing_dmarc_policy_items(db)
    elif report_id == "weak_dkim_keys":
        rows = _build_weak_dkim_keys_items(db, checks_cfg=checks_cfg)
    elif report_id == "hosted_in_m365":
        rows = _build_hosted_in_m365_items(db)
    elif report_id == "spoofable_domains_hosts":
        rows = _build_spoofable_domains_hosts_items(db)
    elif report_id == "authoritative_dns_health":
        rows = _build_authoritative_dns_health_items(db)
    elif report_id == "reputation_blacklist":
        rows = _build_reputation_blacklist_items(db)
    elif report_id == "ct_revocation_gaps":
        rows = _build_ct_revocation_gap_items(db)
    elif report_id == "ca_issuers_used":
        rows = _build_ca_issuers_used_items(db)
    elif report_id == "wildcard_certs_in_use":
        rows = _build_wildcard_certs_in_use_items(db)
    elif report_id == "https_posture_issues":
        rows = _build_https_posture_issue_items(db, checks_cfg=checks_cfg)
    elif report_id == "cipher_hygiene_risk":
        rows = _build_cipher_hygiene_risk_items(db)
    else:
        raise HTTPException(status_code=400, detail="Unsupported report_id")

    effective = _effective_report_severity(
        checks_cfg, report_id, REPORT_DEFINITIONS[report_id]["severity"]
    )
    for row in rows:
        row["severity"] = effective
    return rows


def _normalize_report_id(value: str) -> str:
    report_id = str(value or "").strip().lower()
    aliases = {
        "https_posture": "https_posture_issues",
        "cipher_hygiene": "cipher_hygiene_risk",
        "pqc": "pqc_non_compliant",
        "post_quantum": "pqc_non_compliant",
        "spoofable": "spoofable_domains_hosts",
    }
    return aliases.get(report_id, report_id)


def _render_subject(template: str, report_meta: dict, row_count: int):
    clean = (template or "{finding_name}").strip() or "{finding_name}"
    return (
        clean.replace("{finding_name}", report_meta.get("title") or "")
        .replace("{report_id}", report_meta.get("id") or "")
        .replace("{row_count}", str(row_count))
    )


def _flatten_name(name_pairs):
    out = []
    for rdn in name_pairs or []:
        if not isinstance(rdn, (list, tuple)):
            continue
        for item in rdn:
            if (
                isinstance(item, (list, tuple))
                and len(item) == 2
                and item[0]
            ):
                out.append((str(item[0]), str(item[1])))
    return out


def _format_name_pairs(name_pairs):
    pairs = _flatten_name(name_pairs)
    if not pairs:
        return ""
    return ", ".join(f"{k}={v}" for k, v in pairs)


def _extract_attr(name_pairs, keys):
    keys_l = {str(k).strip().lower() for k in (keys or [])}
    for key, value in _flatten_name(name_pairs):
        if str(key).strip().lower() in keys_l:
            return str(value)
    return ""


def _parse_openssl_time(value):
    text_value = str(value or "").strip()
    if not text_value:
        return None
    try:
        return datetime.strptime(text_value, "%b %d %H:%M:%S %Y GMT").replace(
            tzinfo=timezone.utc
        )
    except Exception:
        return None


def _crawl_live_certificate(hostname, port, timeout_seconds=8):
    host = str(hostname or "").strip()
    result = {
        "ok": False,
        "host": host,
        "port": int(port or 443) if str(port or "").strip() else 443,
        "tls_version": "",
        "cipher": "",
        "subject": "",
        "issuer": "",
        "serial_number": "",
        "not_before": "",
        "not_after": "",
        "days_remaining": None,
        "common_name": "",
        "san_dns_names": [],
        "ocsp_urls": [],
        "ca_issuers": [],
        "crl_distribution_points": [],
        "fingerprint_sha256": "",
        "certificate_pem": "",
        "error": "",
    }
    if not host:
        result["error"] = "empty_hostname"
        return result

    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, int(result["port"])), timeout=timeout_seconds) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                result["tls_version"] = str(tls_sock.version() or "")
                cipher_info = tls_sock.cipher()
                if isinstance(cipher_info, (list, tuple)) and cipher_info:
                    result["cipher"] = str(cipher_info[0] or "")
                der = tls_sock.getpeercert(binary_form=True)
                if not der:
                    result["error"] = "no_peer_certificate"
                    return result

                result["fingerprint_sha256"] = hashlib.sha256(der).hexdigest()
                pem = ssl.DER_cert_to_PEM_cert(der)
                result["certificate_pem"] = pem

                decoded = {}
                try:
                    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=True) as tmp:
                        tmp.write(pem)
                        tmp.flush()
                        decoded = ssl._ssl._test_decode_cert(tmp.name)
                except Exception:
                    decoded = {}

                subject = decoded.get("subject") or []
                issuer = decoded.get("issuer") or []
                san = decoded.get("subjectAltName") or []
                result["subject"] = _format_name_pairs(subject)
                result["issuer"] = _format_name_pairs(issuer)
                result["serial_number"] = str(decoded.get("serialNumber") or "")
                result["not_before"] = str(decoded.get("notBefore") or "")
                result["not_after"] = str(decoded.get("notAfter") or "")
                result["common_name"] = _extract_attr(subject, {"commonName", "CN"})
                result["san_dns_names"] = [
                    str(value)
                    for kind, value in san
                    if str(kind).upper() == "DNS" and value
                ]
                result["ocsp_urls"] = [str(v) for v in (decoded.get("OCSP") or []) if v]
                result["ca_issuers"] = [str(v) for v in (decoded.get("caIssuers") or []) if v]
                result["crl_distribution_points"] = [
                    str(v) for v in (decoded.get("crlDistributionPoints") or []) if v
                ]
                not_after_dt = _parse_openssl_time(result["not_after"])
                if not_after_dt:
                    now = datetime.now(timezone.utc)
                    result["days_remaining"] = int(
                        (not_after_dt - now).total_seconds() // 86400
                    )
                result["ok"] = True
                return result
    except Exception as exc:
        result["error"] = f"{exc.__class__.__name__}: {exc}"
        return result


@app.get("/jobs")
def list_jobs(
    limit: int = 0, offset: int = 0, user=Depends(get_current_user)
):
    db = SessionLocal()
    try:
        total_row = db.execute(
            text(
                """
                SELECT COUNT(*) AS total
                FROM scans
                WHERE status IS NULL OR status != 'purged'
                """
            )
        ).fetchone()
        total = int(total_row._mapping["total"]) if total_row else 0

        if limit and limit > 0:
            limit_clause = "LIMIT :limit OFFSET :offset"
            params = {"limit": limit, "offset": offset}
        else:
            limit_clause = ""
            params = {}

        rows = db.execute(
            text(
                f"""
                SELECT
                  s.id,
                  s.target_id,
                  t.hostname,
                  t.port,
                  t.dns_checks_enabled,
                  t.tls_checks_enabled,
                  s.started_at,
                  s.finished_at,
                  s.status,
                  s.error_message
                FROM scans s
                LEFT JOIN targets t ON t.id = s.target_id
                WHERE s.status IS NULL OR s.status != 'purged'
                ORDER BY s.started_at DESC NULLS LAST
                {limit_clause}
                """
            ),
            params,
        ).fetchall()
        return {
            "items": [dict(r._mapping) for r in rows],
            "total": total,
        }
    finally:
        db.close()


@app.get("/certificates")
def list_certificates(
    limit: int = 0, offset: int = 0, user=Depends(get_current_user)
):
    db = SessionLocal()
    try:
        total_row = db.execute(
            text(
                """
                SELECT COUNT(*) AS total
                FROM targets t
                WHERE t.enabled = true
                  AND t.tls_checks_enabled = true
                """
            )
        ).fetchone()
        total = int(total_row._mapping["total"]) if total_row else 0

        if limit and limit > 0:
            limit_clause = "LIMIT :limit OFFSET :offset"
            params = {"limit": limit, "offset": offset}
        else:
            limit_clause = ""
            params = {}

        rows = db.execute(
            text(
                f"""
                SELECT
                  t.id AS target_id,
                  t.hostname,
                  t.port,
                  latest.scan_id,
                  latest.scan_timestamp_utc,
                  cert.result AS cert_result
                FROM targets t
                LEFT JOIN LATERAL (
                  SELECT
                    s.id AS scan_id,
                    COALESCE(s.finished_at, s.started_at) AS scan_timestamp_utc
                  FROM scans s
                  WHERE s.target_id = t.id
                    AND s.status IN ('completed', 'done')
                  ORDER BY s.finished_at DESC NULLS LAST, s.started_at DESC NULLS LAST
                  LIMIT 1
                ) latest ON TRUE
                LEFT JOIN LATERAL (
                  SELECT r.result
                  FROM scan_results r
                  WHERE r.scan_id = latest.scan_id
                    AND r.plugin = 'certificate_info'
                  LIMIT 1
                ) cert ON TRUE
                WHERE t.enabled = true
                  AND t.tls_checks_enabled = true
                ORDER BY t.hostname ASC, t.port ASC
                {limit_clause}
                """
            ),
            params,
        ).fetchall()

        items = []
        for row in rows:
            data = dict(row._mapping)
            cert_result = data.get("cert_result") or {}
            chain = cert_result.get("certificate_chain") or []
            leaf = chain[0] if isinstance(chain, list) and chain else {}
            san_values = leaf.get("subject_alternative_name") or []
            if not isinstance(san_values, list):
                san_values = []
            cn_value = _extract_leaf_cn(cert_result)
            items.append(
                {
                    "target_id": str(data.get("target_id") or ""),
                    "hostname": data.get("hostname") or "",
                    "port": data.get("port"),
                    "issuer": leaf.get("issuer") or "",
                    "cn": cn_value,
                    "san_names": san_values,
                    "not_before": leaf.get("not_before"),
                    "not_after": leaf.get("not_after"),
                    "scan_id": str(data.get("scan_id") or "") if data.get("scan_id") else "",
                    "scan_timestamp_utc": data.get("scan_timestamp_utc"),
                }
            )

        return {"items": items, "total": total}
    finally:
        db.close()


@app.get("/certificates/{scan_id}/details")
def certificate_details(scan_id: UUID, user=Depends(get_current_user)):
    db = SessionLocal()
    try:
        row = db.execute(
            text(
                """
                SELECT
                  s.id AS scan_id,
                  t.hostname,
                  t.port,
                  COALESCE(s.finished_at, s.started_at) AS scan_timestamp_utc,
                  r.result AS cert_result
                FROM scans s
                LEFT JOIN targets t ON t.id = s.target_id
                LEFT JOIN scan_results r
                  ON r.scan_id = s.id
                 AND r.plugin = 'certificate_info'
                WHERE s.id = :sid
                LIMIT 1
                """
            ),
            {"sid": str(scan_id)},
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Scan not found")

        data = dict(row._mapping)
        cert_result = data.get("cert_result") or {}
        chain = cert_result.get("certificate_chain") or []
        if not isinstance(chain, list) or not chain:
            raise HTTPException(
                status_code=404,
                detail="Certificate details not available for this scan",
            )

        return {
            "scan_id": str(data.get("scan_id") or scan_id),
            "hostname": data.get("hostname") or "",
            "port": data.get("port"),
            "scan_timestamp_utc": data.get("scan_timestamp_utc"),
            "certificate_info": cert_result,
            "live_probe": _crawl_live_certificate(
                data.get("hostname") or "",
                data.get("port") or 443,
            ),
        }
    finally:
        db.close()


@app.delete("/jobs/{scan_id}")
def delete_job(scan_id: UUID, user=Depends(get_current_user)):
    db = SessionLocal()
    try:
        row = db.execute(
            text("SELECT id FROM scans WHERE id=:sid"),
            {"sid": str(scan_id)},
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Result not found")

        db.execute(
            text(
                """
                DELETE FROM scan_diffs
                WHERE old_scan_id=:sid OR new_scan_id=:sid
                """
            ),
            {"sid": str(scan_id)},
        )
        db.execute(
            text("DELETE FROM scan_results WHERE scan_id=:sid"),
            {"sid": str(scan_id)},
        )
        db.execute(
            text("DELETE FROM scans WHERE id=:sid"),
            {"sid": str(scan_id)},
        )
        db.commit()
        return {"status": "deleted", "scan_id": str(scan_id)}
    finally:
        db.close()


@app.get("/reports/catalog")
def reports_catalog(user=Depends(get_current_user)):
    db = SessionLocal()
    try:
        checks_cfg = read_checks_config(db)
        items = []
        for report_id, report in REPORT_DEFINITIONS.items():
            item = dict(report)
            item["enabled"] = _is_report_enabled(checks_cfg, report_id)
            item["effective_severity"] = _effective_report_severity(
                checks_cfg, report_id, report["severity"]
            )
            items.append(item)
        return {"items": items}
    finally:
        db.close()


@app.get("/reports/findings")
def report_findings(
    report_id: str,
    limit: int = 0,
    offset: int = 0,
    user=Depends(get_current_user),
):
    report_id = _normalize_report_id(report_id)
    report_meta = REPORT_DEFINITIONS.get(report_id)
    if not report_meta:
        raise HTTPException(
            status_code=400,
            detail=(
                "report_id must be one of: "
                + ", ".join(sorted(REPORT_DEFINITIONS.keys()))
            ),
        )

    db = SessionLocal()
    try:
        checks_cfg = read_checks_config(db)
        report_meta = dict(report_meta)
        report_meta["enabled"] = _is_report_enabled(checks_cfg, report_id)
        report_meta["effective_severity"] = _effective_report_severity(
            checks_cfg, report_id, report_meta.get("severity")
        )
        rows = _build_report_items(db, report_id)
        total = len(rows)
        start = max(0, int(offset or 0))
        if limit and limit > 0:
            end = start + int(limit)
            page_items = rows[start:end]
        else:
            page_items = rows[start:]

        return {
            "report": report_meta,
            "items": page_items,
            "total": total,
        }
    finally:
        db.close()


@app.post("/reports/email")
def send_report_email(payload: ReportEmailRequest, user=Depends(get_current_admin)):
    report_id = _normalize_report_id(payload.report_id or "")
    report_meta = REPORT_DEFINITIONS.get(report_id)
    if not report_meta:
        raise HTTPException(
            status_code=400,
            detail=(
                "report_id must be one of: "
                + ", ".join(sorted(REPORT_DEFINITIONS.keys()))
            ),
        )

    db = SessionLocal()
    try:
        smtp_cfg = read_smtp_config(db)
        if not smtp_cfg["enabled"]:
            raise HTTPException(
                status_code=400,
                detail="SMTP export is disabled. Enable it in Admin > SMTP.",
            )
        rows = _build_report_items(db, report_id)
    finally:
        db.close()

    selected_target_ids = {
        str(value).strip()
        for value in (payload.selected_target_ids or [])
        if str(value).strip()
    }
    if selected_target_ids:
        rows = [
            row
            for row in rows
            if str(row.get("target_id") or "").strip() in selected_target_ids
        ]
    if not rows:
        raise HTTPException(
            status_code=400,
            detail="No selected hosts match findings for this report.",
        )

    subject = (
        (payload.subject or "").strip()
        or _render_subject(
            smtp_cfg["subject_template"], report_meta, len(rows)
        )
    )

    csv_buffer = StringIO()
    writer = csv.writer(csv_buffer)
    writer.writerow(
        [
            "host_target",
            "finding_id",
            "severity",
            "finding_proof",
            "scan_timestamp_utc",
        ]
    )
    for row in rows:
        writer.writerow(
            [
                row.get("host_target") or "",
                row.get("finding_id") or "",
                row.get("severity") or "",
                row.get("finding_proof") or "",
                row.get("scan_timestamp_utc") or "",
            ]
        )

    body = (
        f"Report: {report_meta['title']}\n"
        f"Description: {report_meta['description']}\n"
        f"Total findings: {len(rows)}\n\n"
        f"Generated by TLSAuditHub user: {user['username']}\n"
        "CSV attachment included.\n"
    )

    message = EmailMessage()
    message["From"] = smtp_cfg["from_address"]
    message["To"] = smtp_cfg["recipient"]
    message["Reply-To"] = smtp_cfg["reply_to"]
    message["Subject"] = subject
    message.set_content(body)
    message.add_attachment(
        csv_buffer.getvalue().encode("utf-8"),
        maintype="text",
        subtype="csv",
        filename=f"{report_id}_findings.csv",
    )

    db = SessionLocal()
    try:
        creds_row = db.execute(
            text(
                """
                SELECT username, password
                FROM smtp_config
                WHERE id = 1
                """
            )
        ).fetchone()
        creds = dict(creds_row._mapping) if creds_row else {}
    finally:
        db.close()

    try:
        with smtplib.SMTP(
            smtp_cfg["host"],
            smtp_cfg["port"],
            timeout=smtp_cfg["timeout_seconds"],
        ) as smtp:
            smtp.ehlo()
            if smtp_cfg["use_starttls"]:
                smtp.starttls()
                smtp.ehlo()
            if smtp_cfg["use_auth"]:
                smtp.login(
                    (creds.get("username") or "").strip(),
                    creds.get("password") or "",
                )
            smtp.send_message(message)
    except Exception as exc:
        raise HTTPException(
            status_code=502, detail=f"SMTP send failed: {exc}"
        ) from exc

    return {
        "status": "sent",
        "report_id": report_id,
        "recipient": smtp_cfg["recipient"],
        "subject": subject,
        "rows": len(rows),
    }


@app.post("/jobs/purge")
def purge_jobs(user=Depends(get_current_admin)):
    db = SessionLocal()
    try:
        deleted = _purge_jobs_data(db)
        return {"status": "purged", **deleted}
    finally:
        db.close()


@app.post("/admin/purge/jobs")
def admin_purge_jobs(user=Depends(get_current_admin)):
    db = SessionLocal()
    try:
        deleted = _purge_jobs_data(db)
        return {"status": "purged", **deleted}
    finally:
        db.close()


@app.post("/admin/purge/dns")
def admin_purge_dns(user=Depends(get_current_admin)):
    db = SessionLocal()
    try:
        ensure_target_dns_table(db)
        dns_row = db.execute(
            text("SELECT COUNT(*) AS c FROM target_dns")
        ).fetchone()
        deleted_dns = int(dns_row._mapping["c"]) if dns_row else 0
        db.execute(text("DELETE FROM target_dns"))
        db.commit()
        return {"status": "purged", "deleted_dns": deleted_dns}
    finally:
        db.close()


@app.post("/admin/purge/targets")
def admin_purge_targets(user=Depends(get_current_admin)):
    db = SessionLocal()
    try:
        ensure_target_dns_table(db)
        targets_row = db.execute(
            text("SELECT COUNT(*) AS c FROM targets")
        ).fetchone()
        dns_row = db.execute(
            text("SELECT COUNT(*) AS c FROM target_dns")
        ).fetchone()
        deleted_targets = int(targets_row._mapping["c"]) if targets_row else 0
        deleted_dns = int(dns_row._mapping["c"]) if dns_row else 0

        deleted_jobs = _purge_jobs_data(db)
        db.execute(text("DELETE FROM target_dns"))
        db.execute(text("DELETE FROM targets"))
        db.commit()

        return {
            "status": "purged",
            "deleted_targets": deleted_targets,
            "deleted_dns": deleted_dns,
            **deleted_jobs,
        }
    finally:
        db.close()


@app.get("/jobs/{scan_id}/results")
def job_results(scan_id: UUID, user=Depends(get_current_user)):
    db = SessionLocal()
    try:
        scan_row = db.execute(
            text("SELECT status, error_message FROM scans WHERE id=:sid"),
            {"sid": str(scan_id)},
        ).fetchone()
        rows = db.execute(
            text(
                """
                SELECT plugin, result
                FROM scan_results
                WHERE scan_id=:sid
                ORDER BY plugin ASC
                """
            ),
            {"sid": str(scan_id)},
        ).fetchall()
        payload = [dict(r._mapping) for r in rows]
        if scan_row and scan_row._mapping.get("status") == "failed":
            error_message = (
                str(scan_row._mapping.get("error_message") or "").strip()
            )
            payload.insert(
                0,
                {
                    "plugin": "scan_error",
                    "result": {
                        "status": "failed",
                        "error": error_message or "Scan failed.",
                    },
                },
            )
        return payload
    finally:
        db.close()


@app.get("/targets/{target_id}/diffs")
def get_diffs(target_id: UUID, user=Depends(get_current_user)):
    db = SessionLocal()
    try:
        rows = db.execute(
            text("""
                SELECT created_at, diff
                FROM scan_diffs
                WHERE target_id=:tid
                ORDER BY created_at DESC
            """),
            {"tid": str(target_id)},
        ).fetchall()
        return [dict(r._mapping) for r in rows]
    finally:
        db.close()
