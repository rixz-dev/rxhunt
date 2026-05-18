import re

# Each entry: pattern_name -> (compiled_regex, severity, description)
PATTERNS = {
    # ── AWS ──────────────────────────────────────────────────────────────
    "aws_access_key_id": (
        re.compile(r'(?<![A-Z0-9])(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])'),
        "CRITICAL", "AWS Access Key ID"
    ),
    "aws_secret_access_key": (
        re.compile(r'(?i)aws[_\-\s.]?secret[_\-\s.]?(?:access[_\-\s.]?)?key["\'`\s]*[:=]["\'`\s]*([A-Za-z0-9/+]{40})'),
        "CRITICAL", "AWS Secret Access Key"
    ),
    "aws_mws_key": (
        re.compile(r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
        "HIGH", "AWS MWS Key"
    ),

    # ── GCP ──────────────────────────────────────────────────────────────
    "gcp_service_account_json": (
        re.compile(r'"type"\s*:\s*"service_account"'),
        "CRITICAL", "GCP Service Account JSON"
    ),
    "gcp_api_key": (
        re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
        "HIGH", "Google/GCP API Key"
    ),
    "google_oauth_client": (
        re.compile(r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'),
        "MEDIUM", "Google OAuth Client ID"
    ),
    "google_oauth_secret": (
        re.compile(r'(?i)client[_\-]?secret["\'`\s]*[:=]["\'`\s]*([A-Za-z0-9\-_]{24,})'),
        "HIGH", "Google OAuth Client Secret"
    ),

    # ── Stripe ───────────────────────────────────────────────────────────
    "stripe_secret_live": (
        re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),
        "CRITICAL", "Stripe Live Secret Key"
    ),
    "stripe_secret_test": (
        re.compile(r'sk_test_[0-9a-zA-Z]{24,}'),
        "MEDIUM", "Stripe Test Secret Key"
    ),
    "stripe_publishable_live": (
        re.compile(r'pk_live_[0-9a-zA-Z]{24,}'),
        "MEDIUM", "Stripe Live Publishable Key"
    ),
    "stripe_restricted": (
        re.compile(r'rk_live_[0-9a-zA-Z]{24,}'),
        "HIGH", "Stripe Restricted Key"
    ),

    # ── GitHub ───────────────────────────────────────────────────────────
    "github_pat_fine": (
        re.compile(r'github_pat_[A-Za-z0-9_]{82}'),
        "CRITICAL", "GitHub Fine-Grained PAT"
    ),
    "github_pat_classic": (
        re.compile(r'ghp_[A-Za-z0-9_]{36,}'),
        "HIGH", "GitHub Classic PAT"
    ),
    "github_oauth_token": (
        re.compile(r'gho_[A-Za-z0-9_]{36,}'),
        "HIGH", "GitHub OAuth Token"
    ),
    "github_actions_token": (
        re.compile(r'ghs_[A-Za-z0-9_]{36,}'),
        "HIGH", "GitHub Actions Token"
    ),
    "github_refresh_token": (
        re.compile(r'ghr_[A-Za-z0-9_]{36,}'),
        "HIGH", "GitHub Refresh Token"
    ),
    "github_legacy_token": (
        re.compile(r'(?i)github[_\-\s.]?(?:api[_\-\s.]?)?token["\'`\s]*[:=]["\'`\s]*([a-f0-9]{40})'),
        "HIGH", "GitHub Legacy Token"
    ),

    # ── Slack ────────────────────────────────────────────────────────────
    "slack_bot_token": (
        re.compile(r'xoxb-[0-9A-Za-z\-]{24,}'),
        "HIGH", "Slack Bot Token"
    ),
    "slack_user_token": (
        re.compile(r'xoxp-[0-9A-Za-z\-]{72,}'),
        "HIGH", "Slack User Token"
    ),
    "slack_app_token": (
        re.compile(r'xapp-[0-9]-[A-Z0-9]+-[0-9]+-[a-f0-9]+'),
        "HIGH", "Slack App Token"
    ),
    "slack_webhook": (
        re.compile(r'https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8,}/B[A-Za-z0-9_]{8,}/[A-Za-z0-9_]{24,}'),
        "HIGH", "Slack Webhook URL"
    ),

    # ── Twilio ───────────────────────────────────────────────────────────
    # FIX: Added word boundary + requires "account" context to reduce false positives.
    # Raw `AC[a-f0-9]{32}` matches any 34-char hex string starting AC.
    "twilio_account_sid": (
        re.compile(r'(?i)(?:account[_\-\s.]?sid|accountSid|TWILIO[_\-\s.]?ACCOUNT[_\-\s.]?SID)["\'\s`]*[:=]["\'`\s]*\b(AC[a-f0-9]{32})\b'),
        "HIGH", "Twilio Account SID"
    ),
    "twilio_auth_token": (
        re.compile(r'(?i)twilio[_\-\s.]?(?:auth[_\-\s.]?)?token["\'`\s]*[:=]["\'`\s]*([a-f0-9]{32})'),
        "HIGH", "Twilio Auth Token"
    ),

    # ── SendGrid ─────────────────────────────────────────────────────────
    "sendgrid_api_key": (
        re.compile(r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}'),
        "HIGH", "SendGrid API Key"
    ),

    # ── Mailchimp ────────────────────────────────────────────────────────
    "mailchimp_api_key": (
        re.compile(r'[0-9a-f]{32}-us[0-9]{1,2}'),
        "MEDIUM", "Mailchimp API Key"
    ),

    # ── JWT ──────────────────────────────────────────────────────────────
    "jwt_token": (
        re.compile(r'eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]+'),
        "HIGH", "JSON Web Token (JWT)"
    ),

    # ── Private Keys ─────────────────────────────────────────────────────
    "private_key_rsa": (
        re.compile(r'-----BEGIN (?:RSA )?PRIVATE KEY-----'),
        "CRITICAL", "RSA Private Key"
    ),
    "private_key_ec": (
        re.compile(r'-----BEGIN EC PRIVATE KEY-----'),
        "CRITICAL", "EC Private Key"
    ),
    "private_key_openssh": (
        re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'),
        "CRITICAL", "OpenSSH Private Key"
    ),
    "pgp_private_key": (
        re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
        "CRITICAL", "PGP Private Key"
    ),

    # ── Firebase ─────────────────────────────────────────────────────────
    "firebase_url": (
        re.compile(r'https://[a-zA-Z0-9\-]+\.firebaseio\.com'),
        "MEDIUM", "Firebase Realtime DB URL"
    ),
    "firebase_api_key": (
        re.compile(r'(?i)firebase[_\-\s.]?(?:api[_\-\s.]?)?key["\'`\s]*[:=]["\'`\s]*([A-Za-z0-9\-_]{35,45})'),
        "MEDIUM", "Firebase API Key"
    ),

    # ── Heroku ───────────────────────────────────────────────────────────
    "heroku_api_key": (
        re.compile(r'(?i)heroku[_\-\s.]?(?:api[_\-\s.]?)?key["\'`\s]*[:=]["\'`\s]*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'),
        "HIGH", "Heroku API Key"
    ),

    # ── Database URLs ────────────────────────────────────────────────────
    "database_url_postgres": (
        re.compile(r'postgres(?:ql)?://[^\s"\'<>]+'),
        "CRITICAL", "PostgreSQL Connection String"
    ),
    "database_url_mysql": (
        re.compile(r'mysql://[^\s"\'<>]+'),
        "CRITICAL", "MySQL Connection String"
    ),
    "database_url_mongodb": (
        re.compile(r'mongodb(?:\+srv)?://[^\s"\'<>]+'),
        "CRITICAL", "MongoDB Connection String"
    ),
    "database_url_redis": (
        re.compile(r'redis(?:s)?://[^\s"\'<>]+'),
        "HIGH", "Redis Connection String"
    ),

    # ── Hardcoded Credentials ────────────────────────────────────────────
    "hardcoded_password": (
        re.compile(r'(?i)(?:password|passwd|pwd)["\'`\s]*[:=]["\'`\s]*([^\s"\'`{}<>]{8,64})'),
        "HIGH", "Hardcoded Password"
    ),
    "hardcoded_secret": (
        re.compile(r'(?i)(?:secret|api_secret|client_secret)["\'`\s]*[:=]["\'`\s]*([^\s"\'`{}<>]{16,})'),
        "HIGH", "Hardcoded Secret Value"
    ),

    # ── Internal Network ─────────────────────────────────────────────────
    "internal_ip_rfc1918": (
        re.compile(r'(?<![.\d])(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?![.\d])'),
        "MEDIUM", "Internal/Private IP Address"
    ),
    "staging_endpoint": (
        re.compile(r'(?i)https?://(?:staging|dev|test|internal|admin|qa|uat)\.[^\s"\'<>]+'),
        "LOW", "Staging/Internal Endpoint"
    ),
    "localhost_url": (
        re.compile(r'(?i)https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?[^\s"\'<>]*'),
        "LOW", "Localhost URL"
    ),

    # ── OpenAI ───────────────────────────────────────────────────────────
    # FIX: Original `sk-(?:proj-)?[A-Za-z0-9\-_]{20,}` was too broad — matched any
    # 20-char `sk-` string. New pattern requires:
    #   - Legacy format: `sk-` + exactly 48 alphanumeric chars (no proj-)
    #   - Project format: `sk-proj-` + 80+ chars (new API key format)
    # This eliminates false positives from common `sk-` prefixed CSS/HTML tokens.
    "openai_api_key": (
        re.compile(r'sk-(?:proj-[A-Za-z0-9\-_]{80,}|[A-Za-z0-9]{48})(?![A-Za-z0-9\-_])'),
        "CRITICAL", "OpenAI API Key"
    ),
    "anthropic_api_key": (
        re.compile(r'sk-ant-[A-Za-z0-9\-_]{90,}'),
        "CRITICAL", "Anthropic API Key"
    ),

    # ── Telegram ─────────────────────────────────────────────────────────
    "telegram_bot_token": (
        re.compile(r'\d{8,10}:[A-Za-z0-9_\-]{35}'),
        "HIGH", "Telegram Bot Token"
    ),

    # ── Cloudflare ───────────────────────────────────────────────────────
    "cloudflare_api_key": (
        re.compile(r'(?i)cloudflare[_\-\s.]?(?:api[_\-\s.]?)?(?:key|token)["\'`\s]*[:=]["\'`\s]*([A-Za-z0-9_\-]{37,})'),
        "HIGH", "Cloudflare API Key"
    ),

    # ── Supabase ─────────────────────────────────────────────────────────
    "supabase_service_key": (
        re.compile(r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+'),
        "HIGH", "Possible Supabase Service/Anon Key (JWT)"
    ),
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

CLOUD_METADATA_ENDPOINTS = {
    "aws": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
        "http://169.254.169.254/latest/meta-data/hostname",
    ],
    "gcp": [
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        "http://169.254.169.254/computeMetadata/v1/",
    ],
    "azure": [
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    ],
    "alibaba": [
        "http://100.100.100.200/latest/meta-data/",
        "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
    ],
    "docker": [
        "http://172.17.0.1/",
        "http://172.18.0.1/",
        "http://172.19.0.1/",
    ],
    "kubernetes": [
        "http://kubernetes.default.svc/api/v1/",
        "https://kubernetes.default.svc/api/",
        "http://10.96.0.1/api/v1/namespaces/",
    ],
    "localhost": [
        "http://localhost/",
        "http://127.0.0.1/",
        "http://0.0.0.0/",
        "http://[::1]/",
        "http://localhost:8080/",
        "http://localhost:8000/",
        "http://localhost:3000/",
        "http://localhost:5000/",
    ],
}

# Indicators that suggest SSRF triggered
SSRF_RESPONSE_INDICATORS = [
    # AWS
    "ami-id", "instance-id", "instance-type", "security-credentials",
    "iam/security-credentials", "placement/", "local-hostname",
    # GCP
    "computemetadata", "service-accounts", "project-id", "google",
    # Azure
    "azurevirtualmachine", "compute/subscriptionId",
    # Generic
    "meta-data", "metadata", "169.254",
]
