"""Constants for Cloudflare mTLS."""

DOMAIN = "cloudflare_mtls"

CONF_API_TOKEN = "api_token"
CONF_ZONE_ID = "zone_id"
CONF_ZONE_NAME = "zone_name"
CONF_ACCOUNT_ID = "account_id"
CONF_HOSTNAME = "hostname"

CERT_DAYS = 3650

LINK_TTL = 24 * 3600
# Browsers and download managers may fetch the file more than once
DOWNLOAD_GRACE = 600
# The app sends its push token shortly after registering
NOTIFY_WAIT = 360

ENROLL_PATH = "/api/cloudflare_mtls/enroll"

ISSUE_BROAD_TOKEN = "broad_token"
ISSUE_MTLS_OFF = "mtls_not_enabled"
