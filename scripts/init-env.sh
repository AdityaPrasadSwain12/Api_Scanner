#!/usr/bin/env sh
set -eu
if [ -f .env ] && [ "${1:-}" != "--force" ]; then
  echo ".env already exists; pass --force to replace it" >&2
  exit 1
fi
random_value() { openssl rand -base64 32 | tr '+/' '-_' | tr -d '\n'; }
cat > .env <<EOF
ENVIRONMENT=development
POSTGRES_PASSWORD=$(random_value)
SCANNER_API_KEY=$(random_value)
SECRET_ENCRYPTION_KEY=$(random_value)
ENGINE_RUNNER_TOKEN=$(random_value)
ZAP_API_KEY=$(random_value)
ALLOWED_TARGETS=vulnerable-api,host.docker.internal
ALLOW_PRIVATE_TARGETS=true
TARGET_SCOPE_MODE=deployment_allowlist
DASHBOARD_AUTH_MODE=api_key
EOF
chmod 600 .env
echo "Created .env"
