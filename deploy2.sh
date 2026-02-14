#!/usr/bin/env bash
set -euo pipefail

# =========================================================
# Zirna Cietoksnis v4 - priekš - Debian 13
# =========================================================

APP_USER="${APP_USER:-zirnis}"
PROJECT_NAME="${PROJECT_NAME:-zirna-cietoksnis}"
PROJECT_DIR="/home/${APP_USER}/${PROJECT_NAME}"

CERT_C="${CERT_C:-LV}"
CERT_ST="${CERT_ST:-Smiltene}"
CERT_L="${CERT_L:-Smiltene}"
CERT_O="${CERT_O:-ZirnaCietoksnis}"
CERT_OU="${CERT_OU:-IT}"
CERT_CN="${CERT_CN:-localhost}"

log()  { echo -e "\n\033[1;32m[INFO]\033[0m $*"; }
warn() { echo -e "\n\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\n\033[1;31m[ERR ]\033[0m $*"; }

if [[ "${EUID}" -ne 0 ]]; then
  err "Palaid ar root tiesībām: sudo bash deploy.sh"
  exit 1
fi

if ! command -v apt >/dev/null 2>&1; then
  err "Šis skripts paredzēts Debian/Ubuntu ar apt."
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

# ---------------------------------------------------------
# 1) Apdeits pirms lielā darba
# ---------------------------------------------------------
log "Atjauninu pakotņu sarakstu un uzlieku bāzes rīkus..."
apt update -y
apt install -y ca-certificates curl gnupg ufw openssl

# ---------------------------------------------------------
# 2) Izveidot lietotāju
# ---------------------------------------------------------
USER_CREATED="false"

if id "${APP_USER}" >/dev/null 2>&1; then
  log "Lietotājs '${APP_USER}' jau eksistē."
else
  log "Veidoju lietotāju '${APP_USER}'..."
  adduser --disabled-password --gecos "" "${APP_USER}"
  USER_CREATED="true"
fi

log "Pievienoju '${APP_USER}' sudo grupai..."
usermod -aG sudo "${APP_USER}"

# Ja lietotājs tikko izveidots, prasa iestatīt paroli
if [[ "${USER_CREATED}" == "true" ]]; then
  echo
  log "Iestati paroli lietotājam '${APP_USER}' (nepieciešama sudo komandām):"
  passwd "${APP_USER}"
fi


# ---------------------------------------------------------
# 3) Docker install
# ---------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  log "Instalēju Docker repo un Docker Engine..."
  install -m 0755 -d /etc/apt/keyrings

  if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
    curl -fsSL https://download.docker.com/linux/debian/gpg \
      | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
  fi

  CODENAME="$(. /etc/os-release && echo "${VERSION_CODENAME}")"
  ARCH="$(dpkg --print-architecture)"
  echo "deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian ${CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list

  apt update -y
  apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
else
  log "Docker jau uzinstalēts."
fi

log "Aktivizēju docker servisu..."
systemctl enable --now docker

log "Pievienoju '${APP_USER}' docker grupai..."
usermod -aG docker "${APP_USER}"

# ---------------------------------------------------------
# 4) Firewall (UFW)
# ---------------------------------------------------------
log "Konfigurēju UFW (22/80/443)..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

# ---------------------------------------------------------
# 5) Projekta izkārtojums
# ---------------------------------------------------------
log "Veidoju projekta mapes: ${PROJECT_DIR}"
install -d -o "${APP_USER}" -g "${APP_USER}" "${PROJECT_DIR}/nginx"
install -d -o "${APP_USER}" -g "${APP_USER}" "${PROJECT_DIR}/certs"
install -d -o "${APP_USER}" -g "${APP_USER}" "${PROJECT_DIR}/scripts"

# ---------------------------------------------------------
# 6) TLS cert (self-signed)
# ---------------------------------------------------------
CRT="${PROJECT_DIR}/certs/selfsigned.crt"
KEY="${PROJECT_DIR}/certs/selfsigned.key"

if [[ -f "${CRT}" && -f "${KEY}" ]]; then
  log "Self-signed sertifikāts jau eksistē."
else
  log "Ģenerēju self-signed sertifikātu..."
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "${KEY}" \
    -out "${CRT}" \
    -subj "/C=${CERT_C}/ST=${CERT_ST}/L=${CERT_L}/O=${CERT_O}/OU=${CERT_OU}/CN=${CERT_CN}"
  chmod 600 "${KEY}"
  chmod 644 "${CRT}"
  chown "${APP_USER}:${APP_USER}" "${KEY}" "${CRT}"
fi

# ---------------------------------------------------------
# 7) docker-compose.yml
# ---------------------------------------------------------
log "Rakstu docker-compose.yml..."
cat > "${PROJECT_DIR}/docker-compose.yml" <<'YAML'
services:
  backend:
    image: hashicorp/http-echo:1.0.0
    container_name: zirna_backend
    command: ["-listen=:8080", "-text={\"status\":\"ok\"}"]
    expose:
      - "8080"
    restart: unless-stopped

  nginx:
    image: nginx:1.27-alpine
    container_name: zirna_nginx
    depends_on:
      - backend
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/default.conf:/etc/nginx/conf.d/default.conf:ro
      - ./certs:/etc/nginx/certs:ro
    restart: unless-stopped
YAML

# ---------------------------------------------------------
# 8) Nginx config
# ---------------------------------------------------------
CONF="${PROJECT_DIR}/nginx/default.conf"
if [[ -f "${CONF}" ]]; then
  TS="$(date +%F_%H-%M-%S)"
  cp "${CONF}" "${CONF}.bak.${TS}"
  log "Backup izveidots: ${CONF}.bak.${TS}"
fi

log "Rakstu Nginx reverse proxy konfigurāciju..."
cat > "${CONF}" <<'NGINX'
# =========================================
# Zirna Cietoksnis v4 - Reverse Proxy
# Logs -> Docker stdout/stderr
# =========================================

log_format main_ext '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    'host="$host" ref="$http_referer" ua="$http_user_agent" '
                    'xff="$http_x_forwarded_for" '
                    'rt=$request_time '
                    'ua_addr="$upstream_addr" ua_status="$upstream_status" '
                    'uct=$upstream_connect_time uht=$upstream_header_time urt=$upstream_response_time';

server {
    listen 80;
    listen [::]:80;
    server_name _;

    access_log /dev/stdout main_ext;
    error_log  /dev/stderr warn;

    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name _;

    ssl_certificate     /etc/nginx/certs/selfsigned.crt;
    ssl_certificate_key /etc/nginx/certs/selfsigned.key;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    access_log /dev/stdout main_ext;
    error_log  /dev/stderr warn;

    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "no-referrer" always;
    add_header X-XSS-Protection "1; mode=block" always;

    location = /health {
        proxy_pass http://backend:8080/;
        proxy_http_version 1.1;

        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        proxy_connect_timeout 3s;
        proxy_read_timeout 5s;
        proxy_send_timeout 5s;
    }

    location = / {
        default_type application/json;
        return 200 '{"service":"zirna-cietoksnis","reverse_proxy":"enabled","version":"v4"}';
    }
}
NGINX

# ---------------------------------------------------------
# 9) Health check script
# ---------------------------------------------------------
log "Rakstu health_check.sh..."
cat > "${PROJECT_DIR}/scripts/health_check.sh" <<'HC'
#!/usr/bin/env bash
set -u

URL="${1:-https://127.0.0.1/health}"
TIMEOUT="${TIMEOUT:-5}"

TMP_BODY="$(mktemp)"
trap 'rm -f "$TMP_BODY"' EXIT
TS="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

HTTP_CODE="$(curl -k -sS --max-time "$TIMEOUT" -o "$TMP_BODY" -w "%{http_code}" "$URL" || echo "000")"
BODY="$(cat "$TMP_BODY" 2>/dev/null || true)"

if [[ "$HTTP_CODE" == "200" ]] && echo "$BODY" | grep -Eq '"status"[[:space:]]*:[[:space:]]*"ok"'; then
  echo "[$TS] OK - health check passed | url=$URL http_code=$HTTP_CODE body=$BODY"
  exit 0
else
  echo "[$TS] CRITICAL - health check failed | url=$URL http_code=$HTTP_CODE body=$BODY"
  exit 2
fi
HC

chmod +x "${PROJECT_DIR}/scripts/health_check.sh"

# ownership
chown -R "${APP_USER}:${APP_USER}" "/home/${APP_USER}/${PROJECT_NAME}"

# ---------------------------------------------------------
# 10) Deploy stack
# ---------------------------------------------------------
log "Palaižu Docker Compose stack..."
su - "${APP_USER}" -c "cd '${PROJECT_DIR}' && docker compose down || true"
su - "${APP_USER}" -c "cd '${PROJECT_DIR}' && docker compose up -d --force-recreate"

log "Pārbaudu nginx config konteinerā..."
docker exec -i zirna_nginx nginx -t

log "Konteineru statuss:"
su - "${APP_USER}" -c "cd '${PROJECT_DIR}' && docker compose ps"

# ---------------------------------------------------------
# 11) Smoke test (ģenerē arī logu rindas)
# ---------------------------------------------------------
IP="$(hostname -I | awk '{print $1}')"
log "Veicu ātro smoke test..."
curl -ksS "https://${IP}/health" >/dev/null || true
curl -ksSI "http://${IP}/health" >/dev/null || true

# ---------------------------------------------------------
# 12) Output
# ---------------------------------------------------------
cat <<EOF

✅ Deploy pabeigts!

Projekts:
  ${PROJECT_DIR}

Ātrie testi:
  curl -k https://${IP}/health
  curl -kL http://${IP}/health
  openssl s_client -connect ${IP}:443 -tls1 </dev/null
  openssl s_client -connect ${IP}:443 -tls1_2 </dev/null

Monitoring:
  ${PROJECT_DIR}/scripts/health_check.sh "https://${IP}/health"

Reverse proxy logi (Nginx):
  docker logs zirna_nginx --tail 50
  docker logs -f zirna_nginx

Servisa logi (Backend):
  docker logs zirna_backend --tail 50

Kur glabājas Docker log faili:
  docker inspect -f '{{.LogPath}}' zirna_nginx
  docker inspect -f '{{.LogPath}}' zirna_backend

Svarīgi:
- Lietotājam '${APP_USER}' ir SSH key login (ja authorized_keys tika nokopēts).
- Ja gribi sudo ar paroli lietotājam '${APP_USER}', uzstādi:
    sudo passwd ${APP_USER}
- Lai docker grupa stātos spēkā jaunajam lietotājam, pārlogo SSH sesiju.
EOF
