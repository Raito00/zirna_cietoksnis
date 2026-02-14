#!/usr/bin/env bash
set -euo pipefail

# =========================================================
# Zirna Cietoksnis v5 - Debian 13 one-shot deploy
# - Izveido lietotāju (zirnis), jautā izveidot paroli
# - kopē root authorized_keys -> zirnis
# - installs Docker + Compose
# - configures UFW (22/80/443)
# - deploys nginx reverse proxy + backend
# - enables TLS1.2/1.3, HTTP->HTTPS
# - health check script
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

SSH_PORT="${SSH_PORT:-22}"

log()  { echo -e "\n\033[1;32m[INFO]\033[0m $*"; }
warn() { echo -e "\n\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\n\033[1;31m[ERR ]\033[0m $*"; }

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    err "Palaid ar root tiesībām: sudo bash deploy2.sh"
    exit 1
  fi
}

backup_file_if_exists() {
  local f="$1"
  if [[ -f "$f" ]]; then
    local ts
    ts="$(date +%F_%H-%M-%S)"
    cp "$f" "${f}.bak.${ts}"
    log "Backup: ${f}.bak.${ts}"
  fi
}

setup_user_and_ssh() {
  log "Lietotāja un SSH sagatavošana..."
  local user_created="false"

  if id "${APP_USER}" >/dev/null 2>&1; then
    log "Lietotājs '${APP_USER}' jau eksistē."
  else
    log "Veidoju lietotāju '${APP_USER}'..."
    adduser --disabled-password --gecos "" "${APP_USER}"
    user_created="true"
  fi

  usermod -aG sudo "${APP_USER}"

  # .ssh mape
  install -d -m 700 -o "${APP_USER}" -g "${APP_USER}" "/home/${APP_USER}/.ssh"

  # autorizētās atslēgas: kopējam no root, ja pieejams
  if [[ -f /root/.ssh/authorized_keys ]] && [[ -s /root/.ssh/authorized_keys ]]; then
    cp /root/.ssh/authorized_keys "/home/${APP_USER}/.ssh/authorized_keys"
    chown "${APP_USER}:${APP_USER}" "/home/${APP_USER}/.ssh/authorized_keys"
    chmod 600 "/home/${APP_USER}/.ssh/authorized_keys"
    log "Nokopēts /root/.ssh/authorized_keys -> /home/${APP_USER}/.ssh/authorized_keys"
  else
    warn "Nav atrasts /root/.ssh/authorized_keys (vai tas ir tukšs)."
    warn "Pievieno publisko atslēgu manuāli failā /home/${APP_USER}/.ssh/authorized_keys"
    touch "/home/${APP_USER}/.ssh/authorized_keys"
    chown "${APP_USER}:${APP_USER}" "/home/${APP_USER}/.ssh/authorized_keys"
    chmod 600 "/home/${APP_USER}/.ssh/authorized_keys"
  fi

  # parole - tikai ja lietotājs tikko izveidots
  if [[ "${user_created}" == "true" ]]; then
    log "Iestati paroli lietotājam '${APP_USER}' (vajadzīga sudo komandām):"
    passwd "${APP_USER}"
  fi

  # SSHD drošie settingi (key-only + root off)
  backup_file_if_exists /etc/ssh/sshd_config

  # Ja parametri nav failā, pievieno; ja ir, aizvieto
  set_or_append_sshd() {
    local key="$1"
    local val="$2"
    if grep -qiE "^[#[:space:]]*${key}[[:space:]]+" /etc/ssh/sshd_config; then
      sed -i -E "s|^[#[:space:]]*${key}[[:space:]]+.*|${key} ${val}|I" /etc/ssh/sshd_config
    else
      echo "${key} ${val}" >> /etc/ssh/sshd_config
    fi
  }

  set_or_append_sshd "PubkeyAuthentication" "yes"
  set_or_append_sshd "PasswordAuthentication" "no"
  set_or_append_sshd "PermitRootLogin" "no"
  set_or_append_sshd "ChallengeResponseAuthentication" "no"
  set_or_append_sshd "UsePAM" "yes"

  # Ja ir AllowUsers, pievieno APP_USER, ja nav
  if grep -qE '^[[:space:]]*AllowUsers[[:space:]]+' /etc/ssh/sshd_config; then
    if ! grep -qE "^[[:space:]]*AllowUsers[[:space:]].*\b${APP_USER}\b" /etc/ssh/sshd_config; then
      sed -i -E "s|^([[:space:]]*AllowUsers[[:space:]].*)$|\1 ${APP_USER}|" /etc/ssh/sshd_config
      log "Pievienoju '${APP_USER}' pie AllowUsers."
    fi
  fi

  sshd -t
  systemctl restart ssh
  log "SSH konfigurācija atjaunināta un sshd restartēts."
}

install_docker() {
  log "Docker instalācija..."
  apt update -y
  apt install -y ca-certificates curl gnupg lsb-release

  if ! command -v docker >/dev/null 2>&1; then
    install -m 0755 -d /etc/apt/keyrings
    if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
      curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
      chmod a+r /etc/apt/keyrings/docker.gpg
    fi

    local codename arch
    codename="$(. /etc/os-release && echo "${VERSION_CODENAME}")"
    arch="$(dpkg --print-architecture)"
    echo "deb [arch=${arch} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian ${codename} stable" \
      > /etc/apt/sources.list.d/docker.list

    apt update -y
    apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  else
    log "Docker jau uzinstalēts."
  fi

  systemctl enable --now docker
  usermod -aG docker "${APP_USER}"
  log "Docker gatavs."
}

setup_firewall() {
  log "UFW konfigurācija..."
  apt install -y ufw
  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow "${SSH_PORT}/tcp"
  ufw allow 80/tcp
  ufw allow 443/tcp
  ufw --force enable
  ufw status verbose || true
}

write_project_files() {
  log "Veidoju projekta struktūru: ${PROJECT_DIR}"
  install -d -o "${APP_USER}" -g "${APP_USER}" "${PROJECT_DIR}/nginx"
  install -d -o "${APP_USER}" -g "${APP_USER}" "${PROJECT_DIR}/certs"
  install -d -o "${APP_USER}" -g "${APP_USER}" "${PROJECT_DIR}/scripts"

  # cert
  local crt="${PROJECT_DIR}/certs/selfsigned.crt"
  local key="${PROJECT_DIR}/certs/selfsigned.key"

  if [[ -f "${crt}" && -f "${key}" ]]; then
    log "Sertifikāts jau eksistē."
  else
    log "Ģenerēju self-signed sertifikātu..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout "${key}" \
      -out "${crt}" \
      -subj "/C=${CERT_C}/ST=${CERT_ST}/L=${CERT_L}/O=${CERT_O}/OU=${CERT_OU}/CN=${CERT_CN}"
    chmod 600 "${key}"
    chmod 644 "${crt}"
    chown "${APP_USER}:${APP_USER}" "${key}" "${crt}"
  fi

  # compose
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

# nginx conf
backup_file_if_exists "${PROJECT_DIR}/nginx/default.conf"
cat > "${PROJECT_DIR}/nginx/default.conf" <<'NGINX'
log_format main_ext '$remote_addr realip="$http_x_real_ip" xff="$http_x_forwarded_for" '
                    '[$time_local] "$request" $status $body_bytes_sent '
                    'host="$host" ua="$http_user_agent" '
                    'rt=$request_time ua_addr="$upstream_addr" ua_status="$upstream_status" '
                    'uct=$upstream_connect_time uht=$upstream_header_time urt=$upstream_response_time';

server {
    listen 80;
    listen [::]:80;
    server_name _;

    access_log /var/log/nginx/access.log main_ext;
    error_log  /var/log/nginx/error.log warn;

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

    access_log /var/log/nginx/access.log main_ext;
    error_log  /var/log/nginx/error.log warn;

    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "no-referrer" always;
    add_header X-XSS-Protection "1; mode=block" always;

    location = /health {
        proxy_pass http://backend:8080/;
        add_header Content-Type application/json always;
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
        return 200 '{"service":"zirna-cietoksnis","reverse_proxy":"enabled","version":"v6"}';
    }
}
NGINX

  # health check
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

  chown -R "${APP_USER}:${APP_USER}" "/home/${APP_USER}"
}

deploy_stack() {
  log "Palaižu stack..."
  su - "${APP_USER}" -c "cd '${PROJECT_DIR}' && docker compose down || true"
  su - "${APP_USER}" -c "cd '${PROJECT_DIR}' && docker compose up -d --force-recreate"

  docker exec -i zirna_nginx nginx -t
  su - "${APP_USER}" -c "cd '${PROJECT_DIR}' && docker compose ps"
}

smoke_test() {
  local ip
  ip="$(hostname -I | awk '{print $1}')"

  log "Veicu smoke test..."
  curl -ksS "https://${ip}/health" >/dev/null
  curl -ksSI "http://${ip}/health" >/dev/null

  # mazs trafiks logiem
  curl -ksS "https://${ip}/" >/dev/null || true

  cat <<EOF

✅ Deploy pabeigts veiksmīgi.

Projektu faili:
  ${PROJECT_DIR}

Ātrie testi:
  curl -k https://${ip}/health
  curl -kL http://${ip}/health
  openssl s_client -connect ${ip}:443 -tls1 </dev/null
  openssl s_client -connect ${ip}:443 -tls1_2 </dev/null

Monitoring:
  ${PROJECT_DIR}/scripts/health_check.sh "https://${ip}/health"

Reverse proxy logi:
  docker logs zirna_nginx --tail 50
  docker logs -f zirna_nginx

Servisa logi:
  docker logs zirna_backend --tail 50

Kur glabājas Docker log faili:
  docker inspect -f '{{.LogPath}}' zirna_nginx
  docker inspect -f '{{.LogPath}}' zirna_backend

SVARĪGI:
- Pārlogo SSH sesiju, lai docker grupas izmaiņas stātos spēkā.
- Pārbaudi SSH login no JAUNA termināļa:
    ssh ${APP_USER}@<server_ip>
- Tikai pēc tam droši aizver root sesiju.
EOF
}

main() {
  require_root
  setup_user_and_ssh
  install_docker
  setup_firewall
  write_project_files
  deploy_stack
  smoke_test
}

main "$@"
