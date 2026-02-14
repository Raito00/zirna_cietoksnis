# Zirņa Cietoksnis 🫛🏰

## Kopsavilkums
Šajā risinājumā:
- Linux vide: **Debian 13 VM**
- Web serviss: uz **iekšējā porta 8080**
- Reverse proxy: **Nginx** uz 80/443
- HTTPS ar **self-signed** sertifikātu
- HTTP tiek pāradresēts uz HTTPS
- TLS 1.0/1.1 atspējots (atļauts TLS 1.2/1.3)
- Drošība ar UFW (atļauti tikai 22/80/443)
- Logging: reverse proxy + servisa logi
- Monitorings: `health_check.sh`

## Palaišana
```bash
sudo apt update && sudo apt install -y git
git clone https://github.com/Raito00/zirna_cietoksnis.git
cd zirna_cietoksnis
chmod +x install.sh
sudo ./install.sh
```

## 1) Linux serveris (VM / Docker vide)
Izvietots uz Debian 13 VM, servisi darbojas Docker konteineros.

### Pārbaude
```bash
whoami
hostnamectl
docker --version
docker compose version
```

---

## 2) Vienkāršs web serviss
Backend serviss klausās uz iekšējā porta `8080` un atgriež JSON:

`GET /health` → `{"status":"ok"}`

### Pārbaude GET /health
```bash
cd ~/zirna-cietoksnis
docker compose ps
curl -k https://89.167.48.65/health
```

---

## 3) Reverse proxy un TLS
Nginx:
- publicē servisu uz HTTPS (443)
- izmanto self-signed sertifikātu
- piespiež HTTP → HTTPS
- TLS 1.0/1.1 ir atspējots

### Pārbaude
```bash
curl -I http://89.167.48.65/health
curl -k https://89.167.48.65/health
curl -kL http://89.167.48.65/health
```

TLS testi:
```bash
openssl s_client -connect 89.167.48.65:443 -tls1 </dev/null
openssl s_client -connect 89.167.48.65:443 -tls1_1 </dev/null
openssl s_client -connect 89.167.48.65:443 -tls1_2 </dev/null
```

---

## 4) Drošība
- UFW firewall konfigurēts
- Atļauti tikai porti: `22`, `80`, `443`
- Backend 8080 nav publiski atvērts

### Pārbaude
```bash
sudo ufw status verbose
docker inspect zirna_backend --format '{{json .HostConfig.PortBindings}}'
```

---

## 5) Logging
- Reverse proxy logi: `docker logs zirna_nginx`
- Servisa logi: `docker logs zirna_backend`
- Fiziskie log faili hostā: `docker inspect -f '{{.LogPath}}' ...`

### Pārbaude
```bash
curl -k https://89.167.48.65/health >/dev/null
docker logs zirna_nginx --since 2m
docker logs zirna_backend --since 2m
docker inspect -f '{{.LogPath}}' zirna_nginx
docker inspect -f '{{.LogPath}}' zirna_backend
```

---

## 6) Monitoring
Izveidots health check skripts:

`~/zirna-cietoksnis/scripts/health_check.sh`

- `0` = OK
- `2` = CRITICAL

### Pārbaude
```bash
~/zirna-cietoksnis/scripts/health_check.sh "https://89.167.48.65/health"
echo $?
```

Kļūmes simulācija:
```bash
docker stop zirna_backend
~/zirna-cietoksnis/scripts/health_check.sh "https://89.167.48.65/health"
echo $?
docker start zirna_backend
~/zirna-cietoksnis/scripts/health_check.sh "https://89.167.48.65/health"
echo $?
```

---

## 7) Video zvana demonstrācija (checklist)

### A) Vide
```bash
whoami
hostnamectl
cd ~/zirna-cietoksnis
docker compose ps
```

### B) Testēšana
```bash
curl -k https://89.167.48.65/health
curl -I http://89.167.48.65/health
curl -kL http://89.167.48.65/health
```

### C) Restart
```bash
docker compose restart
docker compose ps
```

### D) Health check
```bash
~/zirna-cietoksnis/scripts/health_check.sh "https://89.167.48.65/health"
echo $?
```
