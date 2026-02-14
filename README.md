# Zirņa Cietoksnis 🫛🏰

Automātisks deploy skripts Debian 13 VM:
- izveido lietotāju `zirnis`
- uzinstalē Docker + Compose
- konfigurē UFW (22/80/443)
- uzceļ Nginx reverse proxy + backend
- uzstāda HTTPS (self-signed)
- izveido health check skriptu

## Palaišana
```bash
chmod +x deploy.sh
sudo ./deploy.sh
