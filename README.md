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
sudo apt update && sudo apt install -y git
git clone https://github.com/Raito00/zirna_cietoksnis.git
cd zirna_cietoksnis
chmod +x install.sh
sudo ./install.sh
