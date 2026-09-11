#!/bin/bash
# Kurukshetra Honeypot — Google Cloud VM one-time setup
# Run on fresh Ubuntu 22.04 VM: bash gcp-vm-setup.sh
set -euo pipefail

echo "=== Kurukshetra GCP VM Setup ==="

# 1. System updates
sudo apt-get update -y
sudo apt-get upgrade -y

# 2. Docker
if ! command -v docker &>/dev/null; then
  curl -fsSL https://get.docker.com | sudo sh
  sudo usermod -aG docker "$USER" || true
fi

sudo apt-get install -y docker-compose-plugin git ufw

# 3. Firewall — honeypot ports only (SSH honeypot on 2222, NOT 22)
sudo ufw allow 22/tcp
sudo ufw allow 2222/tcp
sudo ufw allow 8080/tcp
sudo ufw --force enable

# 4. App directory
APP_DIR="${HOME}/kurukshetra-honeypot"
if [ ! -d "$APP_DIR" ]; then
  echo "Clone your repo into $APP_DIR or copy project files there."
  mkdir -p "$APP_DIR"
fi

cd "$APP_DIR"

# 5. Environment from example
if [ ! -f .env ]; then
  cp .env.example .env
  EXTERNAL_IP=$(curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip 2>/dev/null || hostname -I | awk '{print $1}')
  sed -i "s/YOUR_GCP_VM_EXTERNAL_IP/${EXTERNAL_IP}/" .env
  echo "Created .env with HONEYPOT_TARGET_IP=${EXTERNAL_IP}"
fi

# 6. Build & start
docker compose up -d --build

echo ""
echo "=== Deployment Complete ==="
echo "SSH Honeypot:  ssh root@${EXTERNAL_IP:-YOUR_IP} -p 2222"
echo "Web Portal:    http://${EXTERNAL_IP:-YOUR_IP}:8080/login"
echo "API Surface:   http://${EXTERNAL_IP:-YOUR_IP}:8080/api/swagger.json"
echo "Backend:       https://kurukshetra-backend.onrender.com"
echo ""
echo "Run attacks from Parrot OS: python attack.py --target ${EXTERNAL_IP:-YOUR_IP} --scenario mixed --loop"
