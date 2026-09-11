#!/bin/bash
# Quick restart on GCP VM after config changes
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose down
docker compose up -d --build
docker compose logs -f honeypot-server
