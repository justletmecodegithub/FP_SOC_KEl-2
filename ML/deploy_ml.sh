#!/bin/bash
# ===========================================================================
# deploy_ml.sh — Setup script for VM-ML (run on 20.41.107.48 as azureuser)
# Installs Python, creates venv, installs deps, sets up systemd service
# ===========================================================================
set -euo pipefail

APP_DIR="/home/azureuser/ml-api"
VENV_DIR="$APP_DIR/venv"
SERVICE_NAME="ml-api"

echo "=== [1/6] Updating system packages ==="
sudo apt-get update -y
sudo apt-get install -y python3 python3-pip python3-venv curl

echo "=== [2/6] Creating app directory ==="
mkdir -p "$APP_DIR"

echo "=== [3/6] Creating Python virtual environment ==="
python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

echo "=== [4/6] Installing Python dependencies ==="
pip install --upgrade pip
pip install -r "$APP_DIR/requirements.txt"

echo "=== [5/6] Setting up systemd service ==="
sudo tee /etc/systemd/system/${SERVICE_NAME}.service > /dev/null <<EOF
[Unit]
Description=Wazuh ML Alert Classifier API
After=network.target

[Service]
Type=simple
User=azureuser
WorkingDirectory=${APP_DIR}
ExecStart=${VENV_DIR}/bin/uvicorn main:app --host 0.0.0.0 --port 8000 --workers 2
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable ${SERVICE_NAME}
sudo systemctl restart ${SERVICE_NAME}

echo "=== [6/6] Verifying ==="
sleep 3
sudo systemctl status ${SERVICE_NAME} --no-pager || true
echo ""
echo "Testing health endpoint..."
curl -s http://localhost:8000/health | python3 -m json.tool || echo "(API may still be starting...)"
echo ""
echo "=== DEPLOY COMPLETE ==="
echo "FastAPI running on http://0.0.0.0:8000"
echo "Check logs: journalctl -u ml-api -f"
