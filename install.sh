#!/data/data/com.termux/files/usr/bin/bash
# RXHUNT — Install Script for Termux
# Usage: bash install.sh

set -e

echo ""
echo "  ██████╗ ██╗  ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗"
echo "  ██╔══██╗╚██╗██╔╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝"
echo "  ██████╔╝ ╚███╔╝ ███████║██║   ██║██╔██╗ ██║   ██║   "
echo "  ██╔══██╗ ██╔██╗ ██╔══██║██║   ██║██║╚██╗██║   ██║   "
echo "  ██║  ██║██╔╝ ██╗██║  ██║╚██████╔╝██║ ╚████║   ██║   "
echo "  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝  "
echo ""
echo "  RXHUNT v1.0.0 — Install for Termux"
echo ""

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "[*] Installing Python..."
    pkg install python -y
fi

# Upgrade pip
echo "[*] Upgrading pip..."
#pip install --upgrade pip --break-system-packages --quiet

# Install deps
echo "[*] Installing dependencies..."
pip install httpx beautifulsoup4 click rich --break-system-packages --quiet

# Make executable
chmod +x rxhunt.py

echo ""
echo "  [OK] Installation complete."
echo ""
echo "  Usage:"
echo "    python rxhunt.py harvest https://target.com"
echo "    python rxhunt.py probe   https://target.com --param url"
echo "    python rxhunt.py scan    https://target.com --param redirect --listen"
echo ""
echo "  For full help:"
echo "    python rxhunt.py --help"
echo "    python rxhunt.py harvest --help"
echo ""
