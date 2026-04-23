#!/bin/bash
# setup_agent.sh - Install log agent dependencies on victim VMs
# Usage: sudo bash setup_agent.sh

set -e

echo "=================================================="
echo "  Cloud Security Lab - Log Agent Setup"
echo "=================================================="

if [ "$EUID" -ne 0 ]; then
    echo "[!] Run as root: sudo bash setup_agent.sh"
    exit 1
fi

echo "[*] Installing auditd..."
apt update -q
apt install -y auditd audispd-plugins bpftool

echo "[*] Configuring auditd bpf() monitoring rule..."
cat > /etc/audit/rules.d/lab-monitor.rules << 'EOF'
# Monitor bpf() syscall - eBPF injection detection
-a always,exit -F arch=b64 -S bpf -k bpf_call
-a always,exit -F arch=b32 -S bpf -k bpf_call
EOF

service auditd restart
echo "[+] auditd configured"

echo "[*] Installing Python dependencies..."
apt install -y python3-pip
pip3 install psutil 2>/dev/null || true

echo ""
echo "=================================================="
echo "[+] Log agent setup complete!"
echo "=================================================="
echo ""
echo "Run the agent with:"
echo "  sudo python3 log_agent.py"
echo ""
echo "Make sure the central collector (10.10.0.20) is running first."
