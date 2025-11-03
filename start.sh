#!/usr/bin/env bash
set -euo pipefail

# Generate minimal torrc that listens on localhost
cat > /etc/tor/torrc <<'EOF'
SocksPort 127.0.0.1:9050
ControlPort 127.0.0.1:9051
CookieAuthentication 0
Log notice stdout
EOF

# Start Tor in background
/usr/bin/tor -f /etc/tor/torrc &

# Wait for Tor SOCKS to be ready
echo "Waiting for Tor SOCKS to be ready..."
for i in {1..30}; do
  if nc -z 127.0.0.1 9050 2>/dev/null; then
    echo "✓ Tor SOCKS is up and ready"
    break
  fi
  if [ $i -eq 30 ]; then
    echo "⚠ Warning: Tor may not be fully ready, but continuing anyway..."
  else
    echo "Waiting for Tor... ($i/30)"
  fi
  sleep 1
done

# Launch Streamlit app
exec streamlit run app.py --server.port ${PORT:-5000} --server.address 0.0.0.0
