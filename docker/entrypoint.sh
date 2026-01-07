#!/bin/bash
set -e

echo "Coding Agent Container Starting..."

# Fix permissions on mounted workspace (running as root at this point)
chown -R agent:agent /workspace

# Clean up previous output
rm -f /workspace/index.html

# Wait for CA certificate to be available
echo "Waiting for CA certificate..."
MAX_WAIT=60
WAITED=0
while [ ! -f /ca/ca.crt ]; do
    sleep 1
    WAITED=$((WAITED + 1))
    if [ $WAITED -ge $MAX_WAIT ]; then
        echo "ERROR: CA certificate not found after ${MAX_WAIT}s"
        exit 1
    fi
done
echo "CA certificate found"

# Set Node.js to use the CA cert
export NODE_EXTRA_CA_CERTS=/ca/ca.crt

# Get the prompt from environment or use default
PROMPT="${AGENT_PROMPT:-Create a website that shows the weather from a random city every 2 seconds. Use Open-Meteo and be sure to test the API before using it. Save it as /workspace/index.html}"

echo "Running Claude Code with prompt: $PROMPT"
echo "---"

# Switch to agent user and run Claude Code
cd /workspace
exec su agent -c "NODE_EXTRA_CA_CERTS=/ca/ca.crt claude --dangerously-skip-permissions -p \"$PROMPT\""
