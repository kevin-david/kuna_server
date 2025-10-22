#!/bin/bash
# Home Assistant Addon Runner for Kuna Server

set -e

# Setup environment for Home Assistant addon
CONFIG_DIR=${CONFIG_DIR:-/config}
LOG_LEVEL=${KUNA_DEBUG:-false}

# Create config directory if it doesn't exist
mkdir -p "$CONFIG_DIR"

# Setup logging
if [ "$LOG_LEVEL" = "true" ]; then
    LOG_LEVEL="DEBUG"
else
    LOG_LEVEL="INFO"
fi

# Validate required environment variables
if [ -z "$KUNA_USERNAME" ] || [ -z "$KUNA_PASSWORD" ]; then
    echo "ERROR: KUNA_USERNAME and KUNA_PASSWORD environment variables are required"
    exit 1
fi

# Log startup information
echo "Starting Kuna Server Addon"
echo "Config directory: $CONFIG_DIR"
echo "Username: $KUNA_USERNAME"
echo "Port: ${KUNA_PORT}"
echo "Debug: ${KUNA_DEBUG:-false}"
echo "Minimal Logging: ${KUNA_MINLOG:-false}"

# Set config directory environment variable for the Python script
export CONFIG_DIR

# Run the main application
exec python3 kuna_server.py
