#!/bin/bash
# Home Assistant Addon Runner for Kuna Server

set -e

# Load bashio if available
if [ -f /usr/lib/bashio/bashio.sh ]; then
    . /usr/lib/bashio/bashio.sh
    USE_BASHIO=true
else
    USE_BASHIO=false
fi

# Create config directory if it doesn't exist
mkdir -p "${CONFIG_DIR:-/config}"

# Read configuration using bashio if available, otherwise use environment variables
if [ "$USE_BASHIO" = "true" ]; then
    export KUNA_USERNAME=$(bashio::config 'username')
    export KUNA_PASSWORD=$(bashio::config 'password')
    export KUNA_PORT=$(bashio::config 'port')
    export KUNA_DEBUG=$(bashio::config 'debug')
    export KUNA_MINLOG=$(bashio::config 'minlog')
    export CONFIG_DIR="${CONFIG_DIR:-/config}"
    
    # Validate required options
    if [ -z "$KUNA_USERNAME" ] || [ -z "$KUNA_PASSWORD" ]; then
        bashio::log.error "username and password are required in addon options"
        exit 1
    fi
    
    # Setup logging
    if [ "$KUNA_DEBUG" = "true" ]; then
        export LOG_LEVEL="DEBUG"
    else
        export LOG_LEVEL="INFO"
    fi
    
    # Log startup information
    bashio::log.info "Starting Kuna Server Addon"
    bashio::log.info "Config directory: $CONFIG_DIR"
    bashio::log.info "Username: $KUNA_USERNAME"
    bashio::log.info "Port: $KUNA_PORT"
    bashio::log.info "Debug: $KUNA_DEBUG"
    bashio::log.info "Minimal Logging: $KUNA_MINLOG"
else
    # Fallback for non-HA environments
    echo "Starting Kuna Server (non-HA mode)"
    echo "Using environment variables for configuration"
fi

# Run the main application
exec python3 /app/kuna_server.py
