#!/usr/bin/with-contenv bashio
# shellcheck shell=bash
set -e

# Create config directory if it doesn't exist
mkdir -p "${CONFIG_DIR:-/config}"
mkdir -p "${CONFIG_DIR:-/config}/logs"

# Read configuration using bashio and export directly
export KUNA_USERNAME=$(bashio::config 'username')
export KUNA_PASSWORD=$(bashio::config 'password')
export KUNA_PORT=$(bashio::config 'port')
export KUNA_DEBUG=$(bashio::config 'debug')
export KUNA_MINLOG=$(bashio::config 'minlog')
export CONFIG_DIR="${CONFIG_DIR:-/config}"
# Set log file path for Home Assistant addon (with rotation)
export KUNA_LOG_FILE="${CONFIG_DIR}/logs/kuna-server.log"

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

# Run the main application
# Log file path is set via KUNA_LOG_FILE environment variable to prevent stdout spam
exec python3 /app/kuna_server.py
