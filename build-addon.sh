#!/bin/bash
# Build script for Home Assistant addon
# Copies required files to addon directory, builds the Docker image

set -e

ADDON_DIR="homeassistant-addon"

echo "Building Home Assistant addon..."

echo "Copying files to addon directory with header comments..."
{
    echo "# AUTO-COPIED FILE - DO NOT EDIT MANUALLY"
    echo "# This file is copied from the root directory during build"
    echo "# Edit the original file: ../kuna_server.py"
    echo ""
    cat kuna_server.py
} > "$ADDON_DIR/kuna_server.py"

{
    echo "# AUTO-COPIED FILE - DO NOT EDIT MANUALLY"
    echo "# This file is copied from the root directory during build"
    echo "# Edit the original file: ../requirements.txt"
    echo ""
    cat requirements.txt
} > "$ADDON_DIR/requirements.txt"

# Build the addon
echo "Building Docker image..."
docker build --build-arg BUILD_FROM=ghcr.io/home-assistant/amd64-base-python:latest -t kuna_server-homeassistant "$ADDON_DIR/"

echo "Build complete! Image: kuna_server-homeassistant"
