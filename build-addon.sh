#!/bin/bash
# Build script for Home Assistant addon
# Copies required files to addon directory, builds, then cleans up

set -e

ADDON_DIR="homeassistant-addon"
TEMP_FILES=("$ADDON_DIR/kuna_server.py" "$ADDON_DIR/requirements.txt")

echo "Building Home Assistant addon..."

# Copy required files to addon directory
echo "Copying files to addon directory..."
cp kuna_server.py "$ADDON_DIR/"
cp requirements.txt "$ADDON_DIR/"

# Add comments to copied files
echo "Adding auto-generated file comments..."
echo "# AUTO-GENERATED FILE - DO NOT EDIT MANUALLY" > "$ADDON_DIR/kuna_server.py.tmp"
echo "# This file is copied from the root directory during build" >> "$ADDON_DIR/kuna_server.py.tmp"
echo "# Edit the original file: ../kuna_server.py" >> "$ADDON_DIR/kuna_server.py.tmp"
echo "" >> "$ADDON_DIR/kuna_server.py.tmp"
cat "$ADDON_DIR/kuna_server.py" >> "$ADDON_DIR/kuna_server.py.tmp"
mv "$ADDON_DIR/kuna_server.py.tmp" "$ADDON_DIR/kuna_server.py"

echo "# AUTO-GENERATED FILE - DO NOT EDIT MANUALLY" > "$ADDON_DIR/requirements.txt.tmp"
echo "# This file is copied from the root directory during build" >> "$ADDON_DIR/requirements.txt.tmp"
echo "# Edit the original file: ../requirements.txt" >> "$ADDON_DIR/requirements.txt.tmp"
echo "" >> "$ADDON_DIR/requirements.txt.tmp"
cat "$ADDON_DIR/requirements.txt" >> "$ADDON_DIR/requirements.txt.tmp"
mv "$ADDON_DIR/requirements.txt.tmp" "$ADDON_DIR/requirements.txt"

# Build the addon
echo "Building Docker image..."
docker build -t kuna_server-homeassistant "$ADDON_DIR/"

# Clean up copied files
echo "Cleaning up temporary files..."
rm "${TEMP_FILES[@]}"

echo "Build complete! Image: kuna_server-homeassistant"
