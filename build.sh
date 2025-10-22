#!/bin/bash
# Build script for Kuna Server image and Home Assistant addon

BASE_IMAGE="kuna-server"
ADDON_IMAGE="kuna-server-homeassistant"

# Build base image
echo "Building base image..."
docker build -t "$BASE_IMAGE" .

if [ $? -eq 0 ]; then
    echo "Base image built successfully!"
else
    echo "Failed to build base image!"
    exit 1
fi

# Build addon image (uses published base image)
echo "Building addon image..."
docker build -t "$ADDON_IMAGE" ./homeassistant-addon

if [ $? -eq 0 ]; then
    echo "Both images built successfully!"
    echo "- Base image: $BASE_IMAGE"
    echo "- Addon image: $ADDON_IMAGE (uses published base image)"
else
    echo "Failed to build addon image!"
    exit 1
fi
