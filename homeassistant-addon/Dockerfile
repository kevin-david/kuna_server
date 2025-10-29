# Home Assistant Addon Dockerfile
# Build context: addon directory
ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base-python:latest
FROM $BUILD_FROM

# Install Python and pip if not available (for HA builds that override BUILD_FROM)
RUN apk add --no-cache python3 py3-pip || (apt-get update && apt-get install -y python3 python3-pip) || true

# Copy the application files
COPY kuna_server.py /app/
COPY requirements.txt /app/
RUN python3 -m pip install --break-system-packages --no-cache-dir -r /app/requirements.txt

# Copy and setup run script
COPY run.sh /
RUN chmod a+x /run.sh

# Run the application
CMD ["/run.sh"]
    