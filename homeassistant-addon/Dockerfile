# Home Assistant Addon Dockerfile
# Build context: addon directory
ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base-python:latest
FROM $BUILD_FROM

# Install pip if not available (for HA builds that override BUILD_FROM)
RUN apk add --no-cache python3 py3-pip || true

# Copy the application files
COPY kuna_server.py /app/
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy and setup run script
COPY run.sh /
RUN chmod a+x /run.sh

# Run the application
CMD ["/run.sh"]
