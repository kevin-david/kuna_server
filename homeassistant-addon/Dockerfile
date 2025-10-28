# Home Assistant Addon Dockerfile
# Build context: addon directory
ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base-python:latest
FROM $BUILD_FROM

# Copy the application files
COPY kuna_server.py /app/
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy and setup run script
COPY run.sh /
RUN chmod a+x /run.sh

# Run the application
CMD ["/run.sh"]
