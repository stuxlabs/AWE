# Use official Python runtime as base image
FROM python:3.11-slim

# Install system dependencies required for Playwright and security tools
RUN apt-get update && apt-get install -y \
    wget \
    gnupg \
    ca-certificates \
    procps \
    xvfb \
    hydra \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better Docker layer caching
COPY requirements.txt .
COPY requirements_proxy.txt .

# Install Python dependencies (base + proxy)
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir -r requirements_proxy.txt

# Install ProjectDiscovery Nuclei using Go
RUN apt-get update && apt-get install -y golang-go git \
    && CGO_ENABLED=1 go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && cp /root/go/bin/nuclei /usr/local/bin/ \
    && apt-get remove -y golang-go \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /root/go

# Install Playwright browsers
RUN playwright install chromium
RUN playwright install-deps chromium

# Copy application code
COPY . .

# Create directories for output
RUN mkdir -p screenshots logs logs/reasoning proxy_captures memory

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV DISPLAY=:99

# Expose port if needed (for future web interface)
EXPOSE 8000

# Default command
CMD ["python", "main.py", "--help"]