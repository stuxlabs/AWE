# Use official Python runtime as base image
FROM python:3.11-slim

# Install system dependencies required for Playwright
RUN apt-get update && apt-get install -y \
    wget \
    gnupg \
    ca-certificates \
    procps \
    xvfb \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better Docker layer caching
COPY requirements.txt .
COPY requirements_proxy.txt .

# Install Python dependencies (base + proxy)
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir -r requirements_proxy.txt

# Install Nuclei
RUN apt-get update && apt-get install -y curl unzip \
    && curl -L -o /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.4.10_linux_amd64.zip" \
    && unzip /tmp/nuclei.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip \
    && apt-get remove -y curl unzip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

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