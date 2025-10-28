#!/bin/bash

# DOM XSS Agent - Docker Runner Script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    print_error "Docker is not running. Please start Docker and try again."
    exit 1
fi

# .env will be passed directly to Docker via --env-file

print_status "Building XSS Agent Docker image..."
docker build -t xss-agent .

print_status "Creating output directories..."
mkdir -p screenshots logs results

# Check if target URL is provided
if [ $# -eq 0 ]; then
    print_status "Running DOM XSS test suite (no target specified)..."
    TARGET_ARGS=""
else
    TARGET_URL="$1"
    print_status "Running DOM XSS Agent against: $TARGET_URL"
    TARGET_ARGS="$TARGET_URL"
fi

# Run the container
if [ -t 0 ]; then
    INTERACTIVE_FLAGS="-it"
else
    INTERACTIVE_FLAGS=""
fi

docker run --rm $INTERACTIVE_FLAGS \
    --network host \
    -v "$(pwd)/screenshots:/app/screenshots" \
    -v "$(pwd)/logs:/app/logs" \
    -v "$(pwd)/results:/app/results" \
    --env-file .env \
    --name dom-xss-agent-run \
    xss-agent python test_dom_xss_agent.py $TARGET_ARGS

print_status "Scan completed! Results saved to:"
echo "  📁 logs/ - Detailed execution logs"
echo "  📄 dom_xss_results.json - DOM XSS vulnerabilities found"
