#!/bin/bash
#
# Smart Docker Run Script for AutoHack
# Automatically enables reasoning transparency and agent memory
#
# Usage:
#   ./run-docker.sh <URL> [OPTIONS]
#

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Check URL
if [ -z "$1" ]; then
    echo -e "${RED}Error: No target URL provided${NC}"
    echo "Usage: $0 <URL> [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --sqli              Run SQL injection detection"
    echo "  --dom               Run DOM XSS detection"
    echo "  --openrouter        Use OpenRouter instead of AWS Bedrock"
    echo "  --model <name>      Specify LLM model (e.g., gpt-4o, llama3.1-70b)"
    echo "  --no-memory         Disable agent memory"
    echo "  --no-reasoning      Disable reasoning transparency"
    echo ""
    echo "Examples:"
    echo "  $0 https://example.com"
    echo "  $0 https://example.com --sqli"
    echo "  $0 https://example.com --openrouter"
    echo "  $0 https://example.com --openrouter --model gpt-4o"
    echo "  $0 https://example.com --openrouter --model llama3.1-70b --sqli"
    exit 1
fi

TARGET_URL="$1"
shift

# Defaults
ENABLE_MEMORY=true
ENABLE_REASONING=true
SCAN_MODE=""
USE_OPENROUTER=false
MODEL_NAME=""

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        --no-memory)
            ENABLE_MEMORY=false
            shift
            ;;
        --no-reasoning)
            ENABLE_REASONING=false
            shift
            ;;
        --sqli|--dom)
            SCAN_MODE="$1"
            shift
            ;;
        --openrouter)
            USE_OPENROUTER=true
            shift
            ;;
        --model)
            MODEL_NAME="$2"
            shift 2
            ;;
        *)
            EXTRA_ARGS="$EXTRA_ARGS $1"
            shift
            ;;
    esac
done

# Build command
CMD="python main.py \"$TARGET_URL\" $SCAN_MODE"

if [ "$ENABLE_MEMORY" = true ]; then
    CMD="$CMD --memory"
fi

if [ "$ENABLE_REASONING" = true ]; then
    CMD="$CMD --reasoning-mode verbose"
fi

CMD="$CMD $EXTRA_ARGS"

# Print info
echo -e "${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║      AutoHack - Intelligent Security Testing        ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}Target:${NC} $TARGET_URL"
echo -e "${GREEN}Mode:${NC} $SCAN_MODE"
echo -e "${GREEN}Memory:${NC} $([ "$ENABLE_MEMORY" = true ] && echo "✓" || echo "✗")"
echo -e "${GREEN}Reasoning:${NC} $([ "$ENABLE_REASONING" = true ] && echo "✓" || echo "✗")"
echo -e "${GREEN}LLM Provider:${NC} $([ "$USE_OPENROUTER" = true ] && echo "OpenRouter" || echo "AWS Bedrock")"
if [ -n "$MODEL_NAME" ]; then
    echo -e "${GREEN}Model:${NC} $MODEL_NAME"
fi
echo ""

# Create dirs
mkdir -p logs/reasoning memory results screenshots html_captures

# Run
echo -e "${BLUE}Running scan...${NC}"
echo ""

# Set LLM_PROVIDER environment variable if using OpenRouter
if [ "$USE_OPENROUTER" = true ]; then
    export LLM_PROVIDER=openrouter
    if [ -n "$MODEL_NAME" ]; then
        docker-compose run --rm -e LLM_PROVIDER=openrouter -e LLM_MODEL="$MODEL_NAME" stuxlab sh -c "$CMD"
    else
        docker-compose run --rm -e LLM_PROVIDER=openrouter stuxlab sh -c "$CMD"
    fi
else
    if [ -n "$MODEL_NAME" ]; then
        docker-compose run --rm -e LLM_MODEL="$MODEL_NAME" stuxlab sh -c "$CMD"
    else
        docker-compose run --rm stuxlab sh -c "$CMD"
    fi
fi

echo ""
echo -e "${GREEN}✓ Scan complete!${NC}"
