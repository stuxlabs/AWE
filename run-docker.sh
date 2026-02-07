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
    echo ""
    echo "Conversational Agent (Recommended):"
    echo "  --agent             Conversational agent: iterative testing with chat"
    echo "  --autoagent         Fully autonomous agent: LLM decides what to test (no user input)"
    echo "  --agent-mode <mode> Agent mode: interactive (asks you) or auto (decides itself)"
    echo ""
    echo "Intelligent Orchestration (Batch Mode):"
    echo "  --auto              Smart mode: automatically discover and test vulnerabilities"
    echo "  --mode <mode>       Orchestration mode: default, aggressive, fast, interactive"
    echo "  --focus <agents>    Focus on specific agents (e.g., sqli,xss)"
    echo "  --skip <agents>     Skip specific agents (e.g., lfi,ssti)"
    echo "  --no-llm-decision   Use rule-based agent selection instead of LLM"
    echo ""
    echo "Manual Mode (Specific Agents):"
    echo "  --sqli              Run SQL injection detection"
    echo "  --ssti              Run Server-Side Template Injection detection"
    echo "  --command-injection Run command injection detection"
    echo "  --lfi               Run Local File Inclusion detection"
    echo "  --idor              Run IDOR (Insecure Direct Object Reference) detection"
    echo "  --xxe               Run XXE (XML External Entity) detection"
    echo "  --dom               Run DOM XSS detection"
    echo ""
    echo "LLM Configuration:"
    echo "  --openrouter        Use OpenRouter instead of AWS Bedrock"
    echo "  --model <name>      Specify LLM model (e.g., gpt-4o, llama3.1-70b)"
    echo ""
    echo "Other Options:"
    echo "  --no-memory         Disable agent memory"
    echo "  --no-reasoning      Disable reasoning transparency"
    echo ""
    echo "Examples:"
    echo "  # Conversational agent (RECOMMENDED)"
    echo "  $0 https://example.com --agent                    # Interactive mode (asks you)"
    echo "  $0 https://example.com --autoagent                # Autonomous mode (LLM decides)"
    echo ""
    echo "  # Batch orchestration"
    echo "  $0 https://example.com --auto"
    echo "  $0 https://example.com --auto --mode aggressive"
    echo "  $0 https://example.com --auto --focus sqli,xss"
    echo ""
    echo "  # Manual mode (specific agents)"
    echo "  $0 https://example.com --sqli"
    echo "  $0 https://example.com --openrouter --model gpt-4o --sqli"
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
AGENT_MODE=false
AGENT_TYPE="interactive"
AUTO_MODE=false
ORCHESTRATOR_MODE="default"
FOCUS_AGENTS=""
SKIP_AGENTS=""
NO_LLM_DECISION=false

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
        --agent)
            AGENT_MODE=true
            shift
            ;;
        --autoagent)
            AGENT_MODE=true
            AGENT_TYPE="auto"
            shift
            ;;
        --agent-mode)
            AGENT_TYPE="$2"
            shift 2
            ;;
        --auto)
            AUTO_MODE=true
            shift
            ;;
        --mode)
            ORCHESTRATOR_MODE="$2"
            shift 2
            ;;
        --focus)
            FOCUS_AGENTS="$2"
            shift 2
            ;;
        --skip)
            SKIP_AGENTS="$2"
            shift 2
            ;;
        --no-llm-decision)
            NO_LLM_DECISION=true
            shift
            ;;
        --sqli|--ssti|--command-injection|--lfi|--idor|--dom|--xxe)
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
if [ "$AGENT_MODE" = true ]; then
    # Conversational agent mode
    CMD="python main.py \"$TARGET_URL\" --agent --agent-mode $AGENT_TYPE"
elif [ "$AUTO_MODE" = true ]; then
    # Intelligent orchestration mode
    CMD="python main.py \"$TARGET_URL\" --auto --orchestrator-mode $ORCHESTRATOR_MODE"

    if [ -n "$FOCUS_AGENTS" ]; then
        CMD="$CMD --focus $FOCUS_AGENTS"
    fi

    if [ -n "$SKIP_AGENTS" ]; then
        CMD="$CMD --skip $SKIP_AGENTS"
    fi

    if [ "$NO_LLM_DECISION" = true ]; then
        CMD="$CMD --no-llm-decision"
    fi
else
    # Manual mode (specific agents)
    CMD="python main.py \"$TARGET_URL\" $SCAN_MODE"
fi

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

if [ "$AGENT_MODE" = true ]; then
    if [ "$AGENT_TYPE" = "auto" ]; then
        echo -e "${GREEN}Mode:${NC} 🤖 Autonomous Agent (LLM-driven)"
        echo -e "${GREEN}Style:${NC} Fully autonomous (no user input needed)"
    else
        echo -e "${GREEN}Mode:${NC} 💬 Conversational Agent"
        echo -e "${GREEN}Style:${NC} Interactive (asks you what to do)"
    fi
elif [ "$AUTO_MODE" = true ]; then
    echo -e "${GREEN}Mode:${NC} 🤖 Intelligent Orchestration ($ORCHESTRATOR_MODE)"
    if [ -n "$FOCUS_AGENTS" ]; then
        echo -e "${GREEN}Focus:${NC} $FOCUS_AGENTS"
    fi
    if [ -n "$SKIP_AGENTS" ]; then
        echo -e "${GREEN}Skip:${NC} $SKIP_AGENTS"
    fi
    echo -e "${GREEN}Decision:${NC} $([ "$NO_LLM_DECISION" = true ] && echo "Rule-based" || echo "LLM-driven")"
else
    echo -e "${GREEN}Mode:${NC} $SCAN_MODE"
fi

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

# Set LLM_PROVIDER environment variable
if [ "$USE_OPENROUTER" = true ]; then
    export LLM_PROVIDER=openrouter
    if [ -n "$MODEL_NAME" ]; then
        docker compose run --rm -e LLM_PROVIDER=openrouter -e LLM_MODEL="$MODEL_NAME" stuxlab sh -c "$CMD"
    else
        docker compose run --rm -e LLM_PROVIDER=openrouter stuxlab sh -c "$CMD"
    fi
else
    # Default to Bedrock
    export LLM_PROVIDER=bedrock
    if [ -n "$MODEL_NAME" ]; then
        docker compose run --rm -e LLM_PROVIDER=bedrock -e LLM_MODEL="$MODEL_NAME" stuxlab sh -c "$CMD"
    else
        docker compose run --rm -e LLM_PROVIDER=bedrock stuxlab sh -c "$CMD"
    fi
fi

echo ""
echo -e "${GREEN}✓ Scan complete!${NC}"
