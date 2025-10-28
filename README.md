# AWE: Adaptive Web Exploitation Framework

Memory-augmented multi-agent system for intelligent XSS and SQL injection detection with transparent reasoning.

## Features

- **Dual-Agent Architecture**: Specialized XSS and SQLi agents covering 12+ vulnerability variants
- **Hybrid Payload Generation**: 722 curated payloads + LLM strategic generation + intelligent mutation
- **Memory-Augmented Learning**: SQLite persistence learns from exploits (8x faster on repeat scans)
- **Reasoning Transparency**: Complete Chain-of-Thought visibility into agent decisions
- **Browser Verification**: Real execution validation with Playwright (zero false positives)

## Quick Start

### Simplified Docker Runner (Recommended)

```bash
# Set up OpenRouter API key
export OPENROUTER_API_KEY="your_openrouter_key"

# Run with simple script
./run-docker.sh "https://target.com" --openrouter --sqli
./run-docker.sh "https://target.com" --openrouter --dom

# Use custom model
./run-docker.sh "https://target.com" --openrouter --model gpt-4o --sqli
./run-docker.sh "https://target.com" --openrouter --model gemini-2-flash --dom

# With all features enabled
./run-docker.sh "https://target.com" --openrouter --sqli --memory --reasoning-mode verbose
```

### Docker (Manual)

```bash
docker build -t awe .

export OPENROUTER_API_KEY="your_key"

# XSS Detection
docker run --rm -e OPENROUTER_API_KEY=$OPENROUTER_API_KEY \
  -v $(pwd)/screenshots:/app/screenshots \
  awe python main.py "https://target.com" --dom --use-framework

# SQL Injection
docker run --rm -e OPENROUTER_API_KEY=$OPENROUTER_API_KEY \
  awe python main.py "https://target.com/page.php?id=1" --sqli
```

### Local

```bash
pip install -r requirements.txt
playwright install chromium

export OPENROUTER_API_KEY="your_key"

python main.py "https://target.com" --dom --use-framework
python main.py "https://target.com/page.php?id=1" --sqli
```

## LLM Provider Setup

AWE uses **OpenRouter** for LLM-powered payload generation, giving you access to multiple AI models through a single API.

### Setup

```bash
export OPENROUTER_API_KEY="your_key"

# Use default model (claude-4-sonnet)
./run-docker.sh "https://target.com" --openrouter --sqli

# Specify custom model
./run-docker.sh "https://target.com" --openrouter --model gpt-4o --sqli
./run-docker.sh "https://target.com" --openrouter --model gemini-2-flash --dom
./run-docker.sh "https://target.com" --openrouter --model llama3.1-70b --sqli
```

### Available Models

- `claude-4-sonnet` (default) - Most advanced Claude model for security testing
- `claude-3.5-sonnet` - Fast and reliable for complex analysis
- `gpt-4o` - Excellent at understanding complex contexts
- `gemini-2-flash` - Fast and cost-effective
- `llama3.1-8b`, `llama3.1-70b`, `llama3.1-405b` - Open source options
- `deepseek-chat`, `qwen-2.5-72b` - Alternative models

See `OPENROUTER_MODELS.md` for full model list and pricing.

## Usage

```bash
# Using run-docker.sh (recommended)
./run-docker.sh "https://target.com" --openrouter --sqli                    # Basic SQLi scan
./run-docker.sh "https://target.com" --openrouter --dom                     # Basic XSS scan
./run-docker.sh "https://target.com" --openrouter --sqli --memory           # With memory enabled
./run-docker.sh "https://target.com" --openrouter --sqli --reasoning-mode verbose  # With reasoning
./run-docker.sh "https://target.com" --openrouter --model gpt-4o --sqli     # Custom model

# Direct python usage
python main.py "https://target.com" --dom --use-framework
python main.py "https://target.com" --sqli --sqli-config aggressive
python main.py "https://target.com" --dom --reasoning-mode verbose
```

## Configuration Presets

**XSS:** `fast` (15), `default` (30), `aggressive` (50), `conservative` (20)
**SQLi:** `fast` (15), `default` (30), `aggressive` (50), `conservative` (20)

## Requirements

- Python 3.8+
- Playwright
- SQLite3
- OpenRouter API key (access to Claude, GPT, Gemini, Llama, and more)
- Nuclei (optional)

## ⚠️ Legal Warning

**FOR AUTHORIZED SECURITY TESTING ONLY**

This tool is designed for:
- ✅ Authorized penetration testing with explicit written permission
- ✅ Bug bounty programs within valid scope
- ✅ Security research on owned infrastructure
- ✅ Academic research with proper authorization

**PROHIBITED:**
- ❌ Unauthorized testing of third-party systems
- ❌ Exploitation without permission
- ❌ Any malicious or illegal activities

**Users are solely responsible for ensuring proper authorization. Unauthorized access to computer systems is illegal.**

## License

MIT License
