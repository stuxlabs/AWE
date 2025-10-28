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
# Set up LLM provider (choose one)
export OPENROUTER_API_KEY="your_openrouter_key"  # OR
export AWS_ACCESS_KEY_ID="your_key"
export AWS_SECRET_ACCESS_KEY="your_secret"

# Run with simple script
./run-docker.sh "https://target.com" --sqli
./run-docker.sh "https://target.com" --dom

# Use OpenRouter with custom model
./run-docker.sh "https://target.com" --openrouter --model gpt-4o --sqli
./run-docker.sh "https://target.com" --openrouter --model gemini-2-flash --dom

# With all features enabled
./run-docker.sh "https://target.com" --openrouter --model claude-3.5-sonnet --sqli --memory --reasoning-mode verbose
```

### Docker (Manual)

```bash
docker build -t awe .

# XSS Detection
docker run --rm -v $(pwd)/screenshots:/app/screenshots \
  awe python main.py "https://target.com" --dom --use-framework

# SQL Injection
docker run --rm awe python main.py "https://target.com/page.php?id=1" --sqli
```

### Local

```bash
pip install -r requirements.txt
playwright install chromium

export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_REGION=us-east-1

python main.py "https://target.com" --dom --use-framework
python main.py "https://target.com/page.php?id=1" --sqli
```

## LLM Providers

AWE supports both **AWS Bedrock** and **OpenRouter** for LLM-powered payload generation.

### AWS Bedrock (Default)
```bash
export AWS_ACCESS_KEY_ID="your_key"
export AWS_SECRET_ACCESS_KEY="your_secret"
export AWS_REGION="us-east-1"

./run-docker.sh "https://target.com" --sqli
```

### OpenRouter
```bash
export OPENROUTER_API_KEY="your_key"

# Use default model (claude-3.5-sonnet)
./run-docker.sh "https://target.com" --openrouter --sqli

# Specify custom model
./run-docker.sh "https://target.com" --openrouter --model gpt-4o --sqli
./run-docker.sh "https://target.com" --openrouter --model gemini-2-flash --dom
./run-docker.sh "https://target.com" --openrouter --model llama3.1-70b --sqli
```

**Available OpenRouter Models:**
- `claude-3.5-sonnet` (default) - Best for security testing
- `gpt-4o` - Excellent at understanding complex contexts
- `gemini-2-flash` - Fast and cost-effective
- `llama3.1-8b`, `llama3.1-70b`, `llama3.1-405b` - Open source options
- `deepseek-chat`, `qwen-2.5-72b` - Alternative models

See `OPENROUTER_MODELS.md` for full model list.

## Usage

```bash
# XSS Detection (DOM, Reflected, Stored, Blind)
python main.py "https://target.com" --dom --use-framework
python main.py "https://target.com" --proxy
python main.py "https://target.com" --oast-mode auto

# SQL Injection (Error, Time, Boolean, UNION)
python main.py "https://target.com/page?id=1" --sqli
python main.py "https://target.com/page?id=1" --sqli --sqli-config aggressive

# With Reasoning Transparency
python main.py "https://target.com" --dom --reasoning-mode verbose

# Using run-docker.sh (recommended)
./run-docker.sh "https://target.com" --sqli                    # Basic SQLi scan
./run-docker.sh "https://target.com" --dom                     # Basic XSS scan
./run-docker.sh "https://target.com" --sqli --memory           # With memory enabled
./run-docker.sh "https://target.com" --sqli --reasoning-mode verbose  # With reasoning
./run-docker.sh "https://target.com" --openrouter --model gpt-4o --sqli  # OpenRouter with custom model
```

## Configuration Presets

**XSS:** `fast` (15), `default` (30), `aggressive` (50), `conservative` (20)
**SQLi:** `fast` (15), `default` (30), `aggressive` (50), `conservative` (20)

## Requirements

- Python 3.8+
- Playwright
- SQLite3
- LLM Provider (choose one):
  - AWS Bedrock access (Claude, Llama models) **OR**
  - OpenRouter API key (Claude, GPT, Gemini, Llama, and more)
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

## Contact

- Ashish Baghel: ashishashish7440@gmail.com
- Akshat Singh Jaswal: sja.akshat@gmail.com
