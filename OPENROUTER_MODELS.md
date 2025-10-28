# OpenRouter Model Support

This document lists all available models when using OpenRouter with AutoHack.

## How to Use

1. Set your OpenRouter API key:
```bash
export OPENROUTER_API_KEY="your-api-key-here"
```

2. Run with OpenRouter and specify a model:
```bash
# Use default model (claude-3.5-sonnet)
./run-docker.sh https://example.com --openrouter --sqli

# Specify a different model
./run-docker.sh https://example.com --openrouter --model gpt-4o --sqli
./run-docker.sh https://example.com --openrouter --model llama3.1-70b --dom
```

## Available Models

### Anthropic Claude (Recommended for Security Testing)
- `claude-3.5-sonnet` - **Default** - Excellent balance of speed and intelligence
- `claude-3-haiku` - Fast and cost-effective
- `claude-3-opus` - Most capable Claude model

### OpenAI GPT
- `gpt-4o` - Latest GPT-4 with vision support
- `gpt-4o-mini` - Faster, more affordable GPT-4
- `gpt-4-turbo` - High-performance GPT-4

### Meta Llama
- `llama3.1-8b` - Fast, smaller model
- `llama3.1-70b` - Strong performance, good balance
- `llama3.1-405b` - Most capable Llama model
- `llama3.2-90b-vision` - Vision-enabled Llama

### Google Gemini
- `gemini-pro` - Text-only model
- `gemini-pro-vision` - Vision-enabled model

### Mistral AI
- `mistral-7b` - Fast, efficient model
- `mistral-large` - Most capable Mistral model

### DeepSeek
- `deepseek-chat` - Cost-effective coding model

### Qwen (Alibaba)
- `qwen-2.5-72b` - Strong performance model

## Model Selection Tips

### For SQL Injection Testing
Recommended models:
- `claude-3.5-sonnet` - Best for SQL injection analysis
- `gpt-4o` - Excellent at understanding database contexts
- `llama3.1-70b` - Good balance of cost and performance

### For XSS Testing
Recommended models:
- `claude-3.5-sonnet` - Excellent at JavaScript/HTML analysis
- `gpt-4o` - Strong understanding of browser behavior
- `llama3.1-405b` - Most thorough analysis (slower/costlier)

### For Cost Optimization
Budget-friendly models:
- `llama3.1-8b` - Very fast, lowest cost
- `claude-3-haiku` - Fast Claude model
- `mistral-7b` - Good for simple payloads

### For Maximum Accuracy
Most capable models:
- `claude-3-opus` - Most thorough analysis
- `gpt-4o` - Latest GPT capabilities
- `llama3.1-405b` - Largest Llama model

## Examples

### Using GPT-4o for SQLi
```bash
./run-docker.sh https://vulnsite.com/page.php?id=1 --openrouter --model gpt-4o --sqli
```

### Using Llama 3.1 70B for XSS
```bash
./run-docker.sh https://vulnsite.com/search --openrouter --model llama3.1-70b --dom
```

### Budget-friendly scan with Llama 3.1 8B
```bash
./run-docker.sh https://vulnsite.com --openrouter --model llama3.1-8b --sqli
```

### Maximum accuracy with Claude Opus
```bash
./run-docker.sh https://vulnsite.com --openrouter --model claude-3-opus --dom --memory
```

## Notes

- If no model is specified, `claude-3.5-sonnet` is used by default
- All models support the same API interface
- Vision models can analyze screenshots (useful for DOM XSS detection)
- Pricing varies by model - check [OpenRouter pricing](https://openrouter.ai/docs#models) for details
