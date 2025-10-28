import os
import time
import requests
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum


class ModelType(Enum):
    TEXT_ONLY = "text"
    VISION = "vision"
    EMBEDDING = "embedding"


@dataclass
class ModelConfig:
    id: str
    name: str
    type: ModelType
    max_tokens: int
    supports_system: bool = True


class OpenRouterClient:
    """
    Unified client for OpenRouter API with interface matching BedrockUnifiedClient
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("OPENROUTER_API_KEY")
        if not self.api_key:
            raise ValueError("OPENROUTER_API_KEY not found in environment variables")

        self.base_url = "https://openrouter.ai/api/v1"
        self.models = self._init_models()

    def _init_models(self) -> Dict[str, ModelConfig]:
        """Initialize model configurations"""
        return {
            # Anthropic Claude Models
            "claude-3-haiku": ModelConfig(
                id="anthropic/claude-3-haiku",
                name="Claude 3 Haiku",
                type=ModelType.VISION,
                max_tokens=4096
            ),
            "claude-3.5-sonnet": ModelConfig(
                id="anthropic/claude-3.5-sonnet",
                name="Claude 3.5 Sonnet",
                type=ModelType.VISION,
                max_tokens=8192
            ),
            "claude-3-opus": ModelConfig(
                id="anthropic/claude-3-opus",
                name="Claude 3 Opus",
                type=ModelType.VISION,
                max_tokens=4096
            ),
            "claude-4-sonnet": ModelConfig(
                id="anthropic/claude-sonnet-4-20250514",
                name="Claude 4 Sonnet",
                type=ModelType.VISION,
                max_tokens=8192
            ),
            # Meta Llama Models
            "llama3.1-8b": ModelConfig(
                id="meta-llama/llama-3.1-8b-instruct",
                name="Llama 3.1 8B Instruct",
                type=ModelType.TEXT_ONLY,
                max_tokens=8192
            ),
            "llama3.1-70b": ModelConfig(
                id="meta-llama/llama-3.1-70b-instruct",
                name="Llama 3.1 70B Instruct",
                type=ModelType.TEXT_ONLY,
                max_tokens=8192
            ),
            "llama3.1-405b": ModelConfig(
                id="meta-llama/llama-3.1-405b-instruct",
                name="Llama 3.1 405B Instruct",
                type=ModelType.TEXT_ONLY,
                max_tokens=8192
            ),
            "llama3.2-90b-vision": ModelConfig(
                id="meta-llama/llama-3.2-90b-vision-instruct",
                name="Llama 3.2 90B Vision",
                type=ModelType.VISION,
                max_tokens=8192
            ),
            # OpenAI Models
            "gpt-4o": ModelConfig(
                id="openai/gpt-4o",
                name="GPT-4o",
                type=ModelType.VISION,
                max_tokens=4096
            ),
            "gpt-4o-mini": ModelConfig(
                id="openai/gpt-4o-mini",
                name="GPT-4o Mini",
                type=ModelType.VISION,
                max_tokens=4096
            ),
            "gpt-4-turbo": ModelConfig(
                id="openai/gpt-4-turbo",
                name="GPT-4 Turbo",
                type=ModelType.VISION,
                max_tokens=4096
            ),
            # Google Models
            "gemini-pro": ModelConfig(
                id="google/gemini-pro",
                name="Gemini Pro",
                type=ModelType.TEXT_ONLY,
                max_tokens=8192
            ),
            "gemini-pro-vision": ModelConfig(
                id="google/gemini-pro-vision",
                name="Gemini Pro Vision",
                type=ModelType.VISION,
                max_tokens=4096
            ),
            "gemini-2-flash": ModelConfig(
                id="google/gemini-2.0-flash-exp:free",
                name="Gemini 2.0 Flash",
                type=ModelType.VISION,
                max_tokens=8192
            ),
            # Mistral Models
            "mistral-7b": ModelConfig(
                id="mistralai/mistral-7b-instruct",
                name="Mistral 7B Instruct",
                type=ModelType.TEXT_ONLY,
                max_tokens=8192
            ),
            "mistral-large": ModelConfig(
                id="mistralai/mistral-large",
                name="Mistral Large",
                type=ModelType.TEXT_ONLY,
                max_tokens=8192
            ),
            # DeepSeek Models
            "deepseek-chat": ModelConfig(
                id="deepseek/deepseek-chat",
                name="DeepSeek Chat",
                type=ModelType.TEXT_ONLY,
                max_tokens=8192
            ),
            # Qwen Models
            "qwen-2.5-72b": ModelConfig(
                id="qwen/qwen-2.5-72b-instruct",
                name="Qwen 2.5 72B",
                type=ModelType.TEXT_ONLY,
                max_tokens=8192
            ),
        }

    def list_models(self) -> List[Dict[str, Any]]:
        """List available models"""
        return [
            {
                "id": key,
                "name": config.name,
                "type": config.type.value,
                "max_tokens": config.max_tokens,
                "supports_vision": config.type == ModelType.VISION
            }
            for key, config in self.models.items()
        ]

    def chat_completion(
        self,
        model: str,
        messages: List[Dict[str, Any]],
        max_tokens: Optional[int] = None,
        temperature: float = 0.7,
        top_p: float = 0.9,
        system: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create a chat completion with OpenAI-like interface

        Args:
            model: Model identifier (use short names like 'llama3.1-70b')
            messages: List of message dicts with 'role' and 'content'
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            top_p: Nucleus sampling parameter
            system: System message (optional)
        """
        if model not in self.models:
            raise ValueError(f"Model '{model}' not found. Available models: {list(self.models.keys())}")

        model_config = self.models[model]
        max_tokens = max_tokens or min(model_config.max_tokens, 1000)

        # Prepare messages
        formatted_messages = []

        # Add system message if provided
        if system and model_config.supports_system:
            formatted_messages.append({
                "role": "system",
                "content": system
            })

        # Convert messages to OpenRouter format
        for msg in messages:
            content = msg["content"]

            # Handle both string and complex content
            if isinstance(content, str):
                formatted_messages.append({
                    "role": msg["role"],
                    "content": content
                })
            elif isinstance(content, list):
                # For vision models, handle image content
                text_parts = []
                image_parts = []

                for item in content:
                    if isinstance(item, dict):
                        if "text" in item:
                            text_parts.append(item["text"])
                        elif "image" in item:
                            # Handle Bedrock-style image format
                            if "source" in item["image"] and "bytes" in item["image"]["source"]:
                                import base64
                                image_bytes = item["image"]["source"]["bytes"]
                                image_format = item["image"].get("format", "png")
                                base64_image = base64.b64encode(image_bytes).decode('utf-8')
                                image_parts.append({
                                    "type": "image_url",
                                    "image_url": {
                                        "url": f"data:image/{image_format};base64,{base64_image}"
                                    }
                                })

                # Combine text and image parts
                if model_config.type == ModelType.VISION and image_parts:
                    # For vision models, use multimodal content format
                    content_parts = []
                    if text_parts:
                        content_parts.append({
                            "type": "text",
                            "text": " ".join(text_parts)
                        })
                    content_parts.extend(image_parts)

                    formatted_messages.append({
                        "role": msg["role"],
                        "content": content_parts
                    })
                else:
                    # For text-only, just join text parts
                    formatted_messages.append({
                        "role": msg["role"],
                        "content": " ".join(text_parts) if text_parts else content
                    })
            else:
                formatted_messages.append({
                    "role": msg["role"],
                    "content": str(content)
                })

        # Prepare request
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/autohack/stuxlab",
            "X-Title": "AutoHack Security Testing"
        }

        payload = {
            "model": model_config.id,
            "messages": formatted_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "top_p": top_p
        }

        # Implement retry logic
        max_retries = 3
        retry_delay = 1.0

        for attempt in range(max_retries):
            try:
                response = requests.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=120
                )

                if response.status_code == 429:
                    # Rate limit - retry
                    if attempt < max_retries - 1:
                        print(f"Rate limit hit (attempt {attempt + 1}/{max_retries}). Retrying in {retry_delay} seconds...")
                        time.sleep(retry_delay)
                        retry_delay *= 2
                        continue
                    else:
                        raise Exception(f"Rate limit exceeded after {max_retries} attempts")

                response.raise_for_status()
                result = response.json()

                return {
                    "id": result.get("id", ""),
                    "model": model,
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": result["choices"][0]["message"]["content"]
                        },
                        "finish_reason": result["choices"][0].get("finish_reason", "stop")
                    }],
                    "usage": result.get("usage", {
                        "prompt_tokens": 0,
                        "completion_tokens": 0,
                        "total_tokens": 0
                    })
                }

            except requests.exceptions.RequestException as e:
                if attempt < max_retries - 1:
                    print(f"Request error (attempt {attempt + 1}/{max_retries}): {e}. Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    retry_delay *= 2
                    continue
                else:
                    raise Exception(f"Failed to call OpenRouter API after {max_retries} attempts: {e}")

        raise Exception(f"Failed to call model {model} after {max_retries} attempts")

    def vision_chat(
        self,
        model: str,
        image_path: str,
        text: str,
        max_tokens: Optional[int] = None,
        temperature: float = 0.7
    ) -> str:
        """
        Simplified vision chat method

        Args:
            model: Vision model identifier
            image_path: Path to image file
            text: Text prompt
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
        """
        if model not in self.models:
            raise ValueError(f"Model '{model}' not found")

        model_config = self.models[model]
        if model_config.type != ModelType.VISION:
            raise ValueError(f"Model '{model}' does not support vision")

        # Read and encode image
        import base64
        with open(image_path, "rb") as f:
            image_bytes = f.read()

        base64_image = base64.b64encode(image_bytes).decode('utf-8')

        # Determine image format
        image_format = "jpeg" if image_path.lower().endswith(('.jpg', '.jpeg')) else "png"

        messages = [{
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": text
                },
                {
                    "type": "image_url",
                    "image_url": {
                        "url": f"data:image/{image_format};base64,{base64_image}"
                    }
                }
            ]
        }]

        result = self.chat_completion(
            model=model,
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature
        )

        return result["choices"][0]["message"]["content"]

    def simple_chat(self, model: str, message: str, **kwargs) -> str:
        """Simple text chat method"""
        messages = [{"role": "user", "content": message}]
        result = self.chat_completion(model, messages, **kwargs)
        return result["choices"][0]["message"]["content"]


# Example usage
if __name__ == "__main__":
    # Initialize client
    client = OpenRouterClient()

    # List available models
    print("Available OpenRouter models:")
    for model in client.list_models():
        print(f"  {model['id']}: {model['name']} ({model['type']})")

    print("\n" + "="*50 + "\n")

    # Test simple chat
    try:
        response = client.simple_chat(
            model="llama3.1-8b",
            message="Explain quantum computing in simple terms.",
            max_tokens=200
        )
        print("Test Response:")
        print(response)
    except Exception as e:
        print(f"Error: {e}")
