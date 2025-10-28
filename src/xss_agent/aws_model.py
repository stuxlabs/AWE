import boto3
from botocore.exceptions import ClientError
import json
import base64
import time
from typing import List, Dict, Any, Optional, Union
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
    use_converse: bool = True

class BedrockUnifiedClient:
    """
    Unified client for AWS Bedrock models with OpenRouter-like interface
    """
    
    def __init__(self, region_name: str = "us-east-1"):
        self.client = boto3.client("bedrock-runtime", region_name=region_name)
        self.models = self._init_models()
    
    def _init_models(self) -> Dict[str, ModelConfig]:
        """Initialize model configurations"""
        return {
            # Meta Llama Models - Using Inference Profiles (Required for Llama 3.2+)
            "llama3.1-8b": ModelConfig(
                id="arn:aws:bedrock:us-east-1:734908905761:inference-profile/us.meta.llama3-1-8b-instruct-v1:0",
                name="Llama 3.1 8B Instruct", 
                type=ModelType.TEXT_ONLY,
                max_tokens=2048
            ),
            "llama3.1-70b": ModelConfig(
                id="arn:aws:bedrock:us-east-1:734908905761:inference-profile/us.meta.llama3-1-70b-instruct-v1:0",
                name="Llama 3.1 70B Instruct",
                type=ModelType.TEXT_ONLY,
                max_tokens=2048
            ),
            "llama3.2-1b": ModelConfig(
                id="arn:aws:bedrock:us-east-1:734908905761:inference-profile/us.meta.llama3-2-1b-instruct-v1:0",
                name="Llama 3.2 1B Instruct",
                type=ModelType.TEXT_ONLY,
                max_tokens=2048
            ),
            "llama3.2-3b": ModelConfig(
                id="arn:aws:bedrock:us-east-1:734908905761:inference-profile/us.meta.llama3-2-3b-instruct-v1:0",
                name="Llama 3.2 3B Instruct", 
                type=ModelType.TEXT_ONLY,
                max_tokens=2048
            ),
            "llama3.2-11b-vision": ModelConfig(
                id="arn:aws:bedrock:us-east-1:734908905761:inference-profile/us.meta.llama3-2-11b-instruct-v1:0",
                name="Llama 3.2 11B Vision Instruct",
                type=ModelType.VISION,
                max_tokens=2048
            ),
            "llama3.2-90b-vision": ModelConfig(
                id="arn:aws:bedrock:us-east-1:734908905761:inference-profile/us.meta.llama3-2-90b-instruct-v1:0", 
                name="Llama 3.2 90B Vision Instruct",
                type=ModelType.VISION,
                max_tokens=2048
            ),
            "llama3.3-70b": ModelConfig(
                id="arn:aws:bedrock:us-east-1:734908905761:inference-profile/us.meta.llama3-3-70b-instruct-v1:0",
                name="Llama 3.3 70B Instruct",
                type=ModelType.TEXT_ONLY,
                max_tokens=2048
            ),
            "llama4-scout": ModelConfig(
                id="arn:aws:bedrock:us-east-1:734908905761:inference-profile/us.meta.llama4-scout-17b-instruct-v1:0",
                name="Llama 4 Scout 17B Instruct",
                type=ModelType.VISION,
                max_tokens=2048
            ),
            "llama4-maverick": ModelConfig(
                id="arn:aws:bedrock:us-east-1:734908905761:inference-profile/us.meta.llama4-maverick-17b-instruct-v1:0",
                name="Llama 4 Maverick 17B Instruct",
                type=ModelType.VISION,
                max_tokens=2048
            ),
            # Legacy models (direct ARNs) - for backward compatibility
            "llama3-8b": ModelConfig(
                id="meta.llama3-8b-instruct-v1:0",
                name="Llama 3 8B Instruct",
                type=ModelType.TEXT_ONLY,
                max_tokens=2048
            ),
            "llama3-70b": ModelConfig(
                id="meta.llama3-70b-instruct-v1:0", 
                name="Llama 3 70B Instruct",
                type=ModelType.TEXT_ONLY,
                max_tokens=2048
            ),
            # Mistral Models
            "mistral-7b": ModelConfig(
                id="mistral.mistral-7b-instruct-v0:2",
                name="Mistral 7B Instruct",
                type=ModelType.TEXT_ONLY,
                max_tokens=4096
            ),
            "mistral-large": ModelConfig(
                id="mistral.mistral-large-2402-v1:0",
                name="Mistral Large",
                type=ModelType.TEXT_ONLY, 
                max_tokens=4096
            ),
            # Claude Models (if available)
            "claude-3-haiku": ModelConfig(
                id="anthropic.claude-3-haiku-20240307-v1:0",
                name="Claude 3 Haiku",
                type=ModelType.VISION,
                max_tokens=4096
            ),
            "claude-3.5-sonnet": ModelConfig(
                id="anthropic.claude-3-5-sonnet-20241022-v2:0",
                name="Claude 3.5 Sonnet",
                type=ModelType.VISION, 
                max_tokens=8192
            ),
            # Claude Sonnet 4 (Claude 4) - Using inference profile ARN as direct model access is not supported
            "claude-4-sonnet": ModelConfig(
                id="arn:aws:bedrock:us-east-1:734908905761:inference-profile/us.anthropic.claude-sonnet-4-20250514-v1:0",
                name="Claude 4 Sonnet",
                type=ModelType.VISION,
                max_tokens=8192
            ),
            # Claude Opus 4 Models
            "claude-4-opus": ModelConfig(
                id="arn:aws:bedrock:us-east-1:734908905761:inference-profile/us.anthropic.claude-opus-4-20250514-v1:0",
                name="Claude 4 Opus",
                type=ModelType.VISION,
                max_tokens=8192
            ),
            "claude-4-opus-4.1": ModelConfig(
                id="arn:aws:bedrock:us-east-1:734908905761:inference-profile/us.anthropic.claude-opus-4-1-20250805-v1:0",
                name="Claude 4 Opus 4.1",
                type=ModelType.VISION,
                max_tokens=8192
            )
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
    
    def check_model_access(self, model_id: str) -> bool:
        """
        Check if a specific model is accessible in the current region
        
        Args:
            model_id: The model ID to check
            
        Returns:
            bool: True if model is accessible, False otherwise
        """
        try:
            # Try to get the model details from Bedrock
            self.client.get_foundation_model(modelIdentifier=model_id)
            return True
        except ClientError as e:
            # Handle specific AWS errors
            error_code = e.response['Error']['Code']
            if error_code in ['AccessDeniedException', 'ValidationException']:
                # Model exists but access is denied or invalid
                return False
            # For other errors, re-raise
            raise e
        except Exception:
            # Any other error means model is not accessible
            return False
    
    def list_accessible_models(self) -> List[Dict[str, Any]]:
        """
        List models that are actually accessible in the current region
        
        Returns:
            List of accessible model information
        """
        accessible_models = []
        for key, config in self.models.items():
            if self.check_model_access(config.id):
                accessible_models.append({
                    "id": key,
                    "name": config.name,
                    "type": config.type.value,
                    "max_tokens": config.max_tokens,
                    "supports_vision": config.type == ModelType.VISION,
                    "model_arn": config.id
                })
        return accessible_models
    
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
            model: Model identifier (use short names like 'llama3-70b')
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
        
        # Prepare messages - Handle system message properly
        formatted_messages = []
        
        # Convert messages to Bedrock format
        for msg in messages:
            content = msg["content"]
            if isinstance(content, str):
                formatted_messages.append({
                    "role": msg["role"],
                    "content": [{"text": content}]
                })
            else:
                # Handle complex content (images, etc.)
                # Filter out duplicate images and limit to 1 image max for Bedrock
                text_parts = []
                image_parts = []
                
                for item in content:
                    if "text" in item:
                        text_parts.append(item)
                    elif "image" in item:
                        image_parts.append(item)
                
                # Limit to 1 image max
                if len(image_parts) > 1:
                    image_parts = image_parts[:1]
                
                # Combine text and image parts
                processed_content = text_parts + image_parts
                
                formatted_messages.append({
                    "role": msg["role"],
                    "content": processed_content if processed_content else content
                })
        
        # Prepare system message for inference config
        inference_config = {
            "maxTokens": max_tokens,
            "temperature": temperature,
            "topP": top_p
        }
        
        # Use system message in system parameter if supported
        converse_params = {
            "modelId": model_config.id,
            "messages": formatted_messages,
            "inferenceConfig": inference_config
        }
        
        if system and model_config.supports_system:
            converse_params["system"] = [{"text": system}]
        
        # Use Converse API (works for all modern Bedrock models)
        # Implement retry logic for throttling errors with minimal delay
        max_retries = 3
        retry_delay = 0.5  # Start with 0.5 second delay
        
        for attempt in range(max_retries):
            try:
                response = self.client.converse(**converse_params)
                
                return {
                    "id": response.get("ResponseMetadata", {}).get("RequestId", ""),
                    "model": model,
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": response["output"]["message"]["content"][0]["text"]
                        },
                        "finish_reason": response["stopReason"] if "stopReason" in response else "stop"
                    }],
                    "usage": {
                        "prompt_tokens": response["usage"]["inputTokens"],
                        "completion_tokens": response["usage"]["outputTokens"],
                        "total_tokens": response["usage"]["totalTokens"]
                    }
                }
                
            except ClientError as e:
                error_code = e.response['Error']['Code']
                
                # Check if this is a throttling error and we should retry
                if error_code == 'ThrottlingException' and attempt < max_retries - 1:
                    print(f"Throttling error encountered (attempt {attempt + 1}/{max_retries}). Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    retry_delay *= 1.5  # Smaller backoff multiplier
                    continue
                else:
                    # Re-raise the exception if it's not a throttling error or we've exhausted retries
                    raise e
            except Exception as e:
                # Provide more specific error handling for common issues
                error_str = str(e)
                if "ValidationException" in error_str and "invalid" in error_str.lower():
                    raise Exception(f"Model '{model}' with ARN '{model_config.id}' is not available in your region or account. "
                                   f"Please check that: 1) The model is enabled in your AWS Bedrock console, "
                                   f"2) Your AWS credentials have the necessary permissions, "
                                   f"3) The model is available in your region. "
                                   f"Error details: {error_str}")
                else:
                    raise Exception(f"Error calling model {model}: {error_str}")
        
        # This should never be reached, but just in case
        raise Exception(f"Failed to call model {model} after {max_retries} attempts due to throttling")
    
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
        with open(image_path, "rb") as f:
            image_bytes = f.read()
        
        # Determine image format
        image_format = "jpeg" if image_path.lower().endswith(('.jpg', '.jpeg')) else "png"
        
        messages = [{
            "role": "user",
            "content": [
                {
                    "image": {
                        "format": image_format,
                        "source": {"bytes": image_bytes}
                    }
                },
                {"text": text}
            ]
        }]
        
        # Implement retry logic for throttling errors with minimal delay
        max_retries = 3
        retry_delay = 0.5  # Start with 0.5 second delay
        
        for attempt in range(max_retries):
            try:
                result = self.chat_completion(
                    model=model,
                    messages=messages,
                    max_tokens=max_tokens,
                    temperature=temperature
                )
                
                return result["choices"][0]["message"]["content"]
                
            except ClientError as e:
                error_code = e.response['Error']['Code']
                
                # Check if this is a throttling error and we should retry
                if error_code == 'ThrottlingException' and attempt < max_retries - 1:
                    print(f"Throttling error encountered (attempt {attempt + 1}/{max_retries}). Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    retry_delay *= 1.5  # Smaller backoff multiplier
                    continue
                else:
                    # Re-raise the exception if it's not a throttling error or we've exhausted retries
                    raise e
            except Exception as e:
                # Re-raise other exceptions
                raise e
        
        # This should never be reached, but just in case
        raise Exception(f"Failed to call vision model {model} after {max_retries} attempts due to throttling")
    
    def simple_chat(self, model: str, message: str, **kwargs) -> str:
        """Simple text chat method"""
        # Implement retry logic for throttling errors with minimal delay
        max_retries = 3
        retry_delay = 0.5  # Start with 0.5 second delay
        
        for attempt in range(max_retries):
            try:
                messages = [{"role": "user", "content": message}]
                result = self.chat_completion(model, messages, **kwargs)
                return result["choices"][0]["message"]["content"]
                
            except ClientError as e:
                error_code = e.response['Error']['Code']
                
                # Check if this is a throttling error and we should retry
                if error_code == 'ThrottlingException' and attempt < max_retries - 1:
                    print(f"Throttling error encountered (attempt {attempt + 1}/{max_retries}). Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    retry_delay *= 1.5  # Smaller backoff multiplier
                    continue
                else:
                    # Re-raise the exception if it's not a throttling error or we've exhausted retries
                    raise e
            except Exception as e:
                # Re-raise other exceptions
                raise e
        
        # This should never be reached, but just in case
        raise Exception(f"Failed to call model {model} after {max_retries} attempts due to throttling")

# Example usage and testing
if __name__ == "__main__":
    # Initialize client
    client = BedrockUnifiedClient()
    
    # List available models
    print("All configured models:")
    for model in client.list_models():
        print(f"  {model['id']}: {model['name']} ({model['type']})")
    
    print("\n" + "="*50 + "\n")
    
    # Check which models are accessible in your region
    print("Models accessible in your region:")
    accessible_models = client.list_accessible_models()
    if accessible_models:
        for model in accessible_models:
            print(f"  {model['id']}: {model['name']} - ARN: {model['model_arn']}")
    else:
        print("  No models are currently accessible. Check your AWS region and permissions.")
    
    print("\n" + "="*50 + "\n")
    
    # Test text chat with different models
    test_models = ["llama3-8b", "claude-3.5-sonnet", "claude-4-sonnet"]
    
    for model_name in test_models:
        try:
            response = client.simple_chat(
                model=model_name,
                message="Explain quantum computing in simple terms."
            )
            print(f"{model_name} Response:")
            print(response)
            break  # Stop after first successful model
        except Exception as e:
            print(f"{model_name} chat failed: {e}")
    
    print("\n" + "="*50 + "\n")
    
    # Test vision chat (uncomment if you have an image file)
    """
    try:
        vision_response = client.vision_chat(
            model="llama3.2-90b-vision",
            image_path="dog.jpg",
            text="Describe this image in detail."
        )
        print("Vision Response:")
        print(vision_response)
    except Exception as e:
        print(f"Vision chat failed: {e}")
    """

