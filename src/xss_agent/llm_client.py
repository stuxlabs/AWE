"""
Unified LLM Client Factory

Automatically selects between AWS Bedrock and OpenRouter based on environment variables.
Provides a consistent interface for both providers.
"""

import os
from typing import Optional


def get_llm_client(provider: Optional[str] = None, **kwargs):
    """
    Factory function to get the appropriate LLM client based on environment variables.

    Priority:
    1. If provider is explicitly specified, use that
    2. Default to OpenRouter
    3. Fall back to Bedrock if OpenRouter fails and AWS credentials are available

    Args:
        provider: Optional provider name ('bedrock' or 'openrouter')
        **kwargs: Additional arguments to pass to the client constructor

    Returns:
        Unified LLM client instance (OpenRouterClient or BedrockUnifiedClient)

    Raises:
        ValueError: If no LLM client can be initialized
    """
    # Check for explicit provider override
    if provider is None:
        provider = os.environ.get("LLM_PROVIDER", "").lower()

    # Determine which provider to use
    if provider == "openrouter":
        # Use OpenRouter
        try:
            from .openrouter_model import OpenRouterClient
            return OpenRouterClient(**kwargs)
        except Exception as e:
            raise ValueError(f"Failed to initialize OpenRouter client: {e}")

    elif provider == "bedrock" or provider == "aws":
        # Use AWS Bedrock
        try:
            from .aws_model import BedrockUnifiedClient
            return BedrockUnifiedClient(**kwargs)
        except Exception as e:
            raise ValueError(f"Failed to initialize Bedrock client: {e}")

    else:
        # Auto-detect based on environment variables
        # Default to AWS Bedrock (preferred default)
        if os.environ.get("AWS_ACCESS_KEY_ID") or os.environ.get("AWS_PROFILE"):
            try:
                from .aws_model import BedrockUnifiedClient
                print("🔄 Using AWS Bedrock as LLM provider")
                return BedrockUnifiedClient(**kwargs)
            except Exception as bedrock_e:
                print(f"⚠️  Bedrock initialization failed: {bedrock_e}")
                # Fall back to OpenRouter
                print("🔄 Falling back to OpenRouter")
                try:
                    from .openrouter_model import OpenRouterClient
                    return OpenRouterClient(**kwargs)
                except Exception as e:
                    raise ValueError(f"Failed to initialize any LLM client. Bedrock: {bedrock_e}, OpenRouter: {e}")
        else:
            # No AWS credentials, try OpenRouter
            try:
                from .openrouter_model import OpenRouterClient
                print("🔄 Using OpenRouter as LLM provider (no AWS credentials found)")
                return OpenRouterClient(**kwargs)
            except Exception as e:
                raise ValueError(f"Failed to initialize LLM client: {e}")


def get_default_model(provider: Optional[str] = None) -> str:
    """
    Get the default model for the specified provider.

    Args:
        provider: Optional provider name ('bedrock' or 'openrouter')

    Returns:
        Default model name
    """
    # Check if user specified a model via environment variable
    custom_model = os.environ.get("LLM_MODEL")
    if custom_model:
        return custom_model

    if provider is None:
        provider = os.environ.get("LLM_PROVIDER", "").lower()

    # Default to Claude 4 Sonnet for both providers
    return "claude-4-sonnet"


# Convenience aliases
create_client = get_llm_client
get_client = get_llm_client


if __name__ == "__main__":
    # Test the factory
    print("Testing LLM Client Factory")
    print("="*50)

    # Try to create a client
    try:
        client = get_llm_client()
        print(f"✓ Successfully created client: {type(client).__name__}")

        # List models
        print("\nAvailable models:")
        for model in client.list_models()[:5]:  # Show first 5
            print(f"  • {model['id']}: {model['name']}")

        # Get default model
        default_model = get_default_model()
        print(f"\n✓ Default model: {default_model}")

    except Exception as e:
        print(f"✗ Error: {e}")
