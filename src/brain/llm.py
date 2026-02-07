"""LLM client with automatic model fallback chain.

To configure:
1. Set JANITOR_MODEL in your .env file (recommended), OR
2. Pass model parameter when creating LLMClient

Fallback chain (automatic rate limit handling):
1. Primary model from JANITOR_MODEL
2. Fallback model 1
3. Fallback model 2
"""
import sys
import time
from pathlib import Path
from openai import OpenAI
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from config import get_config


class LLMClient:
    """AI-powered LLM client with automatic fallback."""

    def __init__(self, api_key: str = None, model: str = None):
        """Initialize LLM client.

        Args:
            api_key: AI API key (loads from config if not provided)
            model: Model to use (loads from JANITOR_MODEL env var if not provided)

        Raises:
            ValueError: If API key not found
        """
        # Load configuration
        config = get_config()

        # Get API key from parameter or config
        if api_key is None:
            api_key = config.ai_api_key

        if not api_key:
            raise ValueError(
                "JANITOR_AI_KEY not found. "
                "Set it in .env file or pass it to the constructor."
            )

        # Get model from parameter or config
        if model is None:
            model = config.ai_model

        # Initialize OpenAI-compatible client (configurable endpoint)
        self.client = OpenAI(
            api_key=api_key,
            base_url=config.ai_base_url,
            default_headers={
                "HTTP-Referer": "https://github.com/the-janitor",
                "X-Title": "The Janitor - Dead Code Remover"
            }
        )

        self.model = model
        self.fallback_models = config.ai_fallback_models

    def _is_rate_limit_error(self, exception: Exception) -> bool:
        """Check if exception is a 429 rate limit error.

        Args:
            exception: Exception to check

        Returns:
            True if rate limit error, False otherwise
        """
        error_str = str(exception).lower()
        return "429" in error_str or "rate limit" in error_str

    def ask_llm(self, system: str, user: str, temperature: float = 0.3) -> str:
        """Send prompt to LLM with automatic model fallback on rate limits.

        Implements fallback chain:
        1. Try primary model (from config)
        2. On 429 error: Wait 2s, try meta-llama/llama-3.3-70b-instruct:free
        3. On 429 error: Try google/gemma-2-9b-it:free

        Args:
            system: System prompt
            user: User prompt
            temperature: Sampling temperature (0.0-1.0)

        Returns:
            LLM response text

        Raises:
            Exception: If all models fail after retries
        """
        # Try each model in fallback chain
        for idx, model in enumerate(self.fallback_models):
            try:
                response = self.client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user}
                    ],
                    temperature=temperature
                )

                return response.choices[0].message.content

            except Exception as e:
                # Check if it's a rate limit error
                if self._is_rate_limit_error(e):
                    # Not the last model in chain - try fallback
                    if idx < len(self.fallback_models) - 1:
                        next_model = self.fallback_models[idx + 1]
                        print(f"Rate limit on {model}, waiting 2s and trying {next_model}...")
                        time.sleep(2)
                        continue
                    else:
                        # Last model also rate limited
                        print(f"All models rate limited. Last error: {e}")
                        raise
                else:
                    # Non-rate-limit error
                    print(f"LLM error on {model}: {e}")
                    raise

        # Should never reach here
        raise Exception("Model fallback chain exhausted")

    def ask_llm_with_fallback(self, system: str, user: str) -> str:
        """Ask LLM with fallback message on failure.

        Args:
            system: System prompt
            user: User prompt

        Returns:
            LLM response or error message
        """
        try:
            return self.ask_llm(system, user)
        except Exception as e:
            return f"[LLM Error: {e}. Unable to generate refactoring suggestion.]"
