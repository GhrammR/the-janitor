"""Configuration management for The Janitor.

Loads environment variables and provides centralized config access.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Version - Managed by tools/sync_version.py (DO NOT EDIT MANUALLY)
__version__ = "4.0.0-alpha"


class Config:
    """Configuration loader with environment variable support."""

    def __init__(self):
        """Initialize config by loading .env file."""
        # Load .env from project root
        project_root = Path(__file__).parent.parent
        env_path = project_root / ".env"
        load_dotenv(env_path)

        # Validate required variables
        self._validate_required()

    def _validate_required(self):
        """Validate that required environment variables exist.

        Raises:
            ValueError: If JANITOR_AI_KEY is missing
        """
        if not self.ai_api_key:
            raise ValueError(
                "JANITOR_AI_KEY not found. "
                "Set it in .env file or environment variables."
            )

    @property
    def ai_api_key(self) -> str:
        """Get AI API key from environment.

        Returns:
            API key string or None if not found
        """
        return os.getenv("JANITOR_AI_KEY")

    @property
    def ai_model(self) -> str:
        """Get AI model from environment with fallback.

        Priority:
        1. JANITOR_MODEL environment variable
        2. Fallback to default model

        Returns:
            Model identifier string
        """
        return os.getenv("JANITOR_MODEL", "arcee-ai/trinity-large-preview:free")

    @property
    def ai_fallback_models(self) -> list[str]:
        """Get fallback models for rate limit handling.

        Returns:
            List of model identifiers to try in sequence
        """
        return [
            "arcee-ai/trinity-large-preview:free",
            "meta-llama/llama-3.3-70b-instruct:free",
            "google/gemma-2-9b-it:free"
        ]

    @property
    def ai_base_url(self) -> str:
        """Get LLM API base URL from environment with fallback.

        Returns:
            API base URL string
        """
        return os.getenv("JANITOR_AI_BASE_URL", "https://openrouter.ai/api/v1")

    @property
    def janitor_db_path(self) -> str:
        """Get ChromaDB storage path.

        Returns:
            Path to .janitor_db directory
        """
        return os.getenv("JANITOR_DB_PATH", ".janitor_db")

    @property
    def janitor_trash_path(self) -> str:
        """Get trash directory path.

        Returns:
            Path to .janitor_trash directory
        """
        return os.getenv("JANITOR_TRASH_PATH", ".janitor_trash")


# Singleton instance
_config = None


def get_config() -> Config:
    """Get or create singleton Config instance.

    Returns:
        Config instance
    """
    global _config
    if _config is None:
        _config = Config()
    return _config
