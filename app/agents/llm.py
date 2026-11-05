"""The one place a chat model is created. Any init_chat_model provider works."""

import os
from functools import lru_cache

from langchain.chat_models import init_chat_model
from langchain_core.language_models import BaseChatModel

from app.core.config import settings


@lru_cache(maxsize=1)
def _build_model() -> BaseChatModel:
    return init_chat_model(
        settings.llm_model,
        api_key=settings.llm_api_key.get_secret_value(),
        timeout=settings.llm_timeout_seconds,
        max_retries=2,
    )


def get_llm() -> BaseChatModel | None:
    """None means no key is configured, so the pipeline uses its deterministic path."""
    return _build_model() if settings.llm_enabled else None


def configure_tracing() -> None:
    """LangSmith reads the process environment. Off unless explicitly enabled."""
    if settings.langsmith_tracing and settings.langsmith_api_key.get_secret_value():
        os.environ["LANGSMITH_TRACING"] = "true"
        os.environ["LANGSMITH_API_KEY"] = settings.langsmith_api_key.get_secret_value()
        os.environ["LANGSMITH_PROJECT"] = settings.langsmith_project
    else:
        os.environ["LANGSMITH_TRACING"] = "false"
