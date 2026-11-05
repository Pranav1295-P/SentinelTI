##the main job of config is read .env and turn into typrd python values

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env",extra='ignore')

    environment: str = "development"

    database_url_async:str
    database_url_sync:str
    redis_url:str
    celery_broker_url: str
    celery_result_backend: str
    storage_path: str = "./storage"
    max_upload_bytes: int = 104857600

    # Auth. An empty secret is only tolerated outside production (see core.security).
    secret_key: SecretStr = SecretStr("")
    access_token_minutes: int = 480
    allow_registration: bool = False
    cookie_secure: bool = False

    # LLM. Any "provider:model" string init_chat_model understands.
    # Empty LLM_API_KEY = the pipeline runs on its deterministic tools only.
    llm_model: str = "anthropic:claude-opus-5-5"
    llm_api_key: SecretStr = SecretStr("")
    llm_timeout_seconds: int = 90
    # Free tiers rate-limit by tokens per minute, so calls wait and retry rather than fail.
    llm_max_retries: int = 6
    llm_max_output_tokens: int = 4096
    agent_max_tool_rounds: int = 6

    # Threat intel. Only ever sent the sample's hash, never the file.
    virustotal_api_key: SecretStr = SecretStr("")
    otx_api_key: SecretStr = SecretStr("")

    # Graph database used by agent 5. Empty URI = graph matching is skipped.
    neo4j_uri: str = ""
    neo4j_username: str = "neo4j"
    neo4j_password: SecretStr = SecretStr("")

    # Tracing sends sample-derived strings to LangSmith, so it stays opt-in.
    langsmith_tracing: bool = False
    langsmith_api_key: SecretStr = SecretStr("")
    langsmith_project: str = "sentinelti"

    # Limits for the isolated parser process.
    parser_timeout_seconds: int = 120
    parser_memory_mb: int = 2048

    login_rate_per_minute: int = 10
    upload_rate_per_minute: int = 20
    chat_rate_per_minute: int = 30

    @property
    def llm_enabled(self) -> bool:
        return bool(self.llm_api_key.get_secret_value())


settings = Settings()
"""
what its doing is it;s reading .env file in
and validating using pydantic storage must be saved in path ./storage
"""
