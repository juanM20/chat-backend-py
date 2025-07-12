from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache

class Settings(BaseSettings):
    SECRET_KEY: str
    ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int

    # Configura Pydantic para cargar desde .env
    model_config = SettingsConfigDict(env_file=".env")

# Usa lru_cache para que la configuración se cargue una sola vez
@lru_cache()
def get_settings():
    return Settings()

settings = get_settings()