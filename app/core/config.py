import os
from pydantic import BaseModel


class Settings(BaseModel):
    APP_NAME: str = "PhishLense"
    APP_VERSION: str = "1.0.0"
    APP_DESCRIPTION: str = "Heuristic and Structural Phishing Intelligence Engine"
    AUTHOR_NAME: str = "AHMAD"
    GITHUB_USERNAME: str = "cys-dexter"
    REPOSITORY_NAME: str = "PhishLense"
    REPOSITORY_URL: str = "https://github.com/cys-dexter/PhishLense"
    HOST: str = os.getenv("PHISHLENSE_HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PHISHLENSE_PORT", "8000"))
    DEBUG: bool = os.getenv("PHISHLENSE_DEBUG", "False").lower() in ("true", "1", "t")


settings = Settings()
