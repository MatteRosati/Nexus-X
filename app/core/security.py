import secrets

from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyHeader

from app.core.config import Settings, get_settings

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(
    supplied_key: str | None = Depends(api_key_header),
    settings: Settings = Depends(get_settings),
) -> None:
    expected = settings.app_api_key.get_secret_value()
    if supplied_key is None or not secrets.compare_digest(supplied_key, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing API key")
