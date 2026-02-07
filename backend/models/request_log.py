from pydantic import BaseModel
from typing import Optional


class RequestLog(BaseModel):
    """Full request/response log entry."""
    id: Optional[int] = None
    timestamp: str = ""
    method: str = ""
    url: str = ""
    host: str = ""
    path: str = ""
    request_headers: dict = {}
    request_body: str = ""
    status_code: int = 0
    response_headers: dict = {}
    response_body: str = ""
    content_type: str = ""
    duration_ms: float = 0.0
    session_id: str = "default"


class RequestLogSummary(BaseModel):
    """Lightweight version for log list display."""
    id: int
    timestamp: str
    method: str
    url: str
    status_code: int
    content_type: str
    duration_ms: float
