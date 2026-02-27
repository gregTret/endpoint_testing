from pydantic import BaseModel
from typing import Optional


class ScanConfig(BaseModel):
    """Configuration for an injection scan."""
    target_url: str
    method: str = "GET"
    params: dict = {}
    headers: dict = {}
    body: str = ""
    injector_type: str = "sql"
    injection_points: list[str] = []  # "params", "headers", "body"
    target_keys: Optional[list[str]] = None  # specific keys to inject into (None = all)
    follow_redirects: bool = False
    timeout: float = 10.0
    extra: dict = {}


class ScanResult(BaseModel):
    """Result of a single injection test."""
    id: Optional[int] = None
    timestamp: str = ""
    target_url: str = ""
    injector_type: str = ""
    payload: str = ""
    injection_point: str = ""
    original_param: str = ""
    response_code: int = 0
    response_body: str = ""
    response_time_ms: float = 0.0
    request_headers: str = ""   # JSON string of headers actually sent
    request_body: str = ""      # body actually sent
    is_vulnerable: bool = False
    confidence: str = "low"  # low, medium, high
    details: str = ""
    session_id: str = "default"


class VulnerabilityReport(BaseModel):
    """Analysis report for a single payload test."""
    is_vulnerable: bool = False
    confidence: str = "low"
    details: str = ""
    evidence: list[str] = []
