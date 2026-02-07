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
    target_keys: list[str] = []       # specific keys to inject into (empty = all)
    follow_redirects: bool = False
    timeout: float = 10.0


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
