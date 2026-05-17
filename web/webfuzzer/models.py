from dataclasses import dataclass, field
from typing import Dict, List


@dataclass(slots=True)
class FuzzRequestConfig:
    method: str
    url: str
    headers_text: str = ""
    body_text: str = ""
    placeholder: str = "§payload§"
    timeout: float = 10.0
    concurrency: int = 5
    verify_ssl: bool = False
    follow_redirects: bool = True
    payload_bindings: Dict[str, List[str]] = field(default_factory=dict)


@dataclass(slots=True)
class FuzzResult:
    index: int
    payload: str
    request_url: str
    final_url: str
    status_code: int = 0
    response_length: int = 0
    elapsed_ms: int = 0
    title: str = ""
    error: str = ""
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_text: str = ""
    similarity: int = 0
    duplicate_of: int = 0
    highlighted: bool = False


@dataclass(slots=True)
class ProxyCapture:
    index: int
    method: str
    scheme: str
    host: str
    port: int
    path: str
    status_code: int = 0
    request_size: int = 0
    response_size: int = 0
    elapsed_ms: int = 0
    client_address: str = ""
    request_headers: Dict[str, str] = field(default_factory=dict)
    response_headers: Dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    response_body: str = ""
    error: str = ""
