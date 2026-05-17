from dataclasses import dataclass
from typing import Dict, Tuple


@dataclass(slots=True)
class ParsedRawRequest:
    method: str
    url: str
    headers_text: str
    body_text: str


def split_raw_http_request(raw_text: str) -> Tuple[str, str]:
    normalized = raw_text.replace("\r\n", "\n").replace("\r", "\n")
    parts = normalized.split("\n\n", 1)
    head = parts[0].strip("\n")
    body = parts[1] if len(parts) > 1 else ""
    return head, body


def parse_header_lines(header_lines: list[str]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for line in header_lines:
        raw = line.strip()
        if not raw or ":" not in raw:
            continue
        key, value = raw.split(":", 1)
        headers[key.strip()] = value.strip()
    return headers


def build_headers_text(headers: Dict[str, str]) -> str:
    removable = {"content-length", "transfer-encoding"}
    lines = [
        f"{key}: {value}"
        for key, value in headers.items()
        if key.lower() not in removable
    ]
    return "\n".join(lines)


def parse_raw_http_request(
    raw_text: str,
    default_scheme: str = "https",
    host_override: str = "",
) -> ParsedRawRequest:
    head, body = split_raw_http_request(raw_text.strip())
    if not head:
        raise ValueError("原始 HTTP 报文为空。")

    lines = head.splitlines()
    request_line = lines[0].strip()
    parts = request_line.split()
    if len(parts) < 2:
        raise ValueError("请求行格式不正确，示例：GET /path HTTP/1.1")

    method = parts[0].upper()
    target = parts[1]
    headers = parse_header_lines(lines[1:])

    host = host_override.strip() or headers.get("Host", "").strip()
    if target.startswith("http://") or target.startswith("https://"):
        url = target
    else:
        if not host:
            raise ValueError("原始 HTTP 报文缺少 Host 头，且未提供主机覆盖值。")
        path = target if target.startswith("/") else f"/{target}"
        url = f"{default_scheme}://{host}{path}"

    return ParsedRawRequest(
        method=method,
        url=url,
        headers_text=build_headers_text(headers),
        body_text=body,
    )
