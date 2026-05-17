import html
import re
import time
from typing import Dict, List

import requests
import urllib3

from .models import FuzzRequestConfig, FuzzResult

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
PLACEHOLDER_PATTERN = re.compile(r"FUZZ\d+|FUZZ|§[^§\r\n]+§")


def parse_headers(headers_text: str) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for line in headers_text.splitlines():
        raw = line.strip()
        if not raw or ":" not in raw:
            continue
        key, value = raw.split(":", 1)
        headers[key.strip()] = value.strip()
    return headers


def detect_placeholders(texts: List[str], custom_placeholder: str = "") -> List[str]:
    found: List[str] = []
    for text in texts:
        for match in PLACEHOLDER_PATTERN.findall(text):
            if match not in found:
                found.append(match)
    custom = custom_placeholder.strip()
    if custom and any(custom in text for text in texts) and custom not in found:
        found.insert(0, custom)
    return found


def apply_payload_bindings(text: str, payload_bindings: Dict[str, str], fallback_placeholder: str = "") -> str:
    result = text
    for placeholder, payload in payload_bindings.items():
        result = result.replace(placeholder, payload)
    if fallback_placeholder and fallback_placeholder in result and len(payload_bindings) == 1:
        result = result.replace(fallback_placeholder, next(iter(payload_bindings.values())))
    if "FUZZ" in result and "FUZZ" in payload_bindings:
        result = result.replace("FUZZ", payload_bindings["FUZZ"])
    return result


def extract_title(body: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    title = re.sub(r"\s+", " ", html.unescape(match.group(1))).strip()
    return title[:120]


def payload_label(payload_bindings: Dict[str, str]) -> str:
    if len(payload_bindings) == 1:
        return next(iter(payload_bindings.values()))
    return " | ".join(f"{placeholder}={value}" for placeholder, value in payload_bindings.items())


def execute_fuzz_request(config: FuzzRequestConfig, payload_bindings: Dict[str, str], index: int) -> FuzzResult:
    start_time = time.perf_counter()
    request_url = apply_payload_bindings(config.url, payload_bindings, config.placeholder)
    headers = {
        key: apply_payload_bindings(value, payload_bindings, config.placeholder)
        for key, value in parse_headers(config.headers_text).items()
    }
    body = apply_payload_bindings(config.body_text, payload_bindings, config.placeholder)

    result = FuzzResult(index=index, payload=payload_label(payload_bindings), request_url=request_url, final_url=request_url)

    try:
        response = requests.request(
            method=config.method.upper(),
            url=request_url,
            headers=headers,
            data=body.encode("utf-8") if body else None,
            timeout=config.timeout,
            verify=config.verify_ssl,
            allow_redirects=config.follow_redirects,
        )
        elapsed_ms = int((time.perf_counter() - start_time) * 1000)
        response.encoding = response.encoding or response.apparent_encoding or "utf-8"
        result.status_code = response.status_code
        result.response_length = len(response.content)
        result.elapsed_ms = elapsed_ms
        result.title = extract_title(response.text)
        result.final_url = response.url
        result.response_headers = dict(response.headers)
        result.response_text = response.text[:20000]
    except requests.RequestException as exc:
        result.elapsed_ms = int((time.perf_counter() - start_time) * 1000)
        result.error = str(exc)

    return result

