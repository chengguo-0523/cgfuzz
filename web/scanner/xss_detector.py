from __future__ import annotations

import html
import json
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from .requester import Requester


class XSSType(Enum):
    REFLECTED = "reflected"
    STORED = "stored"
    DOM = "dom"


@dataclass
class XSSPayload:
    name: str
    payload: str
    xss_type: XSSType = XSSType.REFLECTED
    description: str = ""
    tags: List[str] = field(default_factory=list)


@dataclass
class XSSConfig:
    url: str
    method: str = "GET"
    post_data: Optional[Dict[str, Any]] = None
    post_mode: str = "form"
    xss_types: List[XSSType] = field(default_factory=lambda: [XSSType.REFLECTED])
    custom_payload_files: List[str] = field(default_factory=list)
    timeout: int = 10
    delay: float = 0.0
    stored_view_url: Optional[str] = None
    stored_wait: float = 0.6


@dataclass
class ReflectionContext:
    kind: str
    label: str
    snippet: str
    attribute: str = ""
    quote: str = ""


@dataclass
class PayloadCandidate:
    name: str
    payload: str
    injection_type: str
    context_kind: str
    source: str = "contextual"


@dataclass
class XSSResult:
    vulnerable: bool
    param_name: str = ""
    xss_type: XSSType = XSSType.REFLECTED
    payload: str = ""
    payload_name: str = ""
    url: str = ""
    method: str = "GET"
    response_text: str = ""
    evidence: str = ""
    confidence: str = "low"
    injection_type: str = ""
    context_snippet: str = ""


class XSSDetector:
    URI_ATTRIBUTES = {"href", "src", "action", "formaction", "xlink:href"}
    DANGEROUS_TOKENS = ("<script", "onerror", "onload", "onfocus", "javascript:", "alert(1)")

    def __init__(
        self,
        requester: Requester,
        config: XSSConfig,
        logger: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.requester = requester
        self.config = config
        self.logger = logger
        self.baseline_length = 0
        self.baseline_text = ""
        self.payloads: List[XSSPayload] = []
        self._payload_seen: set[tuple[str, str]] = set()
        self._load_payloads()
        self._probe_counter = 0

        self.patterns = {
            "dangerous_tags": [
                r"<script\b",
                r"<img\b[^>]*(onerror|onload)\s*=",
                r"<svg\b[^>]*(onload|onerror)\s*=",
                r"<iframe\b",
                r"<input\b[^>]*onfocus\s*=",
                r"<body\b[^>]*(onload|onerror)\s*=",
            ],
            "event_handlers": [
                r"\bon[a-z]+\s*=",
            ],
            "dangerous_protocols": [
                r"javascript\s*:",
                r"vbscript\s*:",
                r"data\s*:\s*text/html",
            ],
            "dom_sinks": [
                r"document\.write\s*\(",
                r"document\.writeln\s*\(",
                r"\.innerHTML\s*=",
                r"\.outerHTML\s*=",
                r"eval\s*\(",
                r"new\s+Function\s*\(",
                r"setTimeout\s*\(",
                r"setInterval\s*\(",
            ],
            "dom_sources": [
                r"location(?:\.href|\.search|\.hash)?",
                r"document\.(?:URL|documentURI|baseURI|referrer)",
                r"window\.name",
            ],
        }

    def _log(self, message: str) -> None:
        if self.logger:
            self.logger(message)

    def _load_payloads(self) -> None:
        payload_dir = Path(__file__).resolve().parent.parent / "payloads"
        for default_file in (payload_dir / "xss.json", payload_dir / "xss.txt"):
            self._load_payload_file(default_file)
        for file_path in self.config.custom_payload_files:
            self._load_payload_file(Path(file_path))
        self._log(f"[+] 已加载 {len(self.payloads)} 条 XSS payload")

    def _load_payload_file(self, file_path: Path) -> None:
        suffix = file_path.suffix.lower()
        if suffix == ".txt":
            self._load_text_payload_file(file_path)
            return

        try:
            with open(file_path, "r", encoding="utf-8-sig") as file:
                data = json.load(file)
        except FileNotFoundError:
            self._log(f"[!] 未找到 XSS 字典: {file_path}")
            return
        except json.JSONDecodeError as exc:
            self._log(f"[!] XSS 字典格式错误 {file_path.name}: {exc}")
            return

        payload_items: Any = data.get("payloads", []) if isinstance(data, dict) else data
        if isinstance(data, dict) and "payloads" not in data and "payload" in data:
            payload_items = [data]

        if not isinstance(payload_items, list):
            self._log(f"[!] XSS 字典格式无效: {file_path}")
            return

        added_count = 0
        for item in payload_items:
            if not isinstance(item, dict):
                continue
            payload_value = item.get("payload")
            if not isinstance(payload_value, str) or not payload_value.strip():
                continue

            xss_type = self._parse_xss_type(item.get("xss_type") or item.get("type"))
            if self._register_payload(
                XSSPayload(
                    name=item.get("name", "unnamed"),
                    payload=payload_value.strip(),
                    xss_type=xss_type,
                    description=item.get("description", ""),
                    tags=item.get("tags", []),
                )
            ):
                added_count += 1
        self._log(f"[+] 已加载 XSS 字典 {file_path.name}: {added_count} 条")

    def _load_text_payload_file(self, file_path: Path) -> None:
        try:
            raw_text = file_path.read_text(encoding="utf-8-sig", errors="ignore")
        except FileNotFoundError:
            self._log(f"[!] 未找到 XSS 字典: {file_path}")
            return
        except OSError as exc:
            self._log(f"[!] XSS 字典读取失败 {file_path.name}: {exc}")
            return

        inferred_type = self._infer_xss_type_from_path(file_path)
        added_count = 0
        for index, raw_line in enumerate(raw_text.splitlines(), start=1):
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith(("#", "//", ";", "<!--")):
                continue

            xss_type = inferred_type
            payload_value = line
            if "::" in line:
                prefix, payload_candidate = line.split("::", 1)
                if prefix.strip().lower() in {"reflected", "stored", "dom"}:
                    xss_type = self._parse_xss_type(prefix.strip())
                    payload_value = payload_candidate.strip()
            if not payload_value:
                continue

            if self._register_payload(
                XSSPayload(
                    name=f"{file_path.stem}-{index}",
                    payload=payload_value,
                    xss_type=xss_type,
                )
            ):
                added_count += 1
        self._log(f"[+] 已加载 TXT XSS 字典 {file_path.name}: {added_count} 条")

    def _register_payload(self, payload: XSSPayload) -> bool:
        payload_key = (payload.xss_type.value, payload.payload)
        if payload_key in self._payload_seen:
            return False
        self._payload_seen.add(payload_key)
        self.payloads.append(payload)
        return True

    def _infer_xss_type_from_path(self, file_path: Path) -> XSSType:
        lowered = file_path.stem.lower()
        if "stored" in lowered:
            return XSSType.STORED
        if "dom" in lowered:
            return XSSType.DOM
        return XSSType.REFLECTED

    def _parse_xss_type(self, raw_type: Optional[str]) -> XSSType:
        normalized = str(raw_type or "reflected").lower()
        if normalized == "stored":
            return XSSType.STORED
        if normalized == "dom":
            return XSSType.DOM
        return XSSType.REFLECTED

    def set_baseline(self, response: Any) -> None:
        self.baseline_length = len(response.text)
        self.baseline_text = response.text

    def get_payload_stats(self) -> Dict[str, int]:
        stats = {"reflected": 0, "stored": 0, "dom": 0}
        for payload in self.payloads:
            stats[payload.xss_type.value] += 1
        return stats

    def detect(self) -> List[XSSResult]:
        test_params = self._extract_test_params()
        if not test_params:
            self._log("[!] 未发现可测试参数")
            return []

        results: List[XSSResult] = []
        self._log(f"[*] 发现 {len(test_params)} 个可测试参数")

        for param_info in test_params:
            self._log(f"[*] 正在分析参数: {param_info['name']} ({param_info['type']})")

            if XSSType.REFLECTED in self.config.xss_types:
                reflected_result = self._detect_reflected_param(param_info)
                if reflected_result:
                    results.append(reflected_result)
                    self._log(
                        f"[!] 发现 reflected XSS: "
                        f"{param_info['name']} / {reflected_result.injection_type}"
                    )

            if XSSType.STORED in self.config.xss_types:
                stored_result = self._detect_stored_param(param_info)
                if stored_result:
                    results.append(stored_result)
                    self._log(
                        f"[!] 发现 stored XSS: "
                        f"{param_info['name']} / {stored_result.injection_type}"
                    )

            if XSSType.DOM in self.config.xss_types:
                dom_result = self._detect_dom_param(param_info)
                if dom_result:
                    results.append(dom_result)
                    self._log(
                        f"[!] 发现 dom XSS: "
                        f"{param_info['name']} / {dom_result.injection_type}"
                    )

            if self.config.delay > 0:
                time.sleep(self.config.delay)

        return results

    def _extract_test_params(self) -> List[Dict[str, Any]]:
        params: List[Dict[str, Any]] = []
        parsed = urlparse(self.config.url)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            params.append({"name": key, "type": "get", "original_value": value})

        for key, value in (self.config.post_data or {}).items():
            params.append({"name": key, "type": "post", "original_value": value})

        return params

    def _detect_reflected_param(self, param_info: Dict[str, Any]) -> Optional[XSSResult]:
        probe_value = self._build_probe_value(param_info["name"])
        probe_response = self._send_injected_request(param_info, probe_value)
        if not probe_response:
            return None

        contexts = self._find_reflection_contexts(probe_response.text, probe_value)
        if not contexts and param_info["type"] != "post":
            return None

        if contexts:
            char_profile = self._probe_character_profile(param_info)
            self._log(
                f"[*] 参数 {param_info['name']} 回显上下文: "
                + ", ".join(context.label for context in contexts)
            )
        else:
            contexts = [ReflectionContext("unknown", "未识别回显上下文", "")]
            char_profile = {}
            self._log(f"[*] 参数 {param_info['name']} 未识别到直接回显，尝试字典回退")
        candidates = self._build_contextual_payloads(contexts, char_profile, XSSType.REFLECTED)
        return self._try_payload_candidates(
            param_info=param_info,
            xss_type=XSSType.REFLECTED,
            candidates=candidates,
            review_url=None,
            context_hint=contexts[0],
        )
    def _detect_stored_param(self, param_info: Dict[str, Any]) -> Optional[XSSResult]:
        review_url = self.config.stored_view_url or self.config.url
        probe_value = self._build_probe_value(param_info["name"])
        submit_response = self._send_injected_request(param_info, probe_value)
        if not submit_response:
            return None

        if self.config.stored_wait > 0:
            time.sleep(self.config.stored_wait)

        review_response = self.requester.send_request(review_url, "GET", None)
        if not review_response:
            return None

        contexts = self._find_reflection_contexts(review_response.text, probe_value)
        if not contexts and param_info["type"] != "post":
            return None

        if contexts:
            char_profile = self._probe_character_profile(param_info, review_url=review_url, stored=True)
            self._log(
                f"[*] 参数 {param_info['name']} 存储回显上下文: "
                + ", ".join(context.label for context in contexts)
            )
        else:
            contexts = [ReflectionContext("unknown", "未识别回显上下文", "")]
            char_profile = {}
            self._log(f"[*] 参数 {param_info['name']} 未识别到存储回显上下文，尝试字典回退")
        candidates = self._build_contextual_payloads(contexts, char_profile, XSSType.STORED)
        return self._try_payload_candidates(
            param_info=param_info,
            xss_type=XSSType.STORED,
            candidates=candidates,
            review_url=review_url,
            context_hint=contexts[0],
        )
    def _detect_dom_param(self, param_info: Dict[str, Any]) -> Optional[XSSResult]:
        probe_value = self._build_probe_value(param_info["name"])
        probe_response = self._send_injected_request(param_info, probe_value)
        if not probe_response:
            return None

        matched, evidence, confidence, injection_type = self._check_dom_xss(
            probe_response.text,
            probe_value,
        )
        contexts = self._find_reflection_contexts(probe_response.text, probe_value)
        if not matched and param_info["type"] != "post":
            return None

        if matched:
            if contexts:
                char_profile = self._probe_character_profile(param_info)
                self._log(
                    f"[*] 参数 {param_info['name']} DOM 上下文: "
                    + ", ".join(context.label for context in contexts)
                )
            else:
                contexts = [ReflectionContext("unknown", "未识别 DOM 上下文", "")]
                char_profile = {}
        else:
            contexts = contexts or [ReflectionContext("unknown", "未识别 DOM 上下文", "")]
            char_profile = {}
            self._log(f"[*] 参数 {param_info['name']} DOM probe 未命中，尝试字典回退")

        candidates = self._build_contextual_payloads(contexts, char_profile, XSSType.DOM)
        dom_result = self._try_dom_candidates(
            param_info=param_info,
            candidates=candidates,
            context_hint=contexts[0],
        )
        if dom_result:
            return dom_result
        if not matched:
            return None

        chosen = candidates[0] if candidates else PayloadCandidate(
            name="DOM probe",
            payload=probe_value,
            injection_type=injection_type,
            context_kind=contexts[0].kind if contexts else "dom",
            source="probe",
        )
        return XSSResult(
            vulnerable=True,
            param_name=param_info["name"],
            xss_type=XSSType.DOM,
            payload=chosen.payload,
            payload_name=chosen.name,
            url=getattr(probe_response, "url", self.config.url),
            method="POST" if param_info["type"] == "post" else "GET",
            response_text=probe_response.text[:2000],
            evidence=evidence,
            confidence=confidence,
            injection_type=injection_type or chosen.injection_type,
            context_snippet=contexts[0].snippet if contexts else "",
        )

    def _try_dom_candidates(
        self,
        param_info: Dict[str, Any],
        candidates: List[PayloadCandidate],
        context_hint: ReflectionContext,
    ) -> Optional[XSSResult]:
        best_match: Optional[XSSResult] = None
        best_rank = -1

        for candidate in candidates:
            target_response = self._dispatch_candidate(param_info, candidate.payload, None)
            if not target_response:
                continue

            matched, evidence, confidence, injection_type = self._check_dom_xss(
                target_response.text,
                candidate.payload,
            )
            if not matched:
                continue

            result = XSSResult(
                vulnerable=True,
                param_name=param_info["name"],
                xss_type=XSSType.DOM,
                payload=candidate.payload,
                payload_name=candidate.name,
                url=getattr(target_response, "url", self.config.url),
                method="POST" if param_info["type"] == "post" else "GET",
                response_text=target_response.text[:2000],
                evidence=evidence,
                confidence=confidence,
                injection_type=injection_type or candidate.injection_type,
                context_snippet=context_hint.snippet,
            )
            rank = self._confidence_rank(confidence)
            if rank > best_rank:
                best_match = result
                best_rank = rank
            if confidence == "high":
                return result

            if self.config.delay > 0:
                time.sleep(self.config.delay)

        return best_match
    def _try_payload_candidates(
        self,
        param_info: Dict[str, Any],
        xss_type: XSSType,
        candidates: List[PayloadCandidate],
        review_url: Optional[str],
        context_hint: ReflectionContext,
    ) -> Optional[XSSResult]:
        best_match: Optional[XSSResult] = None
        best_rank = -1

        for candidate in candidates:
            target_response = self._dispatch_candidate(param_info, candidate.payload, review_url)
            if not target_response:
                continue

            matched, evidence, confidence = self._check_payload_reflection(
                target_response.text,
                candidate,
            )
            if not matched:
                continue

            result = XSSResult(
                vulnerable=True,
                param_name=param_info["name"],
                xss_type=xss_type,
                payload=candidate.payload,
                payload_name=candidate.name,
                url=getattr(target_response, "url", review_url or self.config.url),
                method="POST" if param_info["type"] == "post" else "GET",
                response_text=target_response.text[:2000],
                evidence=evidence,
                confidence=confidence,
                injection_type=candidate.injection_type,
                context_snippet=context_hint.snippet,
            )
            rank = self._confidence_rank(confidence)
            if rank > best_rank:
                best_match = result
                best_rank = rank
            if confidence == "high":
                return result

            if self.config.delay > 0:
                time.sleep(self.config.delay)

        return best_match

    def _dispatch_candidate(
        self,
        param_info: Dict[str, Any],
        payload_value: str,
        review_url: Optional[str],
    ) -> Optional[Any]:
        submit_response = self._send_injected_request(param_info, payload_value)
        if not submit_response:
            return None

        if not review_url:
            return submit_response

        if self.config.stored_wait > 0:
            time.sleep(self.config.stored_wait)
        return self.requester.send_request(review_url, "GET", None)

    def _send_injected_request(self, param_info: Dict[str, Any], payload_value: str) -> Optional[Any]:
        if param_info["type"] == "get":
            url = self._inject_get_param(param_info["name"], payload_value)
            return self.requester.send_request(url, "GET", None)

        post_data = dict(self.config.post_data or {})
        post_data[param_info["name"]] = payload_value
        return self.requester.send_request(self.config.url, "POST", post_data, self.config.post_mode)

    def _inject_get_param(self, param_name: str, payload_value: str) -> str:
        parsed = urlparse(self.config.url)
        query_items = parse_qsl(parsed.query, keep_blank_values=True)

        updated_items = []
        replaced = False
        for key, value in query_items:
            if key == param_name:
                updated_items.append((key, payload_value))
                replaced = True
            else:
                updated_items.append((key, value))
        if not replaced:
            updated_items.append((param_name, payload_value))

        return urlunparse(parsed._replace(query=urlencode(updated_items, doseq=True)))

    def _build_probe_value(self, param_name: str) -> str:
        self._probe_counter += 1
        return f"xssprobe{self._probe_counter:02d}_{param_name}"

    def _probe_character_profile(
        self,
        param_info: Dict[str, Any],
        review_url: Optional[str] = None,
        stored: bool = False,
    ) -> Dict[str, str]:
        start_marker = f"xsschr{self._probe_counter:02d}a"
        end_marker = f"xsschr{self._probe_counter:02d}b"
        char_probe = f"{start_marker}'\"<>/{end_marker}"
        response = self._dispatch_candidate(param_info, char_probe, review_url if stored else None)
        if not response:
            return {}

        reflected = self._extract_between(response.text, start_marker, end_marker)
        if reflected is None:
            return {}

        return {
            "'": self._classify_reflected_char(reflected, "'", ("&#39;", "&#x27;", "&apos;")),
            '"': self._classify_reflected_char(reflected, '"', ("&quot;", "&#34;", "&#x22;")),
            "<": self._classify_reflected_char(reflected, "<", ("&lt;", "&#60;", "&#x3c;")),
            ">": self._classify_reflected_char(reflected, ">", ("&gt;", "&#62;", "&#x3e;")),
            "/": self._classify_reflected_char(reflected, "/", ("&#47;", "&#x2f;")),
        }

    def _classify_reflected_char(
        self,
        reflected_text: str,
        raw_char: str,
        encoded_markers: tuple[str, ...],
    ) -> str:
        lowered = reflected_text.lower()
        if raw_char in reflected_text:
            return "raw"
        if any(marker.lower() in lowered for marker in encoded_markers):
            return "encoded"
        return "stripped"

    def _extract_between(self, text: str, start_marker: str, end_marker: str) -> Optional[str]:
        start_index = text.find(start_marker)
        if start_index == -1:
            return None
        end_index = text.find(end_marker, start_index + len(start_marker))
        if end_index == -1:
            return None
        return text[start_index + len(start_marker):end_index]

    def _find_reflection_contexts(self, response_text: str, marker: str) -> List[ReflectionContext]:
        contexts: List[ReflectionContext] = []
        seen: set[tuple[str, str, str]] = set()

        for match in re.finditer(re.escape(marker), response_text):
            context = self._detect_context_for_match(response_text, match.start(), match.end())
            dedupe_key = (context.kind, context.attribute, context.quote)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            contexts.append(context)

        return contexts

    def _detect_context_for_match(
        self,
        response_text: str,
        start: int,
        end: int,
    ) -> ReflectionContext:
        snippet = self._make_snippet(response_text, start, end)

        comment_start = response_text.rfind("<!--", 0, start)
        comment_end = response_text.rfind("-->", 0, start)
        if comment_start != -1 and comment_start > comment_end:
            return ReflectionContext("html_comment", "HTML 注释", snippet)

        script_context = self._detect_script_context(response_text, start, end, snippet)
        if script_context:
            return script_context

        attr_context = self._detect_attribute_context(response_text, start, end, snippet)
        if attr_context:
            return attr_context

        return ReflectionContext("html_text", "HTML 文本", snippet)

    def _detect_script_context(
        self,
        response_text: str,
        start: int,
        end: int,
        snippet: str,
    ) -> Optional[ReflectionContext]:
        for match in re.finditer(r"(?is)<script\b[^>]*>(.*?)</script\s*>", response_text):
            content_start, content_end = match.span(1)
            if not (content_start <= start <= end <= content_end):
                continue

            script_body = match.group(1)
            local_pos = start - content_start
            quote = self._detect_javascript_quote(script_body, local_pos)
            if quote == "'":
                return ReflectionContext("script_string_single", "JavaScript 单引号字符串", snippet, quote=quote)
            if quote == '"':
                return ReflectionContext("script_string_double", "JavaScript 双引号字符串", snippet, quote=quote)
            if quote == "`":
                return ReflectionContext("script_string_template", "JavaScript 模板字符串", snippet, quote=quote)
            return ReflectionContext("script_block", "JavaScript 代码块", snippet)

        return None

    def _detect_javascript_quote(self, script_body: str, position: int) -> str:
        in_quote = ""
        escaped = False
        for index, char in enumerate(script_body):
            if index >= position:
                break
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if in_quote:
                if char == in_quote:
                    in_quote = ""
                continue
            if char in {"'", '"', "`"}:
                in_quote = char
        return in_quote

    def _detect_attribute_context(
        self,
        response_text: str,
        start: int,
        end: int,
        snippet: str,
    ) -> Optional[ReflectionContext]:
        left_angle = response_text.rfind("<", 0, start)
        left_close = response_text.rfind(">", 0, start)
        right_angle = response_text.find(">", end)

        if left_angle == -1 or right_angle == -1 or left_angle < left_close:
            return None

        tag_text = response_text[left_angle:right_angle + 1]
        tag_start = left_angle
        attr_pattern = re.compile(
            r"([^\s\"'<>/=]+)\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))",
            re.IGNORECASE,
        )

        for match in attr_pattern.finditer(tag_text):
            attr_name = match.group(1).lower()
            if match.group(2) is not None:
                value = match.group(2)
                quote = '"'
                value_start = tag_start + match.start(2)
                value_end = tag_start + match.end(2)
                kind = "uri_attribute" if attr_name in self.URI_ATTRIBUTES else "attr_double"
                label = "URI 属性" if kind == "uri_attribute" else "双引号属性值"
            elif match.group(3) is not None:
                value = match.group(3)
                quote = "'"
                value_start = tag_start + match.start(3)
                value_end = tag_start + match.end(3)
                kind = "uri_attribute" if attr_name in self.URI_ATTRIBUTES else "attr_single"
                label = "URI 属性" if kind == "uri_attribute" else "单引号属性值"
            else:
                value = match.group(4) or ""
                quote = ""
                value_start = tag_start + match.start(4)
                value_end = tag_start + match.end(4)
                kind = "uri_attribute" if attr_name in self.URI_ATTRIBUTES else "attr_unquoted"
                label = "URI 属性" if kind == "uri_attribute" else "无引号属性值"

            if value_start <= start <= value_end and value:
                return ReflectionContext(kind, label, snippet, attribute=attr_name, quote=quote)

        return ReflectionContext("tag_body", "HTML 标签内部", snippet)

    def _make_snippet(self, text: str, start: int, end: int, radius: int = 80) -> str:
        left = max(0, start - radius)
        right = min(len(text), end + radius)
        return text[left:right].replace("\n", "\\n")

    def _build_contextual_payloads(
        self,
        contexts: List[ReflectionContext],
        char_profile: Dict[str, str],
        xss_type: XSSType,
    ) -> List[PayloadCandidate]:
        candidates: List[PayloadCandidate] = []
        seen_payloads: set[str] = set()

        for context in contexts:
            for candidate in self._payloads_for_context(context, char_profile):
                if candidate.payload in seen_payloads:
                    continue
                seen_payloads.add(candidate.payload)
                candidates.append(candidate)

        for payload in self.payloads:
            if payload.xss_type != xss_type and not (
                xss_type == XSSType.STORED and payload.xss_type == XSSType.REFLECTED
            ):
                continue
            if payload.payload in seen_payloads:
                continue
            seen_payloads.add(payload.payload)
            fallback_type = contexts[0].label if contexts else xss_type.value
            candidates.append(
                PayloadCandidate(
                    name=payload.name,
                    payload=payload.payload,
                    injection_type=f"{fallback_type} / 字典补充",
                    context_kind=contexts[0].kind if contexts else xss_type.value,
                    source="dictionary",
                )
            )

        return candidates

    def _payloads_for_context(
        self,
        context: ReflectionContext,
        char_profile: Dict[str, str],
    ) -> List[PayloadCandidate]:
        candidates: List[PayloadCandidate] = []
        raw_lt = char_profile.get("<", "raw") == "raw"
        raw_double = char_profile.get('"', "raw") == "raw"
        raw_single = char_profile.get("'", "raw") == "raw"

        def add(name: str, payload: str) -> None:
            candidates.append(
                PayloadCandidate(
                    name=name,
                    payload=payload,
                    injection_type=context.label,
                    context_kind=context.kind,
                )
            )

        if context.kind == "html_text":
            if raw_lt:
                add("HTML 文本 svg onload", "<svg/onload=alert(1)>")
                add("HTML 文本 img onerror", "<img src=x onerror=alert(1)>")
                add("HTML 文本 script", "<script>alert(1)</script>")
        elif context.kind == "html_comment":
            if raw_lt:
                add("注释闭合 svg", "--><svg/onload=alert(1)>")
                add("注释闭合 script", "--><script>alert(1)</script>")
        elif context.kind == "attr_double":
            if raw_double:
                add("双引号属性闭合标签", "\"><svg/onload=alert(1)>")
                add("双引号属性事件注入", "\" autofocus onfocus=alert(1) x=\"")
        elif context.kind == "attr_single":
            if raw_single:
                add("单引号属性闭合标签", "'><svg/onload=alert(1)>")
                add("单引号属性事件注入", "' autofocus onfocus=alert(1) x='")
        elif context.kind == "attr_unquoted":
            add("无引号属性事件注入", " onmouseover=alert(1) x=")
            if raw_lt:
                add("无引号属性闭合标签", "><svg/onload=alert(1)>")
        elif context.kind == "uri_attribute":
            add("URI 协议注入", "javascript:alert(1)")
            if raw_lt:
                add("URI data 协议注入", "data:text/html,<svg/onload=alert(1)>")
            if context.quote == '"' and raw_double:
                add("URI 属性闭合标签", "\"><svg/onload=alert(1)>")
            if context.quote == "'" and raw_single:
                add("URI 属性闭合标签", "'><svg/onload=alert(1)>")
        elif context.kind == "script_string_single":
            if raw_single:
                add("单引号脚本逃逸", "';alert(1);//")
            if raw_lt:
                add("脚本块闭合标签", "</script><svg/onload=alert(1)>")
        elif context.kind == "script_string_double":
            if raw_double:
                add("双引号脚本逃逸", "\";alert(1);//")
            if raw_lt:
                add("脚本块闭合标签", "</script><svg/onload=alert(1)>")
        elif context.kind == "script_string_template":
            add("模板字符串脚本逃逸", "`;alert(1);//")
            if raw_lt:
                add("脚本块闭合标签", "</script><svg/onload=alert(1)>")
        elif context.kind == "script_block":
            add("脚本块直接注入", "alert(1)//")
            if raw_lt:
                add("脚本块闭合标签", "</script><svg/onload=alert(1)>")
        elif context.kind == "tag_body" and raw_lt:
            add("标签内部闭合注入", "><svg/onload=alert(1)>")

        return candidates

    def _check_payload_reflection(
        self,
        response_text: str,
        candidate: PayloadCandidate,
    ) -> tuple[bool, str, str]:
        payload = candidate.payload
        escaped_payload = html.escape(payload, quote=True)
        raw_payload = html.unescape(payload)
        if payload in response_text or raw_payload in response_text or escaped_payload in response_text:
            return True, f"响应中存在可用注入语句: {payload[:100]}", "high"

        if any(token in payload.lower() for token in self.DANGEROUS_TOKENS):
            dangerous_match = self._find_dangerous_fragment(response_text)
            if dangerous_match:
                return True, f"响应中出现危险片段: {dangerous_match[:100]}", "medium"

        if candidate.context_kind.startswith("script"):
            script_match = re.search(r"(?is)<script\b[^>]*>.*?alert\(1\).*?</script\s*>", response_text)
            if script_match:
                return True, "payload 已进入 <script> 执行上下文", "medium"

        if candidate.context_kind.startswith("attr") or candidate.context_kind == "uri_attribute":
            attr_match = re.search(
                r"(?is)\bon[a-z]+\s*=\s*[\"']?alert\(1\)|javascript\s*:\s*alert\(1\)",
                response_text,
            )
            if attr_match:
                return True, f"事件或协议注入成功: {attr_match.group()[:100]}", "high"

        if self.baseline_length:
            diff = abs(len(response_text) - self.baseline_length)
            if diff > 40:
                return True, f"响应长度变化明显: {self.baseline_length} -> {len(response_text)}", "low"

        return False, "", "low"

    def _find_dangerous_fragment(self, response_text: str) -> str:
        for pattern in (
            self.patterns["dangerous_tags"]
            + self.patterns["event_handlers"]
            + self.patterns["dangerous_protocols"]
        ):
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return match.group()
        return ""

    def _check_dom_xss(
        self,
        response_text: str,
        payload_value: str,
    ) -> tuple[bool, str, str, str]:
        sink_match = None
        for pattern in self.patterns["dom_sinks"]:
            sink_match = re.search(pattern, response_text, re.IGNORECASE)
            if sink_match:
                break

        source_match = None
        for pattern in self.patterns["dom_sources"]:
            source_match = re.search(pattern, response_text, re.IGNORECASE)
            if source_match:
                break

        contexts = self._find_reflection_contexts(response_text, payload_value)
        injection_type = "DOM source -> sink"
        if contexts:
            injection_type = f"DOM / {contexts[0].label}"

        if sink_match and source_match:
            return (
                True,
                f"页面同时存在 DOM source 和 sink: {source_match.group()} -> {sink_match.group()}",
                "medium",
                injection_type,
            )

        lowered = response_text.lower()
        if any(token in payload_value.lower() for token in self.DANGEROUS_TOKENS):
            if any(token in lowered for token in self.DANGEROUS_TOKENS):
                return (
                    True,
                    "页面脚本环境包含危险标记，且参数进入了可疑 DOM 上下文",
                    "low",
                    injection_type,
                )

        return False, "", "low", injection_type

    def _confidence_rank(self, confidence: str) -> int:
        mapping = {"low": 1, "medium": 2, "high": 3}
        return mapping.get(confidence, 0)






