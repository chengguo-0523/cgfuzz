from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


class PayloadManager:
    def __init__(
        self,
        payload_dir: Optional[str] = None,
        extra_payload_files: Optional[List[str]] = None,
        logger: Optional[Callable[[str], None]] = None,
    ) -> None:
        if payload_dir is None:
            payload_dir = str(Path(__file__).resolve().parent.parent / "payloads")
        self.payload_dir = Path(payload_dir)
        self.extra_payload_files = [Path(path) for path in extra_payload_files or []]
        self.logger = logger
        self.payloads: Dict[str, List[Dict[str, Any]]] = {
            "sql": [],
            "xss": [],
            "cmd": [],
        }
        self._load_all_payloads()

    def _log(self, message: str) -> None:
        if self.logger:
            self.logger(message)

    def _load_all_payloads(self) -> None:
        payload_files = {
            "sql": "sql.json",
            "xss": "xss.json",
            "cmd": "cmd.json",
        }

        for vuln_type, filename in payload_files.items():
            file_path = self.payload_dir / filename
            try:
                with open(file_path, "r", encoding="utf-8") as file:
                    data = json.load(file)
                self.payloads[vuln_type] = data.get("payloads", [])
            except FileNotFoundError:
                self._log(f"[!] 未找到 payload 文件: {file_path}")
            except json.JSONDecodeError as exc:
                self._log(f"[!] payload 文件格式错误 {filename}: {exc}")

        for file_path in self.extra_payload_files:
            self._load_external_payload_file(file_path)

    def _load_external_payload_file(self, file_path: Path) -> None:
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                data = json.load(file)
        except FileNotFoundError:
            self._log(f"[!] 未找到自定义字典: {file_path}")
            return
        except json.JSONDecodeError as exc:
            self._log(f"[!] 自定义字典格式错误 {file_path.name}: {exc}")
            return

        default_type: Optional[str] = None
        payload_items: Any = data
        if isinstance(data, dict):
            payload_items = data.get("payloads", [])
            default_type = data.get("type")

        if not isinstance(payload_items, list):
            self._log(f"[!] 自定义字典格式无效: {file_path}")
            return

        added_count = 0
        inferred_type = file_path.stem.lower() if file_path.stem.lower() in self.payloads else None
        for item in payload_items:
            if not isinstance(item, dict):
                continue
            payload_value = item.get("payload")
            if not isinstance(payload_value, str) or not payload_value:
                continue

            vuln_type = item.get("type") or default_type or inferred_type
            if vuln_type not in self.payloads:
                self._log(
                    f"[!] 跳过未标注类型的 payload: {file_path.name} / "
                    f"{item.get('name', payload_value[:20])}"
                )
                continue

            payload_copy = item.copy()
            payload_copy["type"] = vuln_type
            self.payloads[vuln_type].append(payload_copy)
            added_count += 1

        self._log(f"[+] 已加载自定义字典 {file_path.name}: {added_count} 条")

    def get_payloads(self, vuln_type: Optional[str] = None) -> List[Dict[str, Any]]:
        if vuln_type:
            return self.payloads.get(vuln_type, [])

        all_payloads: List[Dict[str, Any]] = []
        for current_type, payloads in self.payloads.items():
            for payload in payloads:
                payload_copy = payload.copy()
                payload_copy.setdefault("type", current_type)
                all_payloads.append(payload_copy)
        return all_payloads

    def get_payload_strings(self, vuln_type: Optional[str] = None) -> List[str]:
        return [payload["payload"] for payload in self.get_payloads(vuln_type)]

    def get_payload_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        for payloads in self.payloads.values():
            for payload in payloads:
                if payload.get("name") == name:
                    return payload
        return None

    def add_payload(self, vuln_type: str, payload_data: Dict[str, Any]) -> None:
        self.payloads.setdefault(vuln_type, []).append(payload_data)
        self._log(
            f"[+] 已动态添加 payload: {vuln_type} / "
            f"{payload_data.get('name', 'unnamed')}"
        )

    def get_stats(self) -> Dict[str, int]:
        return {
            vuln_type: len(payloads)
            for vuln_type, payloads in self.payloads.items()
        }
