from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import parse_qsl

from .detector import Detector
from .extractor import ParameterExtractor
from .payloads import PayloadManager
from .requester import Requester

try:
    from ..mysql_storage import MySQLStorage, MySQLStorageError
except ImportError:
    from mysql_storage import MySQLStorage, MySQLStorageError


LogCallback = Optional[Callable[[str], None]]
ProgressCallback = Optional[Callable[[int, int], None]]


@dataclass
class ScanConfig:
    url: str
    method: str = "GET"
    data: Optional[str] = None
    threads: int = 5
    output: Optional[str] = None
    verbose: bool = False
    payload_type: Optional[str] = None
    custom_payload_files: List[str] = field(default_factory=list)

def parse_post_data(raw_data: Optional[str]) -> Optional[Dict[str, str]]:
    if not raw_data:
        return None

    raw_text = raw_data.strip()
    if not raw_text:
        return None

    normalized = raw_text.replace("\r\n", "&").replace("\n", "&")
    parsed = dict(parse_qsl(normalized, keep_blank_values=True))
    if parsed:
        return parsed

    fallback: Dict[str, str] = {}
    for line in raw_text.replace("\r", "").split("\n"):
        current = line.strip()
        if not current:
            continue
        if "=" in current:
            key, value = current.split("=", 1)
            fallback[key.strip()] = value.strip()
        else:
            fallback[current] = ""
    return fallback or None




class ScanRunner:
    def __init__(
        self,
        config: ScanConfig,
        log_callback: LogCallback = None,
        progress_callback: ProgressCallback = None,
    ) -> None:
        self.config = config
        self.log_callback = log_callback
        self.progress_callback = progress_callback

    def log(self, message: str) -> None:
        if self.log_callback:
            self.log_callback(message)

    def update_progress(self, completed: int, total: int) -> None:
        if self.progress_callback:
            self.progress_callback(completed, total)

    def run(self) -> Dict[str, Any]:
        start_time = time.time()
        config = self.config

        if config.method.upper() == "POST" and not config.data:
            raise ValueError("POST 请求需要填写 data，例如 user=admin&pass=123")

        post_data = parse_post_data(config.data)
        requester = Requester(verbose=config.verbose, logger=self.log)
        payload_manager = PayloadManager(
            logger=self.log,
            extra_payload_files=config.custom_payload_files,
        )
        extractor = ParameterExtractor()
        detector = Detector(requester, verbose=config.verbose, logger=self.log)

        self.log("[+] 扫描器初始化完成")
        self.log(f"[+] 目标地址: {config.url}")
        self.log(f"[+] 请求方法: {config.method.upper()}")
        self.log(f"[+] 线程数: {config.threads}")
        if config.payload_type:
            self.log(f"[+] 限定漏洞类型: {config.payload_type}")
        if config.custom_payload_files:
            self.log(f"[+] 额外字典文件: {len(config.custom_payload_files)} 个")

        payload_stats = payload_manager.get_stats()
        self.log("[+] 已加载 payload:")
        for vuln_type, count in payload_stats.items():
            self.log(f"    {vuln_type}: {count}")

        self.log("[*] 正在测试目标连通性...")
        if not requester.test_connection(config.url):
            raise RuntimeError("无法连接到目标，请检查 URL 是否可访问")
        self.log("[+] 目标连通性正常")

        self.log("[*] 正在获取目标页面...")
        response = requester.send_request(config.url, config.method, post_data)
        if not response:
            raise RuntimeError("初始请求失败，无法继续扫描")

        detector.set_baseline(response)
        self.log(
            f"[+] 初始响应成功: status={response.status_code}, length={len(response.text)}"
        )

        get_params = extractor.extract_get_params(config.url)
        forms = extractor.extract_forms(response.text, config.url)
        test_points = extractor.get_testable_params(config.url, response.text)

        if get_params:
            self.log(f"[+] 发现 GET 参数: {', '.join(get_params)}")
        else:
            self.log("[*] 未发现 GET 参数")

        if forms:
            self.log(f"[+] 发现表单: {len(forms)}")
            for index, form in enumerate(forms, start=1):
                param_names = [item["name"] for item in form["inputs"]]
                self.log(
                    f"    表单 {index}: {form['method']} {form['action']} -> "
                    f"{', '.join(param_names)}"
                )
        else:
            self.log("[*] 未发现表单")

        self.log(f"[*] 共发现 {len(test_points)} 个可测试参数点")

        payloads = payload_manager.get_payloads(config.payload_type)
        total_tasks = len(test_points) * len(payloads)
        self.log(f"[*] 准备检测 {len(payloads)} 条 payload")
        self.log(f"[*] 总测试数: {total_tasks}")
        self.update_progress(0, total_tasks)

        results: List[Dict[str, Any]] = []
        completed = 0
        found_vulns = 0

        if total_tasks == 0:
            summary = self._build_summary(
                elapsed_time=time.time() - start_time,
                payload_stats=payload_stats,
                get_params=get_params,
                forms=forms,
                test_points=test_points,
                results=results,
                sql_analysis=None,
                total_tests=0,
                vulnerabilities_found=0,
            )
            if config.output:
                self._write_output(summary, config.output)
            self._persist_summary(summary)
            self.log("[*] 没有可执行的扫描任务")
            return summary

        self.log("[*] 开始漏洞检测...")
        tasks = [
            (test_point, payload)
            for test_point in test_points
            for payload in payloads
        ]

        with ThreadPoolExecutor(max_workers=max(1, config.threads)) as executor:
            future_map = {
                executor.submit(detector.detect_vulnerability, test_point, payload): (
                    test_point,
                    payload,
                )
                for test_point, payload in tasks
            }

            for future in as_completed(future_map):
                completed += 1
                self.update_progress(completed, total_tasks)

                try:
                    result = future.result()
                except Exception as exc:
                    self.log(f"[!] 检测任务异常: {exc}")
                    continue

                if result.get("success") and result.get("vulnerable"):
                    found_vulns += 1
                    results.append(result)
                    self.log(
                        "[!] 发现漏洞: "
                        f"{result['vuln_type']} | {result['param_name']} | {result['payload']}"
                    )
                    self.log(f"    原因: {result['reason']}")
                elif config.verbose and (completed % 10 == 0 or completed == total_tasks):
                    self.log(f"[*] 进度: {completed}/{total_tasks}")

        sql_analysis = self._analyze_sql_results(detector, test_points, results)
        elapsed_time = time.time() - start_time

        summary = self._build_summary(
            elapsed_time=elapsed_time,
            payload_stats=payload_stats,
            get_params=get_params,
            forms=forms,
            test_points=test_points,
            results=results,
            sql_analysis=sql_analysis,
            total_tests=completed,
            vulnerabilities_found=found_vulns,
        )

        self.log("[+] 扫描完成")
        self.log(f"    总测试数: {completed}")
        self.log(f"    发现漏洞: {found_vulns}")
        self.log(f"    耗时: {elapsed_time:.2f} 秒")

        if sql_analysis:
            self.log("[+] SQL 注入详情")
            self.log(f"    参数: {sql_analysis['param']}")
            self.log(f"    类型: {sql_analysis['injection_type']}")
            self.log(f"    数据库: {sql_analysis['database_type']}")
            if sql_analysis.get("database_name"):
                self.log(f"    数据库名: {sql_analysis['database_name']}")

        if config.output:
            self._write_output(summary, config.output)
            self.log(f"[+] 结果已保存到: {config.output}")

        self._persist_summary(summary)
        return summary

    def _build_summary(
        self,
        *,
        elapsed_time: float,
        payload_stats: Dict[str, int],
        get_params: List[str],
        forms: List[Dict[str, Any]],
        test_points: List[Dict[str, Any]],
        results: List[Dict[str, Any]],
        sql_analysis: Optional[Dict[str, Any]],
        total_tests: int,
        vulnerabilities_found: int,
    ) -> Dict[str, Any]:
        return {
            "target": self.config.url,
            "method": self.config.method.upper(),
            "total_tests": total_tests,
            "vulnerabilities_found": vulnerabilities_found,
            "elapsed_time": elapsed_time,
            "payload_stats": payload_stats,
            "custom_payload_files": self.config.custom_payload_files,
            "get_params": get_params,
            "forms": forms,
            "test_points": test_points,
            "results": results,
            "sql_analysis": sql_analysis,
        }

    def _persist_summary(self, summary: Dict[str, Any]) -> None:
        try:
            storage = MySQLStorage(logger=self.log)
            saved = storage.save_scan_summary(summary)
        except MySQLStorageError as exc:
            self.log(f"[!] MySQL 保存失败: {exc}")
            return
        except Exception as exc:
            self.log(f"[!] MySQL 保存异常: {exc}")
            return

        if saved["xss"] or saved["sql"]:
            self.log(
                "[+] MySQL 持久化完成: "
                f"XSS {saved['xss']} 条, SQL {saved['sql']} 条"
            )

    def _analyze_sql_results(
        self,
        detector: Detector,
        test_points: List[Dict[str, Any]],
        results: List[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        sql_results = [
            item
            for item in results
            if item.get("vuln_type") == "sql" and item.get("vulnerable")
        ]
        if not sql_results:
            return None

        first_param = sql_results[0]["param_name"]
        first_test_point = next(
            (item for item in test_points if item["param_name"] == first_param),
            None,
        )
        if not first_test_point:
            return None

        return detector.extract_sql_info(first_test_point, sql_results)

    def _write_output(self, summary: Dict[str, Any], output_path: str) -> None:
        with open(output_path, "w", encoding="utf-8") as file:
            json.dump(summary, file, indent=2, ensure_ascii=False)


