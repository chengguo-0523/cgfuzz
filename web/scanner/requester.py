from __future__ import annotations

from typing import Any, Callable, Dict, Optional

import requests


class Requester:
    def __init__(
        self,
        timeout: int = 10,
        verbose: bool = False,
        logger: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.timeout = timeout
        self.verbose = verbose
        self.logger = logger
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
            }
        )

    def _log(self, message: str) -> None:
        if self.logger:
            self.logger(message)

    def send_request(
        self,
        url: str,
        method: str = "GET",
        data: Optional[Any] = None,
        body_mode: str = "form",
    ) -> Optional[requests.Response]:
        try:
            upper_method = method.upper()
            if self.verbose:
                self._log(f"[DEBUG] {upper_method} {url}")
                if data is not None:
                    self._log(f"[DEBUG] 请求数据({body_mode}): {data}")

            if upper_method == "GET":
                response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            elif upper_method == "POST":
                if body_mode == "json":
                    response = self.session.post(
                        url,
                        json=data,
                        timeout=self.timeout,
                        allow_redirects=True,
                    )
                else:
                    response = self.session.post(
                        url,
                        data=data,
                        timeout=self.timeout,
                        allow_redirects=True,
                    )
            else:
                self._log(f"[!] 不支持的 HTTP 方法: {method}")
                return None

            if self.verbose:
                self._log(
                    f"[DEBUG] 响应状态: {response.status_code}, "
                    f"响应长度: {len(response.text)}"
                )
            return response
        except requests.exceptions.Timeout:
            self._log(f"[!] 请求超时: {url}")
            return None
        except requests.exceptions.ConnectionError:
            self._log(f"[!] 连接失败: {url}")
            return None
        except requests.exceptions.TooManyRedirects:
            self._log(f"[!] 重定向次数过多: {url}")
            return None
        except requests.exceptions.RequestException as exc:
            self._log(f"[!] 请求异常: {exc}")
            return None

    def test_connection(self, url: str) -> bool:
        try:
            response = self.session.head(url, timeout=5, allow_redirects=True)
            if 200 <= response.status_code < 400:
                return True
            response = self.session.get(url, timeout=5, allow_redirects=True)
            return 200 <= response.status_code < 400
        except requests.exceptions.RequestException:
            return False
