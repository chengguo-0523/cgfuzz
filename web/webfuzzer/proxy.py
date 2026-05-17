import http.client
import select
import socket
import socketserver
import ssl
import threading
import time
from typing import Dict, Optional
from urllib.parse import urlsplit

from PyQt6.QtCore import QObject, pyqtSignal

from .models import ProxyCapture

PREVIEW_LIMIT = 20000
TEXTUAL_TYPES = ("text/", "json", "xml", "javascript", "x-www-form-urlencoded")


def decode_preview(data: bytes) -> str:
    if not data:
        return ""
    return data[:PREVIEW_LIMIT].decode("utf-8", errors="ignore")


def is_textual(headers: Dict[str, str]) -> bool:
    content_type = headers.get("Content-Type", "").lower()
    return any(token in content_type for token in TEXTUAL_TYPES)


def sanitize_request_headers(headers: Dict[str, str]) -> Dict[str, str]:
    filtered = dict(headers)
    for key in [
        "Proxy-Connection",
        "Connection",
        "Keep-Alive",
        "Transfer-Encoding",
        "Proxy-Authenticate",
        "Proxy-Authorization",
        "TE",
        "Trailer",
        "Upgrade",
    ]:
        filtered.pop(key, None)
    filtered["Connection"] = "close"
    return filtered


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class ProxyController(QObject):
    capture_ready = pyqtSignal(object)
    status_message = pyqtSignal(str)
    running_changed = pyqtSignal(bool)

    def __init__(self) -> None:
        super().__init__()
        self._server: Optional[ThreadingTCPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._counter = 0
        self._lock = threading.Lock()
        self.host = "127.0.0.1"
        self.port = 8080

    @property
    def is_running(self) -> bool:
        return self._server is not None and self._thread is not None and self._thread.is_alive()

    def next_index(self) -> int:
        with self._lock:
            self._counter += 1
            return self._counter

    def publish_capture(self, capture: ProxyCapture) -> None:
        self.capture_ready.emit(capture)

    def start(self, host: str = "127.0.0.1", port: int = 8080) -> None:
        if self.is_running:
            self.status_message.emit("抓包代理已在运行。")
            return
        self.host = host
        self.port = port
        handler_cls = type("ProxyRequestHandler", (ProxyRequestHandler,), {})
        self._server = ThreadingTCPServer((host, port), handler_cls)
        self._server.controller = self  # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self.status_message.emit(f"抓包代理已启动，监听 {host}:{port}")
        self.running_changed.emit(True)

    def stop(self) -> None:
        if not self._server:
            return
        self._server.shutdown()
        self._server.server_close()
        if self._thread:
            self._thread.join(timeout=2)
        self._server = None
        self._thread = None
        self.status_message.emit("抓包代理已停止。")
        self.running_changed.emit(False)


class ProxyRequestHandler(socketserver.StreamRequestHandler):
    controller: ProxyController

    def handle(self) -> None:
        request_line = self.rfile.readline(65536)
        if not request_line:
            return

        start_time = time.perf_counter()
        method = ""
        target = ""
        headers: Dict[str, str] = {}
        body = b""

        try:
            line_text = request_line.decode("iso-8859-1").strip()
            parts = line_text.split()
            if len(parts) < 2:
                return
            method = parts[0].upper()
            target = parts[1]
            headers = self.read_headers()
            content_length = int(headers.get("Content-Length", "0") or "0")
            if content_length > 0:
                body = self.rfile.read(content_length)

            if method == "CONNECT":
                self.handle_connect(target, headers, start_time)
            else:
                self.handle_http(method, target, headers, body, start_time)
        except Exception as exc:
            capture = ProxyCapture(
                index=self.server.controller.next_index(),  # type: ignore[attr-defined]
                method=method or "UNKNOWN",
                scheme="http",
                host="",
                port=0,
                path=target or "/",
                client_address=self.client_address[0],
                request_headers=headers,
                request_body=decode_preview(body),
                elapsed_ms=int((time.perf_counter() - start_time) * 1000),
                error=str(exc),
            )
            self.server.controller.publish_capture(capture)  # type: ignore[attr-defined]
            try:
                self.wfile.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass

    def read_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        while True:
            line = self.rfile.readline(65536)
            if line in (b"\r\n", b"\n", b""):
                break
            decoded = line.decode("iso-8859-1").strip()
            if not decoded or ":" not in decoded:
                continue
            key, value = decoded.split(":", 1)
            headers[key.strip()] = value.strip()
        return headers

    def handle_connect(self, target: str, headers: Dict[str, str], start_time: float) -> None:
        host, _, port_text = target.partition(":")
        port = int(port_text or "443")
        capture = ProxyCapture(
            index=self.server.controller.next_index(),  # type: ignore[attr-defined]
            method="CONNECT",
            scheme="https",
            host=host,
            port=port,
            path=target,
            client_address=self.client_address[0],
            request_headers=headers,
        )
        upstream = None
        try:
            upstream = socket.create_connection((host, port), timeout=10)
            self.connection.sendall(b"HTTP/1.1 200 Connection Established\r\nConnection: close\r\n\r\n")
            client_to_server, server_to_client = self.relay_tunnel(self.connection, upstream)
            capture.status_code = 200
            capture.request_size = client_to_server
            capture.response_size = server_to_client
        except Exception as exc:
            capture.status_code = 502
            capture.error = str(exc)
            try:
                self.connection.sendall(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
        finally:
            if upstream is not None:
                try:
                    upstream.close()
                except OSError:
                    pass
            capture.elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            self.server.controller.publish_capture(capture)  # type: ignore[attr-defined]

    def relay_tunnel(self, client: socket.socket, upstream: socket.socket) -> tuple[int, int]:
        client.settimeout(1)
        upstream.settimeout(1)
        client_to_server = 0
        server_to_client = 0
        sockets = [client, upstream]
        while True:
            try:
                readable, _, exceptional = select.select(sockets, [], sockets, 1.0)
            except OSError:
                break
            if exceptional:
                break
            if not readable:
                continue
            for current in readable:
                try:
                    chunk = current.recv(8192)
                except OSError:
                    return client_to_server, server_to_client
                if not chunk:
                    return client_to_server, server_to_client
                if current is client:
                    upstream.sendall(chunk)
                    client_to_server += len(chunk)
                else:
                    client.sendall(chunk)
                    server_to_client += len(chunk)
        return client_to_server, server_to_client

    def handle_http(self, method: str, target: str, headers: Dict[str, str], body: bytes, start_time: float) -> None:
        parsed = urlsplit(target)
        if parsed.scheme and parsed.netloc:
            scheme = parsed.scheme.lower()
            host = parsed.hostname or ""
            port = parsed.port or (443 if scheme == "https" else 80)
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"
        else:
            scheme = "http"
            host_header = headers.get("Host", "")
            if not host_header:
                raise ValueError("缺少 Host 请求头")
            if ":" in host_header:
                host, port_text = host_header.rsplit(":", 1)
                port = int(port_text)
            else:
                host = host_header
                port = 80
            path = target if target.startswith("/") else f"/{target}"

        capture = ProxyCapture(
            index=self.server.controller.next_index(),  # type: ignore[attr-defined]
            method=method,
            scheme=scheme,
            host=host,
            port=port,
            path=path,
            client_address=self.client_address[0],
            request_headers=headers,
            request_body=decode_preview(body),
            request_size=len(body),
        )

        connection = None
        try:
            connection = self.create_upstream_connection(scheme, host, port)
            forward_headers = sanitize_request_headers(headers)
            forward_headers["Host"] = headers.get("Host") or host
            connection.request(method, path, body=body or None, headers=forward_headers)
            response = connection.getresponse()
            response_body = response.read()
            response_headers = {key: value for key, value in response.getheaders()}
            capture.status_code = response.status
            capture.response_size = len(response_body)
            capture.response_headers = response_headers
            if is_textual(response_headers):
                capture.response_body = decode_preview(response_body)
            self.send_http_response(response.status, response.reason, response_headers, response_body)
        except Exception as exc:
            capture.status_code = 502
            capture.error = str(exc)
            self.wfile.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
        finally:
            if connection is not None:
                try:
                    connection.close()
                except OSError:
                    pass
            capture.elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            self.server.controller.publish_capture(capture)  # type: ignore[attr-defined]

    def create_upstream_connection(self, scheme: str, host: str, port: int) -> http.client.HTTPConnection:
        if scheme == "https":
            context = ssl._create_unverified_context()
            return http.client.HTTPSConnection(host, port, timeout=15, context=context)
        return http.client.HTTPConnection(host, port, timeout=15)

    def send_http_response(self, status: int, reason: str, headers: Dict[str, str], body: bytes) -> None:
        status_line = f"HTTP/1.1 {status} {reason}\r\n".encode("iso-8859-1", errors="ignore")
        self.wfile.write(status_line)
        skip_headers = {"Transfer-Encoding", "Connection", "Keep-Alive", "Proxy-Connection"}
        for key, value in headers.items():
            if key in skip_headers:
                continue
            header_line = f"{key}: {value}\r\n".encode("iso-8859-1", errors="ignore")
            self.wfile.write(header_line)
        self.wfile.write(f"Content-Length: {len(body)}\r\n".encode("ascii"))
        self.wfile.write(b"Connection: close\r\n\r\n")
        if body:
            self.wfile.write(body)
        self.wfile.flush()

