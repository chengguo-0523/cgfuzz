from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Event
from typing import Dict, List

from PyQt6.QtCore import QThread, pyqtSignal

from .fuzzer import execute_fuzz_request
from .models import FuzzRequestConfig, FuzzResult


class FuzzWorker(QThread):
    result_ready = pyqtSignal(object)
    progress_changed = pyqtSignal(int, int)
    status_message = pyqtSignal(str)
    run_finished = pyqtSignal()

    def __init__(self, config: FuzzRequestConfig, payloads: List[Dict[str, str]]) -> None:
        super().__init__()
        self.config = config
        self.payloads = payloads
        self._stop_event = Event()

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        total = len(self.payloads)
        completed = 0
        self.status_message.emit(f"开始执行，共 {total} 组 payload。")

        with ThreadPoolExecutor(max_workers=max(1, self.config.concurrency)) as executor:
            futures = []
            for index, payload_bindings in enumerate(self.payloads, start=1):
                if self._stop_event.is_set():
                    break
                futures.append(executor.submit(execute_fuzz_request, self.config, payload_bindings, index))

            try:
                for future in as_completed(futures):
                    if self._stop_event.is_set():
                        break
                    result: FuzzResult = future.result()
                    completed += 1
                    self.result_ready.emit(result)
                    self.progress_changed.emit(completed, total)
            finally:
                if self._stop_event.is_set():
                    executor.shutdown(wait=False, cancel_futures=True)
                    self.status_message.emit("任务已停止。")
                else:
                    self.status_message.emit("任务执行完成。")

        self.run_finished.emit()

