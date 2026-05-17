from __future__ import annotations

import itertools
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from PyQt6.QtCore import QThread, Qt, pyqtSignal
from PyQt6.QtGui import QAction, QFont
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QSplitter,
    QStatusBar,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

try:
    from .mysql_storage import (
        CONFIG_PATH,
        MySQLConfig,
        MySQLStorage,
        MySQLStorageError,
        load_mysql_config,
        save_mysql_config,
    )
    from .scanner import parse_post_data
    from .scanner.requester import Requester
    from .scanner.sql_exploit import ExploitMethod, SQLExploitConfig, SQLExploiter
    from .scanner.xss_detector import XSSConfig, XSSDetector, XSSType
    from .webfuzzer.dictionary_tools import (
        build_builtin_dictionary,
        build_mask_dictionary,
        build_mutation_dictionary,
        parse_dictionary_text,
    )
    from .webfuzzer.fuzzer import detect_placeholders
    from .webfuzzer.http_parser import parse_raw_http_request
    from .webfuzzer.models import FuzzRequestConfig, FuzzResult, ProxyCapture
    from .webfuzzer.proxy import ProxyController
    from .webfuzzer.result_tools import calculate_similarity, normalize_response_text
    from .webfuzzer.worker import FuzzWorker
except ImportError:
    from mysql_storage import (
        CONFIG_PATH,
        MySQLConfig,
        MySQLStorage,
        MySQLStorageError,
        load_mysql_config,
        save_mysql_config,
    )
    from scanner import parse_post_data
    from scanner.requester import Requester
    from scanner.sql_exploit import ExploitMethod, SQLExploitConfig, SQLExploiter
    from scanner.xss_detector import XSSConfig, XSSDetector, XSSType
    from webfuzzer.dictionary_tools import (
        build_builtin_dictionary,
        build_mask_dictionary,
        build_mutation_dictionary,
        parse_dictionary_text,
    )
    from webfuzzer.fuzzer import detect_placeholders
    from webfuzzer.http_parser import parse_raw_http_request
    from webfuzzer.models import FuzzRequestConfig, FuzzResult, ProxyCapture
    from webfuzzer.proxy import ProxyController
    from webfuzzer.result_tools import calculate_similarity, normalize_response_text
    from webfuzzer.worker import FuzzWorker


APP_TITLE = "Web漏洞模糊测试工具"
WINDOW_SIZE = (1480, 960)


def maybe_apply_pyonedark(app: QApplication) -> bool:
    for module_name in ("py_one_dark", "PyOneDark"):
        try:
            __import__(module_name)
            return True
        except Exception:
            continue
    return False


def apply_light_theme(app: QApplication) -> None:
    maybe_apply_pyonedark(app)
    app.setStyleSheet(
        """
        QWidget {
            background: #ffffff;
            color: #1f2937;
            font-family: "Microsoft YaHei UI", "Segoe UI", sans-serif;
            font-size: 13px;
        }
        QLabel, QCheckBox, QRadioButton, QGroupBox {
            color: #1f2937;
            background: transparent;
        }
        QMainWindow, QMenuBar, QStatusBar, QTabWidget::pane {
            background: #ffffff;
            color: #1f2937;
        }
        QMenuBar::item, QStatusBar, QMenu, QMenu::item {
            color: #1f2937;
            background: #ffffff;
        }
        QMenu::item:selected {
            background: #eff6ff;
        }
        QFrame#Card {
            background: #ffffff;
            border: 1px solid #dbe4f0;
            border-radius: 16px;
        }
        QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QSpinBox, QTableWidget {
            background: #ffffff;
            color: #111827;
            border: 1px solid #cbd5e1;
            border-radius: 12px;
            padding: 8px 10px;
            selection-background-color: #2563eb;
            selection-color: #ffffff;
        }
        QLineEdit[readOnly="true"] {
            color: #64748b;
            background: #f8fafc;
        }
        QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QComboBox:focus, QSpinBox:focus {
            border: 1px solid #3b82f6;
        }
        QLineEdit::placeholder, QTextEdit::placeholder, QPlainTextEdit::placeholder {
            color: #94a3b8;
        }
        QComboBox QAbstractItemView, QTableWidget QTableCornerButton::section {
            background: #ffffff;
            color: #111827;
        }
        QTableWidget::item {
            color: #111827;
        }
        QPushButton {
            background: #f8fafc;
            color: #1e293b;
            border: 1px solid #cbd5e1;
            border-radius: 12px;
            padding: 9px 16px;
            font-weight: 600;
        }
        QPushButton:hover {
            background: #eff6ff;
            border-color: #93c5fd;
        }
        QPushButton[primary="true"] {
            background: #2563eb;
            color: #ffffff;
            border: none;
        }
        QPushButton[primary="true"]:hover {
            background: #1d4ed8;
        }
        QTabBar::tab {
            background: #f8fafc;
            border: 1px solid #dbe4f0;
            border-bottom: none;
            min-width: 120px;
            padding: 10px 18px;
            margin-right: 6px;
            border-top-left-radius: 12px;
            border-top-right-radius: 12px;
            color: #64748b;
            font-weight: 600;
        }
        QTabBar::tab:selected {
            background: #ffffff;
            color: #0f172a;
        }
        QHeaderView::section {
            background: #f8fafc;
            color: #475569;
            border: none;
            border-bottom: 1px solid #dbe4f0;
            padding: 10px;
            font-weight: 600;
        }
        QProgressBar {
            background: #e2e8f0;
            color: #1f2937;
            border: 1px solid #dbe4f0;
            border-radius: 9px;
            text-align: center;
            min-height: 18px;
        }
        QProgressBar::chunk {
            background: #3b82f6;
            border-radius: 9px;
        }
        QLabel[muted="true"] {
            color: #64748b;
        }
        QLabel[title="true"] {
            font-size: 24px;
            font-weight: 700;
            color: #0f172a;
        }
        """
    )


def card_widget() -> QFrame:
    frame = QFrame()
    frame.setObjectName("Card")
    return frame


def create_button(text: str, primary: bool = False) -> QPushButton:
    button = QPushButton(text)
    button.setProperty("primary", primary)
    button.style().unpolish(button)
    button.style().polish(button)
    return button


def set_table_item(table: QTableWidget, row: int, col: int, value: Any) -> None:
    item = QTableWidgetItem("" if value is None else str(value))
    item.setFlags(item.flags() ^ Qt.ItemFlag.ItemIsEditable)
    table.setItem(row, col, item)


def should_hide_sql_display_value(value: Any) -> bool:
    return isinstance(value, str) and value.lstrip().lower().startswith("<font color")


def sanitize_sql_display_value(value: Any) -> Any:
    if should_hide_sql_display_value(value):
        return ""
    return value


def sanitize_sql_display_data(value: Any) -> Any:
    if should_hide_sql_display_value(value):
        return ""
    if isinstance(value, dict):
        return {key: sanitize_sql_display_data(item) for key, item in value.items()}
    if isinstance(value, list):
        cleaned: List[Any] = []
        for item in value:
            if should_hide_sql_display_value(item):
                continue
            cleaned.append(sanitize_sql_display_data(item))
        return cleaned
    return value


class UiMixin:
    def wrap_layout(self, layout: QHBoxLayout) -> QWidget:
        widget = QWidget()
        widget.setLayout(layout)
        return widget

    def setup_table(self, table: QTableWidget) -> None:
        table.verticalHeader().setVisible(False)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)


class XSSWorker(QThread):
    log_message = pyqtSignal(str)
    finished_results = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, config: XSSConfig, persist_to_db: bool = True) -> None:
        super().__init__()
        self.config = config
        self.persist_to_db = persist_to_db

    def run(self) -> None:
        try:
            requester = Requester(timeout=self.config.timeout, logger=self.log_message.emit)
            baseline = requester.send_request(self.config.url, self.config.method, self.config.post_data, self.config.post_mode)
            detector = XSSDetector(requester, self.config, logger=self.log_message.emit)
            if baseline:
                detector.set_baseline(baseline)
            results = detector.detect()
            self._persist_results(results)
            self.finished_results.emit(results)
        except Exception as exc:
            self.failed.emit(str(exc))

    def _persist_results(self, results: List[Any]) -> None:
        if not self.persist_to_db:
            self.log_message.emit("[*] 本次运行未勾选 XSS 结果入库，已跳过 MySQL 写入")
            return
        try:
            saved = MySQLStorage(logger=self.log_message.emit).save_xss_results(
                self.config,
                results,
            )
        except MySQLStorageError as exc:
            self.log_message.emit(f"[!] MySQL 保存失败: {exc}")
            return
        except Exception as exc:
            self.log_message.emit(f"[!] MySQL 保存异常: {exc}")
            return

        if saved:
            self.log_message.emit(f"[+] XSS 结果已写入 MySQL，共 {saved} 条")


class SQLExploitWorker(QThread):
    log_message = pyqtSignal(str)
    finished_result = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(
        self,
        config: SQLExploitConfig,
        action: str,
        row_limit: int,
        persist_to_db: bool = True,
    ) -> None:
        super().__init__()
        self.config = config
        self.action = action
        self.row_limit = row_limit
        self.persist_to_db = persist_to_db

    def run(self) -> None:
        try:
            requester = Requester(logger=self.log_message.emit)
            exploiter = SQLExploiter(requester, self.config, logger=self.log_message.emit)
            baseline = requester.send_request(self.config.url, self.config.method, self.config.post_data, self.config.post_mode)
            if baseline:
                exploiter.set_baseline(baseline)
            if self.action == "probe":
                result = exploiter.test_basic_injection()
            elif self.action == "databases":
                result = exploiter.exploit_databases()
            elif self.action == "tables":
                result = exploiter.exploit_tables()
            elif self.action == "columns":
                result = exploiter.exploit_columns()
            else:
                result = exploiter.exploit_data(limit=self.row_limit)
            self._persist_result(result)
            self.finished_result.emit(result)
        except Exception as exc:
            self.failed.emit(str(exc))

    def _persist_result(self, result: Any) -> None:
        if not self.persist_to_db:
            self.log_message.emit("[*] 本次运行未勾选 SQL 结果入库，已跳过 MySQL 写入")
            return
        try:
            saved = MySQLStorage(logger=self.log_message.emit).save_sql_result(
                self.config,
                self.action,
                result,
            )
        except MySQLStorageError as exc:
            self.log_message.emit(f"[!] MySQL 保存失败: {exc}")
            return
        except Exception as exc:
            self.log_message.emit(f"[!] MySQL 保存异常: {exc}")
            return

        if saved:
            self.log_message.emit(f"[+] SQL 结果已写入 MySQL，共 {saved} 条")


class DashboardTab(QWidget, UiMixin):
    def __init__(self) -> None:
        super().__init__()
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(16)

        hero = card_widget()
        hero_layout = QVBoxLayout(hero)
        title = QLabel("统一的 Web 安全操作台")
        title.setProperty("title", True)
        subtitle = QLabel("以白色为主的多标签工作区，整合 XSS、SQL 利用、Fuzzer、字典与抓包。")
        subtitle.setProperty("muted", True)
        subtitle.setWordWrap(True)
        hero_layout.addWidget(title)
        hero_layout.addWidget(subtitle)
        root.addWidget(hero)

        grid = QGridLayout()
        grid.setHorizontalSpacing(16)
        grid.setVerticalSpacing(16)
        cards = [
            ("XSS 检测", "反射型、存储型、DOM XSS 独立任务入口"),
            ("SQL 利用", "数据库、表、字段与数据提取编排"),
            ("Web Fuzzer", "占位符识别、多 payload 并发请求与相似度对比"),
            ("字典工具", "内置词典、变异词典、掩码词典生成"),
            ("抓包代理", "HTTP/HTTPS 监听、请求详情与响应预览"),
        ]
        for index, (card_title, card_desc) in enumerate(cards):
            card = card_widget()
            card_layout = QVBoxLayout(card)
            label_title = QLabel(card_title)
            label_title.setFont(QFont("", 13, QFont.Weight.Bold))
            label_desc = QLabel(card_desc)
            label_desc.setProperty("muted", True)
            label_desc.setWordWrap(True)
            card_layout.addWidget(label_title)
            card_layout.addWidget(label_desc)
            grid.addWidget(card, index // 3, index % 3)
        grid_box = QWidget()
        grid_box.setLayout(grid)
        root.addWidget(grid_box)
        root.addStretch()


class DatabaseTab(QWidget, UiMixin):
    def __init__(self) -> None:
        super().__init__()

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(16)

        form_card = card_widget()
        form_layout = QFormLayout(form_card)
        self.db_enabled = QCheckBox("启用 MySQL 结果持久化")
        self.db_xss_enabled = QCheckBox("XSS 结果入库")
        self.db_xss_enabled.setChecked(True)
        self.db_sql_enabled = QCheckBox("SQL 结果入库")
        self.db_sql_enabled.setChecked(True)
        self.db_host = QLineEdit()
        self.db_port = QSpinBox()
        self.db_port.setRange(1, 65535)
        self.db_user = QLineEdit()
        self.db_password = QLineEdit()
        self.db_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.db_name = QLineEdit()
        self.db_charset = QLineEdit()
        self.db_config_path = QLineEdit(str(CONFIG_PATH))
        self.db_config_path.setReadOnly(True)

        action_row = QHBoxLayout()
        self.db_save = create_button("保存配置", primary=True)
        self.db_test = create_button("测试连接")
        self.db_init = create_button("初始化表")
        action_row.addWidget(self.db_save)
        action_row.addWidget(self.db_test)
        action_row.addWidget(self.db_init)
        action_row.addStretch()

        form_layout.addRow("启用状态", self.db_enabled)
        form_layout.addRow("XSS 入库", self.db_xss_enabled)
        form_layout.addRow("SQL 入库", self.db_sql_enabled)
        form_layout.addRow("主机", self.db_host)
        form_layout.addRow("端口", self.db_port)
        form_layout.addRow("用户名", self.db_user)
        form_layout.addRow("密码", self.db_password)
        form_layout.addRow("数据库名", self.db_name)
        form_layout.addRow("字符集", self.db_charset)
        form_layout.addRow("配置文件", self.db_config_path)
        form_layout.addRow("执行", self.wrap_layout(action_row))
        root.addWidget(form_card)

        status_card = card_widget()
        status_layout = QVBoxLayout(status_card)
        self.db_status = QTextEdit()
        self.db_status.setReadOnly(True)
        self.db_status.setPlaceholderText("数据库连接状态和初始化日志")
        status_layout.addWidget(self.db_status)
        root.addWidget(status_card, 1)

        self.db_save.clicked.connect(self.save_settings)
        self.db_test.clicked.connect(self.test_connection)
        self.db_init.clicked.connect(self.initialize_tables)
        self.load_settings()

    def load_settings(self) -> None:
        config = load_mysql_config()
        self.db_enabled.setChecked(config.enabled)
        self.db_xss_enabled.setChecked(config.xss_enabled)
        self.db_sql_enabled.setChecked(config.sql_enabled)
        self.db_host.setText(config.host)
        self.db_port.setValue(config.port)
        self.db_user.setText(config.user)
        self.db_password.setText(config.password)
        self.db_name.setText(config.database)
        self.db_charset.setText(config.charset)
        self.append_status("已加载当前 MySQL 配置。")

    def build_config(self) -> MySQLConfig:
        return MySQLConfig(
            enabled=self.db_enabled.isChecked(),
            xss_enabled=self.db_xss_enabled.isChecked(),
            sql_enabled=self.db_sql_enabled.isChecked(),
            host=self.db_host.text().strip() or "127.0.0.1",
            port=self.db_port.value(),
            user=self.db_user.text().strip() or "root",
            password=self.db_password.text(),
            database=self.db_name.text().strip() or "cgfuzz",
            charset=self.db_charset.text().strip() or "utf8mb4",
        )

    def append_status(self, message: str) -> None:
        self.db_status.append(message)

    def save_settings(self) -> None:
        config = self.build_config()
        try:
            save_mysql_config(config)
        except OSError as exc:
            QMessageBox.critical(self, "保存失败", str(exc))
            self.append_status(f"[!] 保存配置失败: {exc}")
            return

        self.append_status(
            f"[+] MySQL 配置已保存到 {CONFIG_PATH}，当前状态: "
            f"{'启用' if config.enabled else '停用'} | "
            f"XSS 入库: {'开' if config.xss_enabled else '关'} | "
            f"SQL 入库: {'开' if config.sql_enabled else '关'}"
        )
        QMessageBox.information(self, "保存成功", "MySQL 配置已保存。")

    def test_connection(self) -> None:
        try:
            storage = MySQLStorage(self.build_config())
            storage.test_connection()
        except MySQLStorageError as exc:
            QMessageBox.critical(self, "连接失败", str(exc))
            self.append_status(f"[!] 测试连接失败: {exc}")
            return
        except Exception as exc:
            QMessageBox.critical(self, "连接失败", str(exc))
            self.append_status(f"[!] 测试连接失败: {exc}")
            return

        self.append_status("[+] MySQL 连接成功。")
        QMessageBox.information(self, "连接成功", "已成功连接到 MySQL。")

    def initialize_tables(self) -> None:
        try:
            storage = MySQLStorage(self.build_config())
            storage.ensure_tables()
        except MySQLStorageError as exc:
            QMessageBox.critical(self, "初始化失败", str(exc))
            self.append_status(f"[!] 初始化表失败: {exc}")
            return
        except Exception as exc:
            QMessageBox.critical(self, "初始化失败", str(exc))
            self.append_status(f"[!] 初始化表失败: {exc}")
            return

        self.append_status("[+] 已完成 xss_results 和 sql_results 表初始化。")
        QMessageBox.information(self, "初始化成功", "数据表已创建或已存在。")


class XSSTab(QWidget, UiMixin):
    def __init__(self) -> None:
        super().__init__()
        self.worker: Optional[XSSWorker] = None
        self.results: List[Any] = []
        self.xss_custom_payload_files: List[str] = []
        mysql_config = load_mysql_config()

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(16)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        root.addWidget(splitter, 1)

        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(16)

        form_card = card_widget()
        form_layout = QFormLayout(form_card)
        self.xss_url = QLineEdit()
        self.xss_url.setPlaceholderText("https://target.test/search.php?q=hello")
        self.xss_method = QComboBox()
        self.xss_method.addItems(["GET", "POST"])
        self.xss_data = QPlainTextEdit()
        self.xss_data.setMaximumHeight(100)
        self.xss_data.setPlaceholderText("POST 支持 key=value&key2=value2、多行 key=value，或顶层 JSON 对象")
        self.xss_view = QLineEdit()
        self.xss_view.setPlaceholderText("存储型查看页，可选")
        self.xss_timeout = QSpinBox()
        self.xss_timeout.setRange(1, 60)
        self.xss_timeout.setValue(10)
        self.xss_delay = QSpinBox()
        self.xss_delay.setRange(0, 10)
        self.xss_delay.setValue(0)
        self.xss_wait = QSpinBox()
        self.xss_wait.setRange(0, 10)
        self.xss_wait.setValue(1)
        self.xss_reflected = QCheckBox("反射型")
        self.xss_reflected.setChecked(True)
        self.xss_stored = QCheckBox("存储型")
        self.xss_dom = QCheckBox("DOM")
        self.xss_persist = QCheckBox("本次结果写入数据库")
        self.xss_persist.setChecked(mysql_config.enabled and mysql_config.xss_enabled)
        type_row = QHBoxLayout()
        for box in (self.xss_reflected, self.xss_stored, self.xss_dom):
            type_row.addWidget(box)
        type_row.addStretch()

        self.xss_dict_file = QLineEdit()
        self.xss_dict_file.setReadOnly(True)
        self.xss_dict_file.setPlaceholderText("可选：导入 XSS 字典文件（JSON/TXT）")
        self.xss_import_button = create_button("导入字典")
        self.xss_clear_button = create_button("清空字典")
        dict_row = QHBoxLayout()
        dict_row.addWidget(self.xss_import_button)
        dict_row.addWidget(self.xss_clear_button)
        dict_row.addStretch()

        self.xss_start = create_button("开始检测", primary=True)
        form_layout.addRow("目标 URL", self.xss_url)
        form_layout.addRow("请求方法", self.xss_method)
        form_layout.addRow("请求数据", self.xss_data)
        form_layout.addRow("查看页面", self.xss_view)
        form_layout.addRow("检测类型", self.wrap_layout(type_row))
        form_layout.addRow("超时时间", self.xss_timeout)
        form_layout.addRow("请求间隔", self.xss_delay)
        form_layout.addRow("存储等待", self.xss_wait)
        form_layout.addRow("结果入库", self.xss_persist)
        form_layout.addRow("字典文件", self.xss_dict_file)
        form_layout.addRow("字典操作", self.wrap_layout(dict_row))
        form_layout.addRow("执行", self.xss_start)
        left_layout.addWidget(form_card)
        left_layout.addStretch()

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(16)

        result_card = card_widget()
        result_layout = QVBoxLayout(result_card)
        self.xss_table = QTableWidget(0, 6)
        self.xss_table.setHorizontalHeaderLabels(["参数", "类型/上下文", "载荷", "证据", "置信度", "URL"])
        self.setup_table(self.xss_table)
        result_layout.addWidget(self.xss_table)
        right_layout.addWidget(result_card, 1)

        detail_card = card_widget()
        detail_layout = QVBoxLayout(detail_card)
        self.xss_detail = QTextEdit()
        self.xss_detail.setReadOnly(True)
        self.xss_detail.setPlaceholderText("输出结果详情")
        detail_layout.addWidget(self.xss_detail)
        right_layout.addWidget(detail_card, 1)

        log_card = card_widget()
        log_layout = QVBoxLayout(log_card)
        self.xss_log = QPlainTextEdit()
        self.xss_log.setReadOnly(True)
        self.xss_log.setPlaceholderText("XSS 日志")
        log_layout.addWidget(self.xss_log)
        right_layout.addWidget(log_card, 1)

        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setSizes([560, 900])

        self.xss_start.clicked.connect(self.start_xss)
        self.xss_import_button.clicked.connect(self.import_xss_dictionary)
        self.xss_clear_button.clicked.connect(self.clear_xss_dictionary)
        self.xss_table.itemSelectionChanged.connect(self.show_selected)

    def import_xss_dictionary(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(self, "导入 XSS 字典", "", "XSS Dictionary (*.json *.txt);;JSON Files (*.json);;Text Files (*.txt);;All Files (*.*)")
        if not paths:
            return
        self.xss_custom_payload_files = paths
        self.xss_dict_file.setText("; ".join(paths))
        self.xss_log.appendPlainText(f"[+] 已加载 XSS 字典文件: {len(paths)} 个")

    def clear_xss_dictionary(self) -> None:
        self.xss_custom_payload_files = []
        self.xss_dict_file.clear()
        self.xss_log.appendPlainText("[*] 已清空 XSS 自定义字典。")

    def build_xss_post_input(self) -> tuple[Optional[Dict[str, Any]], str]:
        raw_text = self.xss_data.toPlainText().strip()
        if self.xss_method.currentText() != "POST" or not raw_text:
            return None, "form"

        try:
            parsed_json = json.loads(raw_text)
        except json.JSONDecodeError:
            parsed_json = None
        else:
            if not isinstance(parsed_json, dict):
                raise ValueError("POST JSON 仅支持顶层对象，例如 {\"q\": \"test\"}。")
            if any(isinstance(value, (dict, list)) for value in parsed_json.values()):
                raise ValueError("POST JSON 目前仅支持顶层键值对，不支持嵌套对象或数组。")
            return parsed_json, "json"

        parsed_form = parse_post_data(raw_text)
        if parsed_form is None:
            raise ValueError("POST 数据格式不正确，请使用 key=value、每行一个参数，或 JSON 对象。")
        return parsed_form, "form"

    def start_xss(self) -> None:
        url = self.xss_url.text().strip()
        if not url:
            QMessageBox.warning(self, "提示", "请先填写目标 URL。")
            return
        types: List[XSSType] = []
        if self.xss_reflected.isChecked():
            types.append(XSSType.REFLECTED)
        if self.xss_stored.isChecked():
            types.append(XSSType.STORED)
        if self.xss_dom.isChecked():
            types.append(XSSType.DOM)
        if not types:
            QMessageBox.warning(self, "提示", "至少选择一种 XSS 类型。")
            return

        try:
            post_data, post_mode = self.build_xss_post_input()
        except ValueError as exc:
            QMessageBox.warning(self, "提示", str(exc))
            return

        if self.xss_method.currentText() == "POST" and not post_data:
            QMessageBox.warning(self, "提示", "POST 请求请填写请求数据。")
            return

        config = XSSConfig(
            url=url,
            method=self.xss_method.currentText(),
            post_data=post_data,
            post_mode=post_mode,
            xss_types=types,
            custom_payload_files=self.xss_custom_payload_files,
            timeout=self.xss_timeout.value(),
            delay=float(self.xss_delay.value()),
            stored_view_url=self.xss_view.text().strip() or None,
            stored_wait=float(self.xss_wait.value()),
        )
        self.xss_start.setEnabled(False)
        self.xss_log.clear()
        self.xss_detail.clear()
        self.xss_table.setRowCount(0)
        if not self.xss_persist.isChecked():
            self.xss_log.appendPlainText("[*] 本次 XSS 检测结果不会写入数据库。")
        self.worker = XSSWorker(config, persist_to_db=self.xss_persist.isChecked())
        self.worker.log_message.connect(self.xss_log.appendPlainText)
        self.worker.finished_results.connect(self.on_finished)
        self.worker.failed.connect(self.on_failed)
        self.worker.finished.connect(lambda: self.xss_start.setEnabled(True))
        self.worker.start()

    def on_finished(self, results: List[Any]) -> None:
        self.results = results
        self.xss_table.setRowCount(len(results))
        for row_index, item in enumerate(results):
            set_table_item(self.xss_table, row_index, 0, item.param_name)
            set_table_item(self.xss_table, row_index, 1, f"{item.xss_type.value} / {item.injection_type or '-'}")
            set_table_item(self.xss_table, row_index, 2, item.payload)
            set_table_item(self.xss_table, row_index, 3, item.evidence)
            set_table_item(self.xss_table, row_index, 4, item.confidence)
            set_table_item(self.xss_table, row_index, 5, item.url)
        if not results:
            self.xss_detail.setPlainText("未发现明显 XSS。")

    def on_failed(self, message: str) -> None:
        QMessageBox.critical(self, "XSS 检测失败", message)
        self.xss_log.appendPlainText(f"[!] {message}")

    def show_selected(self) -> None:
        row = self.xss_table.currentRow()
        if row < 0 or row >= len(self.results):
            return
        item = self.results[row]
        self.xss_detail.setPlainText(
            "\n".join(
                [
                    f"参数: {item.param_name}",
                    f"类型: {item.xss_type.value}",
                    f"注入类型: {item.injection_type or '-'}",
                    f"注入语句: {item.payload}",
                    f"载荷名称: {item.payload_name}",
                    f"置信度: {item.confidence}",
                    f"证据: {item.evidence}",
                    f"上下文片段: {item.context_snippet or '-'}",
                    "",
                    item.response_text,
                ]
            )
        )


class SQLExploitTab(QWidget, UiMixin):
    def __init__(self) -> None:
        super().__init__()
        self.worker: Optional[SQLExploitWorker] = None

        self.sql_dictionary_payloads: List[str] = []
        mysql_config = load_mysql_config()
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(16)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        root.addWidget(splitter, 1)

        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(16)

        form_card = card_widget()
        form_layout = QFormLayout(form_card)
        self.sql_url = QLineEdit()
        self.sql_url.setPlaceholderText("https://target.test/item.php?id=1")
        self.sql_param = QLineEdit()
        self.sql_param.setPlaceholderText("id")
        self.sql_method = QComboBox()
        self.sql_method.addItems(["GET", "POST"])
        self.sql_data = QPlainTextEdit()
        self.sql_data.setPlaceholderText("POST 支持 key=value&key2=value2、多行 key=value，或顶层 JSON 对象")
        self.sql_data.setMaximumHeight(100)
        self.sql_mode = QComboBox()
        self.sql_mode.addItems(["basic", "dictionary", "error", "boolean", "time"])
        self.sql_db = QLineEdit()
        self.sql_db.setPlaceholderText("数据库名，可选")
        self.sql_table_name = QLineEdit()
        self.sql_table_name.setPlaceholderText("表名，可选")
        self.sql_columns = QLineEdit()
        self.sql_columns.setPlaceholderText("字段列表，逗号分隔")
        self.sql_limit = QSpinBox()
        self.sql_limit.setRange(1, 200)
        self.sql_limit.setValue(20)
        self.sql_delay = QSpinBox()
        self.sql_delay.setRange(1, 10)
        self.sql_delay.setValue(2)
        self.sql_persist = QCheckBox("本次结果写入数据库")
        self.sql_persist.setChecked(mysql_config.enabled and mysql_config.sql_enabled)
        self.sql_charset = QPlainTextEdit()
        self.sql_charset.setMaximumHeight(90)
        self.sql_charset.setPlaceholderText("布尔/时间盲注字符集，例如 abcdef0123456789_-@")
        self.sql_dict_file = QLineEdit()
        self.sql_dict_file.setReadOnly(True)
        self.sql_dict_file.setPlaceholderText("导入 SQL payload 字典（TXT）")
        self.sql_import_button = create_button("导入字典")
        self.sql_clear_dict_button = create_button("清空字典")

        button_row = QHBoxLayout()
        self.sql_probe = create_button("注入探测", primary=True)
        self.sql_databases = create_button("枚举数据库")
        self.sql_tables = create_button("枚举表")
        self.sql_columns_btn = create_button("枚举字段")
        self.sql_dump = create_button("提取数据")
        for button in (self.sql_probe, self.sql_databases, self.sql_tables, self.sql_columns_btn, self.sql_dump):
            button_row.addWidget(button)

        dict_action_row = QHBoxLayout()
        dict_action_row.addWidget(self.sql_import_button)
        dict_action_row.addWidget(self.sql_clear_dict_button)
        dict_action_row.addStretch()

        form_layout.addRow("目标 URL", self.sql_url)
        form_layout.addRow("注入参数", self.sql_param)
        form_layout.addRow("请求方法", self.sql_method)
        form_layout.addRow("请求数据", self.sql_data)
        form_layout.addRow("利用模式", self.sql_mode)
        form_layout.addRow("数据库名", self.sql_db)
        form_layout.addRow("表名", self.sql_table_name)
        form_layout.addRow("字段列表", self.sql_columns)
        form_layout.addRow("数据上限", self.sql_limit)
        form_layout.addRow("时间阈值", self.sql_delay)
        form_layout.addRow("结果入库", self.sql_persist)
        form_layout.addRow("字典文件", self.sql_dict_file)
        form_layout.addRow("字典操作", self.wrap_layout(dict_action_row))
        form_layout.addRow("盲注字符集", self.sql_charset)
        form_layout.addRow("执行", self.wrap_layout(button_row))
        left_layout.addWidget(form_card)
        left_layout.addStretch()

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(16)

        result_card = card_widget()
        result_layout = QVBoxLayout(result_card)
        self.sql_table = QTableWidget(0, 8)
        self.sql_table.setHorizontalHeaderLabels(["值1", "值2", "值3", "值4", "值5", "值6", "值7", "值8"])
        self.setup_table(self.sql_table)
        result_layout.addWidget(self.sql_table)
        right_layout.addWidget(result_card, 1)

        detail_card = card_widget()
        detail_layout = QVBoxLayout(detail_card)
        self.sql_detail = QTextEdit()
        self.sql_detail.setReadOnly(True)
        self.sql_detail.setPlaceholderText("输出结果详情")
        detail_layout.addWidget(self.sql_detail)
        right_layout.addWidget(detail_card, 1)

        log_card = card_widget()
        log_layout = QVBoxLayout(log_card)
        self.sql_log = QPlainTextEdit()
        self.sql_log.setReadOnly(True)
        self.sql_log.setPlaceholderText("SQL 利用日志")
        log_layout.addWidget(self.sql_log)
        right_layout.addWidget(log_card, 1)

        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setSizes([560, 900])

        self.sql_probe.clicked.connect(lambda: self.run_action("probe"))
        self.sql_databases.clicked.connect(lambda: self.run_action("databases"))
        self.sql_tables.clicked.connect(lambda: self.run_action("tables"))
        self.sql_columns_btn.clicked.connect(lambda: self.run_action("columns"))
        self.sql_dump.clicked.connect(lambda: self.run_action("dump"))
        self.sql_import_button.clicked.connect(self.import_sql_dictionary)
        self.sql_clear_dict_button.clicked.connect(self.clear_sql_dictionary)

    def run_action(self, action: str) -> None:
        url = self.sql_url.text().strip()
        param_name = self.sql_param.text().strip()
        if not url or not param_name:
            QMessageBox.warning(self, "提示", "请先填写目标 URL 和注入参数。")
            return
        mode_map = {
            "basic": ExploitMethod.BASIC,
            "dictionary": ExploitMethod.DICTIONARY,
            "error": ExploitMethod.ERROR_BASED,
            "boolean": ExploitMethod.BOOLEAN_BLIND,
            "time": ExploitMethod.TIME_BLIND,
        }
        selected_mode = self.sql_mode.currentText()
        if selected_mode == "dictionary" and action != "probe":
            QMessageBox.warning(self, "提示", "字典模式仅支持注入探测。")
            return
        if selected_mode == "dictionary" and not self.sql_dictionary_payloads:
            QMessageBox.warning(self, "提示", "请先导入 TXT 格式的 SQL payload 字典。")
            return
        raw_charset = self.sql_charset.toPlainText().replace("\r", "").replace("\n", "").replace("\t", "")
        custom_charset = "".join(dict.fromkeys(raw_charset))
        try:
            post_data, post_mode = self.build_sql_post_input()
        except ValueError as exc:
            QMessageBox.warning(self, "提示", str(exc))
            return
        if self.sql_method.currentText() == "POST" and not post_data:
            QMessageBox.warning(self, "提示", "POST 请求请填写请求数据。")
            return
        config_kwargs = dict(
            url=url,
            param_name=param_name,
            method=self.sql_method.currentText(),
            post_data=post_data,
            post_mode=post_mode,
            exploit_method=mode_map[selected_mode],
            database_name=self.sql_db.text().strip() or None,
            table_name=self.sql_table_name.text().strip() or None,
            column_names=[item.strip() for item in self.sql_columns.text().split(",") if item.strip()] or None,
            dictionary_payloads=list(self.sql_dictionary_payloads),
            delay=float(self.sql_delay.value()),
        )
        if custom_charset:
            config_kwargs["charset"] = custom_charset
        config = SQLExploitConfig(**config_kwargs)
        self.toggle_buttons(False)
        self.sql_log.clear()
        self.sql_detail.clear()
        self.sql_table.setRowCount(0)
        if not self.sql_persist.isChecked():
            self.sql_log.appendPlainText("[*] 本次 SQL 运行结果不会写入数据库。")
        self.worker = SQLExploitWorker(
            config,
            action,
            self.sql_limit.value(),
            persist_to_db=self.sql_persist.isChecked(),
        )
        self.worker.log_message.connect(self.sql_log.appendPlainText)
        self.worker.finished_result.connect(self.on_finished)
        self.worker.failed.connect(self.on_failed)
        self.worker.finished.connect(lambda: self.toggle_buttons(True))
        self.worker.start()

    def build_sql_post_input(self) -> tuple[Optional[Dict[str, Any]], str]:
        raw_text = self.sql_data.toPlainText().strip()
        if self.sql_method.currentText() != "POST" or not raw_text:
            return None, "form"

        try:
            parsed_json = json.loads(raw_text)
        except json.JSONDecodeError:
            parsed_json = None
        else:
            if not isinstance(parsed_json, dict):
                raise ValueError("POST JSON 仅支持顶层对象，例如 {\"id\": 1}。")
            if any(isinstance(value, (dict, list)) for value in parsed_json.values()):
                raise ValueError("POST JSON 目前仅支持顶层键值对，不支持嵌套对象或数组。")
            return parsed_json, "json"

        parsed_form = parse_post_data(raw_text)
        if parsed_form is None:
            raise ValueError("POST 数据格式不正确，请使用 key=value、每行一个参数，或 JSON 对象。")
        return parsed_form, "form"

    def import_sql_dictionary(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "导入 SQL 字典", "", "Text Files (*.txt);;All Files (*.*)")
        if not path:
            return
        try:
            raw_text = Path(path).read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            QMessageBox.critical(self, "导入失败", str(exc))
            return

        entries = parse_dictionary_text(raw_text)
        if not entries:
            QMessageBox.warning(self, "提示", "导入的 TXT 字典为空，无法使用。")
            return

        self.sql_dictionary_payloads = entries
        self.sql_dict_file.setText(path)
        self.sql_log.appendPlainText(f"[+] 已导入 SQL TXT 字典: {path} | payload 数={len(entries)}")

    def clear_sql_dictionary(self) -> None:
        self.sql_dictionary_payloads = []
        self.sql_dict_file.clear()
        self.sql_log.appendPlainText("[*] 已清空 SQL payload 字典。")

    def toggle_buttons(self, enabled: bool) -> None:
        for button in (self.sql_probe, self.sql_databases, self.sql_tables, self.sql_columns_btn, self.sql_dump):
            button.setEnabled(enabled)

    def on_finished(self, result: Any) -> None:
        if isinstance(result, dict):
            cleaned_result = sanitize_sql_display_data(result)
            findings = cleaned_result.get("findings", [])
            if findings:
                self.sql_table.setColumnCount(4)
                self.sql_table.setHorizontalHeaderLabels(["注入点", "载荷", "类型", "证据"])
                self.sql_table.setRowCount(len(findings))
                for row_index, finding in enumerate(findings):
                    set_table_item(self.sql_table, row_index, 0, finding.get("injection_point") or cleaned_result.get("injection_point") or "-")
                    set_table_item(self.sql_table, row_index, 1, finding.get("payload") or "-")
                    set_table_item(self.sql_table, row_index, 2, finding.get("type") or cleaned_result.get("injection_type") or "-")
                    set_table_item(self.sql_table, row_index, 3, finding.get("evidence") or "-")
            else:
                self.sql_table.setColumnCount(2)
                self.sql_table.setHorizontalHeaderLabels(["载荷", "判定"])
                payloads = cleaned_result.get("vulnerable_payloads", [])
                self.sql_table.setRowCount(len(payloads))
                for row_index, payload in enumerate(payloads):
                    set_table_item(self.sql_table, row_index, 0, payload)
                    set_table_item(self.sql_table, row_index, 1, cleaned_result.get("injection_type"))
            self.sql_detail.setPlainText(json.dumps(cleaned_result, ensure_ascii=False, indent=2))
            return

        self.sql_detail.setPlainText(sanitize_sql_display_value(result.message) or "已完成。")
        rows: List[List[str]] = []
        headers = ["值"]
        if result.databases:
            headers = ["数据库"]
            rows = [[item] for item in result.databases if not should_hide_sql_display_value(item)]
        elif result.tables:
            headers = ["表名"]
            rows = [[item] for item in result.tables if not should_hide_sql_display_value(item)]
        elif result.columns:
            headers = ["字段名"]
            rows = [[item] for item in result.columns if not should_hide_sql_display_value(item)]
        elif result.rows:
            headers = list(result.rows[0].keys())
            rows = [
                [sanitize_sql_display_value(row.get(key, "")) for key in headers]
                for row in result.rows
            ]

        self.sql_table.setColumnCount(max(1, len(headers)))
        self.sql_table.setHorizontalHeaderLabels(headers)
        self.sql_table.setRowCount(len(rows))
        for row_index, row_values in enumerate(rows):
            for col_index, value in enumerate(row_values):
                set_table_item(self.sql_table, row_index, col_index, sanitize_sql_display_value(value))
    def on_failed(self, message: str) -> None:
        QMessageBox.critical(self, "SQL 利用失败", message)
        self.sql_log.appendPlainText(f"[!] {message}")


class FuzzerTab(QWidget, UiMixin):
    def __init__(self) -> None:
        super().__init__()
        self.worker: Optional[FuzzWorker] = None
        self.results: List[FuzzResult] = []
        self.baseline_text = ""
        self.fuzz_dictionary_payloads: List[str] = []
        self.fuzz_sort_mode = "index"

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(16)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        root.addWidget(splitter, 1)

        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(16)

        request_card = card_widget()
        request_layout = QFormLayout(request_card)
        self.fuzz_method = QComboBox()
        self.fuzz_method.addItems(["GET", "POST", "PUT", "DELETE"])
        self.fuzz_url = QLineEdit()
        self.fuzz_url.setPlaceholderText("https://target.test/api?name=FUZZ")
        self.fuzz_headers = QPlainTextEdit()
        self.fuzz_headers.setMaximumHeight(110)
        self.fuzz_headers.setPlaceholderText("请求头: 值")
        self.fuzz_body = QPlainTextEdit()
        self.fuzz_body.setMaximumHeight(110)
        self.fuzz_body.setPlaceholderText("请求体，可使用 FUZZ、FUZZ1/FUZZ2 或 §payload§")
        self.fuzz_mode = QComboBox()
        self.fuzz_mode.addItems(["共享字典", "占位符并行", "占位符组合"])
        self.fuzz_mode.setCurrentIndex(1)
        self.fuzz_timeout = QSpinBox()
        self.fuzz_timeout.setRange(1, 60)
        self.fuzz_timeout.setValue(10)
        self.fuzz_concurrency = QSpinBox()
        self.fuzz_concurrency.setRange(1, 64)
        self.fuzz_concurrency.setValue(8)
        self.fuzz_verify_ssl = QCheckBox("验证 SSL")
        self.fuzz_follow_redirects = QCheckBox("跟随重定向")
        self.fuzz_follow_redirects.setChecked(True)
        toggle_row = QHBoxLayout()
        toggle_row.addWidget(self.fuzz_verify_ssl)
        toggle_row.addWidget(self.fuzz_follow_redirects)
        toggle_row.addStretch()
        self.fuzz_payloads = QPlainTextEdit()
        self.fuzz_payloads.setMaximumHeight(180)
        self.fuzz_payloads.setPlaceholderText(
            "每行一个 payload；也支持 FUZZ1=admin、FUZZ2=123 这种按占位符字典写法"
        )
        self.fuzz_dict_file = QLineEdit()
        self.fuzz_dict_file.setReadOnly(True)
        self.fuzz_dict_file.setPlaceholderText("可选：导入 Fuzz 字典（TXT/字典文本）")
        self.fuzz_import_dict = create_button("导入字典")
        self.fuzz_clear_dict = create_button("清空字典")
        dict_row = QHBoxLayout()
        dict_row.addWidget(self.fuzz_import_dict)
        dict_row.addWidget(self.fuzz_clear_dict)
        dict_row.addStretch()
        self.fuzz_raw = QPlainTextEdit()
        self.fuzz_raw.setMaximumHeight(140)
        self.fuzz_raw.setPlaceholderText("可选：粘贴原始 HTTP 报文")
        self.fuzz_status = QLabel("就绪")
        self.fuzz_status.setProperty("muted", True)
        self.fuzz_progress = QProgressBar()

        button_row = QHBoxLayout()
        self.fuzz_parse = create_button("解析原始报文")
        self.fuzz_detect = create_button("识别占位符")
        self.fuzz_start = create_button("开始 Fuzz", primary=True)
        self.fuzz_stop = create_button("停止")
        for button in (self.fuzz_parse, self.fuzz_detect, self.fuzz_start, self.fuzz_stop):
            button_row.addWidget(button)

        request_layout.addRow("方法", self.fuzz_method)
        request_layout.addRow("URL", self.fuzz_url)
        request_layout.addRow("请求头", self.fuzz_headers)
        request_layout.addRow("请求体", self.fuzz_body)
        request_layout.addRow("遍历方式", self.fuzz_mode)
        request_layout.addRow("超时", self.fuzz_timeout)
        request_layout.addRow("并发", self.fuzz_concurrency)
        request_layout.addRow("选项", self.wrap_layout(toggle_row))
        request_layout.addRow("字典载荷", self.fuzz_payloads)
        request_layout.addRow("字典文件", self.fuzz_dict_file)
        request_layout.addRow("字典操作", self.wrap_layout(dict_row))
        request_layout.addRow("原始报文", self.fuzz_raw)
        request_layout.addRow("执行", self.wrap_layout(button_row))
        request_layout.addRow("状态", self.fuzz_status)
        request_layout.addRow("进度", self.fuzz_progress)
        left_layout.addWidget(request_card)
        left_layout.addStretch()

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(16)

        result_card = card_widget()
        result_layout = QVBoxLayout(result_card)
        self.fuzz_table = QTableWidget(0, 8)
        self.fuzz_table.setHorizontalHeaderLabels(["序号", "载荷", "状态码", "长度", "耗时", "标题", "相似度", "错误"])
        self.setup_table(self.fuzz_table)
        self.fuzz_table.horizontalHeader().sectionClicked.connect(self.handle_fuzz_header_click)
        result_layout.addWidget(self.fuzz_table)
        right_layout.addWidget(result_card, 1)

        detail_card = card_widget()
        detail_layout = QVBoxLayout(detail_card)
        self.fuzz_detail = QTextEdit()
        self.fuzz_detail.setReadOnly(True)
        self.fuzz_detail.setPlaceholderText("输出结果详情")
        detail_layout.addWidget(self.fuzz_detail)
        right_layout.addWidget(detail_card, 1)

        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setSizes([620, 820])

        self.fuzz_parse.clicked.connect(self.parse_raw_request)
        self.fuzz_detect.clicked.connect(self.detect_placeholder)
        self.fuzz_start.clicked.connect(self.start_fuzz)
        self.fuzz_stop.clicked.connect(self.stop_fuzz)
        self.fuzz_import_dict.clicked.connect(self.import_fuzz_dictionary)
        self.fuzz_clear_dict.clicked.connect(self.clear_fuzz_dictionary)
        self.fuzz_table.itemSelectionChanged.connect(self.show_selected)
    def _format_capture_host(self, capture: ProxyCapture) -> str:
        if not capture.host:
            return ""
        default_port = 443 if capture.scheme == "https" else 80
        if capture.port and capture.port != default_port:
            return f"{capture.host}:{capture.port}"
        return capture.host

    def _apply_raw_request(
        self,
        raw: str,
        default_scheme: str = "https",
        host_override: str = "",
        status_text: str = "原始报文解析完成",
    ) -> bool:
        try:
            parsed = parse_raw_http_request(
                raw,
                default_scheme=default_scheme,
                host_override=host_override,
            )
        except Exception as exc:
            QMessageBox.critical(self, "解析失败", str(exc))
            return False

        self.fuzz_raw.setPlainText(raw)
        self.fuzz_method.setCurrentText(parsed.method)
        self.fuzz_url.setText(parsed.url)
        self.fuzz_headers.setPlainText(parsed.headers_text)
        self.fuzz_body.setPlainText(parsed.body_text)
        self.fuzz_status.setText(status_text)
        return True

    def _build_raw_request_from_capture(self, capture: ProxyCapture) -> str:
        host_header = capture.request_headers.get("Host") or self._format_capture_host(capture)
        request_line = f"{capture.method} {capture.path or '/'} HTTP/1.1"
        header_lines: List[str] = []
        seen_host = False
        for key, value in capture.request_headers.items():
            if key.lower() == "host":
                seen_host = True
                header_lines.append(f"{key}: {host_header}")
            else:
                header_lines.append(f"{key}: {value}")
        if host_header and not seen_host:
            header_lines.insert(0, f"Host: {host_header}")
        return "\r\n".join([request_line, *header_lines, "", capture.request_body or ""])

    def load_proxy_capture(self, capture: ProxyCapture) -> bool:
        if capture.method.upper() == "CONNECT":
            QMessageBox.information(self, "提示", "CONNECT 隧道请求无法直接传送到模糊测试页面。")
            return False

        raw = self._build_raw_request_from_capture(capture)
        return self._apply_raw_request(
            raw,
            default_scheme=capture.scheme or "http",
            host_override=self._format_capture_host(capture),
            status_text=f"已从抓包导入请求: {capture.method} {capture.path}",
        )

    def parse_raw_request(self) -> None:
        raw = self.fuzz_raw.toPlainText().strip()
        if not raw:
            QMessageBox.information(self, "提示", "请先粘贴原始 HTTP 报文。")
            return
        self._apply_raw_request(raw)

    def detect_placeholder(self) -> None:
        found = self._get_fuzz_placeholders()
        self.fuzz_status.setText("识别到占位符: " + (", ".join(found) if found else "无"))

    def _get_fuzz_placeholders(self) -> List[str]:
        return detect_placeholders(
            [self.fuzz_url.text(), self.fuzz_headers.toPlainText(), self.fuzz_body.toPlainText()]
        )

    def import_fuzz_dictionary(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(
            self,
            "导入 Fuzz 字典",
            "",
            "Dictionary Files (*.txt *.dic *.lst *.csv);;Text Files (*.txt);;All Files (*.*)",
        )
        if not paths:
            return

        entries: List[str] = []
        seen: set[str] = set()
        for path in paths:
            try:
                raw_text = Path(path).read_text(encoding="utf-8", errors="ignore")
            except OSError as exc:
                QMessageBox.critical(self, "导入失败", str(exc))
                return

            for item in parse_dictionary_text(raw_text):
                if item not in seen:
                    seen.add(item)
                    entries.append(item)

        if not entries:
            QMessageBox.warning(self, "提示", "导入的字典为空，无法使用。")
            return

        self.fuzz_dictionary_payloads = entries
        self.fuzz_dict_file.setText("; ".join(paths))
        self.fuzz_status.setText(f"已加载 Fuzz 字典: {len(paths)} 个文件 / {len(entries)} 条 payload")

    def clear_fuzz_dictionary(self) -> None:
        self.fuzz_dictionary_payloads = []
        self.fuzz_dict_file.clear()
        self.fuzz_status.setText("已清空 Fuzz 字典。")

    def _build_exact_binding_groups(self, lines: List[str]) -> List[Dict[str, str]]:
        bindings: List[Dict[str, str]] = []
        current: Dict[str, str] = {}
        for line in lines:
            if line == "---":
                if current:
                    bindings.append(dict(current))
                    current.clear()
                continue
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            current[key.strip()] = value.strip()
        if current:
            bindings.append(current)
        return bindings

    def _is_placeholder_key(self, key: str, placeholders: List[str]) -> bool:
        return (
            key in placeholders
            or key == "FUZZ"
            or (key.startswith("FUZZ") and key[4:].isdigit())
            or (key.startswith("§") and key.endswith("§"))
        )

    def _parse_placeholder_dictionaries(
        self,
        lines: List[str],
        placeholders: List[str],
    ) -> Dict[str, List[str]]:
        if not lines or not placeholders or "---" in lines:
            return {}

        payload_map: Dict[str, List[str]] = {}
        seen: Dict[str, set[str]] = {}
        recognized = False
        for line in lines:
            if "=" not in line:
                return {}
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            if not key or not value or not self._is_placeholder_key(key, placeholders):
                return {}
            payload_map.setdefault(key, [])
            seen.setdefault(key, set())
            if value in seen[key]:
                continue
            seen[key].add(value)
            payload_map[key].append(value)
            recognized = True

        return payload_map if recognized else {}

    def _build_shared_payload_bindings(
        self,
        lines: List[str],
        placeholders: List[str],
    ) -> List[Dict[str, str]]:
        unique_values = [line.strip() for line in lines if line.strip()]
        if not unique_values:
            return []

        if not placeholders:
            placeholder = "§payload§"
            return [{placeholder: value, "FUZZ": value} for value in dict.fromkeys(unique_values)]

        bindings: List[Dict[str, str]] = []
        for value in dict.fromkeys(unique_values):
            bindings.append({placeholder: value for placeholder in placeholders})
        return bindings

    def _build_parallel_placeholder_bindings(
        self,
        payload_map: Dict[str, List[str]],
    ) -> List[Dict[str, str]]:
        keys = list(payload_map)
        lengths = [len(payload_map[key]) for key in keys if payload_map[key]]
        if not lengths:
            return []
        if len(set(lengths)) > 1:
            self.fuzz_status.setText("占位符字典长度不一致，按最短列表执行并行遍历。")
        limit = min(lengths)
        return [
            {key: payload_map[key][index] for key in keys}
            for index in range(limit)
        ]

    def _build_cluster_placeholder_bindings(
        self,
        payload_map: Dict[str, List[str]],
    ) -> List[Dict[str, str]]:
        keys = list(payload_map)
        groups = [payload_map[key] for key in keys if payload_map[key]]
        if not groups or len(groups) != len(keys):
            return []
        return [
            {key: value for key, value in zip(keys, combo)}
            for combo in itertools.product(*groups)
        ]

    def build_payload_bindings(self) -> List[Dict[str, str]]:
        manual_lines = [line.strip() for line in self.fuzz_payloads.toPlainText().splitlines() if line.strip()]
        dictionary_lines = list(self.fuzz_dictionary_payloads)
        placeholders = self._get_fuzz_placeholders()

        if "---" in manual_lines:
            bindings = self._build_exact_binding_groups(manual_lines)
            if dictionary_lines:
                bindings.extend(self._build_shared_payload_bindings(dictionary_lines, placeholders))
            return bindings

        placeholder_payloads = self._parse_placeholder_dictionaries(manual_lines, placeholders)
        if placeholder_payloads:
            mode_index = self.fuzz_mode.currentIndex()
            if mode_index == 2:
                bindings = self._build_cluster_placeholder_bindings(placeholder_payloads)
            elif mode_index == 1:
                bindings = self._build_parallel_placeholder_bindings(placeholder_payloads)
            else:
                merged_values: List[str] = []
                for values in placeholder_payloads.values():
                    merged_values.extend(values)
                bindings = self._build_shared_payload_bindings([*merged_values, *dictionary_lines], placeholders)
                return bindings

            if dictionary_lines:
                bindings.extend(self._build_shared_payload_bindings(dictionary_lines, placeholders))
            return bindings

        return self._build_shared_payload_bindings([*manual_lines, *dictionary_lines], placeholders)
    def start_fuzz(self) -> None:
        bindings = self.build_payload_bindings()
        if not bindings:
            QMessageBox.warning(self, "提示", "请先提供至少一个 payload。")
            return
        config = FuzzRequestConfig(
            method=self.fuzz_method.currentText(),
            url=self.fuzz_url.text().strip(),
            headers_text=self.fuzz_headers.toPlainText(),
            body_text=self.fuzz_body.toPlainText(),
            placeholder="§payload§",
            timeout=float(self.fuzz_timeout.value()),
            concurrency=self.fuzz_concurrency.value(),
            verify_ssl=self.fuzz_verify_ssl.isChecked(),
            follow_redirects=self.fuzz_follow_redirects.isChecked(),
        )
        self.results.clear()
        self.baseline_text = ""
        self.fuzz_table.setRowCount(0)
        self.fuzz_detail.clear()
        self.fuzz_progress.setValue(0)
        self.fuzz_start.setEnabled(False)
        self.worker = FuzzWorker(config, bindings)
        self.worker.result_ready.connect(self.on_result_ready)
        self.worker.progress_changed.connect(self.on_progress)
        self.worker.status_message.connect(self.fuzz_status.setText)
        self.worker.run_finished.connect(lambda: self.fuzz_start.setEnabled(True))
        self.worker.start()

    def stop_fuzz(self) -> None:
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.fuzz_status.setText("正在停止任务...")

    def handle_fuzz_header_click(self, column: int) -> None:
        if column != 3:
            return
        if self.fuzz_sort_mode == "length_asc":
            self.fuzz_sort_mode = "length_desc"
            self.fuzz_status.setText("结果已按长度降序排序")
        else:
            self.fuzz_sort_mode = "length_asc"
            self.fuzz_status.setText("结果已按长度升序排序")
        self.refresh_fuzz_table()

    def refresh_fuzz_table(self) -> None:
        if self.fuzz_sort_mode == "length_asc":
            self.results.sort(key=lambda item: (item.response_length, item.index))
        elif self.fuzz_sort_mode == "length_desc":
            self.results.sort(key=lambda item: (-item.response_length, item.index))
        else:
            self.results.sort(key=lambda item: item.index)

        self.fuzz_table.setRowCount(len(self.results))
        for row, result in enumerate(self.results):
            values = [
                result.index,
                result.payload,
                result.status_code,
                result.response_length,
                result.elapsed_ms,
                result.title,
                result.similarity,
                result.error,
            ]
            for col, value in enumerate(values):
                set_table_item(self.fuzz_table, row, col, value)

    def on_result_ready(self, result: FuzzResult) -> None:
        if not self.baseline_text and result.response_text:
            self.baseline_text = normalize_response_text(result.response_text)
        if self.baseline_text:
            result.similarity = calculate_similarity(self.baseline_text, normalize_response_text(result.response_text))
        self.results.append(result)
        self.refresh_fuzz_table()
    def on_progress(self, current: int, total: int) -> None:
        percent = 0 if total == 0 else int(current * 100 / total)
        self.fuzz_progress.setValue(percent)
        self.fuzz_progress.setFormat(f"{current}/{total}")

    def show_selected(self) -> None:
        row = self.fuzz_table.currentRow()
        if row < 0 or row >= len(self.results):
            return
        result = self.results[row]
        self.fuzz_detail.setPlainText(
            "\n".join(
                [
                    f"Payload: {result.payload}",
                    f"Request URL: {result.request_url}",
                    f"Final URL: {result.final_url}",
                    f"状态码: {result.status_code}",
                    f"长度: {result.response_length}",
                    f"耗时: {result.elapsed_ms} ms",
                    f"相似度: {result.similarity}",
                    "",
                    result.response_text or result.error,
                ]
            )
        )


class DictionaryTab(QWidget, UiMixin):
    def __init__(self) -> None:
        super().__init__()
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(16)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        root.addWidget(splitter, 1)

        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(16)

        seed_card = card_widget()
        seed_layout = QVBoxLayout(seed_card)
        title = QLabel("内置与变异词典")
        title.setFont(QFont("", 12, QFont.Weight.Bold))
        self.dict_seed = QPlainTextEdit()
        self.dict_seed.setPlaceholderText("输入种子词，每行一个")
        self.dict_seed.setMaximumHeight(180)
        row = QHBoxLayout()
        self.dict_builtin = create_button("加载内置词典")
        self.dict_mutation = create_button("生成变异词典", primary=True)
        row.addWidget(self.dict_builtin)
        row.addWidget(self.dict_mutation)
        row.addStretch()
        seed_layout.addWidget(title)
        seed_layout.addWidget(self.dict_seed)
        seed_layout.addWidget(self.wrap_layout(row))
        left_layout.addWidget(seed_card)

        mask_card = card_widget()
        mask_layout = QFormLayout(mask_card)
        self.mask_lower = QCheckBox("小写")
        self.mask_lower.setChecked(True)
        self.mask_upper = QCheckBox("大写")
        self.mask_digits = QCheckBox("数字")
        self.mask_digits.setChecked(True)
        self.mask_symbols = QCheckBox("符号")
        charset = QHBoxLayout()
        for box in (self.mask_lower, self.mask_upper, self.mask_digits, self.mask_symbols):
            charset.addWidget(box)
        charset.addStretch()
        self.mask_min = QSpinBox()
        self.mask_min.setRange(1, 6)
        self.mask_min.setValue(1)
        self.mask_max = QSpinBox()
        self.mask_max.setRange(1, 6)
        self.mask_max.setValue(2)
        self.mask_prefix = QLineEdit()
        self.mask_suffix = QLineEdit()
        self.mask_limit = QSpinBox()
        self.mask_limit.setRange(1, 5000)
        self.mask_limit.setValue(500)
        self.mask_generate = create_button("生成掩码词典")
        mask_layout.addRow("字符集", self.wrap_layout(charset))
        mask_layout.addRow("最小长度", self.mask_min)
        mask_layout.addRow("最大长度", self.mask_max)
        mask_layout.addRow("前缀", self.mask_prefix)
        mask_layout.addRow("后缀", self.mask_suffix)
        mask_layout.addRow("数量限制", self.mask_limit)
        mask_layout.addRow("执行", self.mask_generate)
        left_layout.addWidget(mask_card)
        left_layout.addStretch()

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        output_card = card_widget()
        output_layout = QVBoxLayout(output_card)
        self.dict_output = QPlainTextEdit()
        self.dict_output.setPlaceholderText("词典输出")
        output_layout.addWidget(self.dict_output)
        save_row = QHBoxLayout()
        self.dict_parse = create_button("规范化当前内容")
        self.dict_save = create_button("保存到文件")
        save_row.addWidget(self.dict_parse)
        save_row.addWidget(self.dict_save)
        save_row.addStretch()
        output_layout.addWidget(self.wrap_layout(save_row))
        right_layout.addWidget(output_card)

        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setSizes([520, 920])

        self.dict_builtin.clicked.connect(lambda: self.dict_output.setPlainText("\n".join(build_builtin_dictionary())))
        self.dict_mutation.clicked.connect(self.generate_mutation)
        self.mask_generate.clicked.connect(self.generate_mask)
        self.dict_parse.clicked.connect(self.normalize_output)
        self.dict_save.clicked.connect(self.save_output)

    def generate_mutation(self) -> None:
        words = build_mutation_dictionary(self.dict_seed.toPlainText())
        self.dict_output.setPlainText("\n".join(words))

    def generate_mask(self) -> None:
        words = build_mask_dictionary(
            use_lower=self.mask_lower.isChecked(),
            use_upper=self.mask_upper.isChecked(),
            use_digits=self.mask_digits.isChecked(),
            use_symbols=self.mask_symbols.isChecked(),
            min_length=self.mask_min.value(),
            max_length=self.mask_max.value(),
            prefix=self.mask_prefix.text(),
            suffix=self.mask_suffix.text(),
            limit=self.mask_limit.value(),
        )
        self.dict_output.setPlainText("\n".join(words))

    def normalize_output(self) -> None:
        self.dict_output.setPlainText("\n".join(parse_dictionary_text(self.dict_output.toPlainText())))

    def save_output(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "保存词典", "dictionary.txt", "Text Files (*.txt)")
        if path:
            Path(path).write_text(self.dict_output.toPlainText(), encoding="utf-8")


class ProxyTab(QWidget, UiMixin):
    capture_forward_requested = pyqtSignal(object)

    def __init__(self) -> None:
        super().__init__()
        self.controller = ProxyController()
        self.captures: List[ProxyCapture] = []

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(16)

        top_card = card_widget()
        top_layout = QFormLayout(top_card)
        self.proxy_host = QLineEdit("127.0.0.1")
        self.proxy_port = QSpinBox()
        self.proxy_port.setRange(1, 65535)
        self.proxy_port.setValue(8080)
        self.proxy_status = QLabel("代理未启动")
        self.proxy_status.setProperty("muted", True)
        row = QHBoxLayout()
        self.proxy_start = create_button("启动代理", primary=True)
        self.proxy_stop = create_button("停止代理")
        self.proxy_clear = create_button("清空记录")
        row.addWidget(self.proxy_start)
        row.addWidget(self.proxy_stop)
        row.addWidget(self.proxy_clear)
        row.addStretch()
        top_layout.addRow("监听地址", self.proxy_host)
        top_layout.addRow("监听端口", self.proxy_port)
        top_layout.addRow("执行", self.wrap_layout(row))
        top_layout.addRow("状态", self.proxy_status)
        root.addWidget(top_card)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        root.addWidget(splitter, 1)

        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        table_card = card_widget()
        table_layout = QVBoxLayout(table_card)
        self.proxy_table = QTableWidget(0, 8)
        self.proxy_table.setHorizontalHeaderLabels(["序号", "方法", "主机", "端口", "路径", "状态码", "耗时", "错误"])
        self.setup_table(self.proxy_table)
        table_layout.addWidget(self.proxy_table)
        left_layout.addWidget(table_card)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        detail_card = card_widget()
        detail_layout = QVBoxLayout(detail_card)
        self.proxy_detail = QTextEdit()
        self.proxy_detail.setReadOnly(True)
        self.proxy_detail.setPlaceholderText("抓包详情")
        detail_layout.addWidget(self.proxy_detail)
        right_layout.addWidget(detail_card)

        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setSizes([900, 540])

        self.proxy_start.clicked.connect(self.start_proxy)
        self.proxy_stop.clicked.connect(self.controller.stop)
        self.proxy_clear.clicked.connect(self.clear_proxy)
        self.proxy_table.itemSelectionChanged.connect(self.show_selected)
        self.proxy_table.itemDoubleClicked.connect(self.forward_capture_to_fuzzer)
        self.controller.capture_ready.connect(self.add_capture)
        self.controller.status_message.connect(self.proxy_status.setText)

    def forward_capture_to_fuzzer(self, item: QTableWidgetItem) -> None:
        row = item.row()
        if row < 0 or row >= len(self.captures):
            return
        capture = self.captures[row]
        if capture.method.upper() == "CONNECT":
            QMessageBox.information(self, "提示", "CONNECT 隧道请求无法直接传送到模糊测试页面。")
            return
        self.capture_forward_requested.emit(capture)


    def start_proxy(self) -> None:
        try:
            self.controller.start(self.proxy_host.text().strip(), self.proxy_port.value())
        except Exception as exc:
            QMessageBox.critical(self, "启动失败", str(exc))

    def clear_proxy(self) -> None:
        self.captures.clear()
        self.proxy_table.setRowCount(0)
        self.proxy_detail.clear()

    def add_capture(self, capture: ProxyCapture) -> None:
        self.captures.append(capture)
        row = self.proxy_table.rowCount()
        self.proxy_table.insertRow(row)
        values = [capture.index, capture.method, capture.host, capture.port, capture.path, capture.status_code, capture.elapsed_ms, capture.error]
        for col, value in enumerate(values):
            set_table_item(self.proxy_table, row, col, value)

    def show_selected(self) -> None:
        row = self.proxy_table.currentRow()
        if row < 0 or row >= len(self.captures):
            return
        capture = self.captures[row]
        self.proxy_detail.setPlainText(
            "\n".join(
                [
                    f"客户端: {capture.client_address}",
                    f"协议: {capture.scheme}",
                    f"目标: {capture.host}:{capture.port}",
                    f"方法: {capture.method}",
                    f"路径: {capture.path}",
                    f"状态码: {capture.status_code}",
                    f"请求大小: {capture.request_size}",
                    f"响应大小: {capture.response_size}",
                    f"耗时: {capture.elapsed_ms} ms",
                    f"错误: {capture.error or '无'}",
                    "",
                    "请求头:",
                    json.dumps(capture.request_headers, ensure_ascii=False, indent=2),
                    "",
                    "请求体:",
                    capture.request_body,
                    "",
                    "响应头:",
                    json.dumps(capture.response_headers, ensure_ascii=False, indent=2),
                    "",
                    "响应体:",
                    capture.response_body,
                ]
            )
        )


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        self.resize(*WINDOW_SIZE)
        self.setMinimumSize(1280, 820)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)

        header = card_widget()
        header_layout = QHBoxLayout(header)
        text_box = QVBoxLayout()
        title = QLabel(APP_TITLE)
        title.setProperty("title", True)
        subtitle = QLabel(" 本工具包括XSS、SQL、模糊测试、字典与抓包功能")
        subtitle.setProperty("muted", True)
        text_box.addWidget(title)
        text_box.addWidget(subtitle)
        header_layout.addLayout(text_box)
        header_layout.addStretch()
        layout.addWidget(header)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.database_tab = DatabaseTab()
        self.xss_tab = XSSTab()
        self.sql_tab = SQLExploitTab()
        self.fuzzer_tab = FuzzerTab()
        self.dictionary_tab = DictionaryTab()
        self.proxy_tab = ProxyTab()
        self.tabs.addTab(self.database_tab, "数据库")
        self.tabs.addTab(self.xss_tab, "XSS 检测")
        self.tabs.addTab(self.sql_tab, "SQL 注入")
        self.tabs.addTab(self.fuzzer_tab, "模糊测试")
        self.tabs.addTab(self.dictionary_tab, "字典工具")
        self.tabs.addTab(self.proxy_tab, "抓包代理")
        self.proxy_tab.capture_forward_requested.connect(self.open_capture_in_fuzzer)
        layout.addWidget(self.tabs, 1)

        self.setCentralWidget(container)
        self.setStatusBar(QStatusBar())
        file_menu = self.menuBar().addMenu("??")
        exit_action = QAction("??", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)


    def open_capture_in_fuzzer(self, capture: ProxyCapture) -> None:
        if self.fuzzer_tab.load_proxy_capture(capture):
            self.tabs.setCurrentWidget(self.fuzzer_tab)
            self.statusBar().showMessage(
                f"已将 {capture.method} {capture.path} 传送到模糊测试页面",
                5000,
            )


def launch() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName(APP_TITLE)
    apply_light_theme(app)
    window = MainWindow()
    window.show()
    return app.exec()















