from __future__ import annotations

import json
import re
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence

try:
    import pymysql
except ImportError:  # pragma: no cover - optional dependency at runtime
    pymysql = None


Logger = Optional[Callable[[str], None]]
CONFIG_PATH = Path(__file__).resolve().with_name("mysql_config.json")


@dataclass(slots=True)
class MySQLConfig:
    enabled: bool = False
    xss_enabled: bool = True
    sql_enabled: bool = True
    host: str = "127.0.0.1"
    port: int = 3306
    user: str = "root"
    password: str = ""
    database: str = "cgfuzz"
    charset: str = "utf8mb4"


class MySQLStorageError(RuntimeError):
    pass


class MySQLStorage:
    def __init__(
        self,
        config: Optional[MySQLConfig] = None,
        *,
        logger: Logger = None,
    ) -> None:
        self.config = config or load_mysql_config()
        self.logger = logger

    def _log(self, message: str) -> None:
        if self.logger:
            self.logger(message)

    def _is_xss_storage_enabled(self) -> bool:
        return bool(self.config.enabled and self.config.xss_enabled)

    def _is_sql_storage_enabled(self) -> bool:
        return bool(self.config.enabled and self.config.sql_enabled)

    def _require_driver(self) -> None:
        if pymysql is None:
            raise MySQLStorageError(
                "未安装 pymysql，请先执行 pip install -r requirements.txt"
            )

    @contextmanager
    def _connection(self, *, include_database: bool = True) -> Iterator[Any]:
        self._require_driver()
        connect_kwargs = dict(
            host=self.config.host,
            port=int(self.config.port),
            user=self.config.user,
            password=self.config.password,
            charset=self.config.charset,
            autocommit=False,
        )
        if include_database and self.config.database:
            connect_kwargs["database"] = self.config.database
        connection = pymysql.connect(**connect_kwargs)
        try:
            yield connection
        finally:
            connection.close()

    def test_connection(self) -> None:
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()

    def ensure_tables(self, connection: Optional[Any] = None) -> None:
        own_connection = connection is None
        if own_connection:
            self._ensure_database()
            with self._connection() as managed:
                self.ensure_tables(managed)
                managed.commit()
            return

        statements = [
            """
            CREATE TABLE IF NOT EXISTS xss_results (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                scan_id VARCHAR(64) NOT NULL,
                target_url VARCHAR(2048) NOT NULL,
                request_method VARCHAR(16) NOT NULL,
                param_name VARCHAR(255) NOT NULL,
                xss_type VARCHAR(64) NOT NULL,
                payload_name VARCHAR(255) DEFAULT '',
                payload_text MEDIUMTEXT,
                result_url VARCHAR(2048) DEFAULT '',
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                KEY idx_xss_scan_id (scan_id),
                KEY idx_xss_type (xss_type),
                KEY idx_xss_created_at (created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """,
            """
            CREATE TABLE IF NOT EXISTS sql_results (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                scan_id VARCHAR(64) NOT NULL,
                target_url VARCHAR(2048) NOT NULL,
                request_method VARCHAR(16) NOT NULL,
                param_name VARCHAR(255) DEFAULT '',
                database_name VARCHAR(255) DEFAULT '',
                table_name VARCHAR(255) DEFAULT '',
                column_names TEXT,
                evidence TEXT,
                result_summary TEXT,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                KEY idx_sql_scan_id (scan_id),
                KEY idx_sql_created_at (created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """,
        ]

        with connection.cursor() as cursor:
            for statement in statements:
                cursor.execute(statement)
        self._sync_xss_results_schema(connection)
        self._sync_sql_results_schema(connection)

    def _sync_xss_results_schema(self, connection: Any) -> None:
        allowed_columns = {
            "id",
            "scan_id",
            "target_url",
            "request_method",
            "param_name",
            "xss_type",
            "payload_name",
            "payload_text",
            "result_url",
            "created_at",
        }
        required_columns = {
            "scan_id": "ADD COLUMN `scan_id` VARCHAR(64) NOT NULL AFTER `id`",
            "target_url": "ADD COLUMN `target_url` VARCHAR(2048) NOT NULL AFTER `scan_id`",
            "request_method": "ADD COLUMN `request_method` VARCHAR(16) NOT NULL AFTER `target_url`",
            "param_name": "ADD COLUMN `param_name` VARCHAR(255) NOT NULL AFTER `request_method`",
            "xss_type": "ADD COLUMN `xss_type` VARCHAR(64) NOT NULL AFTER `param_name`",
            "payload_name": "ADD COLUMN `payload_name` VARCHAR(255) DEFAULT '' AFTER `xss_type`",
            "payload_text": "ADD COLUMN `payload_text` MEDIUMTEXT AFTER `payload_name`",
            "result_url": "ADD COLUMN `result_url` VARCHAR(2048) DEFAULT '' AFTER `payload_text`",
            "created_at": (
                "ADD COLUMN `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP "
                "AFTER `result_url`"
            ),
        }
        required_indexes = {
            "idx_xss_scan_id": "CREATE INDEX idx_xss_scan_id ON xss_results (scan_id)",
            "idx_xss_type": "CREATE INDEX idx_xss_type ON xss_results (xss_type)",
            "idx_xss_created_at": "CREATE INDEX idx_xss_created_at ON xss_results (created_at)",
        }

        with connection.cursor() as cursor:
            cursor.execute("SHOW COLUMNS FROM xss_results")
            existing_columns = [row[0] for row in cursor.fetchall()]
            add_clauses = [
                clause
                for column, clause in required_columns.items()
                if column not in existing_columns
            ]
            if add_clauses:
                cursor.execute(f"ALTER TABLE xss_results {', '.join(add_clauses)}")

            removable_columns = [
                column for column in existing_columns if column not in allowed_columns
            ]
            if removable_columns:
                drop_clauses = [
                    f"DROP COLUMN `{column.replace('`', '``')}`"
                    for column in removable_columns
                ]
                cursor.execute(f"ALTER TABLE xss_results {', '.join(drop_clauses)}")

            cursor.execute("SHOW INDEX FROM xss_results")
            existing_indexes = {
                row[2] for row in cursor.fetchall() if row[2] and row[2] != "PRIMARY"
            }
            for index_name, statement in required_indexes.items():
                if index_name not in existing_indexes:
                    cursor.execute(statement)

    def _sync_sql_results_schema(self, connection: Any) -> None:
        allowed_columns = {
            "id",
            "scan_id",
            "target_url",
            "request_method",
            "param_name",
            "database_name",
            "table_name",
            "column_names",
            "evidence",
            "result_summary",
            "created_at",
        }
        required_columns = {
            "scan_id": "ADD COLUMN `scan_id` VARCHAR(64) NOT NULL AFTER `id`",
            "target_url": "ADD COLUMN `target_url` VARCHAR(2048) NOT NULL AFTER `scan_id`",
            "request_method": "ADD COLUMN `request_method` VARCHAR(16) NOT NULL AFTER `target_url`",
            "param_name": "ADD COLUMN `param_name` VARCHAR(255) DEFAULT '' AFTER `request_method`",
            "database_name": "ADD COLUMN `database_name` VARCHAR(255) DEFAULT '' AFTER `param_name`",
            "table_name": "ADD COLUMN `table_name` VARCHAR(255) DEFAULT '' AFTER `database_name`",
            "column_names": "ADD COLUMN `column_names` TEXT AFTER `table_name`",
            "evidence": "ADD COLUMN `evidence` TEXT AFTER `column_names`",
            "result_summary": "ADD COLUMN `result_summary` TEXT AFTER `evidence`",
            "created_at": (
                "ADD COLUMN `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP "
                "AFTER `result_summary`"
            ),
        }
        required_indexes = {
            "idx_sql_scan_id": "CREATE INDEX idx_sql_scan_id ON sql_results (scan_id)",
            "idx_sql_created_at": "CREATE INDEX idx_sql_created_at ON sql_results (created_at)",
        }

        with connection.cursor() as cursor:
            cursor.execute("SHOW COLUMNS FROM sql_results")
            existing_columns = [row[0] for row in cursor.fetchall()]
            add_clauses = [
                clause
                for column, clause in required_columns.items()
                if column not in existing_columns
            ]
            if add_clauses:
                cursor.execute(f"ALTER TABLE sql_results {', '.join(add_clauses)}")

            removable_columns = [
                column for column in existing_columns if column not in allowed_columns
            ]
            if removable_columns:
                drop_clauses = [
                    f"DROP COLUMN `{column.replace('`', '``')}`"
                    for column in removable_columns
                ]
                cursor.execute(f"ALTER TABLE sql_results {', '.join(drop_clauses)}")

            cursor.execute("SHOW INDEX FROM sql_results")
            existing_indexes = {
                row[2] for row in cursor.fetchall() if row[2] and row[2] != "PRIMARY"
            }
            for index_name, statement in required_indexes.items():
                if index_name not in existing_indexes:
                    cursor.execute(statement)

    def _ensure_database(self) -> None:
        database_name = (self.config.database or "").strip()
        if not database_name:
            raise MySQLStorageError("请先填写 MySQL 数据库名")

        safe_database = database_name.replace("`", "``")
        safe_charset = self.config.charset.strip() or "utf8mb4"
        if not re.fullmatch(r"[A-Za-z0-9_]+", safe_charset):
            safe_charset = "utf8mb4"

        with self._connection(include_database=False) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    f"CREATE DATABASE IF NOT EXISTS `{safe_database}` CHARACTER SET {safe_charset}"
                )
            connection.commit()

    def save_xss_results(
        self,
        config: Any,
        results: Sequence[Any],
        *,
        source: str = "xss_tab",
        scan_id: Optional[str] = None,
    ) -> int:
        if not self.config.enabled:
            self._log("[*] MySQL 持久化未启用，已跳过 XSS 结果写入")
            return 0
        if not self._is_xss_storage_enabled():
            self._log("[*] XSS 结果入库已关闭，已跳过 XSS 结果写入")
            return 0
        if not results:
            self._log("[*] 本次没有 XSS 结果可写入 MySQL")
            return 0

        payloads: List[tuple[Any, ...]] = []
        batch_id = scan_id or self._new_scan_id()
        method = str(getattr(config, "method", "GET")).upper()
        target_url = str(getattr(config, "url", ""))

        for result in results:
            item = self._serialize(result)
            payloads.append(
                (
                    batch_id,
                    target_url,
                    method,
                    str(item.get("param_name", "")),
                    self._stringify(item.get("xss_type")),
                    str(item.get("payload_name", "")),
                    str(item.get("payload", "")),
                    str(item.get("url", "")),
                )
            )

        if not payloads:
            return 0

        self._ensure_database()
        with self._connection() as connection:
            self.ensure_tables(connection)
            with connection.cursor() as cursor:
                cursor.executemany(
                    """
                    INSERT INTO xss_results (
                        scan_id,
                        target_url,
                        request_method,
                        param_name,
                        xss_type,
                        payload_name,
                        payload_text,
                        result_url
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    payloads,
                )
            connection.commit()

        self._log(f"[+] MySQL 已保存 XSS 结果 {len(payloads)} 条，批次 {batch_id}")
        return len(payloads)

    def save_scan_summary(
        self,
        summary: Dict[str, Any],
        *,
        source: str = "scanner_tab",
        scan_id: Optional[str] = None,
    ) -> Dict[str, int]:
        if not self.config.enabled:
            self._log("[*] MySQL 持久化未启用，已跳过扫描结果写入")
            return {"xss": 0, "sql": 0}
        if not self._is_xss_storage_enabled() and not self._is_sql_storage_enabled():
            self._log("[*] XSS/SQL 结果入库均已关闭，已跳过扫描结果写入")
            return {"xss": 0, "sql": 0}

        batch_id = scan_id or self._new_scan_id()
        normalized = self._serialize(summary)
        target_url = str(normalized.get("target", ""))
        method = str(normalized.get("method", "GET")).upper()
        results = normalized.get("results", []) or []
        sql_analysis = normalized.get("sql_analysis", {}) or {}
        xss_rows: List[tuple[Any, ...]] = []
        sql_rows: List[tuple[Any, ...]] = []

        for item in results:
            vuln_type = str(item.get("vuln_type", "")).lower()
            if vuln_type == "xss" and self._is_xss_storage_enabled():
                xss_rows.append(
                    (
                        batch_id,
                        target_url,
                        method,
                        str(item.get("param_name", "")),
                        str(item.get("xss_type") or item.get("vuln_type", "")),
                        str(item.get("payload_name", "")),
                        str(item.get("payload", "")),
                        str(item.get("url", target_url)),
                    )
                )
            elif vuln_type == "sql" and self._is_sql_storage_enabled():
                sql_rows.append(
                    (
                        batch_id,
                        target_url,
                        method,
                        str(item.get("param_name", "")),
                        str(sql_analysis.get("database_name", "")),
                        "",
                        str(item.get("reason", "")),
                        "综合扫描命中 SQL 规则",
                    )
                )

        if not xss_rows and not sql_rows:
            self._log("[*] 扫描结果中没有 SQL/XSS 命中项，未写入 MySQL")
            return {"xss": 0, "sql": 0}

        self._ensure_database()
        with self._connection() as connection:
            self.ensure_tables(connection)
            with connection.cursor() as cursor:
                if xss_rows:
                    cursor.executemany(
                        """
                        INSERT INTO xss_results (
                            scan_id,
                            target_url,
                            request_method,
                            param_name,
                            xss_type,
                            payload_name,
                            payload_text,
                            result_url
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        xss_rows,
                    )
                if sql_rows:
                    cursor.executemany(
                        """
                        INSERT INTO sql_results (
                            scan_id,
                            target_url,
                            request_method,
                            param_name,
                            database_name,
                            table_name,
                            column_names,
                            evidence,
                            result_summary
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        sql_rows,
                    )
            connection.commit()

        if xss_rows:
            self._log(f"[+] MySQL 已保存扫描 XSS 结果 {len(xss_rows)} 条，批次 {batch_id}")
        if sql_rows:
            self._log(f"[+] MySQL 已保存扫描 SQL 结果 {len(sql_rows)} 条，批次 {batch_id}")
        return {"xss": len(xss_rows), "sql": len(sql_rows)}

    def save_sql_result(
        self,
        config: Any,
        action: str,
        result: Any,
        *,
        source: str = "sql_tab",
        scan_id: Optional[str] = None,
    ) -> int:
        if not self.config.enabled:
            self._log("[*] MySQL 持久化未启用，已跳过 SQL 结果写入")
            return 0
        if not self._is_sql_storage_enabled():
            self._log("[*] SQL 结果入库已关闭，已跳过 SQL 结果写入")
            return 0

        allowed_actions = {"databases", "tables", "columns", "dump"}
        if action not in allowed_actions:
            self._log(f"[*] SQL 动作 {action} 不属于枚举/提取结果，已跳过写入 MySQL")
            return 0

        batch_id = scan_id or self._new_scan_id()
        normalized = self._serialize(result)
        if not isinstance(normalized, dict):
            self._log(f"[*] SQL 动作 {action} 未返回可持久化的数据结构，已跳过写入 MySQL")
            return 0

        method = str(getattr(config, "method", "GET")).upper()
        target_url = str(getattr(config, "url", ""))
        param_name = str(getattr(config, "param_name", ""))
        database_name = str(getattr(config, "database_name", "") or "")
        table_name = str(getattr(config, "table_name", "") or "")
        configured_columns = self._join_values(getattr(config, "column_names", None))
        rows: List[tuple[Any, ...]] = []

        if action == "databases":
            databases = self._extract_sql_result_items(
                normalized.get("databases", []),
                preferred_keys=("database_name", "name", "value"),
            )
            for item in databases:
                rows.append(
                    (
                        batch_id,
                        target_url,
                        method,
                        param_name,
                        item,
                        "",
                        "",
                        "",
                        f"枚举数据库: {item}",
                    )
                )
        elif action == "tables":
            tables = self._extract_sql_result_items(
                normalized.get("tables", []),
                preferred_keys=("table_name", "name", "value"),
            )
            for item in tables:
                rows.append(
                    (
                        batch_id,
                        target_url,
                        method,
                        param_name,
                        database_name,
                        item,
                        "",
                        "",
                        f"枚举表: {database_name}.{item}" if database_name else f"枚举表: {item}",
                    )
                )
        elif action == "columns":
            columns = self._extract_sql_result_items(
                normalized.get("columns", []),
                preferred_keys=("column_name", "name", "value"),
            )
            for item in columns:
                rows.append(
                    (
                        batch_id,
                        target_url,
                        method,
                        param_name,
                        database_name,
                        table_name,
                        item,
                        "",
                        f"枚举字段: {database_name}.{table_name}.{item}".strip("."),
                    )
                )
        elif action == "dump":
            result_rows = normalized.get("rows", [])
            derived_columns = configured_columns
            if not derived_columns and result_rows:
                first_row = result_rows[0]
                if isinstance(first_row, dict):
                    derived_columns = self._join_values(first_row.keys())
            for row_index, row_data in enumerate(result_rows, start=1):
                if not isinstance(row_data, dict):
                    continue
                rows.append(
                    (
                        batch_id,
                        target_url,
                        method,
                        param_name,
                        database_name,
                        table_name,
                        derived_columns,
                        self._to_json(row_data),
                        f"提取数据第 {row_index} 行",
                    )
                )

        if not rows:
            fallback_summary = self._stringify(normalized.get("message", ""))
            fallback_evidence = self._stringify(normalized.get("evidence", ""))
            if fallback_summary:
                rows.append(
                    (
                        batch_id,
                        target_url,
                        method,
                        param_name,
                        database_name,
                        table_name,
                        configured_columns,
                        fallback_evidence,
                        fallback_summary,
                    )
                )
            else:
                self._log(f"[*] SQL 动作 {action} 没有可持久化的数据，已跳过写入 MySQL")
                return 0

        self._ensure_database()
        with self._connection() as connection:
            self.ensure_tables(connection)
            with connection.cursor() as cursor:
                cursor.executemany(
                    """
                    INSERT INTO sql_results (
                        scan_id,
                        target_url,
                        request_method,
                        param_name,
                        database_name,
                        table_name,
                        column_names,
                        evidence,
                        result_summary
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    rows,
                )
            connection.commit()

        self._log(f"[+] MySQL 已保存 SQL 结果 {len(rows)} 条，批次 {batch_id}")
        return len(rows)

    def _new_scan_id(self) -> str:
        return uuid.uuid4().hex

    def _serialize(self, value: Any) -> Any:
        if is_dataclass(value):
            return self._serialize(asdict(value))
        if isinstance(value, Enum):
            return value.value
        if isinstance(value, dict):
            return {str(key): self._serialize(item) for key, item in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [self._serialize(item) for item in value]
        return value

    def _stringify(self, value: Any) -> str:
        if isinstance(value, Enum):
            return str(value.value)
        if value is None:
            return ""
        return str(value)

    def _to_json(self, value: Any) -> str:
        return json.dumps(self._serialize(value), ensure_ascii=False, indent=2)

    def _join_values(self, values: Any) -> str:
        if values is None:
            return ""
        if isinstance(values, dict):
            return json.dumps(values, ensure_ascii=False)
        if isinstance(values, str):
            return values
        if isinstance(values, (list, tuple, set)):
            cleaned = [self._stringify(item) for item in values if self._stringify(item)]
            return ", ".join(cleaned)
        return self._stringify(values)

    def _extract_sql_result_items(
        self,
        values: Any,
        *,
        preferred_keys: Sequence[str] = (),
    ) -> List[str]:
        if not isinstance(values, (list, tuple, set)):
            return []

        items: List[str] = []
        for value in values:
            if isinstance(value, dict):
                extracted = ""
                for key in preferred_keys:
                    extracted = self._stringify(value.get(key))
                    if extracted:
                        break
                if not extracted:
                    extracted = self._join_values(value.values())
            else:
                extracted = self._stringify(value)

            if extracted:
                items.append(extracted)
        return items

    def _summarize_sql_result(self, result: Any, action: str) -> str:
        if not isinstance(result, dict):
            return f"SQL 动作 {action} 已执行"
        if result.get("message"):
            return str(result["message"])
        if result.get("databases"):
            return f"枚举数据库 {len(result['databases'])} 个"
        if result.get("tables"):
            return f"枚举表 {len(result['tables'])} 个"
        if result.get("columns"):
            return f"枚举字段 {len(result['columns'])} 个"
        if result.get("rows"):
            return f"提取数据 {len(result['rows'])} 行"
        if result.get("findings"):
            return f"发现注入证据 {len(result['findings'])} 条"
        if result.get("vulnerable_payloads"):
            return f"命中 payload {len(result['vulnerable_payloads'])} 条"
        return f"SQL 动作 {action} 已执行"


def load_mysql_config(path: Path = CONFIG_PATH) -> MySQLConfig:
    if not path.exists():
        config = MySQLConfig()
        save_mysql_config(config, path)
        return config

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return MySQLConfig()

    return MySQLConfig(
        enabled=bool(data.get("enabled", False)),
        xss_enabled=bool(data.get("xss_enabled", True)),
        sql_enabled=bool(data.get("sql_enabled", True)),
        host=str(data.get("host", "127.0.0.1")),
        port=int(data.get("port", 3306)),
        user=str(data.get("user", "root")),
        password=str(data.get("password", "")),
        database=str(data.get("database", "cgfuzz")),
        charset=str(data.get("charset", "utf8mb4")),
    )


def save_mysql_config(config: MySQLConfig, path: Path = CONFIG_PATH) -> None:
    path.write_text(
        json.dumps(asdict(config), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
