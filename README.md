Web 安全工作台
该目录是将 ctf-scanner-main 与 webfuzzer 合并后的新项目，当前界面已移除“漏洞扫描”页面。

启动
pip install -r requirements.txt
python main.py
MySQL 结果存储
项目已支持将 XSS 检测结果和 SQL 探测/利用结果写入 MySQL。
默认配置文件位于 web/mysql_config.json。
也可以直接在程序中的 数据库 标签页里填写主机、端口、用户名、密码和数据库名。
点击 测试连接 可检查 MySQL 是否可用，点击 初始化表 会自动创建 xss_results 和 sql_results 两张表。
勾选 启用 MySQL 结果持久化 并保存配置后，可分别通过 XSS 结果入库、SQL 结果入库 控制对应结果是否写入数据库。
在 XSS 检测 页和 SQL 利用 页中，还可以通过 本次结果写入数据库 复选框临时决定当前这一次运行是否入库。
SQL 数据库存储字段：id、scan_id、target_url、request_method、param_name、database_name、table_name、column_names、evidence、result_summary、created_at
功能
Web Fuzzer：多占位符绑定、字典管理、智能字典生成、结果过滤与高亮
抓包代理：HTTP/HTTPS 代理监听、请求回放、抓包详情查看
XSS 数据库存储字段：id、scan_id、target_url、request_method、param_name、xss_type、payload_name、payload_text、result_url、created_at
