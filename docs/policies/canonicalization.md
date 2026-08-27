# Canonicalization and bundle verification

policy identity 只取决于被哈希的 `policy_document`。`lifecycle`、binding 和 activation 状态不进入正文；状态变化写入独立的 append-only 表和审计事件。

v1 固定流程：

1. 用严格 Rust 类型解析 JSON；重复字段、未知字段、错误类型、非法枚举和超限内容直接拒绝。
2. 用 RFC 8785 JCS 生成正文 bytes。
3. 计算 `sha256:<64 lowercase hex>`，作为 policy hash。
4. 复用协议 crate 生成实际制品 bytes，并分别计算 SHA-256。
5. 对完整 artifact set 和 vector set 分别做 JCS + SHA-256。
6. 执行全部向量，把 compiler version、policy hash、两个 set digest 和结果绑定进 validation run digest。

JSON 对象键顺序变化不会改变 policy hash；字符串、数字、协议参数或网络配置的任何正文变化都会得到新 hash。bundle 本身也必须是 JCS bytes，`policy inspect` 会重新计算正文、制品、集合、向量与 validation run，并拒绝任何不一致。

制品同时保存 `content_hex` 和确定性的 `content_ref=inline:<artifact_id>`。SQLite 写入保存解码后的 bytes 与 digest；单个制品上限 128 KiB，artifact/vector set 各上限 1 MiB。
