# Catomicals 首批执行清单

日期：2026-08-27

状态：规划完成，尚未启动本清单中的实现批次。

详细架构、数据模型和长期边界见[后端全栈实施路线](2026-08-27-catomicals-backend-roadmap.md)。本清单只保留首批任务的顺序、负责人、文件所有权和验收。

## 分工原则

- DSH 负责路径明确、输入合同冻结、能独立验收的 TypeScript/React 实现。
- Codex 子代理负责 Rust、数据库、密码学、安全、协议和跨模块整合。
- 主代理负责依赖编排、合同合并、回归验证与提交。
- 所有 DSH 任务必须声明 `allowedPaths`、只读路径、禁止路径、输入 schema 和验收命令。
- MCP、Cordis、indexer、UI 和执行器均无权批准交易、释放 FROST share 或绕过 `walletd` 的预签复核。

## 执行顺序

### B0：冻结架构合同

- 执行方：Codex 架构子代理。
- 所有权：`docs/adr/*`、`schemas/agent/*`。
- 输入：当前 `api/v1`、9 个 MCP 工具、Electron IPC、wallet intent/review 类型。
- 输出：walletd 进程边界、节点信任边界、policy 对象、executor session、plugin manifest、chat/tool/UI schema。
- 基线：`cargo test --workspace`、`pnpm --dir desktop test`、`pnpm --dir web test`。
- 完成：ADR 通过安全与合同审查；schema 能生成或校验 desktop、web 和 Rust 所需类型。

### B1：Electron P0 安全

- 执行方：Codex 安全子代理。
- 所有权：`desktop/src/main.ts`、`preload.ts`、`ipc.ts` 及对应测试。
- 输入：B0 IPC 与可信原点合同。
- 输出：可信 renderer origin、frame lineage 校验、导航限制、DNS/redirect 私网复检、browser partition 生命周期、单一 WebAuthn/CORS origin。
- 基线：`pnpm --dir desktop test`、`pnpm --dir desktop build:electron`、`cargo test -p catomicals-wallet --test webauthn_ceremonies`。
- 完成：远程 renderer、非可信 frame、DNS 重绑定、私网跳转、`file:` 和 `devtools:` 负向测试全部通过。

### B2：最小可信节点访问

- 执行方：Codex Rust 子代理。
- 所有权：`crates/node-client/*`、必要的 `apps/catomicals-cli/src/node.rs`。
- 输入：B0 节点信任 ADR。
- 输出：`chain_snapshot`、`resolve_prevouts`、`test_mempool_accept`、`broadcast_transaction`、`transaction_status`。
- 基线：`cargo test -p catomicals-node-client`、`cargo run -p catomicals -- node health`。
- 完成：真实节点集成测试证明错误 prevout、过期 snapshot、deployment 不匹配和广播前预检失败均会关闭写路径。

### B3：Durable walletd

- 执行方：Codex Rust 子代理。
- 所有权：`crates/wallet-storage/*`、`crates/wallet-core/src/store.rs`、`apps/catomicals-cli/src/walletd.rs`、相关迁移和测试。
- 输入：B2 typed node access、路线图中的 restore 状态合同。
- 输出：SQLite WAL、单写者、持久 intent/credential metadata/authorization/nonce claim、审计事件、单钱包加密备份。
- 基线：`cargo test -p catomicals-wallet`、`cargo test -p catomicals wallet_serve::tests`。
- 完成：crash/restart/race 矩阵通过；未完成 ceremony 失效；旧 snapshot、authorization、nonce epoch 不能跨 restore cutover。

### B4：三种执行器适配

- 执行方：DSH，拆成 Codex、DeepSeek Harness、Claude Code 三个独立任务。
- 所有权：每个任务只拥有自己的 `desktop/src/executors/<provider>.ts` 与测试；registry 由 Codex 子代理管理。
- 输入：B0 executor schema、B1 IPC 安全合同。
- 输出：probe、模型发现、创建/恢复会话、发送消息、取消 turn、状态事件。
- 基线：`pnpm --dir desktop test`。
- 完成：三个 provider 都能运行最小会话；执行器只能使用统一 MCP，无钱包批准、签名和广播捷径。

### B5：Cordis 固定插件宿主

- 执行方：Codex TypeScript 子代理。
- 所有权：`desktop/src/cordis/*`、manifest/schema 校验、迁移和宿主测试。
- 输入：B0 plugin manifest、DeepSeek Harness 的 profile/bundle/Service/inject 生命周期参考。
- 输出：固定签名插件、权限、settings schema、health、migration、last-good tree。
- 基线：`pnpm --dir desktop test`。
- 完成：坏包、坏 patch、缺失 service 和失败迁移均隔离在插件命名空间，不污染 `walletd`。

### B6：插件设置与代理代配置

- 执行方：DSH。
- 所有权：限定的 `web/src/*` 与 Cordis client half，不修改 host、MCP 权限和钱包代码。
- 输入：B4 executor registry、B5 plugin host、配置意图 schema。
- 输出：插件目录、设置表单、模型选择、健康状态、配置差异确认卡。
- 基线：`pnpm --dir web test`、`cargo test -p catomicals mcp::tests`。
- 完成：Codex、DSH、Claude Code 可通过 MCP 读取 schema、校验 patch、创建配置意图；用户确认后由 host 重读、复核、健康检查并提升 last-good。

### B7：Indexer 首个纵向切片

- 执行方：Codex Rust 子代理。
- 所有权：`crates/indexer/*`、查询 API、reorg/rebuild 测试。
- 输入：B2 链事件、B3 数据库与审计规范。
- 输出：独立 RocksDB 中的 block、transaction、UTXO、一个 covenant transition、undo、checkpoint；按 column family 分区，并以区块级 `WriteBatch` 原子提交。
- 基线：`cargo test -p catomicals-issuance`、`cargo test -p catomicals-node-client`。
- 完成：从 genesis/checkpoint 重建结果一致；浅层和深层 reorg 均能回滚；indexer 停止或损坏不影响 walletd 预签复核。

### B8：Indexer 查询界面

- 执行方：DSH。
- 所有权：限定的 indexer 查询页、状态图表和前端测试。
- 输入：B7 查询 API 与 stale/reorg 状态。
- 输出：区块、交易、UTXO、transition、同步、重建和 reorg 可视化。
- 基线：`pnpm --dir web test`。
- 完成：落后、不可用、stale、reorg 和重建状态如实显示；界面不把 indexer 结果称为结算真相。

## 启动规则

1. 先执行 B0、B1、B2、B3；B1 与 B2 可在 B0 合同冻结后并行。
2. B4 和 B5 在 B1 完成后并行；B6 等 B4/B5 的稳定接口。
3. B7 等 B2 的链输入稳定，并沿用 B3 的数据库纪律；B8 等 B7 查询 API。
4. 每批完成后，由独立 Codex 子代理做合同、安全和简洁性复审。
5. 只有当前批次的基线、增量测试和负向测试全部通过，主代理才合并并启动下一批。
