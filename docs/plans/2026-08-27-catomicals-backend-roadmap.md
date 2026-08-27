# Catomicals 后端全栈实施路线

日期：2026-08-27

## 目标

这份路线只服务当前仓库已经落下来的 Catomicals 地基：`wallet-core`、`threshold-signer`、`node-client`、`issuance`、`trading`、`desktop`、`web`、`apps/catomicals-cli`。目标是把“研究演示”推进成“可自主部署、可恢复、可审计、可扩展”的本地优先钱包与 covenant 运行设施，同时给发行、撮合、防抢跑、未来 AMM 实验留下稳定接口。

这里的“后端”包含四层：

- 本机守护进程：钱包节点、签名协调、节点网关、索引与存储。
- 桌面宿主：Electron main、设置、密钥封装、执行器接入。
- 代理接口：MCP、ACP、聊天会话、工具事件、生成式界面块。
- 研究协议：发行、订单、资产状态机、实验性 AMM 接口。

## 文档状态约定

为避免把未来设计写成当前能力，本文采用三个状态：

- `现有`：当前工作树已经存在，并能用现有命令验证。
- `本阶段新增`：该阶段要创建的模块、命令、表或测试。验收命令只有在这些对象落地后才成立。
- `后续目标`：长期架构边界，当前阶段不创建空壳包，也不以“接口已定义”冒充完成。

每个阶段的实施顺序固定为：先写失败合同和迁移边界，再创建模块，最后运行阶段验收。文中出现的未来包名与子命令均属于“本阶段新增”，不代表当前仓库已经具备。

## 近期执行顺序

长期模块可以完整设计，近期只按以下顺序实体化：

1. Electron 安全阻断项与单一可信原点。
2. 最小可信节点访问：新鲜链快照、真实 prevout、mempool 预检和广播前复核。
3. `walletd` 持久化：意图、凭据元数据、授权记录、nonce claim 与审计事件。
4. Electron/TypeScript 执行器宿主：Codex、DeepSeek Harness、Claude Code、统一 MCP 与 Cordis 插件设置。
5. policy 文档、编译制品与激活；先完成单钱包备份，再进入分布式 signer 恢复。
6. 可重建 indexer 的第一条纵向链路：区块、交易、UTXO、covenant transition、reorg undo 与 checkpoint。
7. 在真实查询需求出现后，扩展资产、发行、订单、成交、冲突集与市场读侧。

这条顺序保留完整路线，同时避免一次创建多个没有真实消费者的新包。

## 现状审计结论

只读审计基于当前工作树和已有文档，得到几个关键现实：

- 当前 Rust 测试基线是 124 个测试通过，适合拿来做重构保护网。
- `crates/wallet-core/src/store.rs` 仍是 `InMemoryWalletStore`，意图、凭据都在内存里。
- `crates/wallet-core/src/node.rs` 的 `WalletNodeService` 已经把 Passkey、意图、交易检查、交易型意图、交易聊天、FROST 回合串起来了，但状态仍是进程内 `HashMap`。
- `crates/threshold-signer/src/nonce_guard.rs` 已经有 nonce 重放保护语义，当前仅存在内存中，重启后丢失。
- `apps/catomicals-cli/src/wallet_serve.rs` 直接在进程启动时跑本地 DKG，保留单个参与者，明显只是开发演示。
- `desktop/src/main.ts` 已经有桌面壳和 `safeStorage` 可用性探测，但 `desktop/src/settings-store.ts` 仍把设置明文写入 `settings.json`。
- `apps/catomicals-cli/src/mcp.rs` 已经提供 loopback-only MCP，只允许读状态、创建意图、检查交易，不允许批准、签名、广播。
- 当前 MCP 工具面固定为 9 个工具，已经形成第一版安全边界。
- `crates/node-client/src/rpc.rs` 目前只有健康检查，没有节点生命周期管理、网关、重扫、广播、同步监控。
- `crates/issuance/src/indexer.rs` 当前只是单笔 mint 发现型纯函数，还不是真正可重建 indexer。
- `crates/issuance` 与 `crates/trading` 已有可执行验证，发行与挂牌路径可以继续作为后续资产协议层的第一批模板。

因此路线先把 policy、密钥、持久化、恢复、节点网关、索引与执行器注册做实，UI 扩展和更多协议玩法排在这些基础之后。

## 总体架构落点

建议把系统收束成六个长期边界清晰的模块面：

1. `walletd`
   当前 `wallet serve` 的演进体。负责真实状态、交易检查、意图、审批绑定、FROST 协调、节点快照校验、广播决策。

2. `desktop host`
   Electron main 负责窗口、浏览器页、设置、系统登录、系统密钥封装、执行器注册与子进程生命周期；不负责直接保存裸密钥和 quorum share。

3. `node gateway + indexer`
   负责和 Bitcoin Inquisition 或外部节点交互，提供 allowlist 化的链查询、健康检查、同步状态、广播、重扫和可重建查询层。

4. `policy registry`
   负责策略文档、编译产物、测试向量、激活审批、钱包绑定、版本与哈希，不和聊天消息混在一起。

5. `agent runtime`
   负责 Codex、DeepSeek Harness、Claude Code 执行器接入，统一会话、工具事件、模型配置、生成式界面块与权限域。

6. `cordis plugin runtime`
   负责能力注册、配置 schema、权限、生命周期、迁移、健康检查、设置面板，不负责持有钱包真相。

## 强制架构原则

- 钱包真实结算依据来自 `walletd + node snapshot + policy verification`，不来自索引器。
- Passkey 与交易批准是两层概念。Google/Apple/邮箱用于账户和设备身份，交易批准仍要绑定意图摘要、策略摘要、链快照和 signer。
- policy 文档必须不可变、可版本化、可散列、可重编译、可回放验证。
- 每个 FROST share 单独归属、单独备份、单独恢复，不能为了“方便”把 quorum share 集中。
- 索引器可以删库重建；签名权、审批记录、nonce 使用记录、策略激活记录不能靠重建补回来。
- OP_CAT 研究网络、实验性后量子脚本、未来 AMM 都要分层标注 `now`、`experimental`、`future activation`，避免对外叙述混淆。
- `proposal` 阶段和 `pre-sign` 阶段都要独立复核交易与 policy，不复用不透明缓存结论。

## 数据分级

| 等级 | 数据 | 例子 | 存储要求 | 备份要求 |
| --- | --- | --- | --- | --- |
| L0 可重建公开数据 | 区块、交易、可重算索引 | blocks、txs、utxos、index checkpoints | 独立 RocksDB，按区块批量写入 | 默认不进备份，仅保存 schema/version/checkpoint |
| L1 持久业务数据 | 聊天会话、工具事件、设置、资产视图、订单状态 | chat sessions、tool events、orders | SQLite 持久化，WAL | 加密快照可选 |
| L2 敏感控制数据 | 账户会话、Passkey 凭据元数据、policy 激活、广播记录 | auth sessions、credential summaries、policy docs | SQLite + envelope encryption 字段级加密 | 必须进备份 |
| L3 高敏密钥材料 | DEK、FROST share 封装、HSM handle、恢复包引用 | wrapped share、key handles | OS key store / HSM / PKCS#11 | 单独备份，分持有人保存 |
| L4 一次性安全状态 | FROST nonce claim、签名 challenge、审批 ceremony | nonce claims、approval ceremonies | 事务性持久化，崩溃后不得重用 | 备份恢复后立刻失效并轮换 epoch |

## 跨阶段固定的数据对象

### Policy 生命周期对象

每个 policy 都要从第一版开始就按以下对象建模：

- `policy_document`
  原始不可变文档，包含链配置、资产语义、参与者、阈值、批准要求、恢复要求、脚本依赖、实验标记。
- `policy_hash`
  对 canonical serialization 做哈希，作为 policy 身份。
- `policy_artifact`
  编译产物，例如 tapscript、taproot tree、typed template、解析器 schema、UI 片段、引用脚本。
- `policy_test_vector`
  正例、反例、边界例、费用与 witness 规模测量。
- `policy_binding`
  policy 与某钱包、某 signer set、某资产集合、某链 profile 的绑定记录。
- `policy_activation`
  某次激活审批，绑定审批人、时间、依赖条件、上一版本、回滚条件。

### 备份对象

- `backup_manifest`
  记录快照 id、schema version、policy hashes、wallet ids、signer epochs、生成时间、文件哈希。
- `backup_chunk`
  实际加密分片。
- `recovery_receipt`
  恢复演练结果，记录恢复环境、验证命令、恢复后 nonce epoch、失效的 ceremonies。

## 目录与模块演进建议

建议在不推翻现有目录的前提下演进为：

- `apps/catomicals-cli`
  保留开发入口、验收命令与兼容适配器。
- `crates/wallet-core`
  收敛成领域层：意图、审批绑定、policy 绑定、聊天协议、错误模型。
- `crates/wallet-storage`
  近期新增。负责 SQLite、迁移、WAL、事务、审计事件，以及首版本机 secret 封装。出现第二种独立消费方或 HSM provider 后，再从内部模块拆出 `wallet-secrets`。
- `crates/policy-registry`
  新增。负责 policy 文档、编译、测试向量、激活、绑定。
- `crates/node-gateway`
  后续目标。首版能力留在 `crates/node-client` 的 typed adapter；出现远程或多进程消费者后再提取，负责 allowlist RPC、node manager、广播、同步、rescan 与 ZMQ/poll。
- `crates/indexer`
  在最小节点访问稳定后新增。首版直接使用独立 RocksDB，负责查询投影和 reorg undo，不与钱包权威 SQLite 共用文件、writer、WAL 或备份事务。
- `schemas/agent`
  近期新增语言无关的 JSON Schema，负责 chat message part、tool event、review reference 与 generative UI 块。Rust 只消费钱包所需字段。
- `desktop/src/executors`
  近期新增 TypeScript 执行器注册表，负责 Codex、DeepSeek Harness、Claude Code 的进程、会话、模型与权限。
- `desktop/src/cordis`
  近期新增 TypeScript Cordis 宿主，负责固定插件的注册、配置 schema、权限、生命周期、迁移、健康检查和设置面板。
- `desktop`
  负责宿主与系统集成，不持有钱包、节点或索引真相。

## 分期路线（长期能力分组）

下列阶段号用于组织能力和验收边界，不作为机械的开工顺序。实际派工以“近期执行顺序”为准；尤其是 Electron/Cordis 执行器宿主会在完整 indexer 之前启动，但不能越过可信节点访问和 durable walletd 的安全前置条件。

### Phase 0：冻结现状与兼容层

目标：在现有地基上建立可演化边界，避免后面持久化和进程拆分时把接口打碎。

模块与文件：

- 保留 `crates/wallet-core/src/{api,intent,chat,gate,webauthn,node}.rs` 作为领域模型源头。
- 保留 `apps/catomicals-cli/src/{wallet,wallet_serve,mcp}.rs` 作为兼容入口。
- 新增 `docs/adr/`，至少补三份 ADR：
  `walletd-process-boundary.md`、`policy-object-model.md`、`node-gateway-trust-boundary.md`。

接口与表：

- 先冻结当前 `api/v1` 路由族，后续只增不改。
- 新建迁移元表设计：
  `schema_migrations(id, component, version, applied_at, checksum)`.
- 新建协议版本表设计：
  `protocol_compat(component, major, minor, status, min_supported, max_supported)`.

P0 阻断项：

- `desktop/src/main.ts` 当前允许任意 `--renderer-url`，生产态必须锁定可信 localhost origin，不接受任意命令行覆盖。
- IPC 不能只校验 `webContents.id`，还要校验 `senderFrame` origin 与 frame tree。
- `will-navigate`、窗口打开、redirect 之后的最终 URL 都要走 allowlist 复检。
- `web` 开发端口 `5173`、Electron 静态 `5180`、wallet CORS/WebAuthn origin 现在存在漂移，必须收敛到单一 origin 配置源。
- Electron renderer 的 wallet 敏感调用要回收到 main typed bridge；独立 Web 版仍可按现有 localhost HTTP + WebAuthn 合同运行，但必须使用单独的受信任部署配置。
- 浏览器私网拦截要在 DNS 解析后复检，redirect 后再次判定，不能只靠字符串检查 hostname。
- browser partition 生命周期要显式管理，关闭工具页后销毁会话态；需要保留时必须写清持久化策略。
- WebAuthn ceremony TTL、并发容量、过期清理、secret storage 都要形成硬上限和测试。

当前基线验收命令：

```sh
cargo test -p catomicals-wallet
cargo test -p catomicals wallet_serve::tests
cargo test -p catomicals mcp::tests
pnpm --dir desktop test
git diff --check
```

还必须新增并通过以下负向集成测试：

- 生产态拒绝任意远程 `--renderer-url`。
- 非可信 `senderFrame`、子 frame 和导航后的 frame 无法调用桌面 IPC。
- `5173`、`5180` 或后续端口只来自同一个运行时原点配置，钱包 CORS 与 WebAuthn RP origin 完全一致。
- 浏览器页经 DNS 重绑定或 redirect 指向 loopback、私网、`file:`、`devtools:` 时被拒绝。
- browser partition 按会话隔离，销毁后 cookies、storage 与 service worker 符合明确策略。

安全不变量：

- 当前 `api/v1` 公开语义不回退。
- 所有新增持久化设计都要兼容 `intent_digest`、`nonce_guard`、`approval binding` 现有约束。
- 在完成上述 P0 阻断项前，不继续推进生产态 Electron 集成。

不可声称内容：

- 不可声称已经有 durable wallet、恢复能力、节点管理、HSM 接入。

### Phase 1：可信链访问、walletd 进程化与 SQLite 持久化

目标：先消除调用方自报 prevout 和启动时一次性链快照的风险，再把 `wallet serve` 从“内存演示”推进成单机可恢复守护进程。持久 signer 不得早于可信链读侧。

模块与文件：

- 先扩展 `crates/node-client`，新增 typed `chain_snapshot`、`resolve_prevouts`、`test_mempool_accept`、`broadcast_transaction` 和 `transaction_status`；首版保留为 `walletd` 内部受控适配层，不先创建完整 node manager。
- 新增 `crates/wallet-storage/src/{lib.rs,sqlite.rs,migrations.rs,backup.rs}`。
- 新增 `crates/wallet-storage/migrations/*.sql`。
- 新增 `apps/catomicals-cli/src/walletd.rs`，保留 `wallet serve` 作为兼容命令别名。
- `crates/wallet-core/src/store.rs` 改成 trait + `sqlite` 实现分离，领域层不再持有 `HashMap`。
- `desktop/src/main.ts` 增加 walletd 子进程生命周期管理，窗口关闭与后台运行解耦。

核心表：

- `wallet_profiles`
- `signing_intents`
- `intent_events`
- `passkey_credentials`
- `approval_ceremonies`
- `signing_authorizations`
- `frost_nonce_claims`
- `frost_sessions`
- `broadcast_records`
- `node_snapshots`

迁移边界：

- 现有 `wallet serve` 保持开发兼容入口；只有显式提供 `--data-dir` 且完成迁移检查时，才进入 durable 模式。
- durable 模式拒绝调用方提供的 prevout 作为最终事实，必须由 node client 解析并绑定 `node_snapshot_id`。
- 兼容入口、durable 入口和数据库 schema 版本要分别出现在状态响应中，避免旧客户端误判能力。

事务与一致性：

- SQLite 开启 `WAL`。
- 每次 `create_intent`、`approval_start`、`approval_finish`、`signer_round1`、`signer_round2` 都落成 append-only event，再更新投影视图。
- `approval_finish` 与 `authorization` 写入必须同事务完成。
- `signer_round2` 之前必须先持久化 nonce claim；成功与失败都要记录。
- 崩溃恢复后，处于 `approval_started` 或 `round1_ready` 的短期 ceremony 一律标记失效，要求重新发起。
- `walletd` 是钱包权威库的单写者。Web、Electron、MCP、备份与恢复都通过同一服务排队，不直接打开权威数据库。
- 备份只能读取 SQLite 一致快照；恢复时停止新 intent 和 signing session，完成 schema、manifest 与 epoch 校验后原子切换。
- 最小审计字段从本阶段开始写入：`component_version`、`schema_version`、`wallet_id`、`intent_id`、`policy_hash`、`node_snapshot_id` 和 redacted actor reference。

备份与恢复状态合同：

| 状态 | `create_intent` | `approval_finish` / `round1` / `round2` | `backup_export` | restore |
| --- | --- | --- | --- | --- |
| `normal` | 允许 | 允许 | 允许，单任务 | 可进入 `restore_precheck` |
| `snapshotting` | 允许，写入序号高于快照边界 | 允许，写入序号高于快照边界 | 其余导出排队 | 拒绝 |
| `restore_precheck` | 拒绝 | 取消并拒绝；未完成 ceremony 失效 | 拒绝 | 校验 schema、manifest、备份单调性和 signer reference |
| `cutover` | 拒绝 | 拒绝 | 拒绝 | 原子替换数据库并递增 `recovery_epoch` |
| `recovering` | 拒绝 | 拒绝 | 拒绝 | 只开放恢复状态；重新建立节点快照、审计游标和 signer 可用性 |

回到 `normal` 前，旧 `node_snapshot_id`、旧 authorization、旧 nonce epoch 和所有未完成 ceremony 必须统一失效。任何 in-flight `approval_finish` 或 `round2` 都不能跨越 `restore_precheck` 边界。

存储安全：

- 先实现 envelope encryption：
  本地生成 `DEK`，由 `KEK` 包裹。
- `KEK` 来源优先级：
  Electron `safeStorage` 包裹的本机封装值；
  macOS Keychain；
  Windows DPAPI；
  Linux Secret Service；
  最后才允许 file-based dev fallback，并且仅限 `development profile`。

阶段交付物创建后必须通过：

```sh
cargo test -p catomicals-wallet
cargo test -p catomicals-wallet-storage
cargo run -p catomicals -- wallet serve --data-dir ./artifacts/dev-wallet
sqlite3 ./artifacts/dev-wallet/wallet.db "pragma journal_mode;"
```

端到端质量门：

- 节点返回的真实 prevout 与请求材料不一致时，proposal 和 pre-sign 都拒绝。
- 链头变化或 reorg 使 `node_snapshot_id` 过期时，已有 review 进入 `stale`，不能继续批准。
- 在 `approval_finish`、`round1_ready`、`round2`、backup、restore 各事务点注入崩溃，重启后无 nonce 重用、无隐式批准、无半恢复状态。
- restore cutover 期间，旧 `node_snapshot_id`、旧 authorization 和旧 nonce epoch 的请求全部被拒绝。
- secret、token、wrapped material 不进入日志、MCP 结果、聊天记录或明文 `settings.json`。

安全不变量：

- 重启后已经消费过的 intent nonce 不能再次批准。
- 重启后已经 claim 过的 FROST nonce fingerprint 不能再次用于新 session。
- 钱包数据落盘前必须先完成字段级加密或系统密钥封装。

不可声称内容：

- 不能声称已经分布式托管。
- 不能声称备份包足以恢复 quorum 签名，除非后续分签名者恢复链路也完成。

### Phase 2：账户身份、设置与交易批准隔离

目标：把“登录身份”“设备身份”“交易批准”拆清楚，避免账户体系侵入 signer 安全边界。

模块与文件：

- 新增 `desktop/src/auth-bridge.ts`。
- `web/src/lib/account.ts`、`desktop/src/settings-store.ts` 只保留账户入口，不直接管理交易批准。
- `wallet-core` 继续只认 `Passkey approval`、`policy activation approval`、`signer authorization`。
- 首版账户状态留在 desktop host 的独立命名空间，只建立最小 `wallet_identity_links`。当 OAuth、邮件服务或远程设备管理出现第二个独立消费方时，再提取 `crates/account-core` 或独立账户服务。

核心表：

- `account_identities`
- `auth_sessions`
- `device_registrations`
- `passkey_identities`
- `wallet_identity_links`
- `settings_documents`

接口族：

- `account.v1.begin_login`
- `account.v1.finish_login`
- `account.v1.list_devices`
- `account.v1.bind_wallet`
- `account.v1.logout_device`
- 现有 `/api/v1/webauthn/*` 保持钱包批准语义，不改成“通用登录 Passkey”。

边界规则：

- Google/Apple/邮箱只提供账户与设备身份。
- 钱包交易批准仍由 walletd 的本地 Passkey 或后续专业签名硬件完成。
- 账户登录成功不等于能批准交易。
- 一个账户可关联多个 wallet profile，一个 wallet profile 可拒绝任何云账户绑定。

设置与 secret：

- `desktop` 保存界面设置、执行器设置、最近节点配置。
- `walletd` 保存策略、签名、节点与广播状态。
- 敏感设置分成两类：
  `settings_documents` 保存非敏感字段；
  `secret_materials` 保存被包裹的 token、client secret、mail relay secret。

阶段交付物创建后必须通过：

```sh
pnpm --dir desktop test
pnpm --dir web test
```

安全不变量：

- OAuth token、邮件验证 secret 不得进入聊天消息、MCP tool result、browser tab URL。
- 钱包批准接口必须继续绑定 exact intent digest、session、message、expiry。

不可声称内容：

- 不能把 Google/Apple/邮箱登录宣传成链上签名能力。

### Phase 3：policy registry、编译制品与单钱包备份

目标：把 policy 与相关数据从代码中的隐含规则推进成可管理资产，并先完成不涉及 quorum 集中化的单钱包备份。分布式 signer 备份与恢复等 Phase 4 明确 signer ownership、epoch 与 reshare 后再实现。

模块与文件：

- 新增 `crates/policy-registry/src/{document.rs,artifact.rs,compile.rs,activation.rs,backup.rs}`。
- 把 `crates/issuance`、`crates/trading` 的模板编译输出纳入 `policy_artifact`。
- 新增 `docs/policies/`，保存规范示例、canonical serialization 说明、测试向量说明。

核心表：

- `policy_documents`
- `policy_artifacts`
- `policy_test_vectors`
- `policy_bindings`
- `policy_activations`
- `policy_wallet_requirements`
- `backup_manifests`
- `backup_chunks`
- `recovery_receipts`

policy 生命周期：

1. 草拟 `policy_document`。
2. canonical serialize，生成 `policy_hash`。
3. 编译 `policy_artifacts`。
4. 生成 `policy_test_vectors`。
5. 绑定 wallet、signer set、network profile。
6. 发起 `policy_activation`。
7. 批准后进入 `active`。
8. 新版本只能追加，不可覆盖旧版本。

备份策略：

- 备份内容必须包含：
  policy docs、artifacts、test vectors、wallet bindings、credential metadata、broadcast records、intent/event history，以及不可导出 signer 的引用元数据。
- 备份内容默认不含：
  blocks、txs、utxos、derived index tables。
- 本阶段禁止把多个 FROST share 或足以组成 quorum 的恢复材料放进同一备份包。
- 备份包采用：
  `manifest.json + encrypted chunks + file hash list + schema versions`.
- 恢复后必须：
  使所有未完成 approval ceremony 与 signing ceremony 失效；
  使备份前的 nonce/challenge 一律不可再用；
  标记 signer 恢复为未完成，直到 Phase 4 的逐 signer 恢复或 reshare 流程通过。

单钱包恢复演练：

- 恢复演练至少覆盖：
  单机恢复、换机恢复、缺少 signer material 时保持只读、过期备份恢复拒绝。
- 恢复演练结果写入 `recovery_receipts`。

阶段交付物创建后必须通过：

```sh
cargo test -p catomicals-policy-registry
cargo run -p catomicals -- policy compile ./docs/policies/examples/issuance-v1.json
cargo run -p catomicals -- backup export --wallet default --out ./artifacts/backups/dev
cargo run -p catomicals -- backup verify ./artifacts/backups/dev/manifest.json
```

安全不变量：

- policy hash 变了就视作新版本。
- wallet 只能激活通过 test vector 验证的 policy artifact。
- 恢复后所有旧 nonce、old session、unfinished ceremony 都自动作废。

不可声称内容：

- 不能声称本阶段的单钱包备份能恢复整个 quorum。
- 不能声称恢复后未确认交易仍安全延续原会话。

### Phase 4：FROST 传输、硬件接口与恢复链路

目标：把当前单进程 FROST 演示推进成“多参与者、可传输、可恢复”的签名设施。

模块与文件：

- 新增 `crates/signer-transport/src/{broadcast.rs,p2p.rs,session.rs}`。
- 新增 `crates/hsm-provider/src/{pkcs11.rs,soft_hsm.rs,yubikey.rs}`。
- 扩展 `crates/threshold-signer/src/{dkg,participant,session,nonce_guard}.rs`。
- 新增 `docs/security/frost-transport.md`、`docs/security/recovery-runbook.md`。

核心表：

- `signer_participants`
- `signer_epochs`
- `signer_transport_peers`
- `frost_round1_packages`
- `frost_round2_receipts`
- `wrapped_signer_shares`
- `hsm_key_handles`
- `reshare_events`

实施要点：

- round 1 走 authenticated consistent broadcast。
- round 2 走 confidential authenticated point-to-point。
- 签名授权必须绑定：
  intent digest、policy hash、chain snapshot id、signer id、session id、message digest、expiry。
- HSM 接口先实现抽象，不急着支持所有厂商。
- 恢复链路必须支持 `reshare`，而不是重新集中生成 secret。

备份与恢复：

- 每个 signer 保存自己的 wrapped share、设备元数据、epoch、恢复指引。
- quorum 中任何单点都不能收集足够 share 组合。
- 恢复或 reshare 完成后，旧 epoch nonce 池全部废弃。

阶段交付物创建后必须通过：

```sh
cargo test -p catomicals-threshold
cargo test -p catomicals-threshold --test distributed_signing
cargo run -p catomicals -- frost demo
cargo run -p catomicals -- frost reshare --profile dev-2of3
```

安全不变量：

- 同一 nonce fingerprint 不得跨 epoch、跨 session 复用。
- 任一 signer 拒绝请求时，协调器不能代签。
- HSM provider 只暴露签名与封装接口，不回传可导出私钥。

不可声称内容：

- 不能声称已有生产级 HSM 适配，除非实测设备矩阵完成。
- 不能声称 passkey 已直接承担比特币签名，它只是批准层能力。

### Phase 5：最小 typed gateway 与可重建索引层

目标：让链状态读取、广播、重扫、运行节点和索引查询有独立可信边界。

### Phase 5A：最小 typed gateway

模块与文件：

- 扩展 `crates/node-client`，新增 `health`、`chain_snapshot`、`resolve_prevouts`、`test_mempool_accept`、`broadcast_transaction`、`transaction_status`。
- 先作为 `walletd` 内部 allowlist adapter；出现远程或多进程消费者后，再提取 `crates/node-gateway`。
- `desktop` 只增加一个外部全节点 profile 与健康状态，节点真相继续留在 `walletd`。

绝对边界：

- 不允许把 Bitcoin RPC 原样反代给 UI、MCP、执行器或浏览器。
- gateway 只开放 allowlist：
  `get_chain_status`、`resolve_prevouts`、`test_mempool_accept`、`broadcast_tx`、`transaction_status`、`get_deployment_status`。

最小持久字段：

- `node_profile_id`、`source_node_id`、network、deployment state、tip hash、tip height、snapshot time。
- prevout evidence、mempool result、broadcast attempt 与 transaction observation 都绑定 `node_snapshot_id`。

### Phase 5B：首个 indexer 纵向切片

模块与文件：

- 新增 `crates/indexer/src/{db.rs,blocks.rs,transactions.rs,utxos.rs,transitions.rs,reorg.rs}`。
- 只实现区块连接/断开、交易、UTXO、一个 covenant transition 投影、undo 与 checkpoint。

首批 column family / keyspace：

- `indexer_checkpoints`
- `index_chain_heads`
- `index_blocks`
- `index_transactions`
- `index_utxos`
- `index_covenant_transitions`
- `index_reorg_undo`

存储边界：

- indexer 首版直接使用独立 RocksDB，不经过 SQLite 过渡；按 blocks、transactions、utxos、transitions、undo、metadata 划分 column family。
- 单个区块使用 `WriteBatch` 原子写入 undo、投影与 checkpoint；RocksDB WAL、snapshot 和 checkpoint 只服务 indexer 自身。
- indexer 不和 `walletd` 权威 SQLite 共用文件、writer、WAL 或备份事务。
- 每条派生记录至少带 `source_node_id`、`block_hash`、`block_height`、`txid`、输入或输出位置、`checkpoint_hash`、`scan_cursor`、`verifier_version` 和 confirmation state。
- mempool 投影与 confirmed 投影分开保存；交易离开 mempool 不得改写 confirmed 历史。
- 每个 block apply batch 先写 undo，再提交投影与 checkpoint；断链时按高度倒序回放 undo。

首批查询域：

- 链头、区块、区块内交易、交易输入输出。
- UTXO 的 spent/unspent 转移。
- 单一 covenant transition 类型。
- reorg undo、checkpoint 与重建进度。

后续扩展：

- 节点模式再扩为 managed Inquisition dev node、external full node、remote authenticated gateway。
- gateway 再增加 rescan、watch outpoints、fee estimation 和进程管理。
- indexer 再增加 mempool candidate/conflict、assets、mints、orders、fills 和 creator metadata。
- 每项扩展都要由真实产品查询或运维需求触发，不先创建空表。

reorg 与查询规则：

- 每个索引投影都要有 undo 或 checkpoint 回滚能力。
- indexer 只做查询与可用性，不做 ownership/settlement truth。
- 签名前的最终校验必须重新走 `walletd + node snapshot + policy verifier`。
- proposal 阶段可以读 indexer 辅助构造，pre-sign 阶段必须再次走 node snapshot 与 shared verifier 独立复核。
- `review_snapshot` 绑定 `node_snapshot_id` 或 `checkpoint_hash`；链头回退越过该点后立即标记 `stale`。

阶段交付物创建后必须通过：

```sh
cargo test -p catomicals-node-client
cargo test -p catomicals-indexer
cargo run -p catomicals -- node health
```

安全不变量：

- 所有广播前校验必须绑定明确的 chain checkpoint。
- gateway cookie auth、loopback、TLS、deployment check 全部通过后才进入 ready。
- 索引器数据库损坏不应影响签名与真实余额判定。

不可声称内容：

- 不能把 indexer 返回值直接宣传成链上结算依据。
- 不能把 Inquisition 的行为宣传成 Bitcoin 主网能力已存在。

### Phase 6：执行器 registry、聊天协议与生成式界面

目标：让 Codex、DeepSeek Harness、Claude Code 通过统一协议接入，而不是每个前端组件各说各话。

模块与文件：

- 新增 `desktop/src/executors/{registry,codex,deepseek,claude-code,session-store}.ts`，在 Electron main 管理进程、会话、模型与能力发现。
- 新增 `desktop/src/cordis/{host,manifest,permissions,migrations,health,settings}.ts`，使用 TypeScript Cordis 运行时承载固定插件。
- 新增 `schemas/agent/{chat-message,tool-event,ui-block,review-reference}.schema.json`，作为 desktop、web 与 Rust wallet-facing 类型的共同协议源。
- Rust 侧保留现有 `apps/catomicals-cli/src/mcp.rs` 和钱包 review/intent 合同，不创建重复的执行器或 Cordis registry。
- `desktop/src/ipc.ts`、`desktop/src/contracts.ts` 升级成稳定壳层。
- `web/src/lib/{harness,settings,workbench}.ts` 对接统一协议。

执行器对象：

- `executor_provider`
  codex、deepseek、claude-code。
- `executor_profile`
  命令、工作目录、模型默认值、推理等级、MCP 开关、权限域。
- `executor_session`
  会话元数据、thread/session id、运行状态、最近错误、能力列表。

统一 MCP 工具合同：

- Codex、DeepSeek Harness、Claude Code 共用同一份 Catomicals MCP tool schema。
- 工具名、参数 schema、错误码、secret redaction 规则由 `schemas/agent` 统一定义，desktop、web 与 Rust 各自生成或消费所需类型。
- 执行器适配层只负责启动、会话、流式事件和错误映射，不复制钱包业务逻辑。
- 现有 9 个工具作为 `v1` 基线，后续新增只走显式版本升级。
- 每个持久工具调用至少记录：`transport`、`protocol_version`、`tool_call_id`、`tool_name`、`schema_version`、`permission_scope`、`executor_session_id`、可选 `plugin_id/plugin_version`、`intent_id/review_id`、请求摘要、结果摘要和 redaction version。
- 本地 Codex 与 Claude Code 直接使用同一 stdio MCP；DeepSeek Harness 优先通过外部 MCP client bridge 使用相同 schema。可选 Catomicals Cordis bundle 只负责 DSH 内的装配与 UI surface。

聊天与工具协议对象：

- `chat_sessions`
- `chat_messages`
- `message_parts`
- `tool_invocations`
- `tool_results`
- `ui_blocks`
- `approval_cards`
- `review_snapshots`

Cordis 插件对象：

- `plugin_manifests`
- `plugin_installations`
- `plugin_settings`
- `plugin_permissions`
- `plugin_health_checks`
- `plugin_migrations`
- `plugin_ui_surfaces`

首批固定插件：

- `@catomicals/plugin-walletd`：钱包节点地址、进程模式、健康与日志。
- `@catomicals/plugin-bitcoin-node`：Inquisition、外部全节点、远程 gateway profile。
- `@catomicals/plugin-indexer`：数据库、scan cursor、checkpoint、重建与查询 API。
- `@catomicals/plugin-mcp`：本地 stdio/远程 HTTP、scope、执行器绑定。
- `@catomicals/plugin-executor-codex`、`plugin-executor-deepseek`、`plugin-executor-claude-code`：命令、模型、推理等级、工作目录与会话能力。
- `@catomicals/plugin-backup`：单钱包备份位置、计划、保留策略与恢复演练入口。
- `@catomicals/plugin-browser`：主页、会话隔离、下载与私网访问策略。

设置页不再维护一张全局硬编码表。每个固定插件贡献自己的 settings schema、默认值、secret reference 字段、校验器、健康检查和设置 UI surface；宿主只提供统一目录、搜索、保存、回滚与权限提示。

最小插件 manifest：

- `plugin_id`、`plugin_version`、`runtime_api`、`publisher`、`package_digest`、`signature`。
- `host_entry`、`client_entry`、`bundle_patch`。
- required/optional `inject`、`permission_scopes`、`settings_namespace`、`settings_schema_version`。
- `ui_surfaces`、`health_service`、`migration_namespace`、`current_migration`。

Cordis 实施约束：

- 采用固定、签名、allowlist 化的插件包，不采用 agent 现场定义任意插件代码。
- profile manifest 以 `dsh.profile.bundles` 为基础输入。
- 配置补丁通过受控 `cordis.patch.yml` 与 home/CLI overlays 生效。
- patch 按 id 替换整行配置，不依赖深合并语义。
- `Service + inject` 控制依赖生命周期，服务消失时依赖要自动卸载。
- 工具注册按 `ctx.tools.register` 模型管理，插件卸载时 disposer 必须回收。
- 动态 cordis sandbox 只当开发便捷层，不当安全边界；默认不向钱包代理开放。
- 远程 HTTP MCP 只在 OAuth 资源绑定明确后启用；本地 stdio MCP 继续维持进程环境凭据边界。
- 插件配置更新先在隔离 profile 中解析、迁移并健康检查；失败时保留 last-good tree，不能把半更新状态写进 walletd。

代理代配置的 MCP 工具：

- `list_plugins`、`read_plugin_manifest`、`read_plugin_settings_schema`、`read_plugin_health`：只读。
- `validate_plugin_settings_patch`：只校验，不写入。
- `create_plugin_settings_intent`：创建待确认的配置意图，绑定 `plugin_id`、`plugin_version`、旧配置摘要、新配置摘要、permission delta 与 restart impact。
- 不向执行器开放直接的 `apply_plugin_settings`、任意包安装、任意脚本执行或动态 `cordis_run`。
- 用户确认配置卡后，由 desktop host 重新读取当前版本与 secret reference，重新校验 patch，写入候选配置并做健康检查；成功才提升为 last-good，失败则回滚。
- API key、OAuth token、cookie、FROST/HSM material 不进入 MCP 参数或结果；代理只能引用由宿主创建的 opaque secret reference。

协议原则：

- 文本消息、工具事件、确认卡片、图表块全部拆成 typed part。
- UI 块由受控 schema 描述，例如审批卡、交易摘要卡、策略差异卡、费用图表卡。
- 任意执行器都不能直接“渲染可执行代码”进右侧面板。
- 工具结果只能引用 `intent_id`、`review_id`、`policy_hash`、`snapshot_id`，实际金额、输出、摘要再次从 walletd 拉取并复核。
- Cordis 插件只注册能力、设置面板和 UI surface，钱包动作仍回到 walletd 或统一 MCP 合同。
- 禁止 agent 直接调用任意 `cordis_define`、`cordis_run` 式动态代码入口触达钱包能力。

模型与权限：

- 每个执行器会话记录 provider、model、reasoning effort、MCP capability、workspace capability。
- `mcpEnabled=false` 时，执行器只能聊天，不能触达钱包工具。
- 钱包写操作全部走人类确认卡 + walletd 二次验证。
- identity login 成功后可开启插件、同步设置和设备会话，不能直接授权交易或激活 signer。

阶段交付物创建后必须通过：

```sh
pnpm --dir desktop test
pnpm --dir web test
pnpm --dir desktop build:electron
cargo test -p catomicals mcp::tests
```

安全不变量：

- 执行器适配器崩溃不会生成隐式批准。
- UI 卡片里的金额、地址、输出摘要不以执行器生成文本为准。
- 执行器 session secret 不得写进聊天 transcript 明文列。
- 插件迁移失败时只能回退插件本地状态，不能污染 walletd 主数据库。

不可声称内容：

- 不能声称任一模型或执行器“可信到可代替批准流程”。

### Phase 7：发行、订单撮合、防抢跑与未来 AMM 实验接口

目标：在已经稳定的钱包、安全、节点与执行器地基上扩展产品协议层。

模块与文件：

- 扩展 `crates/issuance` 为模板注册源。
- 扩展 `crates/trading` 为 order protocol 源。
- 新增 `crates/market-protocol/src/{orders.rs,matching.rs,conflicts.rs,amm.rs}`。
- 新增 `docs/plans/market-*` 系列，分别记录 minting、orderbook、防抢跑、AMM 实验。

第一批产品接口：

- `issuance.v1.create_policy`
- `issuance.v1.preview_mint`
- `issuance.v1.submit_mint_intent`
- `orders.v1.create_listing`
- `orders.v1.submit_buy_candidate`
- `orders.v1.submit_cancel_candidate`
- `orders.v1.read_conflicts`
- `orders.v1.match_broker_quote`

第二批实验接口：

- `assets.v1.register_creator_terms`
- `assets.v1.transfer_receipt`
- `amm.experimental.quote`
- `amm.experimental.simulate_pool`

研究边界：

- orderbook 防抢跑是近期主线，直接利用当前 `trading` 的 exact transaction verification。
- minting/发行继续以 wallet-verifiable covenant asset 为主，不回到虚拟 UTXO 映射式设计。
- AMM 只先做接口、仿真、费用与 witness 基准，不承诺上线。

索引配合：

- `index_orders`、`index_fills`、`index_conflicts` 提供市场读侧。
- creator 相关元数据属于附加层，不得影响链上结算判断。

阶段交付物创建后必须通过：

```sh
cargo test -p catomicals-issuance
cargo test -p catomicals-trading
scripts/verify-issuance-inquisition.sh
scripts/verify-trading-inquisition.sh
```

安全不变量：

- 任何市场候选单最终都要回到 exact unsigned tx + prevouts + policy verifier。
- broker 可以承担撮合，不能替 walletd 篡改结算依据。

不可声称内容：

- 不能声称 OP_CAT 已经天然支持通用 AMM。
- 不能声称当前市场协议已经摆脱矿工排序与链上竞争。

### Phase 8：可观测性、威胁模型、后量子实验与发布闸门

目标：补齐长期运行所需的证据系统和实验分层。

模块与文件：

- 新增 `docs/security/threat-model.md`
- 新增 `docs/security/backup-matrix.md`
- 新增 `docs/security/pq-roadmap.md`
- 新增 `crates/observability/src/{metrics.rs,audit.rs,redaction.rs}`

日志与审计：

- 审计事件至少覆盖：
  login、wallet bind、policy activation、approval start/finish、nonce claim、sign round1/2、broadcast、rescan、restore、reshare。
- 敏感字段默认 redaction。
- 每条审计事件带 `component_version`、`schema_version`、`policy_hash`、`wallet_id`、`signer_epoch`。

后量子路线分层：

- `now`
  Bitcoin spend path 仍是 BIP340/FROST。
- `experimental`
  crypto agility：algorithm id、key version、hybrid PQ 保护备份与策略制品。
- `future activation`
  OP_CAT + 哈希型签名验证脚本实验，例如 Lamport、WOTS、可能的 SLH-DSA 成本测量；仅在 Inquisition 或研究网络验证。

实验输出：

- witness 大小、script 大小、费用、rotation 周期、恢复复杂度、签名时延。
- 与当时的 Bitcoin PQ BIP 提案对齐记录。

阶段交付物创建后必须通过：

```sh
cargo test --workspace
cargo run -p catomicals-issuance --example measure_models
cargo run -p catomicals -- security benchmark-pq --network inquisition-signet
```

安全不变量：

- 不把实验性 PQ 脚本宣传成主网可用。
- algorithm id 与 key version 升级必须显式记录迁移路径。

不可声称内容：

- 不能声称 Catomicals 已具备主网后量子花费路径。

## API 族收束建议

建议最终形成六层 API：

1. `walletd internal rpc`
   供 desktop host、本机 BFF、CLI 使用。优先 Unix socket 或 loopback。
2. `typed local http`
   兼容现有 `api/v1`，服务 web UI 与本机工具。
3. `mcp tools`
   只暴露受控读写能力，不暴露签名和广播捷径。
4. `node gateway`
   只暴露 allowlist 化链接口，不暴露原始 Bitcoin RPC。
5. `cordis plugin api`
   只暴露插件 manifest、permissions、settings surface、health，真正的钱包动作仍回到 `walletd` 和统一 MCP 合同。
6. `executor session api`
   只暴露执行器注册、模型选择、推理等级、会话生命周期和事件订阅。

兼容矩阵：

| 协议面 | 当前入口 | 新入口 | 兼容规则 |
| --- | --- | --- | --- |
| 钱包 HTTP | `/api/v1/*` | 同族增量端点 | `v1` 只增不改；破坏性变更新开 major |
| 钱包进程 | `catomicals wallet serve` | durable mode 仍由 `wallet serve --data-dir` 启动；后续可增加 `walletd` 别名 | 状态响应必须给出 `runtime_mode`、schema version 与 capabilities；别名稳定两个发布周期后再讨论迁移 |
| 本地 MCP | 当前 9 个工具名 | `catomicals.wallet.v1.*` 逻辑命名空间 | 现有名称保留为 `v1` wire name；schema digest 与 permission scope 单独版本化 |
| 账户 | 当前仅前端占位 | desktop-internal `account.v1.*` | 不进入钱包批准 API，不在首版新增 Rust CLI 顶层命令 |
| 发行与订单 | 当前 Rust verifier / HTTP trade intent | 后续 `issuance.v1.*`、`orders.v1.*` | 先作为 MCP/typed HTTP schema；落地前必须写现有 verifier 到新协议的映射测试 |
| Cordis 配置 | 当前不存在 | desktop host plugin API | 从 `runtime_api=1` 起步；plugin、settings、migration 各自有版本 |

所有新 CLI 子命令、workspace member 和 schema 文件都属于对应阶段的交付物。提交阶段实现时，必须在同一变更中加入入口、帮助文本、迁移说明和验收测试；路线图中的命令不能作为当前能力执行。

短期不做的事：

- 不让浏览器页直接打 Bitcoin RPC。
- 不让 MCP 直接发 `approve`、`round2`、`broadcast`。
- 不让任意执行器通过 prompt 拼接取代 policy verifier。

## 依赖图

```text
desktop host
  -> desktop/src/executors
  -> desktop/src/cordis
  -> schemas/agent
  -> local typed http / ipc bridge
  -> walletd

walletd
  -> wallet-core
  -> wallet-storage (including first-version secrets module)
  -> policy-registry
  -> threshold-signer
  -> node-client / minimal typed gateway

minimal typed gateway
  -> external full node
  -> later managed node / remote authenticated gateway

indexer
  -> minimal typed gateway
  -> wallet policy classifiers

issuance / trading / market-protocol
  -> policy-registry
  -> walletd exact verifier

MCP / chat / generative UI
  -> desktop/src/executors
  -> schemas/agent
  -> walletd read/intent endpoints

Cordis plugins
  -> desktop/src/cordis
  -> desktop/src/executors
  -> schemas/agent
  -> walletd via unified MCP contract
```

## 里程碑建议

| 里程碑 | 完成标志 | 依赖 |
| --- | --- | --- |
| M1 Durable walletd | 重启不丢意图、凭据元数据、已完成授权和 nonce claim；未完成 ceremony 自动失效 | Phase 1 |
| M2 Identity split | 账户登录与交易批准彻底分层 | Phase 2 |
| M3 Policy as asset | policy 文档、编译产物、激活、备份导出全部成型 | Phase 3 |
| M4 Distributed signing | 多参与者 FROST 传输、reshare、恢复演练通过 | Phase 4 |
| M5 Trusted chain plane | 最小 typed gateway 与首个 indexer 纵向切片可用；更多节点模式按需求扩展 | Phase 5 |
| M6 Agent-native shell | Codex/DeepSeek/Claude 统一接入，确认卡与工具事件稳定 | Phase 6 |
| M7 Product protocols | 发行、订单、防抢跑形成可演示产品链路 | Phase 7 |
| M8 Release gate | 威胁模型、恢复演练、PQ 分层、审计日志齐备 | Phase 8 |

## DSH / Codex 子代理分工矩阵

| 工作流 | 适合 DSH 的范围 | 适合 Codex 子代理的范围 | 输入合同 | 验收命令 | 集成责任 |
| --- | --- | --- | --- | --- | --- |
| Electron 与 web 壳层 | `desktop/src/*`、`web/src/*` 中限定路径的独立界面与交互实现 | IPC 边界、安全审计、跨模块收口 | `contracts.ts`、IPC channels、UI schema | `pnpm --dir desktop test` `pnpm --dir web test` | Codex 负责最终边界核对 |
| 执行器适配 | 单个 provider 适配器 wiring，例如 `codex`、`deepseek`、`claude-code` | TypeScript registry、会话协议、权限模型 | `executor_session` schema、错误码、capabilities | `pnpm --dir desktop test` | Codex 负责 registry 收口 |
| MCP 工具面 | 工具结果展示、确认卡渲染、局部前端交互 | tool schema、wallet 权限模型、版本策略 | 统一 9 工具基线 schema | `cargo test -p catomicals -- mcp` | Codex 负责安全边界 |
| Cordis 插件 | 设置面板、插件 UI surface、插件管理视图 | TypeScript host、manifest schema、permissions、migration、health contract | `plugin_manifest`、settings schema、health schema | `pnpm --dir desktop test` | Codex 负责运行时与迁移 |
| 持久化与 secrets | 不建议单独承接 | SQLite、WAL、迁移、envelope encryption、恢复设计 | DB schema、encryption contract、backup manifest | `cargo test -p catomicals-wallet-storage` | Codex 负责主导 |
| FROST 与 HSM | 不建议单独承接 | 传输、reshare、nonce epoch、HSM provider 接口 | signing auth contract、epoch contract、recovery contract | `cargo test -p catomicals-threshold` | Codex 负责主导 |
| node gateway / indexer | dashboard、调试页、状态面板 | typed node adapter、indexer、reorg undo；远程消费者出现后再提取 gateway | chain snapshot schema、checkpoint schema、reorg undo schema | `cargo test -p catomicals-node-client` `cargo test -p catomicals-indexer` | Codex 负责主导 |
| 发行/订单协议 | 可视化、图表、演示页 | policy artifact、verifier、撮合、防抢跑、实验接口 | `policy_hash`、trade request schema、review snapshot schema | `cargo test -p catomicals-issuance` `cargo test -p catomicals-trading` | Codex 负责主导 |

质量门：

- DSH 只接限定路径、限定输入合同、低耦合实现任务。
- Codex 子代理负责架构、安全、协议、数据库、跨模块整合和最终收口。
- 任何 DSH 产出合并前，都要经过对应 Codex 子代理的合同核对与安全审计。

## 首批派工顺序

| 批次 | 任务与文件所有权 | 执行方 | 前置输入 | 完成判据 |
| --- | --- | --- | --- | --- |
| B0 | `docs/adr/*`、`schemas/agent/*` 的边界与版本合同 | Codex 架构子代理 | 当前 9 个 MCP 工具、Electron IPC、wallet API | ADR 通过安全与合同审查；schema 可生成 TS/Rust 类型 |
| B1 | `desktop/src/main.ts`、`preload.ts`、`ipc.ts` 的可信原点、frame 校验、浏览器隔离 | Codex 安全子代理 | B0 IPC 合同 | P0 负向测试全部通过 |
| B2 | `crates/node-client` 的 snapshot、prevout、mempool 预检与广播前复核 | Codex Rust 子代理 | node gateway ADR | 真实节点集成测试证明错误 prevout 与 stale snapshot 被拒绝 |
| B3 | `crates/wallet-storage`、`wallet-core` store trait、`walletd` durable mode | Codex Rust 子代理 | B2 typed node access | crash/restart/race 矩阵通过，单写者与 secret redaction 生效 |
| B4 | `desktop/src/executors/*` 中 Codex、DSH、Claude Code 单 provider 适配 | DSH 分三个限定路径任务 | B0 executor schema、B1 安全 IPC | 各 provider 能 probe、建会话、发消息、取消、恢复；不能越权调用钱包批准 |
| B5 | `desktop/src/cordis/*` 宿主、manifest、权限、迁移与 last-good tree | Codex TypeScript 子代理 | B0 plugin schema、DSH Cordis 参考 | 固定签名插件可加载；坏 patch 与坏迁移不会污染 walletd |
| B6 | Cordis 设置面板、插件 UI surface、执行器模型选择与确认卡 | DSH 限定 `web/src/*` 和 client half | B4/B5 稳定合同 | desktop/web 测试通过，UI 只提交引用 id，不提交可执行金额真相 |
| B7 | `crates/indexer` 纵向切片：block、tx、UTXO、transition、undo、checkpoint | Codex Rust 子代理 | B2 链事件与 B3 存储规范 | 重建结果一致，深浅 reorg 可回滚，独立数据库不阻塞 walletd |
| B8 | indexer 查询页、资产/订单调试页与状态图表 | DSH 限定前端任务 | B7 查询 API | 落后、stale、reorg 和不可用状态均能如实显示 |

开工前基线：

| 批次 | 当前仓库先跑的基线 | 本批新增的主要输出 |
| --- | --- | --- |
| B0 | `cargo test --workspace`、`pnpm --dir desktop test`、`pnpm --dir web test` | ADR 与 `schemas/agent/*` |
| B1 | `pnpm --dir desktop test`、`pnpm --dir desktop build:electron`、`cargo test -p catomicals-wallet --test webauthn_ceremonies` | Electron 负向安全测试与可信 IPC |
| B2 | `cargo test -p catomicals-node-client`、`cargo run -p catomicals -- node health` | `node-client` typed adapter 与真实节点集成测试 |
| B3 | `cargo test -p catomicals-wallet`、`cargo test -p catomicals wallet_serve::tests` | `wallet-storage`、durable mode、crash/restart/race 测试 |
| B4 | `pnpm --dir desktop test` | 三个 `desktop/src/executors/*` provider 适配与会话测试 |
| B5 | `pnpm --dir desktop test` | `desktop/src/cordis/*`、manifest、迁移与 last-good 测试 |
| B6 | `pnpm --dir web test`、`cargo test -p catomicals mcp::tests` | 插件设置面、模型选择、确认卡与配置意图流程 |
| B7 | `cargo test -p catomicals-issuance`、`cargo test -p catomicals-node-client` | `crates/indexer` 首切片、独立数据库、reorg/rebuild 测试 |
| B8 | `pnpm --dir web test` | indexer 查询页、状态图表与 stale/reorg 交互测试 |

派工规则：

- DSH 任务必须冻结 `allowedPaths`、只读路径、禁止路径、输入 schema 与验收命令；一次任务只拥有一个独立面。
- Codex 子代理可以承担 Rust、数据库、安全和跨模块合同，但每个子代理仍要声明文件所有权，避免并行覆盖。
- 主代理只负责依赖编排、合同合并、回归验证和最终提交，不把未审计的并行产物直接合入。

## 每个阶段都要保留的禁区

- 不删除现有 Signet/Inquisition 安全提示。
- 不把内存演示代码包装成生产能力。
- 不把索引器、执行器、浏览器页抬成结算依据。
- 不把账户登录等同于签名权。
- 不把单机备份等同于 quorum 恢复。
- 不把后量子研究脚本等同于 Bitcoin 已采纳能力。
