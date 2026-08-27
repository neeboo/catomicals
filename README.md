# catomicals

`catomicals` 是项目内部工程代号，来自 **CAT + Atomicals** 的文字梗。名称本身没有协议含义。

项目研究并实现由 `OP_CAT` 开启的 Bitcoin 原生 covenant 产品能力，当前范围包括：

- 可验证的资产定义、铸造与状态迁移；
- 防止卖方报价被替换的原生订单市场；
- 创作者发行、交易与后续演化；
- covenant 钱包、签名策略和自主部署设施；
- 对原生流动性池与 AMM 可行性的独立验证。

项目不因这个代号沿用 Atomicals、CAT Protocol 或 CAT20 的协议设计，也不预设发行平台代币。

当前开发网络以 Bitcoin Inquisition 的 `OP_CAT` 环境为准。

## 当前基础

- `cargo run -p catomicals -- node health`：通过 cookie 认证检查本机 Inquisition Signet，并要求 `getdeploymentinfo` 中 BIP 347 / `OP_CAT` 已激活。
- `cargo run -p catomicals -- frost demo`：生成并验证 2-of-3 的 64 字节 BIP340 聚合签名，仅供开发验证。
- `cargo run -p catomicals -- wallet serve`：在 `http://localhost:18787` 运行自托管 WebAuthn RP 和单个 FROST 参与者，提供真实 Passkey 注册、审批与类型化意图接口。
- `cargo run -p catomicals -- mcp serve`：通过标准输入输出运行本地 MCP 服务，连接同一个钱包节点，供 Codex、DeepSeek 等代理读取状态、检查交易、创建待签意图和核验受保护交易；不提供 Passkey 批准、FROST 签名份额或广播。
- `web/`：React + Vite + TanStack Router/Query 的单色（黑白 Codex 风格）钱包界面，只展示钱包节点 API 的真实状态，并实现浏览器内 Passkey 注册与审批。`/transactions` 解码完整未签名交易，核对有序前序输出、金额、手续费、RBF 和输出脚本，并由钱包计算 BIP341 摘要后创建待签意图。`/chat` 保存聊天消息并引导用户进入真实 Passkey 审批；聊天本身没有批准或签名通道。本地启动：`cd web && pnpm install && pnpm run dev`。
- `crates/issuance/`：可执行的 `OP_CAT` 工作量证明铸造门。共识脚本只校验当前状态的工作量证明和剩余量非零；物品所有者输出与后继状态由钱包验证，不属于仅靠 `OP_CAT` 就能强制执行的规则。
- `crates/trading/`：Signet 固定价交易。挂牌把已验证的物品收据转入带买入和到期撤单叶子的 Taproot 输出；钱包与代理分别解析原始交易，核对卖方收款、固定创作者费用、买方所有权证明、物品金额、到期高度和手续费，再生成签名摘要。
- `scripts/verify-issuance-inquisition.sh`：使用 Bitcoin Inquisition `bitcoin-util evalscript`，在 `TAPROOT`、`MINIMALDATA`、`CLEANSTACK` 和 `OP_CAT` 标志下运行有效、零随机数及对抗向量。
- `scripts/verify-trading-inquisition.sh`：把完整交易和前序输出交给 Bitcoin Inquisition 执行买入与撤单脚本，并验证复制签名后修改卖方收款、创作者费用或买方收件地址都会失败。
- `scripts/install-bitcoin-inquisition.sh`：下载官方 `v29.4-inq`，按官方 `SHA256SUMS` 校验并安装，但不会启动节点或同步区块。
- `config/bitcoin-signet.conf`：只监听本机 RPC 的 Signet 示例配置。

发行协议的编码、证据和安全边界见 [docs/plans/2026-08-27-covenant-pow-issuance.md](docs/plans/2026-08-27-covenant-pow-issuance.md)，固定价交易设计见 [docs/plans/2026-08-27-protected-fixed-price-trading-design.md](docs/plans/2026-08-27-protected-fixed-price-trading-design.md)。钱包节点接口、浏览器仪式与部署限制见 [docs/wallet-node.md](docs/wallet-node.md)，MCP 接入方式和工具边界见 [docs/mcp.md](docs/mcp.md)，Web 钱包界面与界面、代理能力对等关系见 [docs/web-wallet.md](docs/web-wallet.md)。安全边界和未完成项见 [docs/security.md](docs/security.md)，组件关系见 [docs/architecture.md](docs/architecture.md)。当前代码未经独立安全审计，所有凭据、重放状态和密钥均只在进程内存中，严禁用于主网或承载真实价值。
