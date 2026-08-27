# Policy registry v1

本目录记录首个可执行 policy registry 合同。当前只支持两种协议输入：

- `catomicals-issuance-v1`：把严格校验后的发行参数交给现有 issuance 实现，逐 lane 生成 terms、issuer state、tapscript 和 output key。
- `catomicals-fixed-price-listing-v1`：编译一笔具体固定价订单，复用现有 trading 实现生成 commitment、buy/cancel leaf、listing output 和 order txout。它不能冒充通用市场模板。

## 当前可用

- 网络固定为 Signet，部署配置固定为 `bitcoin-inquisition-signet-v29.4-op-cat`，`OP_CAT` 固定为 `required`。
- 正文以 RFC 8785 JCS 规范化，profile 为 `catomicals-policy-jcs-v1`，摘要只允许 SHA-256。
- `policy compile` 执行正向、正文篡改、制品篡改和非法参数向量。全部通过后才产生 validation run。
- 带 `--data-dir` 的编译把完整 bundle、制品、向量和验证记录写入钱包 SQLite；完整数据库会进入现有加密备份。
- `policy activate` 只保存 pending proposal，并输出 approval digest。

## 实验边界

这些制品只用于 Bitcoin Inquisition Signet 研究。它们不代表 Bitcoin 主网已启用 OP_CAT。发行脚本不能在共识层检查输出；item output、successor、费用等仍由钱包 policy verifier 检查。固定价订单的 seller 签名绑定具体交易，不能据此声称已有通用撮合、公平排序或 AMM。

pending proposal 没有签名权限，不能作为交易签名，也不会消费 FROST nonce。正式 activation 仍需要后续独立的 `AuthorityIntent + Passkey` 原子授权链；本切片没有实现这条链，也没有任何写入 active 的接口。

恢复在 cutover 递增 wallet epoch。旧 binding 和 activation 行继续保留审计，但 pending proposal 从该时刻失效，旧 binding 不能直接用于签名。
