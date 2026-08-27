# Pending activation proposal

`policy activate` 绑定以下字段：activation id、binding id、policy hash、wallet id、wallet epoch、signer set id、signer epoch、固定 chain profile、artifact-set digest、validation-run digest、创建时间和 expiry。

这些字段连同 `catomicals-policy-activation-proposal-v1` domain 通过 JCS + SHA-256 生成 approval digest。钱包只会在 policy bundle 已完成全部向量验证、digest 与当前 wallet epoch 精确匹配时保存 proposal。

本切片的状态只有 pending。没有 active 写入方法，没有 transaction signing 调用，也没有 FROST nonce 调用。后续实现必须用独立 `AuthorityIntent + Passkey` 原子授权链完成正式 activation，并在授权时重新检查 wallet/signer epoch、chain profile、policy/artifact/vector digest 和 expiry。
