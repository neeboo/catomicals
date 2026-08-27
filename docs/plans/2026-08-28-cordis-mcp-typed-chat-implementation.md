# Cordis MCP 与类型化会话实施计划

## 目标

让 Codex、DeepSeek Harness 和 Claude Code 在明确权限内读取 Catomicals 插件、检查配置并创建待确认的设置意图。代理不能确认配置，也不能因此获得钱包批准、签名或广播能力。

同一阶段把执行器输出整理成统一的类型化会话协议。Web 可以流式显示文本、工具状态和受控卡片，旧调用方暂时保留完整文本结果。

## 能力拆分

首版保留两个独立 MCP 服务：

```text
执行器
  ├─ catomicals-wallet MCP
  │    └─ 现有 walletd 回环接口和 9 项钱包工具
  └─ catomicals-config MCP
       └─ 桌面宿主私有桥和 6 项 Cordis 配置工具
```

钱包 MCP 的严格 9 项工具测试继续保留。Cordis MCP 单独断言 6 项工具，避免配置权限和钱包权限混进同一个服务对象。

## 六项 Cordis 工具

| 工具 | 权限 | 输入 | 权威输出 |
|---|---|---|---|
| `list_plugins` | `plugin.catalog.read` | 空对象 | 插件 ID、版本、ready/isolated、稳定错误码 |
| `read_plugin_manifest` | `plugin.manifest.read` | `plugin_id` | 已验签的固定 manifest |
| `read_plugin_settings_schema` | `plugin.settings_schema.read` | `plugin_id` | 字段、约束、重启影响、secret-reference 标记 |
| `read_plugin_health` | `plugin.health.read` | `plugin_id` | 状态、稳定代码、净化消息和检查时间 |
| `validate_plugin_settings_patch` | `plugin.settings.validate` | 插件 ID 和稀疏补丁 | 有效性、候选摘要和重启影响 |
| `create_plugin_settings_intent` | `plugin.settings_intent.create` | 插件 ID 和稀疏补丁 | intent、review、摘要、权限变化、脱敏差异和有效期 |

插件版本、当前配置摘要、候选摘要、权限变化、重启影响、review ID、intent ID 和 secret 状态都由桌面宿主读取或生成。调用者不能提交这些字段。

MCP 不开放下列动作：

- 确认、应用、回滚或迁移设置；
- 创建、读取或导出秘密；
- 安装、升级或卸载插件；
- 任意脚本、动态包或 `cordis_run`；
- Passkey 批准、FROST 轮次、签名份额、完整签名和广播。

## 桌面私有桥

`desktop/src/cordis/agent-bridge.ts` 负责把六条固定路由映射到现有 `CordisHost`：

- 只监听 `127.0.0.1` 随机端口；
- 每个执行器会话获得随机令牌，令牌只通过进程环境传递；
- 令牌绑定执行器会话、固定权限和过期时间；
- 会话销毁或桌面退出时立即撤销；
- 请求不能自行声明权限；
- 请求体沿用 64 KiB、深度和节点数量限制；
- 不启用 CORS、cookie、重定向和浏览器凭据；
- 返回稳定错误码，不回传文件路径、命令和底层异常；
- 桥接模块不能导入 `cordisDesktopAccess`。

私有桥加入 `ShutdownCoordinator`，退出时先停止接收请求，再撤销令牌并关闭监听。

## 类型化会话

### 完成态消息

现有 `chat-message.schema.json` 继续描述不可变完成态消息。每条消息包含：

- 文本 part；
- 工具调用和工具结果 part；
- review 引用；
- 由宿主构造的 `ui_block`；
- 稳定、可净化的错误 part。

消息完成后再计算 `content_digest`。执行器当前的本地 session ID 可以继续用于界面和兼容接口，协议另设 UUID `protocolSessionId`。

### 流式事件

新增 `chat-stream-event.schema.json`：

- `message_started`
- `text_delta`
- `tool_started`
- `tool_completed`
- `message_completed`
- `message_failed`

事件包含协议会话 UUID、消息 UUID 和单调递增序号。只有 `message_completed` 携带完整且已校验的消息。

`ExecutorSendResult.output` 保留一个兼容周期，同时增加最终 `message`。Electron 用单向事件通道推送增量事件；监听解绑后不能继续接收数据。

### 执行器解析

每个 provider 适配器实现增量解析器：

- Codex 解析 JSONL 的 thread、item、文本和工具事件；
- Claude Code 解析 `stream-json`；
- DeepSeek Harness 能识别结构化事件时再映射，纯文本只产生 `text_delta`。

UTF-8 和 JSON 行都可能跨 chunk。解析器使用流式解码，不能逐块直接转字符串。进程输出保存为 chunk 数组并记录总字节数，避免反复拼接造成性能退化。

## 工具审计与受控卡片

- 工具名到权限的关系使用宿主静态表，忽略执行器自行声明的权限。
- 聊天只保存请求摘要、结果摘要、状态和不可变引用；完整参数和结果留在受控审计层。
- `read_plugin_health` 成功后，宿主可以生成绑定 `plugin_id` 的 `health_status`。
- `create_plugin_settings_intent` 成功后，宿主可以生成绑定 `review_id` 的 `plugin_settings_diff` 或 `review_card`。
- 标题、说明、组件名和动作由宿主投影器生成，不接受代理提供的任意 UI JSON。
- 卡片只允许打开插件、健康状态、review、intent 或关闭自身。确认动作不属于 `ui_block`。

## 协议补齐

- 新增 `schemas/agent/plugin-config-tools.schema.json`。
- 新增 `schemas/agent/chat-stream-event.schema.json`。
- `SettingsReview` 公开存储层已有的只读 `review_digest`。
- 对外 review ID 严格使用 UUID。
- 为六项工具和流式事件补 valid/invalid fixtures。

## 实施顺序

1. 补齐工具、流式事件、review digest 和协议夹具。
2. 实现桌面私有桥、会话令牌和关闭流程。
3. 实现独立的 `catomicals-config` MCP，冻结钱包 MCP 的 9 项合同。
4. 给执行器增加 MCP 装配和真实能力探测；探测通过后才显示 MCP 可用。
5. 把进程输出改成增量事件，实现三个 provider 解析器。
6. 增加消息组装器、工具审计和引用式界面投影器。
7. 接通 preload、Web 流式显示和受控卡片。

## 验收

- 钱包 MCP 严格为 9 项，Cordis MCP 严格为 6 项。
- 两个 MCP 都没有确认、批准、签名和广播工具。
- 错误、过期和已撤销的会话令牌全部拒绝。
- MCP 创建的 review 与桌面界面创建的 review 使用同一宿主逻辑。
- Codex 和 Claude 的 JSON 行跨 chunk 测试通过；DeepSeek 纯文本不会生成虚假工具事件。
- 输出达到 1 MiB 上限时终止进程，序号保持单调，中断后停止派发事件。
- 完成态消息通过 Draft 2020-12 schema 校验。
- Web 只渲染白名单组件，确认前重新读取权威 review。
- Desktop、Web、Rust 工作区测试、类型检查和生产构建全部通过。
