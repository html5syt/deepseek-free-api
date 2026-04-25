# DeepSeek Free API 服务 (AstBot)

<span>[ 中文 | <a href="README_EN.md">English</a> ]</span>

[![](https://img.shields.io/github/license/html5syt/deepseek-free-api.svg)](LICENSE)
![](https://img.shields.io/github/stars/html5syt/deepseek-free-api.svg)
![](https://img.shields.io/github/forks/html5syt/deepseek-free-api.svg)
![](https://img.shields.io/badge/Docker-ghcr.io/fu--jie/deepseek--free--api-blue)

## 支持详情

### 1. 支持模型列表

本项目通过解析模型名称中的关键字，动态注入官方对应的协议参数。各功能可自由排列组合：

| 模型名称 (Model ID) | 对应后端版本 | 专家模式 | 深度思考 | 联网搜索 | 说明 |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `deepseek` | **V4-Flash** | ❌ | ❌ | ❌ | 基础对话模式 |
| `deepseek-expert` | **V4-Pro** | ✅ | ❌ | ❌ | **推荐**：专家增强模式 (1M 上下文, Agent 优化) |
| `deepseek-r1` | **V4-Flash** | ❌ | ✅ | ❌ | 官方 R1 深度思考模式 |
| `deepseek-search` | **V4-Flash** | ❌ | ❌ | ✅ | 官方联网搜索模式 |
| `deepseek-expert-r1` | **V4-Pro** | ✅ | ✅ | ❌ | **顶级推理**：V4 Pro + 深度思考 |
| `deepseek-expert-search` | **V4-Pro** | ✅ | ❌ | ✅ | V4 Pro + 联网搜索 |
| `deepseek-r1-search` | **V4-Flash** | ❌ | ✅ | ✅ | 深度思考 + 联网搜索 |
| `deepseek-expert-r1-search` | **V4-Pro** | ✅ | ✅ | ✅ | **最强形态**：V4 Pro + 思考 + 搜索 |

> **映射逻辑**：无需更改模型名称。系统会自动识别：包含 `expert` 即调用 **V4-Pro**；不包含则默认调用 **V4-Flash**。包含 `think` 或 `r1` 开启思考，包含 `search` 开启搜索。后缀支持 `-silent` 和 `-fold` 模式。

### 2. 快捷触发 (Magic Triggers)

无需更换模型名，您可以通过以下方式在任何模型下触发深度思考：

- 提示词以 `?` 或 `？` 开头。
- 提示词包含 `深度思考` 四个字。

### 3. 连续对话 (Continuous Conversation)

本项目支持通过 `conversation_id` 实现原生的连续对话（即利用 DeepSeek 服务端的记忆，而非通过客户端上传历史 `messages`）。

- **使用方法**：在 OpenAI 兼容请求的 `body` 中加入 `"conversation_id": "YOUR_ID"`。
- **ID 来源**：每一轮 API 响应体的 `id` 字段即为下一轮所需的 `conversation_id`。
- **ID 格式说明**：内部格式为 `session_id@parent_message_id`。
  - `session_id`: 官方会话的 UUID。
  - `parent_message_id`: 上一轮消息的序号（2026 协议要求必须为数字类型，代理层已处理）。
# DeepSeek Free API（AstrBot 插件）

本项目是一个基于 DeepSeek Web 协议的本地 OpenAI 兼容代理服务器实现，作为 AstrBot 插件运行时会在本地启动一个 HTTP 服务，用于将 OpenAI 风格的请求代理到 DeepSeek 的网页端接口。主要功能包括：流式/非流式对话、深度思考（R1）、联网搜索、专家模式支持、PoW 求解器、以及 AstrBot 会话连续性绑定。

[README in English](README_EN.md)

## 主要功能

- OpenAI 兼容的 `/v1/chat/completions`（支持 `stream` SSE）
- Deep-thinking（R1 / think）与 search 模式
- 专家模式（`expert`）自动注入 `model_type: "expert"`
- 会话连续性：支持 `conversation_id`，并在 AstrBot 集成时支持基于 `unified_msg_origin` 的持久绑定（UMO）
- DeepSeek PoW（纯 Python 实现）
- Token 存活检测接口 `/token/check`

## 快速开始

1. 安装依赖（推荐 Python 3.9+）：

```bash
pip install -r requirements.txt
```

2. 作为 AstrBot 插件运行：将本插件放入 AstrBot 的插件目录或通过 AstrBot 的插件加载机制加载。插件初始化时会启动一个本地 HTTP 服务器（默认端口 `5566`）。

3. 直接调用（示例）：

```bash
curl -X POST http://127.0.0.1:5566/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "model": "deepseek-expert",
    "messages": [{"role": "user", "content": "你好，介绍下你自己。"}],
    "stream": false
  }'
```

响应示例与 OpenAI 格式兼容，成功响应的 `id` 可用作下次请求的 `conversation_id`（格式为 `session_id@parent_message_id`）。

## 配置项

- `port`（int）：HTTP 服务监听端口，默认 `5566`。
- `client_identifier`（str）：若配置此字符串，AstrBot 会在请求头 `X-from-which-astrbot` 中包含该标识，插件将检测此请求头并在请求中注入 nonce，以便在服务端建立 UMO → DeepSeek 会话映射。
- `deepseek_token`（str， 可选）：插件级别的 DeepSeek refresh_token，用于覆盖请求头中的 Authorization 值（可选）。

这些配置会在 AstrBot Web UI 中以插件配置项的形式展示（插件初始化时调用 `put_config` 注册）。

## HTTP 接口（概要）

- GET `/ping` — 返回 `pong`。
- GET `/v1/models` — 返回支持的模型 ID 列表。
- POST `/v1/chat/completions` — OpenAI 兼容的对话补全接口；必须在请求头中设置 `Authorization: Bearer <userToken[,userToken2,...]>`。
  - 请求体示例字段：`model`, `messages`, `conversation_id`（可选）, `stream`（可选）。
- POST `/token/check` — 检查 DeepSeek `userToken` 是否存活，入参 JSON `{ "token": "..." }`，返回 `{ "live": true|false }`。

示例：

```json
{
  "model": "deepseek-expert",
  "messages": [{"role": "user", "content": "谁是你？"}],
  "stream": false
}
```

## 支持的模型映射（简要）

- `deepseek` — 默认（V4-Flash）
- `deepseek-expert` — V4-Pro（Expert 模式）
- `deepseek-r1` — R1 深度思考（think）
- `deepseek-search` — 联网搜索
- 可组合：`deepseek-expert-r1-search` 等（`expert`,`r1`,`search` 等关键字将被解析并组合启用对应特性）。

## 数据与持久化

插件会在 AstrBot 数据目录下创建 `plugin_data/deepseek_free_api/umo_conv.db`（SQLite）用于存储 `unified_msg_origin` → `conversation_id` 的映射，以便在 AstrBot 场景下保持云端对话连续性。

## 开发与调试

- 安装依赖后，可在 AstrBot 环境中加载本插件并观察日志。日志中会显示服务启动端口与周期性版本更新信息。
- 开发时请注意 DeepSeek 网页端协议可能会随时间变化，维护本项目需要跟踪网页端实现。

## 风险与免责声明

本项目通过对 DeepSeek Web 协议的逆向适配实现代理功能，协议与行为可能随官方更新而改变，存在被封禁或服务中断风险。仅供研究与个人使用，禁止将本项目或由其构建的服务用于公开商业化服务，使用者需自行承担风险。

## 许可证

请参阅仓库根目录的 `LICENSE` 文件。


### Token统计

由于推理侧不在deepseek-free-api，因此token不可统计，将以固定数字返回。
