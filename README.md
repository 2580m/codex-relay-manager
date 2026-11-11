# Codex Relay Manager

Windows PowerShell 多中转站、多模型管理器。一个 Provider 保存一个 API 根地址、一个加密 API Key，并拥有独立的动态模型缓存及 Responses 兼容性记录。

**运行入口：`codex-relay.ps1`。只有菜单 `[9]` 经预览并确认后才更新 CLI/App 共用 `config.toml`，先备份并保留无关配置；普通启动与测试不改配置。不执行登录/退出登录，不关闭 Codex 沙箱或审批。**

## 1. 安装和启动

支持 Windows PowerShell **5.1** 与 PowerShell **7**，仅支持 Windows。主脚本无第三方 PowerShell 模块依赖。

1. 安装 Node.js LTS（只有通过 npm 安装 Codex 及运行 Mock 测试时需要）。
2. 安装官方 Codex CLI：

   ```powershell
   npm install -g @openai/codex
   codex --version
   codex --help
   ```

3. 在该文件夹打开 PowerShell：

   ```powershell
   .\codex-relay.ps1
   ```

   或明确指定 PowerShell 7：

   ```powershell
   pwsh -NoProfile -File .\codex-relay.ps1
   ```

如果执行策略禁止脚本，请先按组织政策允许本地脚本；例如在获准情况下为当前用户设置 `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`。不要为了此工具关闭系统安全策略。下载的文件应先检查来源和内容，再按需 `Unblock-File`。

若 CLI 不在 PATH，或只能找到自定义包装脚本：

```powershell
.\codex-relay.ps1 -CodexPath 'C:\path\to\codex.exe'
```

管理器优先调用官方原生 `codex.exe`。对于 npm 的 `codex.cmd`/`codex.ps1`，会尝试定位相邻 `node_modules\@openai` 中当前架构的原生 EXE；不通过 `cmd.exe` 重新解释包含用户数据的命令行。无法定位时会明确报错，请指定路径。

已确认本机现有 CLI 位于 `%LOCALAPPDATA%\Programs\OpenAI\Codex\bin\codex.exe`，版本 `0.167.1`。管理器会在当前 PATH 找不到时继续检查持久化用户/系统 PATH 和该常见目录，无需重装，也不修改任何 PATH。此前“没有全局安装”的判断不准确，实际是 ZCode 继承的旧进程 PATH 缺少新目录。

开发验证另有工作区隔离安装，不是日常运行所必需。若要明确使用该隔离副本：

```powershell
.\codex-relay-manager\codex-relay.ps1 -CodexPath '.\.tools\codex\node_modules\@openai\codex-win32-x64\vendor\x86_64-pc-windows-msvc\bin\codex.exe'
```

## 2. 首次添加 Provider

选择 `[1] 添加中转站`，输入名称、Base URL、API Key。密钥使用 `Read-Host -AsSecureString` 隐藏输入，不回显。

根地址自动规范化：

| 输入 | 保存的 API 根地址 |
|---|---|
| `https://example.com` | `https://example.com/v1` |
| `https://example.com/` | `https://example.com/v1` |
| `https://example.com/v1` | `https://example.com/v1` |
| `https://example.com/v1/` | `https://example.com/v1` |
| `https://example.com/v1/models` | `https://example.com/v1` |
| `https://example.com/v1/responses` | `https://example.com/v1` |
| `https://example.com/gateway/v1/models` | `https://example.com/gateway/v1` |

对于无法判断的自定义路径（如 `/gateway` 或 `/api/v2`），必须选择“保留 API 根路径”或“追加 `/v1`”，不会默默改写。重复 `/v1/v1`、重复请求端点、包含用户凭据/查询参数/片段的 URL 被拒绝。非 HTTPS 地址需要额外确认，生产环境应只用 HTTPS。

确认后向 `{BaseURL}/models` 发送带 Bearer 认证的 GET。Provider 先安全保存，再请求模型；即使列表接口失败，Provider 也不会丢失。显示获取数量，动态提取 `data[].id`，按大小写敏感的 ID 去重。**没有内置、预设或硬编码的生产模型列表。**

## 3. 主菜单使用

- `[2] 管理中转站`：选择 Provider，查看模型、刷新、编辑、查看兼容性记录或启动。
- `[3] 获取/刷新模型列表`：刷新指定 Provider 的独立模型缓存。默认整体请求超时 30 秒；失败保留上次缓存。模型选择时可输入 `R` 重试。
- `[4] 测试模型兼容性`：`[1] 单个`、`[2] 批量选择`、`[3] 全部缓存模型`。**实际调用模型可能产生费用**；单次需确认，批量/全部需两次确认。测试只调用选中 Provider，不跨 Provider 共享模型或结果。
- `[5] 启动 Codex`：选择 Provider 和模型，检查兼容性后进入正常 Codex 交互界面，退出 Codex 后回到管理器。
- `[6] 编辑中转站`：修改名称、Base URL 或 API Key。未被共享配置引用时，地址/密钥变更清除旧模型、兼容性缓存和受管模型目录；共享配置仍有引用时，拒绝此类变更，先通过 `[10]` 恢复解除引用，避免目录或认证失效。仅改名保留模型，CLI 覆盖使用新名称，App 中名称需重新接入更新。
- `[7] 删除中转站`：未被共享配置引用时，确认后删除其 Provider 记录、DPAPI 密文、两种缓存及受管模型目录/备份，不影响其他 Provider，也不删除用户额外文件。仍有共享引用时拒绝删除，请先恢复解除接入。
- `[8] 查看配置与运行状态`：查看 PowerShell/CLI 版本、数据位置、当前选择、历史检测时间、分类和原因，不显示明文密钥。
- `[9] 接入 CLI/App 共用配置`：支持单个、批量选择、全部；明确选择默认模型后，预览目标共用 `config.toml`、模型目录、Provider 和备份位置。确认后合并受管目录，部署 DPAPI 凭据助手并备份更新共享配置。
- `[10] 共享配置接入记录与恢复`：查看记录，确认后按指纹恢复修改前配置；存在后续外部编辑时拒绝直接覆盖。
- `[11] 升级已有模型为 OpenAI 官方配置`：备份并升级一个或所有 Provider 的模型目录，保留已有 effort 和自定义字段，不改共享配置。
- `0` 返回/退出；错误输入可重试。Ctrl+C 中止当前 PowerShell 调用，网络资源通过 `finally` 释放，不留下明文环境变量。

### 批量选择规则与颜色

批量测试和批量接入共用同一选择页：可以输入 `1,3,5`（也接受中文逗号），或输入 `1` 回车后继续输入 `3`，再输入下一项。回车只添加当前行，不直接执行；输入 **`00` 完成选择**，输入 **`0` 取消并丢弃整次选择**。两种命令必须单独输入。重复项自动去重并保留首次选择顺序；包含无效序号的一整行不会添加。空选择输入 `00` 会提示继续，不会执行空任务。

未测试显示 `NO_TESTED`，字体为**白色**（旧 `NOT_TESTED` 状态也映射白色）；`COMPATIBLE` 为**绿色**；`INCOMPATIBLE` / `MODEL_UNAVAILABLE` 为**红色**。认证、限流、网络故障和无法判断仍为黄色，避免将服务故障误标为协议不兼容。模型列表、测试结果、历史记录使用同一状态颜色规则。

模型选择界面中 `M` 允许手动输入模型 ID，解决 `/models` 不支持、列表为空或列表权限不足的情况。手动输入不会自动添加兼容标记；必须经过相同检测才能由菜单启动。

## 4. Responses 兼容性如何判定

向 `{BaseURL}/responses` 发送：

```json
{"model":"用户选择的动态模型 ID","input":"Reply with exactly: OK","stream":true}
```

使用 .NET `HttpClient` 的 `ResponseHeadersRead` 和 `StreamReader.ReadAsync` **逐段读取**，不是把 HTTP 200 当成功，也不先缓冲整个 SSE。

`COMPATIBLE` 要求：

1. HTTP 成功，Content-Type 是 `text/event-stream`；
2. SSE `data` 是有效 JSON，`type` 与提供的 `event` 一致；
3. 存在 `response.created` 或 `response.in_progress`；
4. 存在非空字符串 `response.output_text.delta`；
5. 存在 `response.completed` 且其 `response.status` 是 `completed`。

`response.failed`、`response.incomplete`、`error` 不会被标记为兼容；断流、只有 `[DONE]`、只有生命周期、缺少终止事件均不算通过。整体超时覆盖等待响应头与流读取，也限制最大响应大小，不会无限等待。

| 状态 | 含义 |
|---|---|
| `COMPATIBLE` | 此时通过最小 Responses 文本流检测 |
| `INCOMPATIBLE` | 接口/请求/协议明确不支持或返回错误流格式 |
| `AUTH_FAILED` | HTTP 401/403，认证或权限失败 |
| `MODEL_UNAVAILABLE` | 返回可识别的模型不存在/不可用错误码 |
| `RATE_LIMITED` | HTTP 429 |
| `NETWORK_ERROR` | DNS、连接、TLS 或超时 |
| `UNKNOWN` | 服务器 5xx、流提前结束或信息不足 |
| `NO_TESTED` | 白色界面标记：该模型尚无检测记录（兼容旧 `NOT_TESTED`） |

错误信息不输出不可信网关的完整响应体，避免网关在错误正文中回显 API Key 后进入控制台或缓存。HTTP 重定向禁用，避免凭据被转发给其他站点；TLS 证书验证不会关闭。

**重要限制：通过文本检测不代表能完整运行 Codex。** Codex 还需要工具调用、工具结果回传、多轮历史、上下文/推理参数与合适模型元数据等支持。仅支持 Chat Completions 或 Anthropic Messages 的中转站不能因此作为 Responses Provider 使用。检测记录带 UTC 时间，是历史结果，不保证未来一直可用。

## 5. Codex 配置及密钥传递

本次启动通过 CLI 重复的 `--config key=value` 传递七项覆盖：

```toml
model = "选择的模型"
model_provider = "relay_随机ID"

[model_providers.relay_随机ID]
name = "中转站名称"
base_url = "https://example.com/v1"
wire_api = "responses"
env_key = "CODEX_RELAY_API_KEY"
requires_openai_auth = false
```

普通 CLI 启动覆盖不会改写共享配置。菜单 `[9]` 则会在明确确认后，修改 `CODEX_HOME/config.toml`（未设置时为用户目录 `.codex/config.toml`），同时保留受管目录内的 `models.json` 和辅助独立 TOML。API Key 不在新生成的 TOML、覆盖参数或日志中。TOML 字符串单独转义引号、反斜杠和控制字符，再进行 Win32 原生 argv 转义，不使用 JSON 代替 TOML。

### 模型目录文件管理

参照 DeepSeek 安装脚本的 `model_catalog_json` 机制，但不照搬其删除 Profile 或覆盖全局模型目录的做法。每个 Provider 单独保存 `catalog/<ProviderId>/models.json` 和 `relay.config.toml`，按模型 ID 大小写敏感去重并合并已有条目，更新前备份。原来的 Provider/MCP/Profile 文件不会被修改。

菜单 `[9]` 接入完成后，顶层 `model`、`model_provider`、`model_catalog_json` 关联实际共享配置；App 与裸启动 CLI 可从该配置加载模型目录，不再依赖 CLI 临时目录覆盖。全局当前 Provider 只有一个，不会按模型 ID 自动跨中转站路由；接入另一个 Provider 时会明确切换当前默认，同时保留其他 Provider 表。

有激活的 Profile、全局地址覆盖或认证冲突时，工具会指出冲突并拒绝激活，不删除设置。TOML 编辑器采用限定语法保真处理：遇到不能安全识别的复杂目标写法、日期/时间值等不支持语法时明确拒绝，而不是冒险修改。根级 `profile`、`oss_provider`、`openai_base_url`、`forced_login_method` 目前均保守视为激活冲突（无论具体值），不会自动删除。保留原有指令并不保证换模型后的行为完全一致。

#### App 中使用

1. 添加 Provider，刷新并按需检测模型。
2. 菜单 `[9]` 选择模型（支持批量），选择 effort 模式（0跳过／1单个模型API检测／2本次所有模型API检测），再明确默认模型、查看实际共享配置路径，输入 `YES`。
3. 确认显示“配置已写入”，完全退出并重新打开 App，再新建会话。
4. 配置成功不代表真实网关调用成功；若 App 报凭据助手或协议错误，不会退化明文，请先查看版本与兼容性记录。

共享配置中的认证使用 `[model_providers.<id>.auth]`，命令和参数均为绝对路径/非秘密数据。Windows PowerShell 凭据助手从当前用户 DPAPI 密文取 Key，stdout 仅返回纯文本 token，不返回 JSON，异常只输出固定无秘密诊断。不设置 `env_key`，不写 `experimental_bearer_token`，不改变已有 ChatGPT 登录。当前实测协议以 Codex `0.167.1` 为基准；App GUI 是否实际调用成功单独报告。

恢复使用菜单 `[10]`，只有当前文件仍匹配该次写入指纹才自动恢复；若已手动编辑，必须先处理冲突，不会整份覆盖你的新设置。正在被共享配置引用的 Provider 不允许直接清理、删除或更换地址/密钥，请先恢复解除接入。备份可能包含你原配置中已经存在的敏感字段，按密钥文件同等保护，不要上传或同步到公共仓库。进程若在替换成功而事务记录尚未完成时崩溃，可能遗留 `Prepared`；工具会阻止误删引用，但不会猜测自动恢复，需要人工核对记录中的原/新指纹与备份。恢复原文件后若最后记录写入失败，也需核对原指纹，不要强制覆盖后续编辑。跨文件补偿不是系统级崩溃原子事务。

#### 官方模型模板与已有目录升级

已取消旧版 `shell_type = "disabled"`、仅文本、一句话代理指令的占位配置。主脚本离线内嵌 OpenAI `rust-v0.167.1` 官方 `models-manager/models.json`（原文件 SHA256：`1384625c0b6b3e67d3c60da29becea2b017f2c283fc1e2d05b8edafb4698eb10`），无须运行时联网。

- 模型 ID 大小写敏感精确匹配时，复制对应官方条目，包括 GPT-6.1 Sol/Terra 的专属配置和完整代理指令。
- 没有精确条目时，采用明确标注的官方 `gpt-5.5` 模板，保留中转站原模型 ID/自定义显示名，移除模板的升级路由提示，绝不把实际 API 模型改为 GPT。
- Shell、text/image 输入、Node REPL 标志、完整 `model_messages`、补丁/工具声明、技能/App/插件说明等采用模板实际值。GPT-5.5 的三个说明标志为 true；GPT-6.1 的对应官方标志为 false，不强行改成 true。
- 模板默认推理等级、上下文及其他能力是客户端配置声明，不代表第三方网关实际具备相同能力；可使用 effort API 检测覆盖模板推理等级。旧目录中的已有 effort 设置保留。
- 新添加模型即使用官方模板；`[9]` 重新接入时会同步升级本次选中模型。
- **已有模型无需重新接入：选择主菜单 `[11] 升级已有模型为 OpenAI 官方配置`，可升级一个或所有 Provider。** 先逐目录保存 `.bak`，保留额外自定义字段和已有 effort；不改共享配置或登录凭据，引用目录路径不变。升级后完全退出 App，再新建会话。
- 不添加危险权限参数，不改变已有审批与沙箱。恢复 Shell/图片等客户端声明不是绕过服务商能力限制，也不保证模型一定调用工具。

来源：[官方固定版本模型目录](https://github.com/openai/codex/blob/rust-v0.167.1/codex-rs/models-manager/models.json)。脚本使用该固定版本，更新 CLI 后如官方协议有变仍需重新验证。

#### 接入时的 effort 检测

模型选择完成后显示 `[0] 不设置`、`[1] 单个模型 API 检测`、`[2] 所有已选模型 API 检测`，不再提供手动声明模式。

- `0` 不进行 API 检测，保留已有 effort 设置；新模型使用官方模板声明的等级，不标记为 API 已验证。
- `1` 从本次接入模型中选择一个，显示最大请求数和费用，一次确认后检测。
- `2` 只检测本次选中的所有接入模型，不扫描中转站其他模型；需要两次费用确认。
- 每个模型先做一次无 effort 基线；基线通过后尝试预定义候选 `none/minimal/low/medium/high/xhigh/max`。候选列表不是所有网关合法值的穷举；最多每模型8次可能计费请求，无自动重试。`0`（跳过）与 API 值 `none`（发出参数）不是同一件事。
- 请求使用 `reasoning: { effort: "..." }`，仅完整通过 Responses SSE 的等级记为 `API_ACCEPTED`。认证、限流或网络失败会停止当前模型剩余等级；没有等级被接受时保留原设置。
- `API_ACCEPTED` **只能证明带参数的请求完成，不证明思考等级实际生效**，网关可能忽略或改写参数。检测记录与基础兼容性分别保存。
- 已接受等级写入模型 `supported_reasoning_levels`，默认等级优先保留仍被接受的原默认，否则使用首个被接受等级并显示。所选默认模型的等级同步到顶层 `model_reasoning_effort`，App 的 `desktop.enabled-reasoning-efforts` 与已有选项合并，其他桌面设置不变。
- API 检测在最终文件接入确认之前执行；之后取消文件接入不会退还检测费用。文件写入仍需独立确认与备份，失败会补偿模型目录的 effort 改动。

管理器菜单 `[5]` 的 CLI 临时启动仍通过 `ProcessStartInfo.EnvironmentVariables` **仅在启动的 Codex 子进程环境中**设置 `CODEX_RELAY_API_KEY`，父 PowerShell、用户环境、系统环境均不修改，启动后清除暂存引用。若原 Provider 已持久接入共享认证，则为此次 CLI 覆盖使用随机临时 Provider ID，避免 `auth` 与 `env_key` 互斥。子进程继承控制台正常交互。不添加审批绕过或危险沙箱参数。现有用户 ChatGPT 登录、MCP、Profile 等仍由 Codex 自己加载。

若当前 CLI 帮助声明支持 `--no-daemon`，菜单启动时自动添加，避免将临时密钥交给共享后台服务。旧版若不提供该选项则不臆造参数。

## 6. 存储与安全边界

默认位置：

```text
%USERPROFILE%\.codex-relay\
├── providers.json
├── cache\
│   ├── relay_<随机ID>-models.json
│   └── relay_<随机ID>-compatibility.json
├── catalog\
│   └── relay_<随机ID>\
│       ├── models.json
│       ├── relay.config.toml
│       └── *.随机事务ID.bak
├── credentials\
│   └── credential-helper.ps1
├── shared-config\                 # 受限 ACL 的共享配置备份及事务记录
└── logs\
```

可以用 `-DataDirectory 'D:\private\codex-relay-data'` 指定**专用目录**，不要指向项目根目录或与其他应用共享的目录。初始化会收紧该目录 ACL，仅当前 Windows 用户和 SYSTEM 完全控制；拒绝数据目录重解析点。默认不写运行日志，`logs` 目录预留；不记录网络正文或密钥。

API Key 用 Windows **DPAPI `CurrentUser`** 加密后 Base64 存储。解密通常需要原 Windows 用户和可用的 DPAPI 用户配置；只拷贝 JSON 到另一用户/设备不保证能解密。解密失败时可通过编辑菜单重录 Key。非 Windows 明确拒绝运行，不回退明文。磁盘写入先写同目录临时文件再原子替换，进程间互斥锁防止并发写覆盖；损坏 JSON 不自动覆盖，先提示备份修复。

安全边界：DPAPI 不是对当前用户恶意软件的防护；同用户进程、管理员、调试工具仍可能读取运行中内存/子进程环境。PowerShell/.NET 字符串不可保证完全擦除；脚本会清理可清理的字节/BSTR 和引用。删除属于普通逻辑删除，不承诺 SSD、历史备份或快照的不可恢复擦除。Codex 自己运行的子进程也可能继承其环境，按可信 Provider/可信模型/正常审批使用，不要执行不可信命令。

## 7. 常见问题

| 问题 | 处理方法 |
|---|---|
| CLI 未安装 | `npm install -g @openai/codex`，新开终端，检查 `codex --version` |
| 包装脚本无法定位原生 EXE | 使用 `-CodexPath` 指向官方包中的 `codex.exe` |
| CLI 不支持参数/Provider 字段 | 查看原始错误与版本；更新官方 CLI。管理器会检查帮助，不擅自换协议 |
| 401 / 403 | 编辑 Provider 更换 API Key，检查余额、IP 白名单、模型授权 |
| 404 / 405 | 检查根路径。配置应为 `/v1`，而不是 `/v1/responses`；确认网关实现 Responses |
| 429 | 等待或提高网关限额，再重试，不自动批量重试收费请求 |
| 500 / 502 / 503 | 网关故障，稍后重试，不标记为已兼容 |
| DNS / TLS / 连接错误 | 检查域名、证书、代理；不会绕过证书校验 |
| 请求超时 | 请求整体默认 30 秒，菜单可重试；库函数支持 `-TimeoutSeconds 1..300` |
| `/models` 不支持/空列表/非法 JSON | Provider 仍保留，查看旧缓存或 `M` 手动输入，再检测 Responses |
| 只有 Chat Completions | 不会伪装为 Responses；需要网关提供真正兼容的 `/responses` |
| 流 200 却未通过 | 检查 SSE Content-Type、生命周期、delta、completed，不要将普通 JSON 或 `[DONE]` 当 Responses |
| 文本通过但 Codex 工具失败 | 网关还需实现工具调用及多轮上下文；最小探测不是完整工具兼容认证 |
| 密钥无法解密 | 用原用户运行，或在编辑菜单重录；不要尝试回退明文 |
| 数据文件损坏 | 先备份提示的 JSON，修复格式或移到独立备份目录后重录；不会静默覆盖 |
| ACL 设置失败 | 用当前用户可控制的本地专用目录；不要改为公开可读目录 |

## 8. 本地测试

测试只访问 `127.0.0.1` Mock Server，使用假 Key，不消耗真实中转站余额。Node.js 用于 Mock Server，无 npm 依赖；PowerShell 测试无需安装第三方模块。

```powershell
powershell -NoProfile -File .\tests\Run-Tests.ps1
pwsh -NoProfile -File .\tests\Run-Tests.ps1
# 当前环境安装的 Pester 3.4.0 可用：
powershell -NoProfile -File .\tests\Run-Tests.ps1 -UsePester
pwsh -NoProfile -File .\tests\Run-Tests.ps1 -UsePester
```

测试覆盖 URL、DPAPI、JSON、多 Provider 隔离、模型解析/去重/缓存、HTTP 错误、真实分块 SSE、超时、TOML/Windows argv、子进程环境和原 config.toml 不变。具体文件与已执行结果见 `TEST-RESULTS.md`。若安装 Pester，可另外运行提供的 Pester 适配测试；基础 runner 不依赖它。

测试数据放新建的临时目录，不写默认 Provider 数据目录。原 Codex 配置仅做完整性校验，不读取或输出其内容。离线测试不能证明任何真实中转站端到端可用，也不能自动验收真实终端中的所有交互按键。

## 9. 本次核对的规范与版本

开发环境：Windows 10.0.26100，Windows PowerShell 5.1.26100.9711，PowerShell 7.6.10；工作区隔离安装并实际查看 `codex-cli 0.167.1` 的 `--version`、`--help` 和 `exec --help`。

官方规范（2026-11-11 核对）：

- [Codex CLI](https://developers.openai.com/codex/cli)（当前跳转到 [新文档](https://learn.chatgpt.com/docs/codex/cli)）
- [配置参考](https://developers.openai.com/codex/config-reference)（当前跳转到 [新配置参考](https://learn.chatgpt.com/docs/config-file/config-reference)）
- [高级配置](https://learn.chatgpt.com/docs/config-file/config-advanced)
- [CLI 参数参考](https://learn.chatgpt.com/docs/cli/reference)
- [网关兼容性要求](https://learn.chatgpt.com/docs/enterprise/gateway-compatibility)

当前配置参考明确 `wire_api` 只支持 `responses`。高级配置中仍有历史 Chat Completions 字样，不据此添加未验证协议。`requires_openai_auth` 默认 false，本工具明确设为 false，让自定义 Provider 从专用 `env_key` 获取 Bearer Key，而不是覆盖已有 ChatGPT 登录。不同 CLI 版本行为可能变化；启动失败时保留 CLI 原始控制台信息，不报告虚假的成功。
