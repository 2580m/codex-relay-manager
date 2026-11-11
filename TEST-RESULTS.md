# 测试与验收记录

日期：2026-11-11。测试在实际 Windows 环境执行，不是只阅读代码。

## 环境

| 项目 | 实测结果 |
|---|---|
| Windows | 10.0.26100 x64 |
| Windows PowerShell | 5.1.26100.9711 Desktop |
| PowerShell 7 | 7.6.10 Core |
| Pester | 3.4.0，在两个引擎中可用 |
| 原进程 PATH 的 Codex | 未找到；后续确认是进程 PATH 过期，不代表未安装 |
| 本机现有 Codex CLI | `%LOCALAPPDATA%\Programs\OpenAI\Codex\bin\codex.exe`，实际 `--version` 为 `0.167.1` |
| 本机 ChatGPT 应用 | 开始菜单 `ChatGPT`；包 `OpenAI.Codex`，版本 `26.1103.7773.0` |
| 工作区隔离安装 | 官方 npm `@openai/codex`，`codex-cli 0.167.1` |

隔离安装位于工作区 `.tools/codex`，没有修改全局 npm 安装。已获取并检查 `codex --version`、`codex --help`、`codex exec --help`。

## 2026-11-12 凭据助手诊断与沙箱组修复

- 保留 DPAPI，未改为明文。助手 v2 失败输出 `stage`、白名单安全原因、最深异常类型和8位 HRESULT；不输出原始异常/堆栈、Key、密文或JSON。成功 stdout 仍只包含token。
- 实机复现 `ROOT_ACL` 原因：默认数据目录存在本机 `CodexSandboxUsers` 读取/执行授权。旧助手把它当额外账户拒绝。
- 现在按本机账户解析SID，只允许该组的 ReadAndExecute/Synchronize；该组写入/Modify/FullControl及其他额外账户仍拒绝，DPAPI、路径/重解析点与拥有者检查保留。
- `Test-SandboxCredentialAcl.ps1` 新增3项：正常沙箱读取取钥；沙箱写权限拒绝；其他账户拒绝；独立项目目录ACL/沙箱Modify保持不变及文件读写（部分断言合并在同一case）。测试未冒充实际沙箱进程执行项目代码，因此不能据此声称App完整代理任务通过。
- 已升级实际Provider BI4KJD的受管助手，保留旧版本源码备份；最后复测助手源码与当前一致、退出0、token输出存在、stderr为空。未打印密钥、未向中转站请求、共享config.toml前后SHA256不变。
- 实际App GUI是否已恢复需要重开App新会话确认；本次没有关闭App或终止会话。此前被用户中断的PS7回归不记作通过，最终四轮串行重新执行均154/154。

## 自动化结果

当前 154 个独立测试 case（官方模板版151项＋沙箱凭据ACL及项目写入隔离3项），每个 case 还包含多组断言/夹具。以下每轮都包含当前引擎和 Windows PowerShell 5.1 的 AST 解析校验，以及用户 Codex config.toml 的哈希/修改时间不变校验。

| 执行方式 | 引擎 | 通过 | 失败 | 证据 |
|---|---|---:|---:|---|
| 独立 runner | Windows PowerShell 5.1 | 154 | 0 | `tests/results/powershell51.json`、同名 `.log` |
| 独立 runner | PowerShell 7 | 154 | 0 | `tests/results/powershell7.json`、同名 `.log` |
| Pester 3.4.0 | Windows PowerShell 5.1 | 154 | 0 | `tests/results/pester51.json`、同名 `.log` |
| Pester 3.4.0 | PowerShell 7 | 154 | 0 | `tests/results/pester7.json`、同名 `.log` |

新增 `Test-Interaction.ps1` 验证真实选择器与确认逻辑（仅网络/文件提交使用内存替身）：状态颜色、逗号/中文逗号输入、逐行回车、顺序去重、无效整行拒绝、0 取消、00 完成及空选择、批量测试两次确认和批量目录接入确认。

新增 `Test-Catalog.ps1` 验证 Provider 独立目录、按 slug 合并与自定义 metadata 保留、JSON/TOML 备份、错误输入不改原件、仅清理受管文件和启动目录参数。新模型使用保守元数据（无已知思考等级、shell disabled、text only），不将模型存在宣称为工具/推理能力认证。可选真实 CLI 目录用例需设置 `RELAY_TEST_CODEX_EXE`，不计入默认138项。本次另外启用并使用本机现有 `codex-cli 0.167.1` 实跑：Windows PowerShell 5.1 与 PowerShell 7 的 Catalog suite 均 **12/12** 通过，证据为 `tests/results/catalog-official51.json/.log` 和 `catalog-official7.json/.log`。`model/list` 确实返回 Add 产物里的两条随机 slug；删除必填 `shell_type` 后 CLI 报 `failed to parse model_catalog_json ... missing field shell_type`（可能以警告降级，不仅凭进程退出码判断）。真实启动 recorder 也验证自动追加目录参数、密钥只在子进程；精确模拟第二文件提交失败后恢复已提交的第一文件。

### 共享 CLI/App 配置升级验收

- `Test-SharedConfig.ps1` 23 项：TOML 注释、CRLF/BOM、多行字符串、quoted/dotted 非目标键、MCP/Profile、额外 Provider 字段保留；目标冲突、外部认证、受管字段被手改、重复/非法键与表冲突拒写；逐字节备份、受限 ACL、提交前指纹、恢复、Prepared 引用保护。
- `Test-CredentialHelper.ps1` 默认8项：实际无交互子进程、原始 UTF-8 无 BOM token、不同 Provider、坏密文/解密失败、非法 ID/控制字符、ACL/重解析点、修改助手拒绝覆盖，stdout/stderr 不泄露失败凭据、父环境不变。
- `Test-Publish.ps1` 3项：共享接入到恢复的完整集成；配置引用期间禁止删除/清理/换地址且数据不变；并发外部编辑后接入失败并恢复目录；已持久认证的 Provider 在 CLI 临时启动时使用新 ID 避免 auth/env_key 冲突。
- `Test-Interaction.ps1` 32项包含明确选择默认模型、预览冲突零发布、取消、恢复选择与严格 YES 确认。

另外启用 `RELAY_TEST_CODEX_EXE`，使用已安装官方 `codex-cli 0.167.1`：两个引擎的 CredentialHelper suite 均 **9/9 通过**。真实目录和共享配置由管理器函数生成，官方启动不传 Provider/catalog/auth 配置覆盖；`config/read` 确认默认模型/Provider，`model/list` 加载目录，`exec` 退出0，本地 Mock 记录每个 Provider 对应的 DPAPI 假 Key Bearer。没有真实 API 消费。证据：`tests/results/credential-official51.json/.log`、`credential-official7.json/.log`。**这是 CLI/app-server 协议验证，不是已安装 App GUI 的端到端认证。**

本轮实际发现并修复：PS5 单元素 JSON 数组包装；PS7 父进程 PSModulePath 导致 PS5 助手模块自动加载失败（改为 .NET ACL API）；敏感认证字段路径拼接优先级；TOML 键大小写；无效祖先表覆盖。新增启动集成测试原来仅允许14参数的旧辅助断言已修为同时验证额外模型目录参数。初轮失败没有当作最终通过。

### Effort 检测升级

- 接入模型选择后：0不设置保留已有；1从本次模型中选一个API检测；2检测本次所有模型。无手动声明模式。
- `Test-Effort.ps1` 11组 mock 策略断言：单/全费用确认、取消、基线门禁、仅接受完整成功流、错误分类停止、默认保留/首个accepted、零接受不改metadata、整批校验与备份、失败无损。
- `Test-EffortTransport.ps1` 4项本地HTTP与共享编辑断言：nested `reasoning.effort` 真实发送、独立effort缓存且不覆盖基础兼容记录、无效值零请求、desktop既有选项合并、默认与元数据一致、0保留原配置。
- `Test-EffortPublish.ps1` 2项：模型JSON/共享默认/desktop选项一并接入，CLI recorder实际验证默认effort覆盖，提交失败恢复原metadata。
- Interaction增加2项至34项：effort步骤在模型选择之后，设置传入plan/publish；失败零发布。
- 预定义7候选不是所有合法effort值的穷举。官方0.167.1 app-server schema实际允许非空字符串；本工具检测集合固定且不硬编码生产模型。`API_ACCEPTED` 不证明参数实际影响推理。App GUI与真实中转站等级能力未实测，无真实费用。

### 官方模板升级（替代旧受限占位配置）

- 固定官方 `rust-v0.167.1/models-manager/models.json` 原始539696字节，SHA256 `1384625c0b6b3e67d3c60da29becea2b017f2c283fc1e2d05b8edafb4698eb10`，gzip内嵌脚本，运行时不下载/执行远程文件。
- 精确匹配采用对应模型；其他ID采用标明来源的完整GPT-5.5客户端模板，保留请求ID/自定义名称，移除无关升级提示。GPT6.1的skills/apps/plugins官方值为false，GPT5.5为true，并非所有字段一律true。
- `Test-OfficialTemplates.ps1` 10项：完整官方字段、长代理指令、clone不污染源、旧占位配置升级、逐字节备份、effort/custom metadata保留、未知目标整批拒绝、Provider隔离、共享配置hash不变、锁和写失败注入。
- `Test-Catalog.ps1` 新增3项验证精确GPT6.1、非匹配ID及副本隔离，既有启动参数断言适配官方模板默认effort。
- 官方CLI0.167.1 Catalog+CredentialHelper专项两个引擎各24/24：完整目录实际加载、缺schema字段负例、外部凭据正确。证据 `tests/results/official-templates51.json/.log`、`official-templates7.json/.log`。仍未声称真实App GUI/真实网关全能力已验证。
- 实跑发现Windows偶发短暂文件删除共享锁使File.Replace报错；Write-RelayJson增加最多5次、总等待上限500毫秒的本地IO重试（最后一次不再等待）。保持原子替换、不截断原件，绝不重试收费API。
- 用户明确要求升级全部已添加模型后，实际检查默认Provider BI4KJD的6个目录条目，先备份再升级：GPT6-Sol/GPT6.1-Sol精确模板，其余保留ID使用GPT5.5模板。旧effort保留；共享config.toml SHA256前后不变。备份文件 `models.json.91b3f4ac6adf452ba32ec27f2b643bc3.bak` 位于该Provider受管目录。未调用真实模型、未改密钥或登录状态。

### 覆盖范围

- 六种标准 Base URL 输入、前缀保留、自定义根路径明确选择、重复 API 段与非法 URL。
- DPAPI 当前用户加解密、损坏密文错误、不持久化明文密钥。
- JSON 往返、损坏数据不静默覆盖、原子更新、Provider 删除。
- 多 Provider 的同名模型隔离、模型与兼容性缓存分离、重启加载。
- `/models` 实际本地 HTTP 请求、认证头、动态解析、重复 ID、空列表、错误结构、非 JSON。
- HTTP 401、403、404、429、500 分类；刷新失败旧缓存保留。
- 逐段 SSE、事件名及 data.type、生命周期、文本 delta、completed 成功状态。
- 普通 JSON、Chat Completions SSE、错误 JSON、failed/error、缺生命周期、缺文本、错误终止状态、提前断流不产生假阳性。
- 响应头等待及流读取超时、流量与事件边界保护。
- TOML 双引号/反斜杠/Unicode/控制字符转义，七组 `--config` 参数。
- 实际编译 C# argv recorder EXE，检验 Windows 原生参数往返。
- 实际启动 recorder 子进程，检查密钥仅在子进程环境，已有父环境值不变、原本无 Key 也不新增。
- 原有 `~/.codex/config.toml`（及已设置的 CODEX_HOME 配置）不变。
- 重复初始化目录不需要审计/安全特权，目录 ACL 限制当前用户及 SYSTEM。

Mock Server 为 Node.js 内置 `http`，仅监听 `127.0.0.1` 动态端口；假密钥和测试 fixture 与生产模型列表无关。没有真实收费 API 调用。

## 已发现并修复的问题

1. **Windows PowerShell 5.1 的 File.Replace 空备份参数**：`$null` 被绑定成空路径导致替换失败。改为 `[NullString]::Value`，原子更新与删除回归通过。
2. **第二次启动的 ACL 权限错误**：`Set-Acl` 尝试触及安全审计部分导致 `SeSecurityPrivilege` 错误。改为各运行时的 .NET DACL 专用设置，双版本反复初始化通过，不要求提升权限。
3. **Provider ID 正则默认不区分大小写**：改为 `-cnotmatch`，不接受大写或注入形态的 ID。新增回归还发现删除路径原先先写盘、后校验缓存 ID；现已将删除 ID 校验移到任何写入之前，确保非法 ID 报错时持久化数据完全不变。
4. 测试环境的 PowerShell 7 对缺失环境变量可能呈现 null/空串差异：测试改为启动前后精确比较原值，而不武断断言必须是某一种表示。应用启动逻辑没有修改父环境。

失败均在发现后复测，最终结果见落盘 JSON；没有把初轮失败宣称为通过。

## 官方 Codex 原生 EXE 验证

另使用 `.tools/verification` 下独立验证脚本，所有运行使用隔离临时 CODEX_HOME、假密钥、本地 HTTP Mock。不会读取真实 auth.json，也不执行登录操作。

最终官方 CLI 验证 **24/24 断言通过**，父进程环境严格比较不变，真实配置 SHA256 不变。机器汇总：`../.tools/verification/latest-summary.json`；最终证据目录：`../.tools/verification/run-20261111-205519-835cc569`。早期验证器恢复环境变量时出现 null→空串差异，已修正验证隔离方式并保留历史失败记录；没有将失败轮次当作通过。

已实测：

- 官方 0.167.1 帮助声明 `-c, --config <key=value>`，值按 TOML 解析，支持 dotted key。
- 七项自定义 Provider 覆盖可以被官方 CLI 加载；`-c` 与 `--config` 两种形式都接受。
- 原生 EXE 实际发出 `POST /v1/responses`；中文、空格、双引号及尾部反斜杠模型 ID 在捕获请求中保持一致。
- 两个独立子进程使用两个不同的假 Key，各自生成正确 Bearer；不提供专用 env_key 时 CLI 明确提示缺失密钥。
- `wire_api="chat"` 被此版本明确报告不再支持。
- `app-server --stdio` 的 `config/read` 可回读七项覆盖，名称和模型的特殊字符无损，来源为 `sessionFlags`。
- 所有 CLI 执行验证启用正常 `read-only` 沙箱及已确认支持的 `--no-daemon`，不使用危险权限绕过。

Mock 对此验证故意返回 HTTP 400，让 CLI 在完成配置加载和请求发出后安全退出。**此处 exec 退出码 1 是预期的 Mock 拒绝，不是完整推理成功。** 最小 SSE 成功路径由上述独立 HTTP/SSE 测试覆盖。

详细证据在工作区 `.tools/verification`，该目录属于开发验证辅助材料，不是运行管理器所必需的依赖。

## 菜单冒烟测试

- Windows PowerShell 5.1：指定隔离 CLI EXE，实际显示中文主菜单、检测版本、输入 0 正常退出。
- PowerShell 7：CLI 未在 PATH 情况下提示安装，不崩溃；输入无效菜单项后能重试；输入 8 显示状态，再输入 0 正常退出。
- 主脚本采用 UTF-8 BOM，避免 Windows PowerShell 5.1 中文乱码。

## 未执行或不保证的项目

- **真实中转站端到端调用**：用户未提供真实地址/密钥，本次不消耗余额；添加自己的 Provider 后需进行收费风险确认和实际探测。
- **真实 Codex 成功工具调用、多轮代码任务**：Mock 不等同于模型服务，未宣称验收。文本 SSE 通过不能推导工具兼容。
- **完整真人交互与 Ctrl+C 所有时机**：已执行菜单冒烟与原生子进程控制台设计，但自动化管道不能覆盖真实终端每个按键/焦点行为。
- **其他 Codex 版本及 Windows ARM64**：只实测 0.167.1、Windows x64；启动按帮助检测，版本变化仍可能需要适配。
- **跨 Windows 用户/设备 DPAPI**：设计上绑定当前用户，未伪造跨用户可解密测试。
- **默认共享 daemon 的密钥保留行为**：没有复现或证明存在泄露；支持时使用 `--no-daemon` 是防御性隔离措施。
- **安全擦除、同用户恶意软件防护**：普通文件删除与 DPAPI 不提供此保证，详见 README 安全边界。

## 复现

在 `codex-relay-manager` 目录中：

```powershell
powershell -NoProfile -File .\tests\Run-Tests.ps1 -ResultPath .\tests\results\powershell51.json
pwsh -NoProfile -File .\tests\Run-Tests.ps1 -ResultPath .\tests\results\powershell7.json
powershell -NoProfile -File .\tests\Run-Tests.ps1 -UsePester -ResultPath .\tests\results\pester51.json
pwsh -NoProfile -File .\tests\Run-Tests.ps1 -UsePester -ResultPath .\tests\results\pester7.json
```

不安装 Pester 也能运行前两条。Pester 适配器针对当前实测的 3.4/4.x API；未宣称 Pester 5 适配通过。
