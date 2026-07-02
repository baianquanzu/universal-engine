# Universal Engine Development Guide

本文件面向两类读者：

- 新接手的开发者
- 需要继续迭代本项目的代码模型

目标是让接手方可以在尽量少上下文的情况下，快速理解程序结构、数据流、约束边界与下一步改造位置。

## 1. 项目定位

Universal Engine 当前是一个防守型 Linux CLI 工具，不再以 Web UI 作为主入口。

它的职责是：

- 导入与管理资产
- 从表格中自动提取 URL 并测活
- 进行指纹识别
- 导入安全检测模板
- 根据指纹路由模板
- 执行检测并生成发现与报告
- 定位上游开源仓库地址

它不是：

- 自动利用框架
- 通用 exploit 执行器
- 白盒自动下载审计平台

## 2. 当前入口

主入口：

- `cli/ue.js`

Linux 启动器：

- `ue`

安装脚本：

- `install-linux.sh`

Node 包入口：

- `package.json`
  - `start`: `node cli/ue.js`
  - `cli`: `node cli/ue.js`
  - `server`: `node server/index.js`

## 3. 核心目录

```text
universal engine/
  cli/
    ue.js
  server/
    index.js
    lib/
      state.js
      asset-import-service.js
      fingerprint-service.js
      builtin-fingerprint-library.js
      ai-fingerprint-service.js
      template-service.js
      nuclei-executor.js
      scan-orchestrator.js
      ai-review-service.js
      upstream-locator-service.js
    scripts/
      import-github-templates.js
  data/
    runtime/
      state.json
```

## 4. 状态存储

状态文件：

- `data/runtime/state.json`

默认由 `server/lib/state.js` 负责加载与保存。

主要状态字段：

- `assets`
- `templates`
- `tasks`
- `queue`
- `upstreamLookups`
- `findings`
- `reports`
- `settings`

这是一个本地 JSON 状态仓，不是数据库。做功能改造时，优先保持 schema 兼容。

## 5. CLI 命令面

当前 CLI 分组：

- `status`
- `assets`
- `templates`
- `scans`
- `findings`
- `reports`
- `settings`
- `upstream`

同时支持 flag 映射风格，例如：

- `ue --status`
- `ue --assets-list`
- `ue --templates-import --path ./pack.zip`
- `ue --scan --project "Lab"`

如果扩展命令，优先同时维护：

- 子命令模式
- flag 映射模式

## 6. 核心工作流

### 6.1 资产工作流

1. 用户导入表格或手动新增资产
2. `asset-import-service.js` 提取 URL 候选
3. 系统进行测活并补充标题、状态码、最终 URL
4. 资产被写入 `state.assets`
5. 用户执行 `assets refingerprint`
6. `fingerprint-service.js` 生成资产指纹

### 6.2 模板工作流

1. 用户导入目录、压缩包或文本文件
2. `template-service.js` 执行安全导入
3. 内容被标准化为统一模板对象
4. 模板被分成：
   - `runnable`
   - `metadataOnly`
5. 去重后写入 `state.templates`

### 6.3 扫描工作流

1. 用户发起扫描任务
2. `scan-orchestrator.js` 创建任务
3. 对资产做指纹识别
4. 根据指纹筛选匹配模板
5. 仅对 `runnable` 模板进入执行
6. `nuclei-executor.js` 调用 nuclei
7. 收集 findings
8. 如启用 AI，则交给 `ai-review-service.js` 做复核
9. 生成 report 并写入状态

### 6.4 上游定位工作流

1. 用户传入资产 ID 或关键词
2. `upstream-locator-service.js` 构造查询
3. 调用 GitHub 搜索候选仓库
4. 返回源码地址与下载地址

注意：当前不自动拉取源码，也不自动审计。

## 7. 模板模型

统一模板对象的关键字段包括：

- `id`
- `nucleiId`
- `sourceName`
- `sourceType`
- `importFormat`
- `name`
- `severity`
- `tags`
- `product`
- `category`
- `frameworkFamily`
- `classificationLabel`
- `safe`
- `runnable`
- `executionMode`
- `metadataOnly`
- `cveIds`
- `references`
- `versionRange`
- `summary`
- `raw`

语义说明：

- `runnable=true` 且 `raw` 存在：允许进入执行链
- `metadataOnly=true`：仅用于归档、分类、比对，不执行
- `sourceType=nuclei`：来自标准检测模板
- `sourceType=advisory`：来自公告、描述、元数据文件

## 8. 安全导入边界

模板导入器的设计是本项目当前最重要的安全边界之一。

支持文件类型：

- `zip`
- `yaml`
- `yml`
- `json`
- `md`
- `txt`

默认拦截：

- `py`
- `js`
- `ts`
- `go`
- `php`
- `sh`
- `ps1`
- `bat`
- `cmd`
- `exe`
- `dll`
- `jar`
- 其他脚本与二进制

额外规则：

- nuclei 模板若包含高风险执行段，当前不会进入 `runnable`
- 未知文本可转为 `metadataOnly` 记录
- JSON/YAML 公告会被尽量提取为结构化元数据

如果未来要扩展模板支持，优先继续沿用“标准化 + 分级 + 默认不执行”的思路。

## 9. 关键模块说明

### `server/lib/state.js`

负责：

- 默认状态
- 加载状态文件
- 深度合并老状态
- 保存状态

### `server/lib/asset-import-service.js`

负责：

- 从表格文本中提取 URL
- 测活
- 自动命名
- 生成导入资产对象

### `server/lib/fingerprint-service.js`

负责：

- 内置规则匹配
- 结合页面标题、头部、URL、正文片段识别产品
- 在需要时调用 AI 做最终归类

### `server/lib/template-service.js`

负责：

- 安全模板导入
- 解析 ZIP / YAML / JSON / MD / TXT
- 标准化模板对象
- 分类
- 去重
- 拦截危险文件

这是当前最敏感、最值得继续维护的模块之一。

### `server/lib/scan-orchestrator.js`

负责：

- 创建任务
- 多资产并发扫描
- 模板匹配
- 更新任务进度
- 处理 findings
- 生成报告

### `server/lib/nuclei-executor.js`

负责：

- 将 `runnable` 模板写入临时文件
- 调用 nuclei
- 解析 JSONL 输出
- 转为 finding

如果模板是 `metadataOnly`，这里会直接跳过。

### `server/lib/ai-review-service.js`

负责：

- 对 findings 做 AI 复核
- 输出 `confirmed / likely / pending` 等结果

### `server/lib/upstream-locator-service.js`

负责：

- 按资产或关键词检索 GitHub 仓库
- 返回仓库地址、候选、ZIP 下载地址

## 10. 进度与彩色输出

CLI 中已经有一组可复用的输出辅助函数，位于：

- `cli/ue.js`

包括：

- `tone`
- `renderBar`
- `showProgress`
- `printSection`
- `printKeyValue`

如果后续继续优化 CLI 交互，优先复用这些能力，不要重复造一套输出系统。

## 11. 当前已知问题

### 11.1 CLI 文件仍有少量历史乱码

`cli/ue.js` 中仍有部分旧中文字符串是历史编码遗留，功能不受影响，但后续建议统一清理。

### 11.2 状态文件会持续增长

当前 `state.json` 长期运行会不断累积：

- tasks
- findings
- reports
- templates

后续建议增加：

- 归档
- 分页导出
- 状态压缩
- SQLite 持久化

### 11.3 旧 Web 端仍在仓库中

`public/` 与 `server/index.js` 还保留旧服务端能力，但它已经不是主交互入口。继续开发 CLI 时，优先保证 CLI 逻辑完整。

## 12. 推荐扩展方向

优先级较高：

1. 完善 CLI 彩色摘要输出
2. 给 `templates import` 增加实时进度条
3. 增加 `templates audit` 查看被拦截文件和元数据模板
4. 增加 `assets export` / `findings export` / `reports export`
5. 把状态层从 JSON 迁移到 SQLite

可选方向：

1. 模板质量评分
2. 模板签名校验
3. 离线模板仓索引
4. 多项目状态隔离
5. 更清晰的任务日志流

## 13. 修改约束

接手模型或开发者建议遵守：

- 默认保持 ASCII 编辑风格
- 继续使用 `apply_patch` 做人工改动
- 不要把元数据模板直接变成可执行逻辑
- 不要绕过 `runnable` / `metadataOnly` 边界
- 不要删除用户已有状态文件，除非明确要求
- 优先兼容现有 `state.json` 结构

## 14. 快速验证命令

```bash
node cli/ue.js --help
node cli/ue.js --status
node cli/ue.js templates groups
node cli/ue.js settings show
```

模板导入验证：

```bash
node cli/ue.js templates import ./template-pack
```

扫描验证：

```bash
node cli/ue.js scans run --project "Default Project"
```

## 15. 给下一位模型的最短提示

如果你是接手本项目的模型，先做这几件事：

1. 读 `README.md`
2. 读本文件
3. 读 `cli/ue.js`
4. 读 `server/lib/template-service.js`
5. 读 `server/lib/scan-orchestrator.js`
6. 读 `server/lib/state.js`

然后再决定改 CLI、改状态层，还是改模板导入链路。
