# Universal Engine CLI

Universal Engine 目前已经收敛为一个面向 Linux 终端的防守型 CLI 工具，用于：

- 管理资产与项目
- 批量导入表格资产
- 对资产做测活与指纹识别
- 导入安全检测模板库
- 按指纹路由模板并执行检测
- 输出发现与报告
- 查询上游开源仓库地址

当前入口风格同时支持传统子命令和接近 `nmap` 的单命令参数风格。

## 安装

```bash
cd /opt/universal-engine
npm install
chmod +x ./install-linux.sh
sudo ./install-linux.sh
```

安装完成后可直接使用：

```bash
ue --status
```

如果不安装系统级软链接，也可以直接运行：

```bash
./ue --status
node cli/ue.js --status
```

## 常用命令

### nmap 风格

```bash
ue --status
ue --assets-list --project "Lab"
ue --asset-add --name "Demo" --target "https://demo.local" --project "Lab"
ue --assets-import-file --file ./targets.xlsx --project "Lab" --owner "Ops" --tags web,external
ue --assets-refingerprint --project "Lab"
ue --templates-import --path ./templates.zip
ue --templates-groups
ue --scan --project "Lab" --name "Nightly Scan"
ue --findings-list --project "Lab"
ue --report-latest --project "Lab" --format md --output ./lab-report.md
ue --settings-show
ue --upstream-lookup --query wordpress
```

### 传统子命令风格

```bash
ue status
ue assets list --project "Lab"
ue assets add --name "Demo" --target "https://demo.local"
ue assets import-file ./targets.xlsx --project "Lab"
ue assets refingerprint --project "Lab"
ue templates import ./templates.zip
ue templates groups
ue scans run --project "Lab"
ue reports latest --format json
```

## 典型使用流程

1. 查看状态与配置

```bash
ue --status
ue --settings-show
```

2. 导入资产

```bash
ue assets import-file ./targets.xlsx --project "Q3-External"
```

3. 进行指纹识别

```bash
ue assets refingerprint --project "Q3-External"
```

4. 导入模板库

```bash
ue templates import ./template-pack.zip
```

5. 发起扫描

```bash
ue scans run --project "Q3-External" --name "Baseline Scan"
```

6. 导出结果

```bash
ue findings list --project "Q3-External"
ue reports latest --project "Q3-External" --format md --output ./baseline-report.md
```

## 安全模板导入规则

当前模板导入器是“安全标准化管道”，不会把所有文件直接转成可执行检测逻辑。

支持导入：

- `zip`
- `yaml`
- `yml`
- `json`
- `md`
- `txt`

导入时会自动：

- 提取 `CVE`、产品名、标签、严重级别、引用链接
- 将内容标准化为统一模板记录
- 识别 `nuclei` 检测模板
- 区分 `runnable` 与 `metadataOnly`
- 做去重与分类归档

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
- 其他脚本或二进制类型

导入结果会返回：

- `imported`
- `skippedDuplicates`
- `importStats`
- `groups`

其中 `importStats` 会给出：

- `runnableTemplates`
- `metadataOnlyTemplates`
- `blockedFiles`
- `unsupportedFiles`
- `templatesByFamily`
- `templatesBySourceType`

## 当前能力边界

- 只允许安全可审计的检测模板进入执行链
- 元数据模板只用于归档、分类、比对，不执行
- 上游定位功能只返回源码仓库地址，不自动下载审计
- 默认数据存储在本地 JSON 状态文件中，不依赖数据库

## 目录结构

```text
universal engine/
  cli/                  CLI 入口
  ue                    Linux 启动器
  install-linux.sh      Linux 安装脚本
  server/lib/           核心服务层
  server/scripts/       辅助脚本
  data/runtime/         运行态数据
  public/               旧前端静态资源
```

## 运行数据

运行态默认保存在：

```text
data/runtime/state.json
```

## 附加说明

- `npm start` 当前默认启动 CLI
- `npm run server` 仍可临时启动旧服务端
- 更完整的开发说明见 [DEVELOPMENT.md](./DEVELOPMENT.md)
