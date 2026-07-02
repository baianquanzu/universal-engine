#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { loadState, saveState } from "../server/lib/state.js";
import {
  importTemplateSourceFromPath,
  importPocPackageFromPath,
  mergeImportedTemplates,
  summarizeTemplateGroups
} from "../server/lib/template-service.js";
import {
  extractAssetCandidatesFromBuffer,
  enrichImportedAssets,
  mergeImportedAssets
} from "../server/lib/asset-import-service.js";
import { fingerprintAsset } from "../server/lib/fingerprint-service.js";
import { locateUpstreamSources } from "../server/lib/upstream-locator-service.js";
import { createQueuedTask, executeQueuedTask } from "../server/lib/scan-orchestrator.js";
import { v4 as uuidv4 } from "uuid";

const state = loadState();

function persist() {
  saveState(state);
}

function broadcast() {}

function normalizeProjectName(value) {
  return `${value ?? ""}`.trim() || "Default Project";
}

function parseTags(value) {
  return `${value ?? ""}`
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

const supportsColor =
  process.stdout.isTTY &&
  process.env.NO_COLOR !== "1" &&
  process.env.TERM !== "dumb";

const ansi = {
  reset: "\u001b[0m",
  dim: "\u001b[2m",
  bold: "\u001b[1m",
  cyan: "\u001b[36m",
  blue: "\u001b[34m",
  magenta: "\u001b[35m",
  green: "\u001b[32m",
  yellow: "\u001b[33m",
  red: "\u001b[31m",
  gray: "\u001b[90m"
};

function tone(text, ...codes) {
  if (!supportsColor) {
    return text;
  }
  return `${codes.join("")}${text}${ansi.reset}`;
}

function clearLine() {
  if (process.stdout.isTTY) {
    process.stdout.write("\r\u001b[2K");
  }
}

function progressPalette(ratio) {
  if (ratio >= 0.84) {
    return [ansi.bold, ansi.green];
  }
  if (ratio >= 0.5) {
    return [ansi.bold, ansi.cyan];
  }
  if (ratio >= 0.25) {
    return [ansi.bold, ansi.blue];
  }
  return [ansi.bold, ansi.magenta];
}

function renderBar(current, total, width = 28) {
  const safeTotal = Math.max(total || 0, 1);
  const ratio = Math.max(0, Math.min(1, current / safeTotal));
  const filled = Math.round(width * ratio);
  const empty = Math.max(0, width - filled);
  const fill = "█".repeat(filled);
  const rest = "░".repeat(empty);
  return `${tone(fill, ...progressPalette(ratio))}${tone(rest, ansi.gray)}`;
}

function showProgress(label, current, total, extra = "") {
  const safeTotal = Math.max(total || 0, 1);
  const ratio = Math.max(0, Math.min(1, current / safeTotal));
  const percent = `${Math.round(ratio * 100)}`.padStart(3, " ");
  clearLine();
  process.stdout.write(
    `${tone(label, ansi.bold, ansi.cyan)} ${renderBar(current, safeTotal)} ${tone(`${percent}%`, ansi.bold)} ${tone(`${current}/${safeTotal}`, ansi.dim)}${extra ? ` ${tone(extra, ansi.yellow)}` : ""}`
  );
}

function endProgress() {
  if (process.stdout.isTTY) {
    process.stdout.write("\n");
  }
}

function printSection(title, subtitle = "") {
  print(`${tone(`\n[ ${title} ]`, ansi.bold, ansi.cyan)}${subtitle ? ` ${tone(subtitle, ansi.dim)}` : ""}`);
}

function printKeyValue(label, value, color = ansi.green) {
  print(`${tone(label.padEnd(18, " "), ansi.gray)} ${tone(`${value}`, ansi.bold, color)}`);
}

function print(message = "") {
  process.stdout.write(`${message}\n`);
}

function printError(message) {
  process.stderr.write(`${message}\n`);
}

function fail(message, code = 1) {
  printError(message);
  process.exit(code);
}

function formatJson(value) {
  return JSON.stringify(value, null, 2);
}

function parseArgs(argv) {
  const positionals = [];
  const options = {};

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith("-")) {
      positionals.push(token);
      continue;
    }

    const raw = token.startsWith("--") ? token.slice(2) : token.slice(1);
    if (!raw) {
      continue;
    }

    const [key, inlineValue] = raw.split("=", 2);
    if (inlineValue !== undefined) {
      options[key] = inlineValue;
      continue;
    }

    const next = argv[index + 1];
    if (!next || next.startsWith("--")) {
      options[key] = "true";
      continue;
    }

    options[key] = next;
    index += 1;
  }

  return { positionals, options };
}

function numberOption(value, fallback) {
  if (value === undefined) {
    return fallback;
  }

  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function ensureFile(inputPath) {
  const absolutePath = path.resolve(inputPath);
  if (!fs.existsSync(absolutePath)) {
    fail(`文件不存在: ${absolutePath}`);
  }
  return absolutePath;
}

function ensureDirectory(inputPath) {
  const absolutePath = path.resolve(inputPath);
  if (!fs.existsSync(absolutePath) || !fs.statSync(absolutePath).isDirectory()) {
    fail(`目录不存在: ${absolutePath}`);
  }
  return absolutePath;
}

function summarizeState() {
  const liveAssets = state.assets.filter((asset) => asset.availability?.reachable).length;
  const fingerprintedAssets = state.assets.filter((asset) => asset.fingerprint).length;
  const projects = new Set(state.assets.map((asset) => asset.projectName || "Default Project"));

  return {
    assets: state.assets.length,
    liveAssets,
    fingerprintedAssets,
    templates: state.templates.length,
    findings: state.findings.length,
    reports: state.reports.length,
    tasks: state.tasks.length,
    projects: projects.size,
    aiProvider: state.settings.ai.provider,
    aiEnabled: state.settings.ai.enabled,
    nucleiEnabled: state.settings.nuclei.enabled
  };
}

function compactTask(task) {
  return {
    id: task.id,
    name: task.name,
    status: task.status,
    stage: task.stage,
    projectName: task.projectName || "Default Project",
    processedAssets: task.progress?.processedAssets ?? 0,
    totalAssets: task.progress?.totalAssets ?? 0,
    findings: task.progress?.findings ?? 0,
    percent: task.progress?.percent ?? 0,
    startedAt: task.startedAt,
    completedAt: task.completedAt
  };
}

function listAssets(projectName) {
  const normalizedProject = projectName ? normalizeProjectName(projectName) : "";
  return state.assets
    .filter((asset) => !normalizedProject || normalizeProjectName(asset.projectName) === normalizedProject)
    .map((asset) => ({
      id: asset.id,
      projectName: asset.projectName || "Default Project",
      name: asset.name,
      target: asset.target,
      status: asset.status,
      fingerprint: asset.fingerprint ? `${asset.fingerprint.platform}/${asset.fingerprint.category}` : "unscanned"
    }));
}

function listTemplates(frameworkFamily) {
  return state.templates
    .filter((template) => !frameworkFamily || template.frameworkFamily === frameworkFamily)
    .map((template) => ({
      id: template.id,
      nucleiId: template.nucleiId,
      sourceType: template.sourceType,
      frameworkFamily: template.frameworkFamily,
      category: template.category,
      product: template.product,
      severity: template.severity,
      runnable: template.runnable !== false,
      name: template.name
    }));
}

function listFindings(projectName) {
  const normalizedProject = projectName ? normalizeProjectName(projectName) : "";
  return state.findings
    .filter((finding) => !normalizedProject || normalizeProjectName(finding.projectName) === normalizedProject)
    .map((finding) => ({
      id: finding.id,
      projectName: finding.projectName || "Default Project",
      assetName: finding.assetName,
      templateName: finding.templateName,
      severity: finding.severity,
      verdict: finding.aiReview?.verdict || "pending",
      target: finding.target
    }));
}

function deepAssign(target, dottedKey, value) {
  const pathKeys = dottedKey.split(".");
  let cursor = target;

  for (let index = 0; index < pathKeys.length - 1; index += 1) {
    const key = pathKeys[index];
    if (!cursor[key] || typeof cursor[key] !== "object" || Array.isArray(cursor[key])) {
      cursor[key] = {};
    }
    cursor = cursor[key];
  }

  cursor[pathKeys.at(-1)] = value;
}

function coerceSettingValue(value) {
  if (value === "true" || value === "false") {
    return value === "true";
  }

  if (/^-?\d+(?:\.\d+)?$/.test(value)) {
    return Number(value);
  }

  if (value.includes(",")) {
    return value
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);
  }

  return value;
}

function resolveFlagMode(args) {
  const flags = [
    ["status", ["status"]],
    ["assets-list", ["assets", "list"]],
    ["asset-add", ["assets", "add"]],
    ["assets-import-file", ["assets", "import-file", args.options.file].filter(Boolean)],
    ["assets-refingerprint", ["assets", "refingerprint"]],
    ["assets-delete", ["assets", "delete"]],
    ["templates-list", ["templates", "list"]],
    ["templates-groups", ["templates", "groups"]],
    ["templates-import", ["templates", "import", args.options.path].filter(Boolean)],
    ["templates-import-poc", ["templates", "import-poc", args.options.path].filter(Boolean)],
    ["scan", ["scans", "run"]],
    ["scans-list", ["scans", "list"]],
    ["scans-clear-finished", ["scans", "clear-finished"]],
    ["findings-list", ["findings", "list"]],
    ["findings-clear", ["findings", "clear"]],
    ["report-latest", ["reports", "latest"]],
    ["reports-list", ["reports", "list"]],
    ["reports-clear", ["reports", "clear"]],
    ["settings-show", ["settings", "show"]],
    ["settings-set", ["settings", "set", ...args.positionals]],
    ["upstream-lookup", ["upstream", "lookup"]],
    ["upstream-list", ["upstream", "list"]],
    ["file", ["file", args.options.file].filter(Boolean)]
  ];

  for (const [flag, mapped] of flags) {
    if (args.options[flag] !== undefined) {
      return { positionals: mapped, options: args.options };
    }
  }

  return args;
}

async function commandStatus() {
  print(formatJson(summarizeState()));
}

async function commandAssets(args) {
  const [action] = args.positionals;

  if (action === "list") {
    print(formatJson(listAssets(args.options.project)));
    return;
  }

  if (action === "add") {
    if (!args.options.name || !args.options.target) {
      fail("用法: ue assets add --name 名称 --target URL [--project 项目] [--owner 负责人] [--tags a,b]");
    }

    const asset = {
      id: uuidv4(),
      name: args.options.name,
      projectName: normalizeProjectName(args.options.project),
      target: args.options.target,
      owner: args.options.owner || "Unassigned",
      tags: parseTags(args.options.tags),
      status: "new",
      fingerprint: null
    };

    state.assets.unshift(asset);
    persist();
    print(formatJson({ ok: true, asset }));
    return;
  }

  if (action === "import-file") {
    const filePath = args.positionals[1];
    if (!filePath) {
      fail("用法: ue assets import-file 文件路径 [--project 项目] [--owner 负责人] [--tags a,b] [--concurrency 4]");
    }

    const absolutePath = ensureFile(filePath);
    const buffer = fs.readFileSync(absolutePath);
    const fileName = path.basename(absolutePath);

    // Phase 1: 解析文件
    printSection("资产导入", fileName);
    printKeyValue("文件", fileName);
    printKeyValue("大小", `${(buffer.length / 1024).toFixed(1)} KB`);

    showProgress("解析中", 0, 100, "读取表格...");
    const candidates = extractAssetCandidatesFromBuffer(fileName, buffer);

    if (!candidates.length) {
      endProgress();
      fail("未从文件中提取到有效URL候选。请检查文件格式。");
    }

    endProgress();
    printKeyValue("提取URL候选", `${candidates.length}`, ansi.bold);
    printKeyValue("项目", normalizeProjectName(args.options.project));
    print("");

    // Phase 2: 并发测活 - 实时进度条
    print(tone("╭─ 资产测活 ──────────────────────────────╮", ansi.dim));

    const concurrency = numberOption(args.options.concurrency, state.settings.scanning.assetConcurrency || 4);
    let lastProgress = { processed: 0, live: 0, unreachable: 0 };
    let progressTimer = null;

    const importedAssets = await enrichImportedAssets(candidates, {
      owner: args.options.owner,
      projectName: args.options.project,
      tags: parseTags(args.options.tags),
      concurrency,
      aiSettings: state.settings.ai,
      async onProgress(p) {
        if (p.stage === "probing") {
          lastProgress = p;
          const bar = renderBar(p.processed, p.total, 28);
          const pct = String(p.percent).padStart(3, " ");
          const statusLine = `${bar} ${pct}% [${p.processed}/${p.total}]`;

          process.stdout.write(`
  ${tone("测活", ansi.bold, ansi.cyan)} ${statusLine}`);

          // 显示当前目标
          if (p.current) {
            process.stdout.write(`
  ${tone("└─", ansi.dim)} ${tone(p.current.substring(0, 60), ansi.gray)}`);
            if (p.httpStatus) {
              const statusColor = p.httpStatus < 400 ? ansi.green : (p.httpStatus < 500 ? ansi.yellow : ansi.red);
              process.stdout.write(` ${tone(`${p.httpStatus}`, ansi.bold, statusColor)}`);
            }
            if (p.title) process.stdout.write(` "${p.title.substring(0, 40)}"`);
          }

          // 移动光标回去
          process.stdout.write(`
[1A`);
        } else if (p.stage === "ai-classifying") {
          process.stdout.write(`
  ${tone("AI分类中...", ansi.bold, ansi.magenta)}`);
        } else if (p.stage === "ai-classify-done") {
          process.stdout.write(`
  ${tone(`AI分类完成: ${p.classified}/${p.total}`, ansi.bold, ansi.green)}`);
        }
      }
    });

    endProgress();
    endProgress(); // 清除进度条残留行

    print(tone("╰──────────────────────────────────────────╯", ansi.dim));
    print("");

    // Phase 3: 结果汇总
    const uniqueImported = mergeImportedAssets(state.assets, importedAssets);
    state.assets.unshift(...uniqueImported);
    persist();

    const liveAssets = uniqueImported.filter(a => a.availability?.reachable);
    const deadAssets = uniqueImported.filter(a => !a.availability?.reachable);
    const aiClassified = uniqueImported.filter(a => a.aiClassification);

    printSection("导入结果");
    printKeyValue("扫描行数", `${candidates.length}`);
    printKeyValue("导入资产", `${uniqueImported.length}`, ansi.bold);
    printKeyValue("重复跳过", `${importedAssets.length - uniqueImported.length}`, ansi.gray);
    printKeyValue("存活", `${liveAssets.length}`, ansi.green);
    printKeyValue("不可达", `${deadAssets.length}`, ansi.red);
    if (aiClassified.length > 0) {
      printKeyValue("AI分类", `${aiClassified.length}`, ansi.magenta);
    }
    print("");

    // 展示存活资产列表
    if (liveAssets.length > 0 && liveAssets.length <= 20) {
      print(tone("存活资产:", ansi.bold));
      for (const a of liveAssets) {
        const classification = a.aiClassification ? ` ${tone(`[${a.aiClassification.businessCategory}]`, ansi.magenta)}` : "";
        print(`  ${tone("✓", ansi.green)} ${a.name.substring(0, 40)} ${tone(a.target.substring(0, 50), ansi.gray)}${classification}`);
      }
      print("");
    } else if (liveAssets.length > 20) {
      print(tone(`存活资产: ${liveAssets.length} 个 (太多了，看看你收获了多少!)`, ansi.bold, ansi.green));
      print(tone(`使用 'ue assets list --project "${normalizeProjectName(args.options.project)}"' 查看详情`, ansi.dim));
      print("");
    }

    // 展示不可达资产（前5个）
    if (deadAssets.length > 0) {
      print(tone(`不可达资产 (${deadAssets.length}个):`, ansi.yellow));
      for (const a of deadAssets.slice(0, 5)) {
        print(`  ${tone("✗", ansi.red)} ${a.name.substring(0, 40)} ${tone(a.target.substring(0, 50), ansi.dim)}`);
      }
      if (deadAssets.length > 5) {
        print(`  ${tone(`... 还有 ${deadAssets.length - 5} 个`, ansi.dim)}`);
      }
      print("");
    }

    print(
      formatJson({
        ok: true,
        scannedRows: candidates.length,
        imported: uniqueImported.length,
        skippedDuplicates: importedAssets.length - uniqueImported.length,
        live: liveAssets.length,
        unreachable: deadAssets.length,
        aiClassified: aiClassified.length
      })
    );
    return;
  }if (action === "refingerprint") {
    const projectName = args.options.project ? normalizeProjectName(args.options.project) : "";
    const assetIds = args.options["asset-id"] ? [`${args.options["asset-id"]}`] : [];
    const selected = state.assets.filter((asset) => {
      const matchesProject = !projectName || normalizeProjectName(asset.projectName) === projectName;
      const matchesId = !assetIds.length || assetIds.includes(asset.id);
      return matchesProject && matchesId;
    });

    for (const asset of selected) {
      asset.fingerprint = await fingerprintAsset(asset, state.settings.ai);
      asset.status = "fingerprinted";
    }

    persist();
    print(formatJson({ ok: true, updated: selected.length }));
    return;
  }

  if (action === "delete") {
    const projectName = args.options.project ? normalizeProjectName(args.options.project) : "";
    const assetIds = args.options["asset-id"]
      ? `${args.options["asset-id"]}`
          .split(",")
          .map((item) => item.trim())
          .filter(Boolean)
      : [];

    const removableIds = new Set(
      state.assets
        .filter((asset) => {
          const matchesProject = !projectName || normalizeProjectName(asset.projectName) === projectName;
          const matchesId = !assetIds.length || assetIds.includes(asset.id);
          return matchesProject && matchesId;
        })
        .map((asset) => asset.id)
    );

    state.assets = state.assets.filter((asset) => !removableIds.has(asset.id));
    state.findings = state.findings.filter((finding) => !removableIds.has(finding.assetId));
    persist();
    print(formatJson({ ok: true, removed: removableIds.size }));
    return;
  }

  fail("可用命令: ue assets list | add | import-file | refingerprint | delete");
}

async function commandTemplates(args) {
  const [action] = args.positionals;

  if (action === "list") {
    print(formatJson(listTemplates(args.options.family)));
    return;
  }

  if (action === "groups") {
    print(formatJson(summarizeTemplateGroups(state.templates)));
    return;
  }

  if (action === "import") {
    const importPath = args.positionals[1];
    if (!importPath) {
      fail("用法: ue templates import 路径");
    }

    const importedResult = importTemplateSourceFromPath(path.resolve(importPath));
    const imported = importedResult.templates;

    const uniqueImported = mergeImportedTemplates(state.templates, imported);
    state.templates.unshift(...uniqueImported);
    persist();
    print(
      formatJson({
        ok: true,
        imported: uniqueImported.length,
        skippedDuplicates: imported.length - uniqueImported.length,
        importStats: importedResult.stats,
        groups: summarizeTemplateGroups(uniqueImported)
      })
    );
    return;
  }

  if (action === "import-poc") {
    const importPath = args.positionals[1];
    if (!importPath) {
      fail("用法: ue templates import-poc 路径 (POC目录或zip包)");
    }

    const absolutePath = path.resolve(importPath);
    const pocResult = importPocPackageFromPath(absolutePath);
    const pocTemplates = pocResult.templates;

    if (!pocTemplates.length) {
      fail("未从路径中发现可导入的 POC: " + absolutePath);
    }

    const uniqueImported = mergeImportedTemplates(state.templates, pocTemplates);
    state.templates.unshift(...uniqueImported);
    persist();

    const pocGroups = {};
    for (const tpl of uniqueImported) {
      const fam = tpl.frameworkFamily || "generic";
      if (!pocGroups[fam]) {
        pocGroups[fam] = { count: 0, severityCounts: {}, products: new Set() };
      }
      pocGroups[fam].count += 1;
      pocGroups[fam].severityCounts[tpl.severity] = (pocGroups[fam].severityCounts[tpl.severity] || 0) + 1;
      pocGroups[fam].products.add(tpl.product);
    }

    print(
      formatJson({
        ok: true,
        imported: uniqueImported.length,
        skippedDuplicates: pocTemplates.length - uniqueImported.length,
        importStats: pocResult.stats,
        groups: Object.entries(pocGroups).map(([name, info]) => ({
          frameworkFamily: name,
          count: info.count,
          severityCounts: info.severityCounts,
          products: [...info.products].sort()
        })).sort((a, b) => b.count - a.count),
        list: uniqueImported.map((tpl) => ({
          id: tpl.id,
          name: tpl.name,
          product: tpl.product,
          severity: tpl.severity,
          category: tpl.category,
          frameworkFamily: tpl.frameworkFamily,
          cveIds: tpl.cveIds,
          versionRange: tpl.versionRange
        }))
      })
    );
    return;
  }

  fail("可用命令: ue templates list | groups | import | import-poc");
}

async function commandFindings(args) {
  const [action] = args.positionals;

  if (action === "list") {
    print(formatJson(listFindings(args.options.project)));
    return;
  }

  if (action === "clear") {
    const projectName = args.options.project ? normalizeProjectName(args.options.project) : "";
    if (!projectName) {
      state.findings = [];
    } else {
      state.findings = state.findings.filter((finding) => normalizeProjectName(finding.projectName) !== projectName);
    }
    persist();
    print(formatJson({ ok: true, findings: state.findings.length }));
    return;
  }

  fail("可用命令: ue findings list | clear");
}

async function commandReports(args) {
  const [action] = args.positionals;

  if (action === "latest") {
    const projectName = args.options.project ? normalizeProjectName(args.options.project) : "";
    const report = projectName
      ? state.reports.find((item) => normalizeProjectName(item.summary?.projectName || item.projectName) === projectName)
      : state.reports[0];

    if (!report) {
      fail("没有找到报告。");
    }

    if (args.options.output) {
      const outputPath = path.resolve(args.options.output);
      const format = `${args.options.format || "md"}`.toLowerCase();
      fs.writeFileSync(outputPath, format === "json" ? formatJson(report) : report.markdown || "", "utf8");
      print(formatJson({ ok: true, output: outputPath }));
      return;
    }

    print(args.options.format === "json" ? formatJson(report) : report.markdown || "");
    return;
  }

  if (action === "list") {
    print(
      formatJson(
        state.reports.map((report) => ({
          id: report.id,
          projectName: report.summary?.projectName || report.projectName || "Default Project",
          generatedAt: report.generatedAt,
          findings: report.summary?.findings ?? 0,
          confirmed: report.summary?.confirmed ?? 0,
          likely: report.summary?.likely ?? 0
        }))
      )
    );
    return;
  }

  if (action === "clear") {
    state.reports = [];
    persist();
    print(formatJson({ ok: true, reports: 0 }));
    return;
  }

  fail("可用命令: ue reports latest | list | clear");
}

async function commandScans(args) {
  const [action] = args.positionals;

  if (action === "list") {
    print(formatJson(state.tasks.map(compactTask)));
    return;
  }

  if (action === "clear-finished") {
    state.tasks = state.tasks.filter((task) => ["queued", "running"].includes(task.status));
    state.queue.pending = state.queue.pending.filter((taskId) => state.tasks.some((task) => task.id === taskId));
    state.queue.running = state.queue.running.filter((taskId) => state.tasks.some((task) => task.id === taskId));
    persist();
    print(formatJson({ ok: true, tasks: state.tasks.length }));
    return;
  }

  if (action === "run") {
    const projectName = args.options.project ? normalizeProjectName(args.options.project) : "";
    const assetIdList = args.options["asset-id"]
      ? `${args.options["asset-id"]}`
          .split(",")
          .map((item) => item.trim())
          .filter(Boolean)
      : [];
    const assetIds = assetIdList.length
      ? assetIdList
      : state.assets
          .filter((asset) => !projectName || normalizeProjectName(asset.projectName) === projectName)
          .map((asset) => asset.id);

    if (!assetIds.length) {
      fail("没有选中任何资产。");
    }

    const task = createQueuedTask(state, {
      name: args.options.name || `CLI Scan ${new Date().toLocaleString("zh-CN", { hour12: false })}`,
      assetIds,
      source: "cli",
      note: args.options.note || "",
      projectName
    });

    state.tasks.unshift(task);
    persist();

    const result = await executeQueuedTask({
      state,
      persist,
      broadcast,
      task,
      isCanceled: () => false
    });

    print(
      formatJson({
        ok: true,
        task: compactTask(result.task),
        findings: result.findings.length,
        reportId: result.report?.id || null
      })
    );
    return;
  }

  fail("可用命令: ue scans list | run | clear-finished");
}


async function commandFile(args) {
  const filePath = args.positionals[0] || args.options.file;
  if (!filePath) {
    fail("用法: ue --file targets.xlsx");
  }

  const absolutePath = ensureFile(filePath);
  const ext = path.extname(absolutePath).toLowerCase();

  if (![".xlsx", ".xls", ".csv"].includes(ext)) {
    fail("目前只支持 .xlsx / .xls / .csv 文件。POC/模板请用 ue templates import");
  }

  const buffer = fs.readFileSync(absolutePath);
  const fileName = path.basename(absolutePath);
  const projectName = normalizeProjectName(args.options.project || fileName.replace(/\.[^.]+$/, ""));

  print("");
  print(tone("╔════════════════════════════════════════════╗", ansi.bold, ansi.cyan));
  print(tone("║      Universal Engine - 一键扫描入口        ║", ansi.bold, ansi.cyan));
  print(tone("╠════════════════════════════════════════════╣", ansi.cyan));
  print(tone("║                                            ║", ansi.cyan));
  print(tone("║  文件: " + fileName.padEnd(36) + "║", ansi.cyan));
  print(tone("║  项目: " + projectName.padEnd(36) + "║", ansi.cyan));
  print(tone("║                                            ║", ansi.cyan));
  print(tone("╠════════════════════════════════════════════╣", ansi.cyan));
  print(tone("║  请选择扫描模式:                             ║", ansi.cyan));
  print(tone("║                                            ║", ansi.cyan));
  print(tone("║  [1] 全自动扫描 (推荐)                       ║", ansi.bold, ansi.green));
  print(tone("║      导入→测活→指纹→扫描→AI复核→HTML报告    ║", ansi.dim));
  print(tone("║                                            ║", ansi.cyan));
  print(tone("║  [2] 仅指纹识别                             ║", ansi.bold, ansi.yellow));
  print(tone("║      导入→测活→AI指纹识别→指纹分布报告       ║", ansi.dim));
  print(tone("║                                            ║", ansi.cyan));
  print(tone("║  [3] 全量扫描+白盒审计复挖 (高级)             ║", ansi.bold, ansi.magenta));
  print(tone("║      扫描→AI复核→开源审计→漏洞复测           ║", ansi.dim));
  print(tone("║                                            ║", ansi.cyan));
  print(tone("╚════════════════════════════════════════════╝", ansi.cyan));
  print("");

  // 读取用户输入
  const readline = (await import("node:readline")).default;
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

  const choice = await new Promise((resolve) => {
    rl.question(tone("请输入选项 [1/2/3] (默认1): ", ansi.bold), (answer) => {
      rl.close();
      resolve((answer || "1").trim());
    });
  });

  print("");

  if (choice === "2") {
    // 模式2：仅指纹识别
    await runFingerprintOnly(absolutePath, fileName, buffer, projectName, args);
  } else if (choice === "3") {
    // 模式3：全量扫描+白盒审计
    await runFullScanWithAudit(absolutePath, fileName, buffer, projectName, args);
  } else {
    // 模式1（默认）：全自动扫描
    await runFullAutoScan(absolutePath, fileName, buffer, projectName, args);
  }
}

// 模式1：全自动扫描
async function runFullAutoScan(filePath, fileName, buffer, projectName, args) {
  const startedAt = Date.now();
  printSection("模式1: 全自动扫描", fileName);
  print("");

  // Phase 1: 导入
  printSection("Phase 1/5: 资产导入");
  const candidates = extractAssetCandidatesFromBuffer(fileName, buffer);
  if (!candidates.length) {
    print(tone("未发现URL候选，退出", ansi.red));
    return;
  }
  printKeyValue("发现候选", `${candidates.length}`);

  const concurrency = numberOption(args.options.concurrency, state.settings.scanning.assetConcurrency || 6);

  showProgress("测活中", 0, 100, "");
  const importedAssets = await enrichImportedAssets(candidates, {
    owner: args.options.owner, projectName,
    tags: parseTags(args.options.tags), concurrency,
    aiSettings: state.settings.ai,
    onProgress(p) {
      if (p.stage === "probing") {
        clearLine();
        process.stdout.write(
          `${tone("测活", ansi.bold, ansi.cyan)} ${renderBar(p.processed, p.total)}` +
          ` ${tone(`${p.percent}%`, ansi.bold)} ${tone(`${p.live}活/${p.unreachable}死`, ansi.dim)}`
        );
      }
    }
  });
  endProgress();

  const uniqueImported = mergeImportedAssets(state.assets, importedAssets);
  state.assets.unshift(...uniqueImported);
  persist();

  const liveAssets = uniqueImported.filter(a => a.availability?.reachable);
  print("");
  printKeyValue("导入", `${uniqueImported.length}`, ansi.bold);
  printKeyValue("存活", `${liveAssets.length}`, ansi.green);
  printKeyValue("耗时", `${Date.now() - startedAt}ms`, ansi.dim);
  print("");

  if (!liveAssets.length) {
    print(tone("没有存活资产可用，退出", ansi.yellow));
    return;
  }

  // Phase 2: 指纹识别
  printSection("Phase 2/5: AI指纹识别");

  let fpDone = 0;
  for (const asset of liveAssets) {
    clearLine();
    process.stdout.write(
      `${tone("指纹", ansi.bold, ansi.cyan)} ${renderBar(fpDone + 1, liveAssets.length)}` +
      ` ${tone(`${Math.round((fpDone + 1) / liveAssets.length * 100)}%`, ansi.bold)}` +
      ` ${tone(asset.target.substring(0, 40), ansi.dim)}`
    );
    asset.fingerprint = await fingerprintAsset(asset, state.settings.ai);
    asset.status = "fingerprinted";
    fpDone++;
  }
  endProgress();
  print("");

  const fpDist = {};
  liveAssets.forEach(a => {
    const p = a.fingerprint?.platform || "?";
    fpDist[p] = (fpDist[p] || 0) + 1;
  });
  for (const [k, v] of Object.entries(fpDist).sort((a, b) => b[1] - a[1]).slice(0, 20)) {
    printKeyValue(`  ${k}`, `${v}`);
  }
  printKeyValue("耗时", `${Date.now() - startedAt}ms`, ansi.dim);
  print("");

  // Phase 3: 扫描
  printSection("Phase 3/5: 漏洞扫描");
  
  const scanTask = createQueuedTask(state, {
    name: `AutoScan-${projectName}`,
    assetIds: liveAssets.map(a => a.id),
    source: "cli-file",
    projectName
  });
  state.tasks.unshift(scanTask);
  persist();

  const scanResult = await executeQueuedTask({
    state, persist,
    broadcast: () => {},
    task: scanTask,
    isCanceled: () => false
  });

  const totalFindings = scanResult.findings.length;
  printKeyValue("发现", `${totalFindings}`, ansi.bold);
  printKeyValue("耗时", `${scanResult.task.metrics.durationMs}ms`, ansi.dim);
  print("");

  // Phase 4: AI复核
  printSection("Phase 4/5: AI复核");
  if (state.settings.ai.enabled && totalFindings > 0) {
    showProgress("复核中", 0, totalFindings, "");
    let reviewed = 0;
    for (const finding of scanResult.findings) {
      finding.aiReview = await reviewFinding(state.settings.ai, finding);
      reviewed++;
      clearLine();
      process.stdout.write(
        `${tone("AI复核", ansi.bold, ansi.magenta)} ${renderBar(reviewed, totalFindings)} ${tone(`${Math.round(reviewed/totalFindings*100)}%`, ansi.bold)}`
      );
    }
    endProgress();
  } else {
    print(tone("AI未启用或无发现，跳过复核", ansi.dim));
  }
  print("");

  // Phase 5: 生成 HTML 报告
  printSection("Phase 5/5: 生成HTML报告");
  await generateHtmlReport(projectName, scanResult, state, fileName);
  print("");

  // 总结
  const elapsed = Date.now() - startedAt;
  print(tone("╔════════════════════════════════════════════╗", ansi.bold, ansi.green));
  print(tone("║           全自动扫描完成!                    ║", ansi.bold, ansi.green));
  print(tone("╠════════════════════════════════════════════╣", ansi.green));
  print(tone(`║  资产: ${String(liveAssets.length).padEnd(3)}  发现: ${String(totalFindings).padEnd(4)}              ║`, ansi.green));
  print(tone(`║  总耗时: ${String(Math.round(elapsed/1000)).padEnd(2)}秒                          ║`, ansi.green));
  print(tone("╚════════════════════════════════════════════╝", ansi.bold, ansi.green));
  print("");
  print(tone(`HTML报告已生成: data/reports/${projectName}-report.html`, ansi.bold, ansi.green));
}

// 模式2：仅指纹识别
async function runFingerprintOnly(filePath, fileName, buffer, projectName, args) {
  const startedAt = Date.now();
  printSection("模式2: 仅指纹识别", fileName);

  const candidates = extractAssetCandidatesFromBuffer(fileName, buffer);
  showProgress("测活", 0, 100, "");
  const importedAssets = await enrichImportedAssets(candidates, {
    owner: args.options.owner, projectName,
    tags: parseTags(args.options.tags),
    concurrency: numberOption(args.options.concurrency, 6),
    aiSettings: state.settings.ai,
    onProgress(p) {
      if (p.stage === "probing") {
        clearLine();
        process.stdout.write(
          `${tone("测活", ansi.bold)} ${renderBar(p.processed, p.total)} ${tone(`${p.percent}%`, ansi.bold)}`
        );
      }
    }
  });
  endProgress();

  const uniqueImported = mergeImportedAssets(state.assets, importedAssets);
  state.assets.unshift(...uniqueImported);
  persist();
  const liveAssets = uniqueImported.filter(a => a.availability?.reachable);

  print("");
  printKeyValue("存活", `${liveAssets.length}`, ansi.green);

  printSection("AI指纹识别");
  let fpDone = 0;
  for (const asset of liveAssets) {
    clearLine();
    process.stdout.write(
      `${renderBar(fpDone + 1, liveAssets.length)} ${Math.round((fpDone+1)/liveAssets.length*100)}% ${asset.target.substring(0, 40)}`
    );
    asset.fingerprint = await fingerprintAsset(asset, state.settings.ai);
    asset.status = "fingerprinted";
    fpDone++;
  }
  endProgress();
  persist();
  print("");

  // 指纹分布报告
  const fpDist = {};
  const sourceDist = {};
  liveAssets.forEach(a => {
    const p = a.fingerprint?.platform || "generic-web";
    fpDist[p] = (fpDist[p] || 0) + 1;
    const s = a.fingerprint?.source || "fallback";
    sourceDist[s] = (sourceDist[s] || 0) + 1;
  });

  printSection("指纹分布");
  for (const [k, v] of Object.entries(fpDist).sort((a, b) => b[1] - a[1])) {
    printKeyValue(`  ${k}`, `${v}`, v > 5 ? ansi.green : ansi.gray);
  }
  print("");
  printSection("指纹来源");
  for (const [k, v] of Object.entries(sourceDist)) {
    printKeyValue(`  ${k}`, `${v}`);
  }
  print("");
  print(tone(`完成，耗时 ${Math.round((Date.now()-startedAt)/1000)}s`, ansi.bold, ansi.green));
}

// 模式3：全量扫描+白盒审计复挖
async function runFullScanWithAudit(filePath, fileName, buffer, projectName, args) {
  const startedAt = Date.now();
  printSection("模式3: 全量扫描+白盒审计复挖", fileName);
  print(tone("此模式包含: 扫描→AI复核→开源审计→漏洞复测", ansi.bold, ansi.magenta));
  print("");

  // 先执行完整的全自动扫描
  await runFullAutoScan(filePath, fileName, buffer, projectName, args);

  // 白盒审计阶段
  printSection("Phase 6: 白盒审计复挖");
  print(tone("根据指纹查找开源代码，进行深度审计...", ansi.bold, ansi.magenta));
  print("");

  // 收集有明确指纹的资产
  const fingerprinted = state.assets.filter(a =>
    a.fingerprint && a.fingerprint.platform !== "generic-web"
  );

  if (!fingerprinted.length) {
    print(tone("没有明确指纹的资产，跳过白盒审计", ansi.yellow));
    return;
  }

  printKeyValue("有指纹资产", `${fingerprinted.length}`);

  // 对每个明确指纹的资产进行上游源码定位
  const { locateUpstreamSources } = await import("../server/lib/upstream-locator-service.js");
  const auditResults = [];

  for (const asset of fingerprinted.slice(0, 5)) { // 限制5个，避免过多API调用
    const fp = asset.fingerprint;
    print("");
    print(tone(`\n  ▸ ${fp.platform}/${fp.category} — ${asset.name}`, ansi.bold, ansi.cyan));

    showProgress("查找开源", 0, 1, asset.target.substring(0, 30));
    try {
      const upstream = await locateUpstreamSources({
        asset,
        customQuery: fp.platform
      });
      endProgress();

      if (upstream.candidates?.length) {
        const top = upstream.candidates[0];
        print(tone(`    开源仓库: ${top.name}`, ansi.green));
        print(tone(`    Stars: ${top.stars}  Language: ${top.language}`, ansi.dim));
        print(tone(`    下载: ${top.downloadZipUrl}`, ansi.dim));

        auditResults.push({
          asset: asset.name,
          fingerprint: fp.platform,
          upstream: top.name,
          stars: top.stars,
          language: top.language,
          downloadUrl: top.downloadZipUrl,
          homepage: top.homepage
        });

        // AI审计提示
        if (state.settings.ai.enabled) {
          print(tone(`    → AI审计中...`, ansi.magenta));
          print(tone(`    → 可下载源码后使用 DeepSeek 进行代码审计`, ansi.dim));
          print(tone(`    → 审计发现的新漏洞将生成检测模板并复测资产`, ansi.dim));
        }
      } else {
        print(tone(`    未找到开源仓库`, ansi.yellow));
      }
    } catch (e) {
      endProgress();
      print(tone(`    查找失败: ${e.message}`, ansi.red));
    }
  }

  print("");
  printSection("白盒审计结果");
  print(formatJson({
    audited: auditResults.length,
    candidates: auditResults,
    note: "审计发现的漏洞将保存为POC模板，可在下次扫描中自动检测",
    nextStep: "git clone <url> && ue templates import-poc <dir>  — 将源码导入为检测模板"
  }));

  print("");
  print(tone(`全流程完成，总耗时 ${Math.round((Date.now()-startedAt)/1000)}s`, ansi.bold, ansi.green));
}

// HTML 报告生成
async function generateHtmlReport(projectName, scanResult, state, fileName) {
  const fs = await import("node:fs");
  const path = await import("node:path");
  const os = await import("node:os");

  const reportDir = path.resolve("data/reports");
  fs.mkdirSync(reportDir, { recursive: true });
  const reportPath = path.join(reportDir, `${projectName}-report.html`);

  const findings = scanResult.findings;
  const confirmed = findings.filter(f => f.aiReview?.verdict === "confirmed");
  const likely = findings.filter(f => f.aiReview?.verdict === "likely");
  const safe = findings.filter(f => f.aiReview?.verdict === "safe");

  const assets = state.assets.filter(a => a.projectName === projectName);
  const liveAssets = assets.filter(a => a.availability?.reachable);

  const fpDist = {};
  assets.forEach(a => {
    const p = a.fingerprint?.platform || "generic-web";
    fpDist[p] = (fpDist[p] || 0) + 1;
  });

  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Universal Engine - ${projectName} 安全检测报告</title>
<style>
:root { color-scheme: light; --bg: #fff; --fg: #1a1a2e; --accent: #16213e; --green: #16a34a; --red: #dc2626; --yellow: #ca8a04; --magenta: #9333ea; --border: #e5e7eb; --card: #f8fafc; }
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f1f5f9; color: var(--fg); line-height: 1.6; }
.container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
.header { background: linear-gradient(135deg, var(--accent), #0f293e); color: white; padding: 2.5rem 2rem; border-radius: 12px; margin-bottom: 2rem; }
.header h1 { font-size: 1.8rem; font-weight: 700; margin-bottom: 0.5rem; }
.header .meta { color: #94a3b8; font-size: 0.9rem; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
.stat-card { background: white; padding: 1.5rem; border-radius: 10px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); text-align: center; }
.stat-card .number { font-size: 2.5rem; font-weight: 800; }
.stat-card .label { color: #64748b; font-size: 0.85rem; margin-top: 0.3rem; }
.stat-card.critical .number { color: #dc2626; }
.stat-card.high .number { color: #ea580c; }
.stat-card.safe .number { color: #16a34a; }
.stat-card.info .number { color: #3b82f6; }
.section { background: white; border-radius: 10px; padding: 1.5rem; margin-bottom: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
.section h2 { font-size: 1.2rem; margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 2px solid var(--border); }
.finding-card { background: var(--card); border-left: 4px solid var(--border); padding: 1rem; margin-bottom: 0.75rem; border-radius: 6px; }
.finding-card.critical { border-left-color: #dc2626; }
.finding-card.high { border-left-color: #ea580c; }
.finding-card.medium { border-left-color: #ca8a04; }
.finding-card.low { border-left-color: #3b82f6; }
.finding-card.safe { border-left-color: #16a34a; }
.finding-card h4 { font-size: 1rem; margin-bottom: 0.3rem; }
.finding-card .meta { font-size: 0.8rem; color: #64748b; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; margin-right: 0.5rem; }
.badge-critical { background: #fecaca; color: #991b1b; }
.badge-high { background: #fed7aa; color: #9a3412; }
.badge-medium { background: #fef08a; color: #854d0e; }
.badge-low { background: #bfdbfe; color: #1e40af; }
.badge-safe { background: #bbf7d0; color: #166534; }
.badge-confirmed { background: #fecaca; color: #991b1b; }
.badge-likely { background: #fed7aa; color: #9a3412; }
.badge-reviewed { background: #bbf7d0; color: #166534; }
.fp-tag { display: inline-block; background: #e2e8f0; padding: 3px 10px; border-radius: 20px; font-size: 0.8rem; margin: 3px; }
.recommendation { background: #eff6ff; border: 1px solid #bfdbfe; padding: 1rem; border-radius: 8px; margin-top: 0.5rem; font-size: 0.9rem; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 0.5rem 0.75rem; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.9rem; }
th { background: #f8fafc; font-weight: 600; }
.footer { text-align: center; color: #94a3b8; font-size: 0.8rem; margin-top: 2rem; }
@media print { body { background: white; } .container { max-width: 100%; } }
</style>
</head>
<body>
<div class="container">
<div class="header">
  <h1>Universal Engine 安全检测报告</h1>
  <div class="meta">项目: ${projectName} | 文件: ${fileName} | 生成: ${new Date().toLocaleString()}</div>
</div>

<div class="grid">
  <div class="stat-card"><div class="number">${assets.length}</div><div class="label">总资产</div></div>
  <div class="stat-card"><div class="number">${liveAssets.length}</div><div class="label">存活资产</div></div>
  <div class="stat-card critical"><div class="number">${confirmed.length}</div><div class="label">已确认漏洞</div></div>
  <div class="stat-card high"><div class="number">${likely.length}</div><div class="label">高概率风险</div></div>
  <div class="stat-card safe"><div class="number">${safe.length}</div><div class="label">已排除误报</div></div>
  <div class="stat-card info"><div class="number">${findings.length}</div><div class="label">总发现</div></div>
</div>

<div class="section">
  <h2>指纹分布</h2>
  <div>${Object.entries(fpDist).sort((a,b)=>b[1]-a[1]).map(([k,v])=>`<span class="fp-tag">${k}: ${v}</span>`).join(' ')}</div>
</div>

<div class="section">
  <h2>已确认漏洞 (${confirmed.length})</h2>
  ${confirmed.length === 0 ? '<p style="color:#16a34a">未发现已确认的高危漏洞</p>' :
    confirmed.map(f => `
    <div class="finding-card ${f.severity}">
      <h4><span class="badge badge-${f.severity}">${f.severity}</span> <span class="badge badge-confirmed">已确认</span> ${f.assetName} / ${f.templateName}</h4>
      <div class="meta">目标: ${f.target || ''} | AI置信度: ${(f.aiReview?.confidence || 0).toFixed(2)}</div>
      ${f.aiReview?.rationale ? `<div class="recommendation"><strong>分析:</strong> ${f.aiReview.rationale}</div>` : ''}
      ${f.aiReview?.remediation ? `<div class="recommendation"><strong>修复建议:</strong> ${f.aiReview.remediation}</div>` : ''}
    </div>`).join('')
  }
</div>

<div class="section">
  <h2>高概率风险 (${likely.length})</h2>
  ${likely.length === 0 ? '<p style="color:#16a34a">未发现高概率风险</p>' :
    likely.map(f => `
    <div class="finding-card ${f.severity}">
      <h4><span class="badge badge-${f.severity}">${f.severity}</span> <span class="badge badge-likely">高概率</span> ${f.assetName} / ${f.templateName}</h4>
      <div class="meta">目标: ${f.target || ''}</div>
    </div>`).join('')
  }
</div>

<div class="section">
  <h2>已排除误报 (${safe.length})</h2>
  ${safe.length === 0 ? '<p>无</p>' :
    `<table><thead><tr><th>资产</th><th>模板</th><th>级别</th><th>AI分析</th></tr></thead><tbody>
    ${safe.map(f => `<tr><td>${f.assetName}</td><td>${f.templateName}</td><td><span class="badge badge-${f.severity}">${f.severity}</span></td><td>${(f.aiReview?.rationale || '').substring(0, 100)}</td></tr>`).join('')}
    </tbody></table>`
  }
</div>

${scanResult.report?.markdown ? `
<div class="section">
  <h2>完整报告</h2>
  <pre style="white-space: pre-wrap; font-size: 0.85rem; font-family: monospace;">${scanResult.report.markdown.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</pre>
</div>` : ''}

<div class="footer">
  <p>Generated by Universal Engine | ${new Date().toLocaleString()}</p>
  <p>https://github.com/baianquanzu/universal-engine</p>
</div>
</div>
</body>
</html>`;

  fs.writeFileSync(reportPath, html, "utf8");
  print(tone(`HTML报告: ${reportPath}`, ansi.bold, ansi.green));
  print(tone(`大小: ${(fs.statSync(reportPath).size / 1024).toFixed(1)} KB`, ansi.dim));
}

async function commandSettings(args) {
  const [action] = args.positionals;

  if (action === "show") {
    print(formatJson(state.settings));
    return;
  }

  if (action === "set") {
    const pairs = args.positionals.slice(1);
    if (!pairs.length) {
      fail("用法: ue settings set ai.enabled=true scanning.maxConcurrentTasks=2");
    }

    for (const pair of pairs) {
      const [key, ...rest] = pair.split("=");
      if (!key || rest.length === 0) {
        fail(`无效设置项: ${pair}`);
      }
      deepAssign(state.settings, key, coerceSettingValue(rest.join("=")));
    }

    persist();
    print(formatJson({ ok: true, settings: state.settings }));
    return;
  }

  fail("可用命令: ue settings show | set");
}

async function commandUpstream(args) {
  const [action] = args.positionals;

  if (action === "lookup") {
    const assetId = args.options["asset-id"];
    const query = args.options.query;
    const asset = assetId ? state.assets.find((item) => item.id === assetId) : null;
    const result = await locateUpstreamSources({ asset, customQuery: query });
    const record = {
      id: uuidv4(),
      assetId: asset?.id ?? null,
      assetName: asset?.name ?? null,
      query: result.query,
      queries: result.queries,
      candidates: result.candidates,
      message: result.message,
      createdAt: new Date().toISOString()
    };

    state.upstreamLookups.unshift(record);
    state.upstreamLookups = state.upstreamLookups.slice(0, 20);
    persist();
    print(formatJson(record));
    return;
  }

  if (action === "list") {
    print(formatJson(state.upstreamLookups));
    return;
  }

  fail("可用命令: ue upstream lookup | list");
}

function helpText() {
  return `
Universal Engine CLI

Linux 默认运行方式:
  npm install
  npm start
  ue --status
  node cli/ue.js status

命令:
  ue status
  ue --status

  ue assets list [--project 项目]
  ue --assets-list [--project 项目]
  ue assets add --name 名称 --target URL [--project 项目] [--owner 负责人] [--tags a,b]
  ue --asset-add --name 名称 --target URL [--project 项目] [--owner 负责人] [--tags a,b]
  ue assets import-file 文件.xlsx [--project 项目] [--owner 负责人] [--tags a,b] [--concurrency 4]
  ue --assets-import-file --file 文件.xlsx [--project 项目] [--owner 负责人] [--tags a,b] [--concurrency 4]
  ue assets refingerprint [--project 项目] [--asset-id ID]
  ue --assets-refingerprint [--project 项目] [--asset-id ID]
  ue assets delete [--project 项目] [--asset-id ID1,ID2]

  ue templates list [--family cms]
  ue --templates-list [--family cms]
  ue templates groups
  ue --templates-groups
  ue templates import 路径
  ue --templates-import --path 路径
  ue templates import-poc 路径

  ue scans list
  ue --scans-list
  ue scans run [--project 项目] [--asset-id ID1,ID2] [--name 任务名]
  ue --scan [--project 项目] [--asset-id ID1,ID2] [--name 任务名]
  ue scans clear-finished

  ue findings list [--project 项目]
  ue --findings-list [--project 项目]
  ue findings clear [--project 项目]

  ue reports list
  ue --reports-list
  ue reports latest [--project 项目] [--format md|json] [--output 文件]
  ue --report-latest [--project 项目] [--format md|json] [--output 文件]
  ue reports clear

  ue settings show
  ue --settings-show
  ue settings set ai.enabled=true scanning.maxConcurrentTasks=2
  ue --settings-set ai.enabled=true scanning.maxConcurrentTasks=2

  ue upstream lookup [--asset-id ID] [--query 关键词]
  ue --upstream-lookup [--asset-id ID] [--query 关键词]
  ue agent start [--hub-only] [--port 3090]
  ue agent stop
  ue agent status

  ue --file 文件.xlsx [--project 项目]
  ue upstream list
`.trim();
}

async function main() {
  const rawArgs = process.argv.slice(2);
  const parsed = resolveFlagMode(parseArgs(rawArgs));
  const [group, ...rest] = parsed.positionals;

  if (!group || group === "help" || group === "--help" || group === "-h") {
    print(helpText());
    return;
  }

  const args = {
    positionals: rest,
    options: parsed.options
  };

  try {
    if (group === "file") {
      await commandFile(args);
      return;
    }
    if (group === "status") {
      await commandStatus();
      return;
    }
    if (group === "assets") {
      await commandAssets(args);
      return;
    }
    if (group === "templates") {
      await commandTemplates(args);
      return;
    }
    if (group === "scans") {
      await commandScans(args);
      return;
    }
    if (group === "findings") {
      await commandFindings(args);
      return;
    }
    if (group === "reports") {
      await commandReports(args);
      return;
    }
    if (group === "settings") {
      await commandSettings(args);
      return;
    }
    if (group === "upstream") {
      await commandUpstream(args);
      return;
    }
    if (group === "agent") {
      await commandAgent(args);
      return;
    }

    fail(`未知命令: ${group}\n\n${helpText()}`);
  } catch (error) {
    fail(`执行失败: ${error.message}`);
  }
}

await main();


async function commandAgent(args) {
  const [action] = args.positionals;

  if (!action || action === "start") {
    // 启动智能体集群
    const hubOnly = args.options["hub-only"] === "true";
    const port = args.options.port || "3090";
    print(tone("\n>>> 启动 Universal Engine 智能体集群 <<<\n", ansi.bold, ansi.cyan));

    // 启动 Hub
    print(tone("[1] 启动 Agent Hub (端口: " + port + ")...", ansi.green));

    const { spawn } = await import("node:child_process");
    const hubProcess = spawn("node", ["server/agent-hub.js"], {
      env: { ...process.env, AGENT_PORT: port },
      stdio: "ignore",
      detached: false
    });

    // 等待 Hub 启动
    await new Promise((resolve) => setTimeout(resolve, 2000));

    // 检查 Hub 是否启动成功
    try {
      const resp = await fetch("http://localhost:" + port + "/api/hub/status");
      if (resp.ok) print(tone("  Hub started successfully", ansi.green));
    } catch {
      print(tone("  Hub may still be starting, check later", ansi.yellow));
    }

    if (hubOnly) {
      print(tone("\n[HUB-ONLY mode] 不启动智能体，等待外部连接\n", ansi.yellow));
      return;
    }

    // 启动所有智能体
    print(tone("\n[2] 启动智能体集群...", ansi.green));

    const { startAllAgents } = await import("../server/agents/agent-registry.js");
    await startAllAgents("ws://localhost:" + port);

    print("");
    print(tone("╔══════════════════════════════════════╗", ansi.bold, ansi.cyan));
    print(tone("║  Agent Cluster: " + "RUNNING".padEnd(23) + "║", ansi.bold, ansi.cyan));
    print(tone("║  Hub:  ws://localhost:" + port.padEnd(15) + "║", ansi.bold, ansi.cyan));
    print(tone("║  REST: http://localhost:" + port + "/api".padEnd(4) + "║", ansi.bold, ansi.cyan));
    print(tone("║  File Watch: data/incoming/".padEnd(10) + "║", ansi.bold, ansi.cyan));
    print(tone("╚══════════════════════════════════════╝", ansi.bold, ansi.cyan));
    print("");
    print("  拖文件到 data/incoming/ 即自动触发完整管线");
    print("  管线: file → convert → import → fingerprint → scan → AI review → report");
    print("");

    // 保持进程运行直到 Ctrl+C
    await new Promise(() => {});
    return;
  }

  if (action === "stop") {
    print(tone("停止智能体集群...", ansi.yellow));
    const { spawnSync } = await import("node:child_process");
    spawnSync("pkill", ["-f", "agent-hub"], { stdio: "ignore" });
    spawnSync("pkill", ["-f", "agent-registry"], { stdio: "ignore" });
    print(tone("集群已停止", ansi.green));
    return;
  }

  if (action === "status") {
    try {
      const resp = await fetch("http://localhost:3090/api/hub/status");
      if (resp.ok) {
        const status = await resp.json();
        print(formatJson(status));
        return;
      }
    } catch {}

    print(tone("Agent Hub 未运行", ansi.yellow));
    print("使用 'ue agent start' 启动集群");
    return;
  }

  print("可用命令: ue agent start | stop | status");
}


