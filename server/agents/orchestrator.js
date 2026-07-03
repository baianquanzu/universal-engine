// Orchestrator Agent
// 核心协调层 — 统一调度所有智能体，标准化任务管线流转
// 管线：file-watch → poc-convert → asset-import → fingerprint → scan → ai-review → report

import { v4 as uuidv4 } from "uuid";
import { loadState, saveState } from "../lib/state.js";
import { fingerprintAsset } from "../lib/fingerprint-service.js";
import { reviewFinding } from "../lib/ai-review-service.js";
import { getToolStrategy } from "./kali-toolbox.js";
import { filterLowValueFindings, SCAN_MODES } from "./scan-executor.js";

// ----- 任务管线定义 -----
// 每个阶段定义了前置依赖、执行逻辑、成功后的下一阶段
const PIPELINE = {
  // Stage 1: 文件入口 → 分类路由
  "file-ingest": {
    label: "文件接收",
    agent: "file-watcher",
    next: {
      ".xlsx": "asset-import",
      ".xls": "asset-import",
      ".csv": "asset-import",
      ".yaml": "template-import",
      ".yml": "template-import",
      ".json": "template-import",
      ".md": "template-import",
      // All other types → POC converter
      "*": "poc-convert"
    }
  },

  // Stage 2a: POC 转化
  "poc-convert": {
    label: "POC转化",
    agent: "poc-converter",
    action: "poc:convert",
    next: "template-merge"
  },

  // Stage 2b: 模板导入
  "template-import": {
    label: "模板导入",
    agent: "template-importer",
    action: "template:import",
    next: "template-merge"
  },

  // Stage 3: 模板合并去重
  "template-merge": {
    label: "模板合并",
    agent: "orchestrator",
    action: "merge:templates",
    next: null  // 终点：无需后续
  },

  // Stage 4: 资产导入
  "asset-import": {
    label: "资产导入",
    agent: "asset-importer",
    action: "asset:import-file",
    next: "recon"
  },

  // Stage 5: 指纹识别
  "recon": {
    label: "信息搜集",
    agent: "recon-agent",
    action: "recon:full-pipeline",
    next: "fingerprint"
  },

  "fingerprint": {
    label: "指纹识别",
    agent: "fingerprinter",
    action: "fingerprint:batch",
    next: "scan"  // 可跳过到 report
  },

  // Stage 6: 扫描执行（可选）
  "scan": {
    label: "漏洞扫描",
    agent: "scan-executor",
    action: "scan:batch",
    next: "ai-review"  // 可选
  },

  // Stage 7: AI复核（可选）
  "ai-review": {
    label: "AI复核",
    agent: "ai-reviewer",
    action: "review:batch",
    next: "report"
  },

  // Stage 8: 报告生成
  "report": {
    label: "报告生成",
    agent: "orchestrator",
    action: "generate:report",
    next: null  // 终点
  }
};

// ----- 智能体路由表 -----
const AGENT_ROUTING = {
  "file-watcher": { capabilities: ["file:watch", "file:detect", "file:route"] },
  "poc-converter": { capabilities: ["poc:convert", "poc:import", "poc:classify"], handler: "convertMultiPoc" },
  "asset-importer": { capabilities: ["asset:import-file", "asset:import-text", "asset:add"], handler: "importAssetsFromFile" },
  "fingerprinter": { capabilities: ["fingerprint:single", "fingerprint:batch"], handler: "fingerprintBatch" },
  "scan-executor": { capabilities: ["scan:execute", "scan:batch", "scan:strategy"], handler: "executeScan" },
  "ai-reviewer": { capabilities: ["review:single", "review:batch"], handler: "reviewBatch" },
  "kali-toolbox": { capabilities: ["tool:nmap", "tool:nikto", "tool:sqlmap", "tool:httpx", "scan:asset"] },
  "recon-agent": { capabilities: ["recon:quick", "recon:port-scan", "recon:subdomain", "recon:deep", "recon:batch", "recon:full-pipeline"] },
  "orchestrator": { capabilities: ["merge:templates", "generate:report", "pipeline:execute", "pipeline:status"] }
};

// ----- 管线执行引擎 -----
class PipelineEngine {
  constructor(state) {
    this.state = state;
    this.activePipelines = new Map(); // pipelineId → { stages, currentStage, status }
    this.callbacks = {};
  }

  // 注册回调：当某阶段完成时触发
  on(event, cb) {
    this.callbacks[event] = cb;
  }

  // 启动一个完整的自动化管线
  async execute(input, stages = ["file-ingest"]) {
    const pipelineId = uuidv4();
    const pipeline = {
      id: pipelineId,
      input,
      stages: [],
      currentStage: stages[0],
      status: "running",
      results: {},
      logs: [],
      startedAt: new Date().toISOString()
    };

    this.activePipelines.set(pipelineId, pipeline);
    this.emit("pipeline:started", { pipelineId, input });

    let currentStage = stages[0];
    let stageInput = input;

    while (currentStage) {
      const config = PIPELINE[currentStage];
      if (!config) {
        pipeline.logs.push(`Unknown stage: ${currentStage}`);
        break;
      }

      pipeline.logs.push(`[${config.label}] Starting...`);
      pipeline.currentStage = currentStage;
      this.emit("pipeline:stage:started", { pipelineId, stage: currentStage, label: config.label });

      try {
        // 执行阶段
        const result = await this.executeStage(currentStage, stageInput, pipeline);
        pipeline.results[currentStage] = result;
        pipeline.stages.push(currentStage);

        pipeline.logs.push(`[${config.label}] Completed: ${JSON.stringify(this.summarizeResult(currentStage, result))}`);
        this.emit("pipeline:stage:completed", { pipelineId, stage: currentStage, result });

        // 确定下一阶段
        if (config.next) {
          currentStage = typeof config.next === "function" ? config.next(result) : config.next;
          stageInput = result; // 传递结果到下一阶段
        } else if (currentStage === "file-ingest" && config.next && typeof config.next === "object") {
          // file-ingest 按扩展名路由
          const ext = input.extension || "*";
          currentStage = config.next[ext] || config.next["*"];
          stageInput = { path: input.path, extension: ext };
        } else {
          currentStage = null; // 终点
        }

      } catch (error) {
        pipeline.logs.push(`[${config.label}] Failed: ${error.message}`);
        pipeline.status = "failed";
        pipeline.error = error.message;
        this.emit("pipeline:failed", { pipelineId, stage: currentStage, error: error.message });
        break;
      }
    }

    if (pipeline.status === "running") {
      pipeline.status = "completed";
      pipeline.completedAt = new Date().toISOString();
    }

    pipeline.logs.push(`Pipeline ${pipeline.status} in ${pipeline.stages.length} stages`);
    this.emit("pipeline:completed", { pipelineId, status: pipeline.status });

    return pipeline;
  }

  // 执行单个阶段
  async executeStage(stageName, input, pipeline) {
    const config = PIPELINE[stageName];

    switch (stageName) {
      case "file-ingest":
        return this.handleFileIngest(input, pipeline);

      case "poc-convert": {
        const { convertMultiPoc } = await import("./poc-converter.js");
        const result = convertMultiPoc({ path: input.path });
        return result;
      }

      case "template-merge": {
        // 合并 POC 模板到 state
        if (input.templates?.length) {
          const { mergeImportedTemplates } = await import("../lib/template-service.js");
          const unique = mergeImportedTemplates(this.state.templates, input.templates);
          this.state.templates.unshift(...unique);
          saveState(this.state);
          return { merged: unique.length, totalTemplates: this.state.templates.length };
        }
        return { merged: 0, message: "No templates to merge" };
      }

      case "asset-import": {
        return await this.handleAssetImport(input, pipeline);
      }

      case "recon": {
        return await this.handleRecon(input, pipeline);
      }

      case "fingerprint": {
        return await this.handleFingerprint(input, pipeline);
      }

      case "scan": {
        return await this.handleScan(input, pipeline);
      }

      case "ai-review": {
        return await this.handleAIReview(input, pipeline);
      }

      case "report": {
        return await this.handleReport(input, pipeline);
      }

      default:
        return { message: `Stage ${stageName} not implemented yet` };
    }
  }

  // ---- 各阶段的实现 ----

  async handleFileIngest(input, pipeline) {
    // input: { path, type } — from file watcher
    const ext = input.extension || path.extname(input.path || "").toLowerCase();
    const route = {
      ".xlsx": "asset-import",
      ".xls": "asset-import",
      ".csv": "asset-import",
      ".yaml": "template-import",
      ".yml": "template-import",
      ".json": "template-import",
      ".md": "template-import",
    }[ext] || "poc-convert";

    return { extension: ext, routedTo: route, path: input.path };
  }

  async handleAssetImport(input, pipeline) {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const { extractAssetCandidatesFromBuffer, enrichImportedAssets, mergeImportedAssets } = await import("../lib/asset-import-service.js");

    const filePath = input.path;
    if (!filePath || !fs.existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }

    const buffer = fs.readFileSync(filePath);
    const candidates = extractAssetCandidatesFromBuffer(path.basename(filePath), buffer);

    pipeline.logs.push(`[资产导入] Extracted ${candidates.length} URL candidates`);

    const importedAssets = await enrichImportedAssets(candidates, {
      projectName: input.projectName || "Auto-Import",
      owner: input.owner || "Orchestrator",
      tags: input.tags || [],
      concurrency: this.state.settings?.scanning?.assetConcurrency || 4
    });

    const uniqueImported = mergeImportedAssets(this.state.assets, importedAssets);
    this.state.assets.unshift(...uniqueImported);
    saveState(this.state);

    pipeline.logs.push(`[资产导入] Imported ${uniqueImported.length} assets (${importedAssets.length - uniqueImported.length} duplicates skipped)`);

    return {
      scannedRows: candidates.length,
      imported: uniqueImported.length,
      skippedDuplicates: importedAssets.length - uniqueImported.length,
      live: uniqueImported.filter(a => a.availability?.reachable).length,
      assetIds: uniqueImported.map(a => a.id)
    };
  }

  async handleRecon(input, pipeline) {
    // 对导入的资产进行信息搜集：端口扫描 + 子域名发现
    const assetIds = input.assetIds || [];
    let assets;

    if (assetIds.length > 0) {
      assets = this.state.assets.filter(a => assetIds.includes(a.id));
    } else if (input.projectName) {
      assets = this.state.assets.filter(a => (a.projectName || "") === input.projectName);
    } else {
      assets = this.state.assets;
    }

    pipeline.logs.push(`[信息搜集] Processing ${assets.length} assets`);

    // 调用 recon-agent 的 fullReconPipeline
    const { fullReconPipeline } = await import("./recon-agent.js");
    const result = await fullReconPipeline(assets, this.state, {
      timeout: 60000
    });

    pipeline.logs.push(`[信息搜集] Found ${result.portsScanned} open ports, ${result.subdomainsFound} subdomains`);
    pipeline.logs.push(`[信息搜集] ${result.newAssetsDiscovered} new assets discovered (${result.aliveNewAssets} alive)`);

    return result;
  }

  async handleFingerprint(input, pipeline) {
    // input 来自上一阶段的结果或直接指定的资产ID
    const assetIds = input.assetIds || [];
    let assets;

    if (assetIds.length > 0) {
      assets = this.state.assets.filter(a => assetIds.includes(a.id));
    } else if (input.projectName) {
      assets = this.state.assets.filter(a => (a.projectName || "") === input.projectName);
    } else {
      assets = this.state.assets.filter(a => !a.fingerprint);
    }

    pipeline.logs.push(`[指纹识别] Processing ${assets.length} assets`);

    const aiSettings = this.state.settings.ai;
    let processed = 0;

    for (const asset of assets) {
      asset.fingerprint = await fingerprintAsset(asset, aiSettings);
      asset.status = "fingerprinted";
      processed++;
    }

    saveState(this.state);

    const fpDist = {};
    assets.forEach(a => {
      const p = a.fingerprint?.platform || "?";
      fpDist[p] = (fpDist[p] || 0) + 1;
    });

    return { processed, fingerprintDistribution: fpDist };
  }

  async handleScan(input, pipeline) {
    // 智能扫描：按指纹分组，每组用最佳工具策略
    const projectName = input.projectName || "";
    const mode = input.mode || "standard";
    const assets = projectName
      ? this.state.assets.filter(a => (a.projectName || "") === projectName)
      : this.state.assets;

    const reachableAssets = assets.filter(a => a.availability?.reachable);
    pipeline.logs.push(`[扫描] Mode=${mode}, ${reachableAssets.length}/${assets.length} reachable`);

    const allFindings = [];
    const scanMode = SCAN_MODES[mode] || SCAN_MODES.standard;

    let processed = 0;
    for (const asset of reachableAssets) {
      if (!asset.fingerprint) continue;

      const strategy = getToolStrategy(asset.fingerprint);
      pipeline.logs.push(`[扫描] ${asset.name}: ${strategy.tools.join(", ")}`);

      // 对每个资产执行 nuclei 扫描
      const { runNucleiTemplate } = await import("../lib/nuclei-executor.js");
      const templates = this.state.templates.filter(t => t.runnable && t.raw);
      const matchedTemplates = templates.filter(t => {
        if (!t.tags?.length) return false;
        const platform = (asset.fingerprint?.platform || "").toLowerCase();
        const tags = t.tags.map(x => x.toLowerCase());
        return tags.includes(platform) || platform === "generic-web" && tags.includes("generic");
      });

      // Execute matched runnable templates
      for (const template of matchedTemplates.slice(0, 20)) { // Limit per asset
        try {
          const result = await runNucleiTemplate(asset, asset.fingerprint, template, this.state.settings.nuclei);
          for (const finding of (result.findings || [])) {
            finding.projectName = asset.projectName;
            allFindings.push(finding);
          }
        } catch (e) {
          pipeline.logs.push(`[扫描] ${asset.name}: ${template.nucleiId} failed - ${e.message}`);
        }
      }

      processed++;
    }

    // Filter low value
    const filtered = filterLowValueFindings(allFindings);
    const filteredCount = allFindings.length - filtered.length;

    // Save findings
    const findingRecords = filtered.map(f => ({
      id: uuidv4(),
      assetId: f.assetId || "",
      assetName: f.assetName || "",
      projectName: f.projectName || "",
      target: f.target || "",
      templateId: f.templateId || "",
      templateName: f.templateName || "",
      severity: f.severity || "info",
      tags: f.tags || [],
      fingerprint: f.fingerprint || {},
      evidence: f.evidence || [],
      status: "candidate",
      createdAt: new Date().toISOString(),
      aiReview: null
    }));

    this.state.findings.unshift(...findingRecords);
    saveState(this.state);

    pipeline.logs.push(`[扫描] ${findingRecords.length} findings (${filteredCount} low-value filtered)`);

    return {
      processedAssets: processed,
      totalFindings: allFindings.length,
      acceptedFindings: findingRecords.length,
      filteredCount,
      findingIds: findingRecords.map(f => f.id)
    };
  }

  async handleAIReview(input, pipeline) {
    const findingIds = input.findingIds || [];
    const findings = findingIds.length
      ? this.state.findings.filter(f => findingIds.includes(f.id))
      : this.state.findings.filter(f => !f.aiReview || f.aiReview.status === "skipped");

    if (!this.state.settings.ai.enabled) {
      pipeline.logs.push(`[AI复核] Skipped - AI disabled in settings`);
      return { reviewed: 0, skipped: findings.length, reason: "AI disabled" };
    }

    pipeline.logs.push(`[AI复核] Reviewing ${findings.length} findings`);
    let reviewed = 0;
    const results = { confirmed: 0, likely: 0, safe: 0, pending: 0 };

    for (const finding of findings) {
      try {
        finding.aiReview = await reviewFinding(this.state.settings.ai, finding);
        const v = finding.aiReview?.verdict || "pending";
        results[v] = (results[v] || 0) + 1;
        reviewed++;
      } catch (e) {
        finding.aiReview = { status: "failed", verdict: "pending", confidence: 0, rationale: e.message };
      }
    }

    saveState(this.state);

    pipeline.logs.push(`[AI复核] Reviewed ${reviewed} findings: ${JSON.stringify(results)}`);
    return { reviewed, ...results };
  }

  async handleReport(input, pipeline) {
    const projectName = input.projectName || "";
    const findings = projectName
      ? this.state.findings.filter(f => (f.projectName || "") === projectName)
      : this.state.findings;

    const confirmed = findings.filter(f => f.aiReview?.verdict === "confirmed");
    const likely = findings.filter(f => f.aiReview?.verdict === "likely");
    const safe = findings.filter(f => f.aiReview?.verdict === "safe");

    const report = {
      id: uuidv4(),
      projectName: projectName || "All Projects",
      generatedAt: new Date().toISOString(),
      summary: {
        totalAssets: this.state.assets.length,
        totalFindings: findings.length,
        confirmed: confirmed.length,
        likely: likely.length,
        safe: safe.length,
        aiReviewed: findings.filter(f => f.aiReview?.status === "complete").length
      },
      topFindings: [...confirmed, ...likely].slice(0, 20).map(f => ({
        severity: f.severity,
        assetName: f.assetName,
        templateName: f.templateName,
        target: f.target,
        verdict: f.aiReview?.verdict,
        confidence: f.aiReview?.confidence
      })),
      markdown: generateMarkdownReport(projectName, findings, this.state)
    };

    this.state.reports.unshift(report);
    saveState(this.state);

    pipeline.logs.push(`[报告] Generated: ${confirmed.length} confirmed, ${likely.length} likely, ${safe.length} safe`);
    return { reportId: report.id, ...report.summary };
  }

  // ---- 辅助 ----
  summarizeResult(stage, result) {
    const summaries = {
      "asset-import": `Imported ${result.imported || 0} assets`,
      "fingerprint": `Fingerprinted ${result.processed || 0} assets`,
      "scan": `${result.acceptedFindings || 0} findings`,
      "ai-review": `${result.reviewed || 0} reviewed`,
      "report": `Report ${result.reportId || ""}`,
      "poc-convert": `${result.templates?.length || 0} POCs`,
      "template-merge": `${result.merged || 0} merged`,
    };
    return summaries[stage] || JSON.stringify(result).slice(0, 100);
  }

  emit(event, data) {
    if (this.callbacks[event]) {
      this.callbacks[event](data);
    }
    // Also broadcast to hub if connected
    if (global.hubBroadcast) {
      global.hubBroadcast({ type: event, ...data });
    }
  }

  // 查询管线状态
  getStatus(pipelineId) {
    if (pipelineId) return this.activePipelines.get(pipelineId);
    return [...this.activePipelines.values()].map(p => ({
      id: p.id,
      stages: p.stages,
      currentStage: p.currentStage,
      status: p.status
    }));
  }
}

// ----- Markdown报告生成 -----
function generateMarkdownReport(projectName, findings, state) {
  const confirmed = findings.filter(f => f.aiReview?.verdict === "confirmed");
  const likely = findings.filter(f => f.aiReview?.verdict === "likely");
  const safe = findings.filter(f => f.aiReview?.verdict === "safe");

  const lines = [
    `# Universal Engine 安全检测报告`,
    ``,
    `## 一、概览`,
    `- 生成时间：${new Date().toLocaleString()}`,
    `- 项目名称：${projectName || "全部项目"}`,
    `- 资产总数：${state.assets.length}`,
    `- 发现总数：${findings.length}`,
    `- 已确认漏洞：${confirmed.length}`,
    `- 高概率风险：${likely.length}`,
    `- 已排除误报：${safe.length}`,
    ``,
    `## 二、已确认漏洞`,
    ...(confirmed.length ? confirmed.map(f => [
      `### ${f.assetName} / ${f.templateName}`,
      `- 目标：${f.target}`,
      `- 风险等级：${f.severity}`,
      `- AI置信度：${f.aiReview?.confidence || "N/A"}`,
      `- 分析：${f.aiReview?.rationale || "待分析"}`,
      `- 修复建议：${f.aiReview?.remediation || "人工确认"}`,
      ``
    ].join("\n")) : ["未发现已确认漏洞", ""]),
    ``,
    `## 三、高概率风险`,
    ...(likely.length ? likely.map(f => [
      `### ${f.assetName} / ${f.templateName}`,
      `- 目标：${f.target}`,
      `- 风险等级：${f.severity}`,
      `- 分析：${f.aiReview?.rationale || "待分析"}`,
      ``
    ].join("\n")) : ["未发现高概率风险", ""]),
    ``,
    `## 四、指纹分布`,
    ...(() => {
      const fp = {};
      state.assets.forEach(a => {
        const p = a.fingerprint?.platform || "unknown";
        fp[p] = (fp[p] || 0) + 1;
      });
      return Object.entries(fp).sort((a, b) => b[1] - a[1])
        .map(([k, v]) => `- ${k}: ${v}`);
    })(),
    ``
  ];

  return lines.join("\n");
}

// ----- Agent API -----
export const agentType = "orchestrator";
export const capabilities = [
  "pipeline:execute", "pipeline:status",
  "asset:import", "fingerprint:batch",
  "scan:execute", "review:batch",
  "generate:report", "merge:templates"
];

export async function handleTask(task) {
  const { action, data } = task;
  const engine = new PipelineEngine(loadState());

  try {
    switch (action) {
      case "pipeline:execute": {
        const result = await engine.execute(data.input, data.stages);
        return { success: true, pipeline: result };
      }

      case "pipeline:status": {
        const status = engine.getStatus(data?.pipelineId);
        return { success: true, pipelines: status };
      }

      case "asset:auto-import": {
        const result = await engine.handleAssetImport(data, { logs: [] });
        return { success: true, ...result };
      }

      case "fingerprint:batch": {
        const result = await engine.handleFingerprint(data, { logs: [] });
        return { success: true, ...result };
      }

      case "scan:auto": {
        const result = await engine.handleScan(data, { logs: [] });
        return { success: true, ...result };
      }

      case "review:batch": {
        const result = await engine.handleAIReview(data, { logs: [] });
        return { success: true, ...result };
      }

      case "report:generate": {
        const result = await engine.handleReport(data, { logs: [] });
        return { success: true, ...result };
      }

      case "quick-pipeline": {
        // 最常用的快捷管线：导入 → 指纹 → 扫描 → AI复核 → 报告
        const pipeline = await engine.execute(data, [
          "asset-import", "fingerprint", "scan", "ai-review", "report"
        ]);
        return { success: true, pipeline };
      }

      default:
        return { success: false, error: `Unknown action: ${action}` };
    }
  } catch (error) {
    return { success: false, error: error.message };
  }
}

export function getStatus() {
  return {
    type: agentType,
    capabilities,
    pipelines: PIPELINE,
    routing: AGENT_ROUTING
  };
}

export { PipelineEngine, PIPELINE, AGENT_ROUTING, generateMarkdownReport };
