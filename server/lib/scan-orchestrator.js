import { v4 as uuidv4 } from "uuid";
import { fingerprintAsset } from "./fingerprint-service.js";
import { reviewFinding } from "./ai-review-service.js";
import { runNucleiTemplate } from "./nuclei-executor.js";

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function normalizePositiveInteger(value, fallback) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 1) {
    return fallback;
  }

  return Math.floor(parsed);
}

function templateMatches(template, fingerprint) {
  if (!template || !fingerprint?.platform || !fingerprint?.category || !Array.isArray(template.tags)) {
    return false;
  }

  const tags = template.tags.map((item) => item.toLowerCase());
  const platform = fingerprint.platform.toLowerCase();
  const category = fingerprint.category.toLowerCase();
  const product = template.product.toLowerCase();

  if (platform === "generic-web") {
    return product === "generic-web" || tags.includes("generic-web") || tags.includes("generic");
  }

  return (
    tags.includes(platform) ||
    tags.includes(category) ||
    product === platform
  );
}

function buildReport(task, findings) {
  const confirmed = findings.filter((item) => item.aiReview?.verdict === "confirmed");
  const likely = findings.filter((item) => item.aiReview?.verdict === "likely");
  const verdictLabel = (review) => {
    const verdict = review?.verdict || "pending";
    return (
      {
        confirmed: "已确认",
        likely: "高概率",
        pending: "待复核",
        "not-reviewed": "未复核"
      }[verdict] || verdict
    );
  };
  const rationaleLabel = (review) => {
    if (!review?.rationale) {
      return "等待 AI 复核或人工确认。";
    }
    if (review.rationale === "AI review is disabled in settings.") {
      return "当前未启用 AI 复核，请结合证据进行人工确认。";
    }
    if (review.rationale === "No AI review available") {
      return "当前没有 AI 复核结果。";
    }
    return review.rationale;
  };
  const remediationLabel = (review) => {
    if (!review?.remediation || review.remediation === "Manual review required") {
      return "建议结合业务上下文做进一步人工复核与修复。";
    }
    if (review.remediation === "Enable a provider to perform evidence-based rechecks.") {
      return "建议先启用 AI 提供方，再基于证据进行复测确认。";
    }
    return review.remediation;
  };

  return {
    id: uuidv4(),
    taskId: task.id,
    projectName: task.projectName || "",
    generatedAt: new Date().toISOString(),
    summary: {
      taskName: task.name,
      projectName: task.projectName || "",
      scannedAssets: task.assetIds.length,
      findings: findings.length,
      confirmed: confirmed.length,
      likely: likely.length,
      durationMs: task.metrics.durationMs ?? 0
    },
    items: findings.map((item) => ({
      id: item.id,
      assetId: item.assetId,
      assetName: item.assetName,
      projectName: item.projectName,
      target: item.target,
      templateId: item.templateId,
      templateName: item.templateName,
      severity: item.severity,
      tags: item.tags,
      fingerprint: item.fingerprint,
      evidence: item.evidence,
      createdAt: item.createdAt,
      aiReview: item.aiReview
    })),
    markdown: [
      `# Universal Engine 漏洞检测报告`,
      ``,
      `## 一、任务概览`,
      `- 扫描任务：${task.name}`,
      `- 生成时间：${new Date().toLocaleString()}`,
      `- 所属项目：${task.projectName || "混合项目"}`,
      `- 扫描资产数：${task.assetIds.length}`,
      `- 发现总数：${findings.length}`,
      `- 已确认：${confirmed.length}`,
      `- 高概率：${likely.length}`,
      `- 扫描耗时：${task.metrics.durationMs ?? 0} ms`,
      ``,
      `## 二、漏洞明细`,
      ...findings.map((item) =>
        [
          `### ${item.assetName} / ${item.templateName}`,
          `- 漏洞目标：${item.target}`,
          `- 风险等级：${item.severity}`,
          `- 指纹结果：${item.fingerprint.platform} / ${item.fingerprint.category}`,
          `- 复核结论：${verdictLabel(item.aiReview)}`,
          `- 分析说明：${rationaleLabel(item.aiReview)}`,
          `- 修复建议：${remediationLabel(item.aiReview)}`,
          `- 证据：${(item.evidence || []).join("；") || "暂无证据"}`,
          ``
        ].join("\n")
      )
    ].join("\n")
  };
}

function createTaskProgress(assetIds) {
  return {
    totalAssets: assetIds.length,
    processedAssets: 0,
    activeAssets: 0,
    totalTemplates: 0,
    processedTemplates: 0,
    findings: 0,
    percent: 0
  };
}

function updatePercent(task) {
  const assetRatio = task.progress.totalAssets
    ? task.progress.processedAssets / task.progress.totalAssets
    : 0;
  const templateRatio = task.progress.totalTemplates
    ? task.progress.processedTemplates / task.progress.totalTemplates
    : 0;
  const computedPercent = Math.min(100, Math.round((assetRatio * 0.4 + templateRatio * 0.6) * 100));

  if (task.status === "running" && task.progress.activeAssets > 0 && task.progress.processedTemplates === 0) {
    task.progress.percent = Math.max(task.progress.percent || 0, 1);
    return;
  }

  task.progress.percent = Math.max(task.progress.percent || 0, computedPercent);
}

function appendLog(task, message, broadcast) {
  task.logs.push(message);
  task.logs = task.logs.slice(-40);
  broadcast("task:log", { taskId: task.id, message });
}

function createSnapshot(state) {
  return {
    pending: state.queue.pending.length,
    running: state.queue.running.length,
    completed: state.queue.completed,
    failed: state.queue.failed,
    canceled: state.queue.canceled
  };
}

export function createQueuedTask(state, payload = {}) {
  const assetIds = payload.assetIds?.length ? payload.assetIds : state.assets.map((asset) => asset.id);
  return {
    id: uuidv4(),
    name: payload.name || `Scan ${new Date().toLocaleTimeString()}`,
    status: "queued",
    stage: "pending-dispatch",
    assetIds,
    createdAt: new Date().toISOString(),
    queuedAt: new Date().toISOString(),
    startedAt: null,
    completedAt: null,
    queuePosition: 0,
    progress: createTaskProgress(assetIds),
    metrics: {
      findings: 0,
      durationMs: 0
    },
    filters: {
      source: payload.source || "manual",
      note: payload.note || ""
    },
    projectName: payload.projectName || "",
    logs: ["Task queued and waiting for a worker slot."]
  };
}

async function handleFinding({ state, persist, broadcast, task, finding, findings }) {
  if (state.settings.scanning.autoAiReview) {
    finding.aiReview = await reviewFinding(state.settings.ai, finding);
  }

  state.findings.unshift(finding);
  findings.push(finding);
  task.progress.findings += 1;
  task.metrics.findings = task.progress.findings;
  persist();
  broadcast("finding:new", finding);
}

async function processAsset({ asset, task, state, persist, broadcast, findings, isCanceled }) {
  if (!asset || isCanceled()) {
    return;
  }

  task.stage = "fingerprinting";
  task.progress.activeAssets += 1;
  updatePercent(task);
  appendLog(task, `Fingerprinting ${asset.target}`, broadcast);
  broadcast("task:update", task);

  const fingerprint = await fingerprintAsset(asset, state.settings.ai);
  asset.fingerprint = fingerprint;
  asset.status = "fingerprinted";
  persist();
  broadcast("asset:update", asset);

  await wait(160);

  const templates = state.templates.filter((template) => templateMatches(template, fingerprint));
  const runnableTemplates = templates.filter((template) => template.runnable !== false && template.raw);
  const metadataOnlyTemplates = templates.length - runnableTemplates.length;
  task.progress.totalTemplates += templates.length;
  task.stage = "template-routing";
  updatePercent(task);
  appendLog(task, `Selected ${templates.length} templates for ${asset.name}`, broadcast);
  if (metadataOnlyTemplates > 0) {
    appendLog(task, `Skipped ${metadataOnlyTemplates} metadata-only templates for ${asset.name}`, broadcast);
  }
  broadcast("task:update", task);

  if (!state.settings.nuclei.enabled) {
    task.progress.processedTemplates += templates.length;
    updatePercent(task);
    appendLog(task, "Nuclei execution is disabled, so matched templates were not executed.", broadcast);
    broadcast("task:update", task);
    task.progress.processedAssets += 1;
    task.progress.activeAssets = Math.max(0, task.progress.activeAssets - 1);
    updatePercent(task);
    task.stage = "asset-finished";
    broadcast("task:update", task);
    return;
  }

  if (!runnableTemplates.length) {
    task.progress.processedTemplates += templates.length;
    updatePercent(task);
    task.progress.processedAssets += 1;
    task.progress.activeAssets = Math.max(0, task.progress.activeAssets - 1);
    task.stage = "asset-finished";
    broadcast("task:update", task);
    return;
  }

  task.progress.processedTemplates += metadataOnlyTemplates;

  for (const template of runnableTemplates) {
    if (isCanceled()) {
      break;
    }

    await wait(80);
    task.stage = "template-execution";
    const nucleiResult = await runNucleiTemplate(asset, fingerprint, template, state.settings.nuclei);
    const emittedFindings = nucleiResult.mode === "nuclei" ? nucleiResult.findings : [];

    if (nucleiResult.mode === "error") {
      appendLog(task, `Nuclei execution failed for ${template.nucleiId}: ${nucleiResult.error}`, broadcast);
    }

    for (const finding of emittedFindings) {
      if (isCanceled()) {
        break;
      }

      task.stage = "ai-review";
      await handleFinding({ state, persist, broadcast, task, finding, findings });
    }

    task.progress.processedTemplates += 1;
    updatePercent(task);
    broadcast("task:update", task);
  }

  task.progress.processedAssets += 1;
  task.progress.activeAssets = Math.max(0, task.progress.activeAssets - 1);
  updatePercent(task);
  task.stage = "asset-finished";
  broadcast("task:update", task);
}

async function runPool(items, workerCount, worker) {
  let cursor = 0;

  async function consume() {
    while (cursor < items.length) {
      const index = cursor;
      cursor += 1;
      await worker(items[index], index);
    }
  }

  const size = Math.min(workerCount, Math.max(items.length, 1));
  await Promise.all(Array.from({ length: size }, () => consume()));
}

export async function executeQueuedTask({ state, persist, broadcast, task, isCanceled }) {
  task.status = "running";
  task.stage = "dispatching";
  task.startedAt = new Date().toISOString();
  task.queuePosition = 0;
  appendLog(task, "Worker slot acquired. Dispatching assets.", broadcast);
  persist();
  broadcast("task:update", task);

  const findings = [];
  const startedAt = Date.now();
  const assetConcurrency = normalizePositiveInteger(state.settings.scanning.assetConcurrency, 4);
  const assetIds = [...task.assetIds];

  await runPool(assetIds, assetConcurrency, async (assetId) => {
    const asset = state.assets.find((item) => item.id === assetId);
    await processAsset({ asset, task, state, persist, broadcast, findings, isCanceled });
  });

  task.metrics.durationMs = Date.now() - startedAt;

  if (isCanceled()) {
    task.status = "canceled";
    task.stage = "canceled";
    task.completedAt = new Date().toISOString();
    appendLog(task, "Task was canceled before completion.", broadcast);
    persist();
    broadcast("task:update", task);
    return { task, report: null, findings };
  }

  task.status = "completed";
  task.stage = "reporting";
  task.completedAt = new Date().toISOString();
  updatePercent(task);

  const report = buildReport(task, findings);
  state.reports.unshift(report);
  persist();

  broadcast("report:new", report);
  broadcast("task:update", task);
  return { task, report, findings };
}

export function createScanManager({ state, persist, broadcast }) {
  const canceledTaskIds = new Set();
  let processing = false;

  function syncQueuePositions() {
    state.queue.pending.forEach((taskId, index) => {
      const task = state.tasks.find((item) => item.id === taskId);
      if (task) {
        task.queuePosition = index + 1;
      }
    });
  }

  function broadcastQueue() {
    broadcast("queue:update", createSnapshot(state));
  }

  function recoverQueueState() {
    state.queue.pending = [];
    state.queue.running = [];

    for (const task of state.tasks) {
      if (task.status === "queued") {
        task.stage = "pending-dispatch";
        task.queuePosition = 0;
        state.queue.pending.push(task.id);
        continue;
      }

      if (task.status === "running") {
        task.status = "failed";
        task.stage = "failed";
        task.completedAt = new Date().toISOString();
        task.queuePosition = 0;
        task.progress.activeAssets = 0;
        task.logs = task.logs || [];
        task.logs.push("Task interrupted by a server restart. Please retry the scan.");
        task.logs = task.logs.slice(-40);
        state.queue.failed += 1;
      }
    }

    syncQueuePositions();
    persist();
  }

  function finalizeTaskCounters(task) {
    if (task.status === "completed") {
      state.queue.completed += 1;
    } else if (task.status === "failed") {
      state.queue.failed += 1;
    } else if (task.status === "canceled") {
      state.queue.canceled += 1;
    }
  }

  async function processQueue() {
    if (processing) {
      return;
    }

    processing = true;
    try {
      const limit = normalizePositiveInteger(state.settings.scanning.maxConcurrentTasks, 2);
      while (state.queue.running.length < limit && state.queue.pending.length > 0) {
        const taskId = state.queue.pending.shift();
        const task = state.tasks.find((item) => item.id === taskId);
        if (!task || task.status === "canceled") {
          syncQueuePositions();
          persist();
          broadcastQueue();
          continue;
        }

        state.queue.running.push(task.id);
        syncQueuePositions();
        persist();
        broadcastQueue();

        executeQueuedTask({
          state,
          persist,
          broadcast,
          task,
          isCanceled: () => canceledTaskIds.has(task.id)
        })
          .catch((error) => {
            task.status = "failed";
            task.stage = "failed";
            task.completedAt = new Date().toISOString();
            appendLog(task, `Task failed: ${error.message}`, broadcast);
            persist();
            broadcast("task:update", task);
          })
          .finally(() => {
            state.queue.running = state.queue.running.filter((id) => id !== task.id);
            finalizeTaskCounters(task);
            syncQueuePositions();
            persist();
            broadcastQueue();
            processQueue().catch((error) => console.error(error));
          });
      }
    } finally {
      processing = false;
    }
  }

  function enqueueScan(payload = {}) {
    const task = createQueuedTask(state, payload);
    state.tasks.unshift(task);
    state.queue.pending.push(task.id);
    syncQueuePositions();
    persist();
    broadcast("task:update", task);
    broadcastQueue();
    processQueue().catch((error) => console.error(error));
    return task;
  }

  function cancelTask(taskId) {
    const task = state.tasks.find((item) => item.id === taskId);
    if (!task) {
      return null;
    }

    if (task.status === "queued") {
      state.queue.pending = state.queue.pending.filter((id) => id !== taskId);
      task.status = "canceled";
      task.stage = "canceled-before-start";
      task.completedAt = new Date().toISOString();
      task.queuePosition = 0;
      task.logs.push("Task canceled while still in queue.");
      state.queue.canceled += 1;
      syncQueuePositions();
      persist();
      broadcast("task:update", task);
      broadcastQueue();
      return task;
    }

    if (task.status === "running") {
      canceledTaskIds.add(taskId);
      appendLog(task, "Cancellation requested. Waiting for active workers to stop.", broadcast);
      persist();
      broadcast("task:update", task);
      return task;
    }

    return task;
  }

  function retryTask(taskId) {
    const task = state.tasks.find((item) => item.id === taskId);
    if (!task) {
      return null;
    }

    return enqueueScan({
      name: `${task.name} Retry`,
      assetIds: task.assetIds,
      source: "retry",
      note: `Retry of ${task.id}`
    });
  }

  function clearFinishedTasks() {
    const removable = new Set(
      state.tasks
        .filter((task) => ["completed", "failed", "canceled"].includes(task.status))
        .map((task) => task.id)
    );

    state.tasks = state.tasks.filter((task) => !removable.has(task.id));
    state.queue.pending = state.queue.pending.filter((id) => !removable.has(id));
    state.queue.running = state.queue.running.filter((id) => !removable.has(id));
    syncQueuePositions();
    persist();
    broadcastQueue();
    broadcast("tasks:reset", state.tasks);
    return state.tasks;
  }

  return {
    recoverQueueState,
    enqueueScan,
    cancelTask,
    retryTask,
    clearFinishedTasks,
    processQueue
  };
}
