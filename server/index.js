import fs from "node:fs";
import path from "node:path";
import { createServer } from "node:http";
import express from "express";
import cors from "cors";
import multer from "multer";
import { WebSocketServer } from "ws";
import { loadState, saveState } from "./lib/state.js";
import {
  importTemplateUploads,
  loadSampleTemplates,
  mergeImportedTemplates,
  summarizeTemplateGroups
} from "./lib/template-service.js";
import { createScanManager } from "./lib/scan-orchestrator.js";
import { locateUpstreamSources } from "./lib/upstream-locator-service.js";
import {
  enrichImportedAssets,
  extractAssetCandidatesFromBuffer,
  mergeImportedAssets
} from "./lib/asset-import-service.js";
import { fingerprintAsset } from "./lib/fingerprint-service.js";
import { v4 as uuidv4 } from "uuid";

function normalizeProjectName(value) {
  return `${value ?? ""}`.trim() || "Default Project";
}

function parseTags(value) {
  if (Array.isArray(value)) {
    return value.map((item) => `${item}`.trim()).filter(Boolean);
  }

  return `${value ?? ""}`
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function assetMatchesSelection(asset, { projectName, assetIds }) {
  const matchesProject = !projectName || normalizeProjectName(asset.projectName) === normalizeProjectName(projectName);
  const matchesIds = !assetIds?.length || assetIds.includes(asset.id);
  return matchesProject && matchesIds;
}

function toCsv(rows) {
  if (!rows.length) {
    return "";
  }

  const headers = Object.keys(rows[0]);
  const escapeCell = (value) => `"${`${value ?? ""}`.replaceAll('"', '""')}"`;
  return [headers.join(","), ...rows.map((row) => headers.map((header) => escapeCell(row[header])).join(","))].join("\n");
}

const app = express();
const server = createServer(app);
const wss = new WebSocketServer({ server });
const runtimeState = {
  assetImport: null
};
const upload = multer({
  limits: {
    fileSize: 40 * 1024 * 1024,
    files: 30
  }
});
const state = loadState();
const scanManager = createScanManager({ state, persist, broadcast });

if (state.templates.length === 0) {
  state.templates = loadSampleTemplates();
  saveState(state);
}

function persist() {
  saveState(state);
}

function broadcast(type, payload) {
  const message = JSON.stringify({ type, payload });
  for (const client of wss.clients) {
    if (client.readyState === 1) {
      client.send(message);
    }
  }
}

app.use(cors());
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.resolve("public")));

app.get("/api/bootstrap", (_req, res) => {
  res.json({
    ...state,
    runtime: runtimeState
  });
});

app.post("/api/assets", (req, res) => {
  const asset = {
    id: uuidv4(),
    name: req.body.name,
    projectName: normalizeProjectName(req.body.projectName),
    target: req.body.target,
    owner: req.body.owner || "Unassigned",
    tags: parseTags(req.body.tags),
    status: "new",
    fingerprint: null
  };

  state.assets.unshift(asset);
  persist();
  broadcast("asset:new", asset);
  res.status(201).json(asset);
});

app.post("/api/assets/import", (req, res) => {
  const records = Array.isArray(req.body.assets) ? req.body.assets : [];
  const imported = records
    .filter((item) => item?.target && item?.name)
    .map((item) => ({
      id: uuidv4(),
      name: item.name,
      projectName: normalizeProjectName(item.projectName || req.body.projectName),
      target: item.target,
      owner: item.owner || "Imported",
      tags: Array.isArray(item.tags) ? item.tags : parseTags(req.body.tags),
      status: "new",
      fingerprint: null
    }));

  state.assets.unshift(...imported);
  persist();
  imported.forEach((asset) => broadcast("asset:new", asset));
  res.json({ imported: imported.length });
});

app.post("/api/assets/refingerprint", async (req, res) => {
  const assetIds = Array.isArray(req.body.assetIds) ? req.body.assetIds : [];
  const projectName = req.body.projectName ? normalizeProjectName(req.body.projectName) : "";
  const selectedAssets = state.assets.filter((asset) => assetMatchesSelection(asset, { projectName, assetIds }));

  for (const asset of selectedAssets) {
    asset.fingerprint = await fingerprintAsset(asset, state.settings.ai);
    asset.status = "fingerprinted";
    broadcast("asset:update", asset);
  }

  persist();
  res.json({
    ok: true,
    updated: selectedAssets.length,
    assets: selectedAssets.slice(0, 30)
  });
});

app.post("/api/assets/import-file", upload.single("file"), async (req, res) => {
  if (!req.file) {
    res.status(400).json({ error: "file is required" });
    return;
  }

  try {
    const candidates = extractAssetCandidatesFromBuffer(req.file.originalname, req.file.buffer);
    runtimeState.assetImport = {
      id: crypto.randomUUID(),
      fileName: req.file.originalname,
      projectName: normalizeProjectName(req.body.projectName || "Default Project"),
      status: "running",
      stage: "extracting",
      processed: 0,
      total: candidates.length,
      percent: 0,
      imported: 0,
      skippedDuplicates: 0,
      live: 0,
      unreachable: 0,
      currentTarget: "",
      startedAt: new Date().toISOString(),
      finishedAt: null
    };
    broadcast("asset-import:update", runtimeState.assetImport);

    const importedAssets = await enrichImportedAssets(candidates, {
      owner: req.body.owner,
      projectName: req.body.projectName,
      tags: parseTags(req.body.tags),
      concurrency: Math.min(state.settings?.scanning?.assetConcurrency || 4, 12),
      onProgress: ({ processed, total, candidate, probe }) => {
        if (!runtimeState.assetImport) {
          return;
        }

        runtimeState.assetImport = {
          ...runtimeState.assetImport,
          stage: "probing",
          processed,
          total,
          percent: total ? Math.min(99, Math.round((processed / total) * 100)) : 0,
          currentTarget: probe.finalUrl || candidate.target,
          live: runtimeState.assetImport.live + (probe.reachable ? 1 : 0),
          unreachable: runtimeState.assetImport.unreachable + (probe.reachable ? 0 : 1)
        };
        broadcast("asset-import:update", runtimeState.assetImport);
      }
    });
    const uniqueImported = mergeImportedAssets(state.assets, importedAssets);

    state.assets.unshift(...uniqueImported);
    persist();
    uniqueImported.forEach((asset) => broadcast("asset:new", asset));

    runtimeState.assetImport = {
      ...runtimeState.assetImport,
      status: "completed",
      stage: "finished",
      percent: 100,
      imported: uniqueImported.length,
      skippedDuplicates: importedAssets.length - uniqueImported.length,
      live: uniqueImported.filter((asset) => asset.availability?.reachable).length,
      unreachable: uniqueImported.filter((asset) => !asset.availability?.reachable).length,
      finishedAt: new Date().toISOString()
    };
    broadcast("asset-import:update", runtimeState.assetImport);

    res.json({
      scannedRows: candidates.length,
      imported: uniqueImported.length,
      skippedDuplicates: importedAssets.length - uniqueImported.length,
      live: uniqueImported.filter((asset) => asset.availability?.reachable).length,
      unreachable: uniqueImported.filter((asset) => !asset.availability?.reachable).length,
      assets: uniqueImported.slice(0, 30)
    });
  } catch (error) {
    runtimeState.assetImport = {
      ...(runtimeState.assetImport || {}),
      status: "failed",
      stage: "failed",
      error: error.message,
      finishedAt: new Date().toISOString()
    };
    broadcast("asset-import:update", runtimeState.assetImport);
    res.status(500).json({ error: error.message });
  }
});

app.delete("/api/assets", (req, res) => {
  const assetIds = Array.isArray(req.body.assetIds) ? req.body.assetIds : [];
  const projectName = req.body.projectName ? normalizeProjectName(req.body.projectName) : "";
  const removableIds = new Set(
    state.assets.filter((asset) => assetMatchesSelection(asset, { projectName, assetIds })).map((asset) => asset.id)
  );

  state.assets = state.assets.filter((asset) => !removableIds.has(asset.id));
  state.findings = state.findings.filter((finding) => !removableIds.has(finding.assetId));
  state.tasks = state.tasks.filter((task) => !task.assetIds.some((assetId) => removableIds.has(assetId)));
  state.queue.pending = state.queue.pending.filter((taskId) => state.tasks.some((task) => task.id === taskId));
  state.queue.running = state.queue.running.filter((taskId) => state.tasks.some((task) => task.id === taskId));
  persist();
  broadcast("tasks:reset", state.tasks);
  res.json({ removed: removableIds.size, remainingAssets: state.assets.length });
});

app.delete("/api/projects", (_req, res) => {
  const removedProjects = new Set(state.assets.map((asset) => asset.projectName || "Default Project")).size;
  const removedAssets = state.assets.length;
  const removedFindings = state.findings.length;
  const removedTasks = state.tasks.length;
  const removedReports = state.reports.length;

  state.assets = [];
  state.findings = [];
  state.tasks = [];
  state.reports = [];
  state.queue.pending = [];
  state.queue.running = [];
  state.queue.completed = 0;
  state.queue.failed = 0;
  state.queue.canceled = 0;

  persist();
  broadcast("tasks:reset", state.tasks);
  broadcast("queue:update", state.queue);

  res.json({
    ok: true,
    removedProjects,
    removedAssets,
    removedFindings,
    removedTasks,
    removedReports
  });
});

app.get("/api/assets/export", (req, res) => {
  const projectName = req.query.projectName ? normalizeProjectName(req.query.projectName) : "";
  const format = `${req.query.format || "json"}`.toLowerCase();
  const assets = state.assets.filter((asset) => assetMatchesSelection(asset, { projectName }));

  if (format === "csv") {
    const rows = assets.map((asset) => ({
      projectName: asset.projectName || "",
      name: asset.name,
      target: asset.target,
      owner: asset.owner || "",
      status: asset.status || "",
      title: asset.availability?.title || "",
      httpStatus: asset.availability?.httpStatus || "",
      finalUrl: asset.availability?.finalUrl || "",
      tags: (asset.tags || []).join("|")
    }));
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="assets-${projectName || "all"}.csv"`);
    res.send(toCsv(rows));
    return;
  }

  res.json({
    projectName: projectName || "all",
    count: assets.length,
    assets
  });
});

app.get("/api/findings/export", (req, res) => {
  const projectName = req.query.projectName ? normalizeProjectName(req.query.projectName) : "";
  const format = `${req.query.format || "json"}`.toLowerCase();
  const findings = state.findings.filter((finding) => !projectName || normalizeProjectName(finding.projectName) === projectName);

  if (format === "csv") {
    const rows = findings.map((finding) => ({
      projectName: finding.projectName || "",
      assetName: finding.assetName,
      target: finding.target,
      templateName: finding.templateName,
      severity: finding.severity,
      verdict: finding.aiReview?.verdict || "pending",
      rationale: finding.aiReview?.rationale || "",
      createdAt: finding.createdAt
    }));
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="findings-${projectName || "all"}.csv"`);
    res.send(toCsv(rows));
    return;
  }

  res.json({
    projectName: projectName || "all",
    count: findings.length,
    findings
  });
});

app.post("/api/upstream/lookup", async (req, res) => {
  const asset = req.body.assetId ? state.assets.find((item) => item.id === req.body.assetId) : null;

  try {
    const result = await locateUpstreamSources({
      asset,
      customQuery: req.body.query
    });

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
    broadcast("upstream:new", record);
    res.json(record);
  } catch (error) {
    res.status(502).json({ error: error.message });
  }
});

app.post("/api/templates/import", upload.array("files"), (req, res) => {
  const importResult = importTemplateUploads(req.files ?? [], req.body.text || "", req.body.sourceName || "inline.yaml");
  const imported = importResult.templates;

  const uniqueImported = mergeImportedTemplates(state.templates, imported);

  state.templates.unshift(...uniqueImported);
  persist();
  uniqueImported.forEach((template) => broadcast("template:new", template));
  res.json({
    imported: uniqueImported.length,
    skippedDuplicates: imported.length - uniqueImported.length,
    importStats: importResult.stats,
    templates: uniqueImported,
    groups: summarizeTemplateGroups(uniqueImported)
  });
});

app.put("/api/settings", (req, res) => {
  state.settings = {
    ...state.settings,
    ...req.body,
    scanning: {
      ...state.settings.scanning,
      ...(req.body.scanning || {})
    },
    nuclei: {
      ...state.settings.nuclei,
      ...(req.body.nuclei || {})
    },
    ai: {
      ...state.settings.ai,
      ...(req.body.ai || {})
    }
  };

  persist();
  broadcast("settings:update", state.settings);
  scanManager.processQueue().catch((error) => {
    console.error(error);
  });
  res.json(state.settings);
});

app.post("/api/scans", async (req, res) => {
  const task = scanManager.enqueueScan({
    ...(req.body || {}),
    projectName: req.body?.projectName || ""
  });
  res.status(202).json({ accepted: true, task });
});

app.post("/api/scans/:taskId/cancel", (req, res) => {
  const task = scanManager.cancelTask(req.params.taskId);
  if (!task) {
    res.status(404).json({ error: "task not found" });
    return;
  }

  res.json({ ok: true, task });
});

app.post("/api/scans/:taskId/retry", (req, res) => {
  const task = scanManager.retryTask(req.params.taskId);
  if (!task) {
    res.status(404).json({ error: "task not found" });
    return;
  }

  res.status(202).json({ ok: true, task });
});

app.delete("/api/tasks/finished", (_req, res) => {
  const tasks = scanManager.clearFinishedTasks();
  res.json({ ok: true, tasks });
});

app.get("/api/reports/latest", (_req, res) => {
  res.json(state.reports[0] ?? null);
});

app.get("/api/reports/export/latest", (req, res) => {
  const projectName = req.query.projectName ? normalizeProjectName(req.query.projectName) : "";
  const format = `${req.query.format || "md"}`.toLowerCase();
  const report = projectName
    ? state.reports.find((item) => normalizeProjectName(item.summary?.projectName || item.projectName) === projectName)
    : state.reports[0];

  if (!report) {
    res.status(404).json({ error: "report not found" });
    return;
  }

  if (format === "json") {
    res.json(report);
    return;
  }

  res.setHeader("Content-Type", "text/markdown; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="report-${projectName || "latest"}.md"`);
  res.send(report.markdown || "");
});

app.get("/monitoring", (_req, res) => {
  const monitoringPath = path.resolve("public/monitoring.html");
  if (fs.existsSync(monitoringPath)) {
    res.sendFile(monitoringPath);
    return;
  }

  res.status(404).send("Universal Engine monitoring screen not found.");
});

wss.on("connection", (socket) => {
  socket.send(
    JSON.stringify({
      type: "hello",
      payload: {
        connectedAt: new Date().toISOString(),
        queue: state.queue
      }
    })
  );
});

app.get("*", (_req, res) => {
  const indexPath = path.resolve("public/index.html");
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
    return;
  }

  res.status(404).send("Universal Engine UI not found.");
});

const port = process.env.PORT || 3080;
server.listen(port, () => {
  console.log(`Universal Engine listening on http://localhost:${port}`);
  scanManager.recoverQueueState();
  scanManager.processQueue().catch((error) => {
    console.error(error);
  });
});
