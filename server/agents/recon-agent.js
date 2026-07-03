// Recon Agent
// 信息搜集智能体：端口扫描→子域名发现→HTTP探测→服务识别→扩展资产面积
// 集成 Kali 工具：nmap, subfinder, httpx, whatweb, naabu

import { spawn } from "node:child_process";
import { v4 as uuidv4 } from "uuid";
import { getToolStrategy } from "./kali-toolbox.js";

// ----- Recon Phase 定义 -----
const RECON_PHASES = {
  "quick": {
    name: "快速侦察",
    tools: ["httpx"],
    timeout: 30000,
    description: "HTTP快速探测，确认存活和基本信息"
  },
  "port-scan": {
    name: "端口扫描",
    tools: ["nmap"],
    timeout: 120000,
    description: "全端口扫描 + 服务版本识别"
  },
  "subdomain": {
    name: "子域名发现",
    tools: ["subfinder"],
    timeout: 60000,
    description: "子域名枚举，扩大攻击面"
  },
  "deep": {
    name: "深度侦察",
    tools: ["nmap", "subfinder", "httpx", "whatweb"],
    timeout: 300000,
    description: "全方位信息搜集"
  }
};

// ----- 核心侦察引擎 -----
async function runRecon(asset, phase = "quick", options = {}) {
  const results = {
    assetId: asset.id,
    assetName: asset.name,
    target: asset.target,
    startedAt: new Date().toISOString(),
    phases: {},
    discoveredAssets: [],  // 新发现的资产（子域名、其他端口上的服务等）
    openPorts: [],
    subdomains: [],
    technologies: [],
    rawOutput: {}
  };

  let hostname;
  try {
    hostname = new URL(asset.target).hostname;
  } catch {
    hostname = asset.target.replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
  }
  const ip = asset.availability?.finalUrl ? await resolveHost(hostname) : hostname;

  // Phase 1: HTTP 快速探测
  if (phase === "quick" || phase === "deep") {
    results.phases.httpx = await runHttpx(hostname, options);
    results.technologies = results.phases.httpx.technologies || [];
  }

  // Phase 2: 端口扫描
  if (phase === "port-scan" || phase === "deep") {
    results.phases.nmap = await runNmapScan(hostname, options);
    results.openPorts = results.phases.nmap.ports || [];

    // 为每个开放端口创建新资产候选
    for (const port of results.openPorts) {
      if (port.service === "http" || port.service === "https" || port.service === "http-proxy") {
        const scheme = port.service === "https" || port.port === 443 ? "https" : "http";
        const portSuffix = (port.port === 80 || port.port === 443) ? "" : `:${port.port}`;
        results.discoveredAssets.push({
          target: `${scheme}://${hostname}${portSuffix}`,
          type: "port-discovery",
          port: port.port,
          service: port.service,
          version: port.version || "",
          confidence: 0.85,
          source: "nmap"
        });
      }
    }
  }

  // Phase 3: 子域名发现
  if (phase === "subdomain" || phase === "deep") {
    results.phases.subfinder = await runSubfinder(hostname, options);
    results.subdomains = results.phases.subfinder.subdomains || [];

    // 为每个子域名创建新资产候选
    for (const sub of results.subdomains) {
      results.discoveredAssets.push({
        target: `https://${sub}`,
        type: "subdomain-discovery",
        subdomain: sub,
        confidence: 0.75,
        source: "subfinder"
      });
      // 也探测 HTTP
      results.discoveredAssets.push({
        target: `http://${sub}`,
        type: "subdomain-discovery",
        subdomain: sub,
        confidence: 0.65,
        source: "subfinder"
      });
    }
  }

  // Phase 4: 技术栈识别
  if (phase === "deep") {
    results.phases.whatweb = await runWhatweb(hostname, options);
    if (results.phases.whatweb.technologies) {
      results.technologies = [...new Set([...results.technologies, ...results.phases.whatweb.technologies])];
    }
  }

  results.completedAt = new Date().toISOString();
  return results;
}

// ----- 批量侦察引擎 -----
async function runReconBatch(assets, phase = "quick", options = {}) {
  const allResults = [];
  const allDiscoveredAssets = [];
  const summary = {
    totalAssets: assets.length,
    processedAssets: 0,
    totalOpenPorts: 0,
    totalSubdomains: 0,
    totalDiscovered: 0,
    startedAt: new Date().toISOString()
  };

  for (const asset of assets) {
    const result = await runRecon(asset, phase, options);
    allResults.push(result);
    allDiscoveredAssets.push(...result.discoveredAssets);

    summary.processedAssets++;
    summary.totalOpenPorts += result.openPorts.length;
    summary.totalSubdomains += result.subdomains.length;
  }

  // 去重发现资产
  const seen = new Set();
  const uniqueDiscovered = allDiscoveredAssets.filter(a => {
    const key = a.target.toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  summary.totalDiscovered = uniqueDiscovered.length;
  summary.completedAt = new Date().toISOString();

  return {
    results: allResults,
    discoveredAssets: uniqueDiscovered,
    summary
  };
}

// ----- 工具调用封装 -----
function resolveHost(hostname) {
  // 简单 resolve（不依赖 dns 模块）
  return hostname;
}

async function runHttpx(target, options = {}) {
  return new Promise((resolve) => {
    const args = ["-silent", "-status-code", "-title", "-tech-detect", "-server", "-follow-redirects", "-timeout", "8"];
    const child = spawn("httpx", [...args, "-u", target], {
      stdio: ["ignore", "pipe", "pipe"],
      timeout: options.timeout || 30000
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", chunk => stdout += chunk.toString());
    child.stderr.on("data", chunk => stderr += chunk.toString());

    child.on("close", code => {
      const lines = stdout.split("\n").filter(Boolean);
      const technologies = [];
      let statusCode = 0;
      let title = "";
      let finalUrl = target;

      for (const line of lines) {
        // httpx output: url [status] [title] [tech1,tech2,...]
        const parts = line.match(/^(\S+)\s+\[(\d+)\]\s+\[(.*?)\]\s+\[(.*?)\]$/);
        if (parts) {
          finalUrl = parts[1];
          statusCode = parseInt(parts[2]);
          title = parts[3];
          technologies.push(...parts[4].split(",").map(t => t.trim()).filter(Boolean));
        }
      }

      resolve({
        success: code === 0,
        target,
        finalUrl,
        statusCode,
        title,
        technologies: [...new Set(technologies)],
        rawOutput: stdout.slice(0, 500)
      });
    });

    child.on("error", err => {
      resolve({ success: false, target, error: err.message, technologies: [] });
    });
  });
}

async function runNmapScan(target, options = {}) {
  return new Promise((resolve) => {
    const args = [
      "-sV", "-T4", "--open",
      "-p", options.ports || "80,443,8080,8443,9090,3000,5000,8000,3306,5432,6379,27017,22,21",
      "--max-retries", "1",
      "--host-timeout", "60s"
    ];

    const child = spawn("nmap", [...args, target], {
      stdio: ["ignore", "pipe", "pipe"],
      timeout: options.timeout || 120000
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", chunk => stdout += chunk.toString());
    child.stderr.on("data", chunk => stderr += chunk.toString());

    child.on("close", code => {
      const ports = [];
      const lines = stdout.split("\n");

      for (const line of lines) {
        const match = line.match(/^(\d+)\/(tcp|udp)\s+open\s+(\S+)\s*(.*)/);
        if (match) {
          ports.push({
            port: parseInt(match[1]),
            protocol: match[2],
            service: match[3],
            version: match[4]?.trim() || ""
          });
        }
      }

      resolve({
        success: true,
        target,
        ports,
        portCount: ports.length,
        rawOutput: stdout.slice(0, 1000)
      });
    });

    child.on("error", err => {
      resolve({ success: false, target, error: err.message, ports: [] });
    });
  });
}

async function runSubfinder(domain, options = {}) {
  return new Promise((resolve) => {
    const child = spawn("subfinder", ["-d", domain, "-silent", "-timeout", "30"], {
      stdio: ["ignore", "pipe", "pipe"],
      timeout: options.timeout || 60000
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", chunk => stdout += chunk.toString());
    child.stderr.on("data", chunk => stderr += chunk.toString());

    child.on("close", code => {
      const subdomains = stdout.split("\n")
        .map(s => s.trim())
        .filter(s => s && s.length > 3 && !s.startsWith("*"));

      resolve({
        success: true,
        domain,
        subdomains: [...new Set(subdomains)],
        count: subdomains.length,
        rawOutput: stdout.slice(0, 1000)
      });
    });

    child.on("error", err => {
      resolve({ success: false, domain, error: err.message, subdomains: [] });
    });
  });
}

async function runWhatweb(target, options = {}) {
  return new Promise((resolve) => {
    const child = spawn("whatweb", ["--no-errors", target], {
      stdio: ["ignore", "pipe", "pipe"],
      timeout: options.timeout || 30000
    });

    let stdout = "";
    child.stdout.on("data", chunk => stdout += chunk.toString());

    child.on("close", code => {
      const technologies = [];
      // whatweb output: url [tech1][tech2]...
      const techMatch = stdout.match(/\[(.*?)\]/g);
      if (techMatch) {
        techMatch.forEach(t => technologies.push(t.replace(/[\[\]]/g, "").trim()));
      }

      resolve({
        success: code === 0,
        target,
        technologies: [...new Set(technologies)],
        rawOutput: stdout.slice(0, 500)
      });
    });

    child.on("error", err => {
      resolve({ success: false, target, error: err.message, technologies: [] });
    });
  });
}

// ----- 资产去重合并（从子域名和端口发现的新资产）-----
function mergeDiscoveredAssets(existingAssets, discoveredTargets) {
  const seen = new Set(
    existingAssets.map(a => (a.target || "").toLowerCase().replace(/\/$/, ""))
  );

  const newAssets = [];

  for (const disco of discoveredTargets) {
    const normalizedTarget = disco.target.toLowerCase().replace(/\/$/, "");
    if (seen.has(normalizedTarget)) continue;
    seen.add(normalizedTarget);

    newAssets.push({
      id: uuidv4(),
      name: disco.subdomain || disco.target.replace(/^https?:\/\//, ""),
      projectName: disco.projectName || "Recon-Discovered",
      target: disco.target,
      owner: "ReconAgent",
      tags: ["recon-discovered", disco.type, disco.source].filter(Boolean),
      status: "new",
      fingerprint: null,
      availability: null,
      reconMeta: {
        discoveryType: disco.type,
        discoveryConfidence: disco.confidence || 0.7,
        discoverySource: disco.source,
        discoveryPort: disco.port,
        discoveryService: disco.service,
        discoveredAt: new Date().toISOString()
      }
    });
  }

  return newAssets;
}

// ----- 完整侦察+扩展管线（供 Orchestrator 调用）-----
async function fullReconPipeline(assets, state, options = {}) {
  // Phase 1: 对每个资产进行端口扫描
  const portResults = [];
  for (const asset of assets) {
    const result = await runRecon(asset, "port-scan", options);
    portResults.push(result);

    // 更新资产的开放端口信息
    if (!asset.availability) asset.availability = {};
    asset.availability.ports = result.openPorts.map(p => p.port);
  }

  // Phase 2: 对每个域名进行子域名发现
  const domains = [...new Set(
    assets.map(a => {
      try { return new URL(a.target).hostname; }
      catch { return a.target.replace(/^https?:\/\//, "").split("/")[0]; }
    })
  )];

  const subResults = [];
  for (const domain of domains.slice(0, 20)) {  // 限制子域名发现数量
    const subs = await runSubfinder(domain, options);
    subResults.push(subs);
  }

  // Phase 3: 收集所有新发现的资产
  const allDiscovered = [];
  for (const r of portResults) {
    allDiscovered.push(...r.discoveredAssets);
  }
  for (const s of subResults) {
    for (const sub of (s.subdomains || [])) {
      allDiscovered.push({
        target: `https://${sub}`,
        type: "subdomain-discovery",
        subdomain: sub,
        confidence: 0.75,
        source: "subfinder"
      });
    }
  }

  // Phase 4: 对新发现的 HTTP 资产做 HTTP 探测
  const httpTargets = allDiscovered.filter(a =>
    a.target.startsWith("http://") || a.target.startsWith("https://")
  );

  // 去重
  const seen = new Set();
  const uniqueHttpTargets = httpTargets.filter(a => {
    const key = a.target.toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // HTTP 快速探测（并发）
  const httpxResults = [];
  for (const dt of uniqueHttpTargets.slice(0, 50)) {  // 限制探测数量
    const probe = await runHttpx(dt.target.replace(/^https?:\/\//, ""), options);
    if (probe.success && probe.statusCode > 0 && probe.statusCode < 500) {
      dt.alive = true;
      dt.statusCode = probe.statusCode;
      dt.title = probe.title;
      dt.technologies = probe.technologies;
    } else {
      dt.alive = false;
    }
    httpxResults.push({ target: dt.target, ...probe });
  }

  // 标记存活的资产并合并到现有资产列表
  const aliveDiscovered = uniqueHttpTargets.filter(a => a.alive);

  const newAssets = mergeDiscoveredAssets(state.assets, aliveDiscovered);
  state.assets.unshift(...newAssets);

  return {
    phase: "full-recon",
    originalAssets: assets.length,
    portsScanned: portResults.reduce((sum, r) => sum + r.openPorts.length, 0),
    subdomainsFound: subResults.reduce((sum, r) => sum + (r.subdomains || []).length, 0),
    newAssetsDiscovered: newAssets.length,
    aliveNewAssets: aliveDiscovered.length,
    discoveredAssets: newAssets.map(a => ({
      name: a.name,
      target: a.target,
      type: a.reconMeta?.discoveryType,
      status: a.status
    })),
    startedAt: new Date().toISOString()
  };
}

// ----- Agent API -----
export const agentType = "recon-agent";
export const capabilities = [
  "recon:quick", "recon:port-scan", "recon:subdomain",
  "recon:deep", "recon:batch", "recon:full-pipeline",
  "recon:discover"
];

export async function handleTask(task) {
  const { action, asset, assets, phase, options } = task.data || {};

  try {
    switch (action) {
      case "recon:quick":
      case "recon:port-scan":
      case "recon:subdomain":
      case "recon:deep": {
        if (!asset) throw new Error("asset required");
        const result = await runRecon(asset, action.replace("recon:", ""), options);
        return { success: true, ...result };
      }

      case "recon:batch": {
        if (!assets?.length) throw new Error("assets array required");
        const result = await runReconBatch(assets, phase || "quick", options);
        return { success: true, ...result };
      }

      case "recon:discover": {
        // 从单个资产出发，自动扩展攻击面
        if (!asset) throw new Error("asset required");
        const result = await runRecon(asset, "deep", options);
        return {
          success: true,
          asset: asset.name,
          openPorts: result.openPorts,
          subdomains: result.subdomains,
          technologies: result.technologies,
          discoveredCount: result.discoveredAssets.length,
          discovered: result.discoveredAssets
        };
      }

      case "recon:full-pipeline": {
        if (!assets?.length) throw new Error("assets array required");
        // state 需要从外部传入
        const state = task._state || task.data.state;
        if (!state) throw new Error("state object required for full-pipeline");
        const result = await fullReconPipeline(assets, state, options);
        return { success: true, ...result };
      }

      case "recon:phases":
        return { success: true, phases: Object.keys(RECON_PHASES).map(k => ({ name: k, ...RECON_PHASES[k] })) };

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
    reconPhases: Object.keys(RECON_PHASES),
    tools: ["nmap", "subfinder", "httpx", "whatweb"],
    status: "ready"
  };
}

export { runRecon, runReconBatch, fullReconPipeline, RECON_PHASES, mergeDiscoveredAssets };
