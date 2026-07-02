// Scan Executor Agent
// 智能扫描执行引擎 - 按指纹选择工具组合，分阶段扫描
// 集成：nuclei, nikto, sqlmap, nmap NSE, httpx (via kali-toolbox)

import { v4 as uuidv4 } from "uuid";
import { getToolStrategy, TOOL_REGISTRY } from "./kali-toolbox.js";

// ----- Fingerprint-to-Runnable Template Matcher -----
function matchTemplates(fingerprint, templates) {
  if (!fingerprint?.platform) return [];

  const platform = fingerprint.platform.toLowerCase();
  const category = (fingerprint.category || "").toLowerCase();

  return templates.filter(t => {
    if (!t.runnable || t.metadataOnly) return false;
    const tags = (t.tags || []).map(x => x.toLowerCase());
    const product = (t.product || "").toLowerCase();

    return (
      tags.includes(platform) ||
      tags.includes(category) ||
      product === platform ||
      tags.some(tag => platform.includes(tag)) ||
      (platform === "generic-web" && (tags.includes("generic") || tags.includes("web")))
    );
  });
}

// ----- Scan Phase Definitions -----
const SCAN_PHASES = {
  "quick": {
    name: "快速侦察",
    timeout: 30000,       // 30s per asset
    tools: ["httpx"],     // Fast HTTP probe
    maxConcurrent: 8,
    description: "HTTP存活探测和技术栈识别"
  },
  "port": {
    name: "端口扫描",
    timeout: 120000,      // 2min per asset
    tools: ["nmap"],
    maxConcurrent: 3,
    description: "端口发现和服务版本识别"
  },
  "web-vuln": {
    name: "Web漏洞扫描",
    timeout: 300000,      // 5min per asset
    tools: ["nuclei", "nikto"],
    maxConcurrent: 2,
    description: "Nuclei模板扫描 + Nikto Web漏洞检测"
  },
  "injection": {
    name: "注入漏洞检测",
    timeout: 600000,      // 10min per asset
    tools: ["sqlmap"],
    maxConcurrent: 1,
    description: "SQL注入深度检测"
  },
  "deep": {
    name: "深度扫描",
    timeout: 600000,
    tools: ["nuclei", "nmap", "nikto", "sqlmap"],
    maxConcurrent: 1,
    description: "全工具深度扫描"
  }
};

// ----- Main Scan Execution -----
async function executeScan(asset, fingerprint, phase = "quick", options = {}) {
  const phaseConfig = SCAN_PHASES[phase] || SCAN_PHASES.quick;
  const strategy = getToolStrategy(fingerprint);
  const allFindings = [];
  const logs = [];
  const startedAt = Date.now();

  logs.push(`[${phaseConfig.name}] Starting scan: ${asset.name} (${fingerprint.platform}/${fingerprint.category})`);

  // Filter tools based on phase and strategy
  const toolsToRun = phaseConfig.tools.filter(t =>
    strategy.tools.includes(t) || options.allTools
  );

  for (const toolName of toolsToRun) {
    const tool = TOOL_REGISTRY[toolName];
    if (!tool) continue;
    if (tool.checkInstall && !tool.checkInstall()) {
      logs.push(`[${phaseConfig.name}] ${toolName}: not installed, skipping`);
      continue;
    }

    logs.push(`[${phaseConfig.name}] ${toolName}: running...`);
    const toolStart = Date.now();

    try {
      const result = await runToolWithRetry(tool, asset.target, strategy.args[toolName] || tool.defaultArgs || [], phaseConfig.timeout);
      const toolDuration = Date.now() - toolStart;

      if (result.findings.length > 0) {
        logs.push(`[${phaseConfig.name}] ${toolName}: ${result.findings.length} finding(s) in ${toolDuration}ms`);
        allFindings.push(...result.findings);
      } else {
        logs.push(`[${phaseConfig.name}] ${toolName}: no findings in ${toolDuration}ms`);
      }
    } catch (e) {
      logs.push(`[${phaseConfig.name}] ${toolName}: error - ${e.message}`);
    }
  }

  logs.push(`[${phaseConfig.name}] Completed: ${allFindings.length} total findings in ${Date.now() - startedAt}ms`);

  return { findings: allFindings, logs, durationMs: Date.now() - startedAt };
}

// Run tool via direct process spawn (happens inside this agent)
async function runToolWithRetry(tool, target, args, timeout) {
  const { spawn } = await import("node:child_process");
  const binary = tool.binary || tool.name;

  return new Promise((resolve) => {
    const child = spawn(binary, [...args, target], {
      stdio: ["ignore", "pipe", "pipe"],
      timeout: Math.min(timeout, 120000)
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", chunk => stdout += chunk.toString());
    child.stderr.on("data", chunk => stderr += chunk.toString());

    child.on("close", code => {
      const findings = parseToolOutput(tool.name || binary, stdout);
      resolve({ code, stdout, stderr, findings });
    });

    child.on("error", err => {
      resolve({ code: -1, stdout: "", stderr: err.message, findings: [] });
    });
  });
}

function parseToolOutput(toolName, output) {
  if (!output?.trim()) return [];

  const findings = [];
  try {
    switch (toolName) {
      case "nuclei":
        for (const line of output.split("\n").filter(Boolean)) {
          try {
            const j = JSON.parse(line);
            findings.push({
              source: "nuclei",
              templateId: j["template-id"] || j.templateID,
              name: j.info?.name || j["template-id"],
              severity: j.info?.severity || "info",
              matched: j["matched-at"] || j.matched,
              extracted: j["extracted-results"] || []
            });
          } catch {}
        }
        break;

      case "nmap":
        for (const line of output.split("\n")) {
          const m = line.match(/(\d+)\/(tcp|udp)\s+open\s+(\S+)/);
          if (m) findings.push({
            source: "nmap", type: "open-port",
            port: Number(m[1]), protocol: m[2], service: m[3]
          });
          const v = line.match(/\|[\s_]+([^:]+):\s*(.+)/);
          if (v) findings.push({
            source: "nmap", type: "nse",
            script: v[1].trim(), detail: v[2].trim()
          });
        }
        break;

      case "nikto":
        for (const line of output.split("\n")) {
          if (line.startsWith("+")) {
            findings.push({ source: "nikto", detail: line.substring(2).trim() });
          }
        }
        break;

      case "sqlmap":
        if (output.includes("vulnerable")) {
          findings.push({
            source: "sqlmap", type: "sqli",
            detail: output.split("\n").filter(l => l.includes("vulnerable") || l.includes("payload")).join(" | ")
          });
        }
        break;

      case "httpx":
        for (const line of output.split("\n").filter(Boolean)) {
          findings.push({ source: "httpx", raw: line });
        }
        break;

      default:
        findings.push({ source: toolName, raw: output.slice(0, 500) });
    }
  } catch {}

  return findings;
}

// ----- AI 复核规则引擎 -----
// 在扫描过程中内建误报过滤规则，不需要等AI调用
const LOW_VALUE_PATTERNS = [
  /missing.security.headers/i,
  /xss.protection.header/i,
  /content.type.options/i,
  /x.content.type.options/i,
  /x.frame.options/i,
  /strict.transport.security/i,
  /csp.header/i,
  /content.security.policy/i,
  /server.header/i,
  /x.powered.by/i,
  /favicon/i,
  /robots.txt/i,
  /trace.method/i,
  /options.method/i,
  /tls.version/i,
  /ssl.version/i,
  /weak.cipher/i,
  /fingerprint/i,
  /tech.detect/i,
  /waf.detect/i,
];

function filterLowValueFindings(findings) {
  return findings.filter(f => {
    const name = (f.name || f.templateId || f.detail || "").toLowerCase();
    return !LOW_VALUE_PATTERNS.some(p => p.test(name));
  });
}

// ----- 扫描模式定义 -----
const SCAN_MODES = {
  "quick": {
    phases: ["quick"],
    filterLowValue: true,
    skipUnreachable: true,
    label: "快速侦察"
  },
  "standard": {
    phases: ["port", "web-vuln"],
    filterLowValue: true,
    skipUnreachable: true,
    label: "标准扫描"
  },
  "deep": {
    phases: ["port", "web-vuln", "injection"],
    filterLowValue: true,
    skipUnreachable: false,
    label: "深度扫描"
  },
  "full": {
    phases: ["quick", "port", "web-vuln", "injection", "deep"],
    filterLowValue: false,
    skipUnreachable: false,
    label: "全量扫描"
  }
};

async function runScanBatch(assets, templates, mode = "standard", options = {}) {
  const scanMode = SCAN_MODES[mode] || SCAN_MODES.standard;
  const results = {
    mode: scanMode.label,
    startedAt: new Date().toISOString(),
    totalAssets: 0,
    processedAssets: 0,
    findings: [],
    filteredFindings: 0,
    logs: [],
    perAsset: {}
  };

  // Filter assets
  let targets = assets;
  if (scanMode.skipUnreachable) {
    targets = assets.filter(a => a.availability?.reachable);
    results.logs.push(`Filtered to ${targets.length} reachable assets (from ${assets.length} total)`);
  }

  results.totalAssets = targets.length;

  // Process each asset
  for (const asset of targets) {
    // Phase 1: Ensure fingerprint
    if (!asset.fingerprint) {
      results.logs.push(`No fingerprint for ${asset.name}, skipping`);
      continue;
    }

    const assetFindings = [];
    const assetLogs = [];

    for (const phase of scanMode.phases) {
      const scan = await executeScan(asset, asset.fingerprint, phase, options);
      assetFindings.push(...scan.findings);
      assetLogs.push(...scan.logs);
    }

    // Filter if enabled
    let finalFindings = assetFindings;
    if (scanMode.filterLowValue) {
      finalFindings = filterLowValueFindings(assetFindings);
      results.filteredFindings += assetFindings.length - finalFindings.length;
    }

    results.findings.push(...finalFindings);
    results.perAsset[asset.id] = {
      name: asset.name,
      target: asset.target,
      fingerprint: asset.fingerprint,
      findings: finalFindings.length,
      rawCount: assetFindings.length
    };

    results.processedAssets++;
    results.logs.push(`[${asset.name}] ${finalFindings.length} findings (${assetFindings.length - finalFindings.length} filtered)`);
  }

  results.completedAt = new Date().toISOString();
  results.durationMs = new Date(results.completedAt) - new Date(results.startedAt);

  return results;
}

// ----- Agent API -----
export const agentType = "scan-executor";
export const capabilities = [
  "scan:execute", "scan:batch", "scan:phase",
  "scan:mode", "scan:template-match"
];

export async function handleTask(task) {
  const { action, asset, assets, fingerprint, templates, mode, options } = task.data || {};

  try {
    switch (action) {
      case "scan:asset": {
        const finding = await executeScan(asset, fingerprint || asset.fingerprint, task.data.phase || "quick");
        return { success: true, ...finding };
      }

      case "scan:batch": {
        if (!assets?.length) throw new Error("assets array required");
        const results = await runScanBatch(assets, templates || [], mode || "standard", options);
        return { success: true, ...results };
      }

      case "scan:strategy": {
        if (!fingerprint) throw new Error("fingerprint required");
        const strategy = getToolStrategy(fingerprint);
        return { success: true, strategy, modes: Object.keys(SCAN_MODES) };
      }

      case "scan:template-match": {
        if (!fingerprint) throw new Error("fingerprint required");
        const matched = matchTemplates(fingerprint, templates || []);
        return { success: true, matched: matched.length, templates: matched.map(t => ({ id: t.id, name: t.name })) };
      }

      case "scan:modes":
        return { success: true, modes: Object.keys(SCAN_MODES).map(k => ({ name: k, ...SCAN_MODES[k] })) };

      case "scan:phase-list":
        return { success: true, phases: Object.entries(SCAN_PHASES).map(([k, v]) => ({ name: k, ...v })) };

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
    scanModes: Object.keys(SCAN_MODES),
    builtinFilters: LOW_VALUE_PATTERNS.length
  };
}

export { executeScan, runScanBatch, SCAN_MODES, SCAN_PHASES, filterLowValueFindings };
