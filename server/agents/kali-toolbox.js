// Kali Toolbox Agent
// 封装 Kali 内置安全工具，统一输出为 finding 标准结构
// 工具：nmap, nikto, sqlmap, httpx, subfinder, whatweb

import { spawn } from "node:child_process";
import { v4 as uuidv4 } from "uuid";

// ----- 工具注册表 -----
const TOOL_REGISTRY = {
  nmap: {
    binary: "nmap",
    description: "Network mapper - port scanning + NSE scripts",
    category: "network-recon",
    checkInstall: () => checkBinary("nmap"),
    defaultArgs: ["-sV", "-T4", "--open"],
    nseArgs: {
      http: ["--script", "http-*", "-p", "80,443,8080,8443,9090"],
      vuln: ["--script", "vuln", "-p", "1-65535"],
      ssl: ["--script", "ssl-*", "-p", "443,8443"],
      mysql: ["--script", "mysql-*", "-p", "3306"],
      smb: ["--script", "smb-*", "-p", "445"],
      dns: ["--script", "dns-*", "-p", "53"],
    }
  },

  nikto: {
    binary: "nikto",
    description: "Web server scanner",
    category: "web-vuln",
    checkInstall: () => checkBinary("nikto"),
    defaultArgs: ["-Tuning", "1234567890", "-Format", "json"]
  },

  sqlmap: {
    binary: "sqlmap",
    description: "SQL injection detection and exploitation",
    category: "injection",
    checkInstall: () => checkBinary("sqlmap"),
    defaultArgs: ["--batch", "--random-agent", "--level=1", "--risk=1"]
  },

  httpx: {
    binary: "httpx",
    description: "HTTP probing and fingerprinting",
    category: "web-recon",
    checkInstall: () => checkBinary("httpx"),
    defaultArgs: ["-silent", "-tech-detect", "-status-code", "-title", "-server", "-follow-redirects"]
  },

  subfinder: {
    binary: "subfinder",
    description: "Subdomain discovery",
    category: "recon",
    checkInstall: () => checkBinary("subfinder"),
    defaultArgs: ["-silent"]
  },

  whatweb: {
    binary: "whatweb",
    description: "Web technology fingerprinting",
    category: "web-recon",
    checkInstall: () => checkBinary("whatweb"),
    defaultArgs: ["--no-errors"]
  },

  nuclei: {
    binary: "nuclei",
    description: "Template-based vulnerability scanner",
    category: "vuln-scan",
    checkInstall: () => checkBinary("nuclei"),
    defaultArgs: ["-silent", "-rl", "150"]
  }
};

// ----- 工具组合策略 -----
// 按指纹+端口自动选择最佳工具组合
function getToolStrategy(fingerprint, ports = []) {
  const platform = (fingerprint?.platform || "").toLowerCase();
  const category = (fingerprint?.category || "").toLowerCase();
  const portSet = new Set(ports.map(p => Number(p)));

  const strategy = {
    tools: [],
    args: {},
    priority: []
  };

  // Phase 1: 快速侦察 (所有资产)
  strategy.tools.push("httpx");
  strategy.args.httpx = [];

  // Phase 2: 按指纹选择专项工具
  if (platform === "wordpress" || category === "cms") {
    strategy.tools.push("nuclei");
    strategy.args.nuclei = ["-tags", "wordpress,cms"];
    strategy.tools.push("nikto");
    strategy.args.nikto = [];
    strategy.tools.push("sqlmap");  // CMS often has SQLi
    strategy.priority.push("cms-scan");
  }

  if (platform === "spring-boot" || platform === "apache-tomcat" || category === "java") {
    strategy.tools.push("nuclei");
    strategy.args.nuclei = ["-tags", "java,spring,tomcat"];
    strategy.tools.push("nmap");
    strategy.args.nmap = ["--script", "http-*"];
    strategy.priority.push("java-scan");
  }

  if (category === "middleware" || platform === "nginx" || platform === "apache") {
    strategy.tools.push("nuclei");
    strategy.args.nuclei = ["-tags", "nginx,apache,middleware"];
    strategy.tools.push("nmap");
    strategy.args.nmap = ["--script", "http-*"];
    strategy.tools.push("nikto");
    strategy.priority.push("middleware-scan");
  }

  if (platform === "phpmyadmin" || category === "database") {
    strategy.tools.push("sqlmap");
    strategy.args.sqlmap = ["--batch", "--level=2", "--risk=2"];
    strategy.priority.push("database-scan");
  }

  // Phase 3: Port-based
  if (portSet.has(3306) || portSet.has(1433) || portSet.has(5432)) {
    if (!strategy.tools.includes("sqlmap")) strategy.tools.push("sqlmap");
    if (!strategy.tools.includes("nmap")) strategy.tools.push("nmap");
    strategy.args.nmap = [...(strategy.args.nmap || []), "--script", "mysql-*,ms-sql-*"];
  }

  if (portSet.has(443) || portSet.has(8443)) {
    if (!strategy.tools.includes("nmap")) strategy.tools.push("nmap");
    const existing = strategy.args.nmap || [];
    if (!existing.includes("ssl-*")) {
      strategy.args.nmap = [...existing, "--script", "ssl-*"];
    }
  }

  // Default: always include nuclei
  if (!strategy.tools.includes("nuclei")) {
    strategy.tools.push("nuclei");
    strategy.args.nuclei = [];
  }
  if (!strategy.tools.includes("nmap")) {
    strategy.tools.push("nmap");
  }

  return strategy;
}

// ----- 工具执行 -----
function checkBinary(name) {
  try {
    const { spawnSync } = require("node:child_process");
    const result = spawnSync("which", [name], { timeout: 3000 });
    return result.status === 0;
  } catch { return false; }
}

function runTool(binary, args, target, timeout = 120000) {
  return new Promise((resolve) => {
    const child = spawn(binary, [...args, target], {
      stdio: ["ignore", "pipe", "pipe"],
      timeout
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", chunk => stdout += chunk.toString());
    child.stderr.on("data", chunk => stderr += chunk.toString());

    child.on("close", code => {
      resolve({ code, stdout, stderr, binary, args, target });
    });

    child.on("error", err => {
      resolve({ code: -1, stdout, stderr: err.message, binary, args, target });
    });
  });
}

// ----- 输出解析 -----
function parseNmapOutput(output) {
  const findings = [];
  const lines = output.split("\n");

  // Parse open ports
  for (const line of lines) {
    const portMatch = line.match(/(\d+)\/(tcp|udp)\s+open\s+(\S+)/);
    if (portMatch) {
      findings.push({
        port: Number(portMatch[1]),
        protocol: portMatch[2],
        service: portMatch[3],
        type: "open-port"
      });
    }
  }

  // Parse NSE script output
  let currentHost = "";
  for (const line of lines) {
    const hostMatch = line.match(/Nmap scan report for (.+)/);
    if (hostMatch) currentHost = hostMatch[1];

    const vulnMatch = line.match(/\|[\s_]+([^:]+):\s*(.+)/);
    if (vulnMatch) {
      findings.push({
        type: "nse-finding",
        host: currentHost,
        script: vulnMatch[1].trim(),
        detail: vulnMatch[2].trim()
      });
    }
  }

  return findings;
}

function parseNiktoOutput(output) {
  const findings = [];
  try {
    // Nikto JSON output
    const json = JSON.parse(output);
    if (json.vulnerabilities) {
      for (const v of json.vulnerabilities) {
        findings.push({
          type: "nikto",
          id: v.id,
          method: v.method,
          url: v.url,
          msg: v.msg,
          osvdb: v.OSVDB
        });
      }
    }
  } catch {
    // Plain text output
    const lines = output.split("\n");
    for (const line of lines) {
      if (line.startsWith("+")) {
        findings.push({
          type: "nikto",
          detail: line.substring(2).trim()
        });
      }
    }
  }
  return findings;
}

function parseSqlmapOutput(output) {
  const findings = [];
  if (output.includes("is vulnerable") || output.includes("Parameter")) {
    findings.push({
      type: "sqlmap",
      vulnerable: true,
      rawLines: output.split("\n").filter(l =>
        l.includes("vulnerable") || l.includes("Parameter") || l.includes("payload")
      )
    });
  }
  return findings;
}

function parseHttpxOutput(output) {
  const findings = [];
  const lines = output.split("\n").filter(Boolean);
  for (const line of lines) {
    // httpx format: url [status] [title] [tech]
    findings.push({
      type: "httpx",
      raw: line
    });
  }
  return findings;
}

function parseNucleiOutput(output) {
  const findings = [];
  const lines = output.split("\n").filter(Boolean);
  for (const line of lines) {
    try {
      const json = JSON.parse(line);
      findings.push({
        type: "nuclei",
        templateId: json["template-id"] || json.templateID,
        name: json.info?.name,
        severity: json.info?.severity,
        matched: json["matched-at"] || json.matched,
        extracted: json["extracted-results"] || []
      });
    } catch {
      // non-JSON line (progress info)
    }
  }
  return findings;
}

// ----- 统一 Finding 标准化 -----
function normalizeFinding(raw, toolName, asset, fingerprint) {
  // Map raw tool output to standard finding format
  let severity = "info";
  let name = "";
  let evidence = [];

  if (raw.type === "nuclei") {
    severity = raw.severity || "info";
    name = raw.name || raw.templateId;
    evidence = [`Nuclei: ${raw.templateId}`, raw.matched ? `Matched: ${raw.matched}` : ""].filter(Boolean);
  } else if (raw.type === "nikto") {
    const detail = raw.msg || raw.detail || "";
    if (/critical|urgent/i.test(detail)) severity = "critical";
    else if (/high|important/i.test(detail)) severity = "high";
    else if (/medium|moderate/i.test(detail)) severity = "medium";
    else severity = "info";
    name = `Nikto: ${raw.id || detail.slice(0, 60)}`;
    evidence = [detail];
  } else if (raw.type === "sqlmap") {
    severity = raw.vulnerable ? "high" : "info";
    name = "SQL Injection (sqlmap)";
    evidence = raw.rawLines || ["SQLmap detected vulnerability"];
  } else if (raw.type === "nse-finding") {
    name = `Nmap NSE: ${raw.script}`;
    evidence = [raw.detail];
    severity = /vuln|exploit|bypass/i.test(raw.script) ? "high" : "info";
  } else if (raw.type === "open-port") {
    name = `Open Port: ${raw.port}/${raw.protocol} (${raw.service})`;
    evidence = [`Port ${raw.port}/${raw.protocol} ${raw.service} open`];
    severity = "info";
  } else {
    name = `${toolName} finding`;
    evidence = [JSON.stringify(raw)];
  }

  return {
    id: uuidv4(),
    assetId: asset.id,
    assetName: asset.name,
    projectName: asset.projectName || "Default Project",
    target: asset.target,
    templateId: `kali:${toolName}:${name}`,
    templateName: name,
    severity,
    tags: [toolName, fingerprint?.platform, fingerprint?.category].filter(Boolean),
    fingerprint,
    evidence,
    status: "candidate",
    createdAt: new Date().toISOString(),
    aiReview: null,
    source: `kali-toolbox:${toolName}`
  };
}

// ----- 合并 API -----
async function scanAsset(asset, fingerprint, options = {}) {
  const targets = [asset.target];
  // Also add the bare hostname without path
  try { targets.push(new URL(asset.target).hostname); } catch {}

  // Parse ports from availability data
  const ports = asset.availability?.ports || [];
  const strategy = getToolStrategy(fingerprint, ports);
  const allFindings = [];

  for (const toolName of strategy.tools) {
    const tool = TOOL_REGISTRY[toolName];
    if (!tool) continue;
    if (tool.checkInstall && !tool.checkInstall()) continue;

    const args = strategy.args[toolName] || tool.defaultArgs || [];

    for (const target of targets.slice(0, 2)) { // Max 2 targets per tool
      const result = await runTool(tool.binary, [...args, "-oN", "-"], target, options.timeout || 60000);
      if (result.code < 0) continue; // Tool error

      let rawFindings = [];
      switch (toolName) {
        case "nmap": rawFindings = parseNmapOutput(result.stdout); break;
        case "nikto": rawFindings = parseNiktoOutput(result.stdout); break;
        case "sqlmap": rawFindings = parseSqlmapOutput(result.stdout); break;
        case "httpx": rawFindings = parseHttpxOutput(result.stdout); break;
        case "nuclei": rawFindings = parseNucleiOutput(result.stdout); break;
        default: rawFindings = [{ type: toolName, raw: result.stdout }];
      }

      for (const raw of rawFindings) {
        allFindings.push(normalizeFinding(raw, toolName, asset, fingerprint));
      }
    }
  }

  return allFindings;
}

// ----- Agent API -----
export const agentType = "kali-toolbox";
export const capabilities = [
  "tool:nmap", "tool:nikto", "tool:sqlmap", "tool:httpx",
  "tool:subfinder", "tool:whatweb", "tool:nuclei",
  "scan:asset", "scan:strategy"
];

export async function handleTask(task) {
  const { action, asset, fingerprint, target, options } = task.data || {};

  try {
    switch (action) {
      case "scan:asset":
        if (!asset) throw new Error("asset required");
        const findings = await scanAsset(asset, fingerprint || asset.fingerprint, options);
        return { success: true, findings, count: findings.length };

      case "scan:strategy":
        if (!fingerprint) throw new Error("fingerprint required");
        const strategy = getToolStrategy(fingerprint, options?.ports || []);
        return { success: true, strategy };

      case "tool:list":
        return { success: true, tools: Object.keys(TOOL_REGISTRY).map(k => ({
          name: k, ...TOOL_REGISTRY[k], available: TOOL_REGISTRY[k].checkInstall()
        })) };

      case "tool:run": {
        const { tool, args, target: tgt } = task.data;
        if (!TOOL_REGISTRY[tool]) throw new Error(`Unknown tool: ${tool}`);
        const result = await runTool(tool, args || [], tgt, options?.timeout || 30000);
        return { success: true, ...result };
      }

      default:
        // Direct scan action
        if (asset) {
          const findings = await scanAsset(asset, asset.fingerprint, options);
          return { success: true, findings, count: findings.length };
        }
        return { success: false, error: `Unknown action: ${action}` };
    }
  } catch (error) {
    return { success: false, error: error.message };
  }
}

export function getStatus() {
  const toolStatus = {};
  for (const [name, tool] of Object.entries(TOOL_REGISTRY)) {
    toolStatus[name] = tool.checkInstall ? tool.checkInstall() : false;
  }
  return { type: agentType, capabilities, tools: toolStatus };
}

export { getToolStrategy, TOOL_REGISTRY };
