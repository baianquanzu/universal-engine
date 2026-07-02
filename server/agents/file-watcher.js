// File Watcher Agent
// 监控 data/incoming/ 目录，自动识别文件类型并触发对应智能体

import fs from "node:fs";
import path from "node:path";
import { v4 as uuidv4 } from "uuid";

const WATCH_DIR = process.env.WATCH_DIR || path.resolve("data/incoming");
const PROCESSED_DIR = path.join(WATCH_DIR, ".processed");
const ERROR_DIR = path.join(WATCH_DIR, ".errors");

// 文件类型 -> 智能体路由映射
const FILE_TYPE_ROUTES = {
  ".xlsx": { agentType: "asset-importer", action: "asset:import-file" },
  ".xls": { agentType: "asset-importer", action: "asset:import-file" },
  ".csv": { agentType: "asset-importer", action: "asset:import-file" },
  ".yaml": { agentType: "template-importer", action: "template:import" },
  ".yml": { agentType: "template-importer", action: "template:import" },
  ".json": { agentType: "template-importer", action: "template:import" },
  ".md": { agentType: "template-importer", action: "template:import" },
  // All archive and code files go to POC converter
  ".zip": { agentType: "poc-converter", action: "poc:convert" },
  ".tar.gz": { agentType: "poc-converter", action: "poc:convert" },
  ".tgz": { agentType: "poc-converter", action: "poc:convert" },
  ".rar": { agentType: "poc-converter", action: "poc:convert" },
  ".7z": { agentType: "poc-converter", action: "poc:convert" },
  ".py": { agentType: "poc-converter", action: "poc:convert" },
  ".js": { agentType: "poc-converter", action: "poc:convert" },
  ".ts": { agentType: "poc-converter", action: "poc:convert" },
  ".c": { agentType: "poc-converter", action: "poc:convert" },
  ".cpp": { agentType: "poc-converter", action: "poc:convert" },
  ".cs": { agentType: "poc-converter", action: "poc:convert" },
  ".java": { agentType: "poc-converter", action: "poc:convert" },
  ".go": { agentType: "poc-converter", action: "poc:convert" },
  ".rs": { agentType: "poc-converter", action: "poc:convert" },
  ".php": { agentType: "poc-converter", action: "poc:convert" },
  ".rb": { agentType: "poc-converter", action: "poc:convert" },
  ".pl": { agentType: "poc-converter", action: "poc:convert" },
  ".sh": { agentType: "poc-converter", action: "poc:convert" },
  ".bash": { agentType: "poc-converter", action: "poc:convert" },
  ".ps1": { agentType: "poc-converter", action: "poc:convert" },
  ".bat": { agentType: "poc-converter", action: "poc:convert" },
  ".txt": { agentType: "poc-converter", action: "poc:convert" },
  ".sql": { agentType: "poc-converter", action: "poc:convert" },
  ".http": { agentType: "poc-converter", action: "poc:convert" },
};

let wsClient = null;
let hubUrl = "ws://localhost:3090";
let agentId = null;
let watching = false;

function ensureDirs() {
  fs.mkdirSync(WATCH_DIR, { recursive: true });
  fs.mkdirSync(PROCESSED_DIR, { recursive: true });
  fs.mkdirSync(ERROR_DIR, { recursive: true });
}

function getFileType(filePath) {
  const basename = path.basename(filePath).toLowerCase();
  // Check for compound extensions first
  if (basename.endsWith(".tar.gz")) return ".tar.gz";
  const ext = path.extname(filePath).toLowerCase();
  return ext;
}

function resolveRoute(filePath) {
  const ext = getFileType(filePath);
  // Directories: scan contents for POC structure
  if (fs.statSync(filePath).isDirectory()) {
    return { agentType: "poc-converter", action: "poc:convert" };
  }
  return FILE_TYPE_ROUTES[ext] || { agentType: "poc-converter", action: "poc:convert" };
}

async function processFile(filePath, hubClient) {
  const fileName = path.basename(filePath);
  const stats = fs.statSync(filePath);
  const route = resolveRoute(filePath);

  const label = route.label || route.action;
  console.log("[FileWatcher] [INBOX] " + label + ": " + fileName + " (" + (stats.size/1024).toFixed(1) + "KB)");
  if (stats.isDirectory()) console.log("[FileWatcher]   Type: directory, scanning for POC structure...");

  // If it's a directory, process as POC
  if (stats.isDirectory()) {
    const task = {
      type: "task:submit",
      data: {
        targetType: route.agentType,
        type: route.action,
        data: { path: filePath, sourceName: fileName },
        priority: 3
      }
    };
    hubClient.send(JSON.stringify(task));
    return;
  }

  // Handle large files - copy to working dir for safety
  const task = {
    type: "task:submit",
    data: {
      targetType: route.agentType,
      type: route.action,
      data: { path: filePath, sourceName: fileName },
      priority: 3
    }
  };
  hubClient.send(JSON.stringify(task));
}

function startWatching(hubClient, ws) {
  ensureDirs();

  // Process existing files in incoming/
  const existing = fs.readdirSync(WATCH_DIR).filter(f => !f.startsWith("."));
  for (const file of existing) {
    const filePath = path.join(WATCH_DIR, file);
    processFile(filePath, hubClient || ws);
    // Move to processed
    try {
      const dest = path.join(PROCESSED_DIR, file);
      fs.renameSync(filePath, dest);
    } catch {}
  }

  // Set up fs.watch polling (Kali compatible)
  let lastCheck = Date.now();
  const interval = setInterval(() => {
    try {
      const files = fs.readdirSync(WATCH_DIR).filter(f => !f.startsWith("."));
      for (const file of files) {
        const filePath = path.join(WATCH_DIR, file);
        const fstat = fs.statSync(filePath);
        if (fstat.mtimeMs > lastCheck) {
          // New or modified file
          processFile(filePath, hubClient || ws);
          try {
            const dest = path.join(PROCESSED_DIR, file + "-" + Date.now());
            fs.renameSync(filePath, dest);
          } catch {}
        }
      }
      lastCheck = Date.now();
    } catch (e) { /* directory may be temporarily locked */ }
  }, 2000); // Poll every 2 seconds

  watching = true;
  console.log(`[FileWatcher] Watching: ${WATCH_DIR}`);
  console.log(`[FileWatcher] Supported types: ${Object.keys(FILE_TYPE_ROUTES).length}`);

  return {
    watchDir: WATCH_DIR,
    stop: () => { clearInterval(interval); watching = false; }
  };
}

// ----- Agent API -----
export const agentType = "file-watcher";
export const capabilities = ["file:watch", "file:detect", "file:route"];

export function getStatus() {
  return {
    type: agentType,
    capabilities,
    status: watching ? "watching" : "idle",
    watchDir: WATCH_DIR
  };
}

export async function handleTask(task) {
  const { data } = task;
  if (data.action === "start") {
    // Client should provide their WebSocket for hub communication
    return { success: true, watchDir: WATCH_DIR, message: "File watcher started" };
  }
  if (data.action === "stop") {
    watching = false;
    return { success: true, message: "File watcher stopped" };
  }
  if (data.action === "process") {
    const filePath = data.path;
    if (filePath && fs.existsSync(filePath)) {
      const route = resolveRoute(filePath);
      return { success: true, route, file: path.basename(filePath) };
    }
    return { success: false, error: "File not found" };
  }
  return { success: false, error: "Unknown action: " + data.action };
}

// Standalone runner
if (process.argv[1] && process.argv[1].includes("file-watcher")) {
  import("ws").then(({ default: WebSocket }) => {
    const hubUrl = process.env.HUB_URL || "ws://localhost:3090";
    const ws = new WebSocket(hubUrl);

    ws.on("open", () => {
      console.log("[FileWatcher] Connected to Hub");

      // Register
      ws.send(JSON.stringify({
        type: "agent:register",
        agent: {
          type: agentType,
          name: "FileWatcher",
          capabilities
        }
      }));

      // Start watching
      startWatching(ws);
    });

    ws.on("message", (raw) => {
      const msg = JSON.parse(raw.toString());
      if (msg.type === "agent:registered") {
        agentId = msg.agentId;
        console.log("[FileWatcher] Registered as:", agentId);
      }
    });

    ws.on("close", () => {
      console.log("[FileWatcher] Disconnected");
      process.exit(0);
    });

    // Heartbeat
    setInterval(() => {
      if (ws.readyState === 1) {
        ws.send(JSON.stringify({ type: "agent:heartbeat" }));
      }
    }, 10000);
  });
}
