// Agent Registry & Bootstrap
// 所有智能体的统一注册、启动、健康检查
// 每个 agent 必须实现：agentType, capabilities, handleTask(task), getStatus()

import fs from "node:fs";
import path from "node:path";

// ----- 智能体契约定义 -----
// 每个智能体必须导出的接口：
//   export const agentType = "xxx";          // 唯一类型标识
//   export const capabilities = [...];       // 能力列表
//   export async function handleTask(task);  // 任务处理：{ action, data } -> { success, ...result }
//   export function getStatus();             // 状态查询

// ----- 注册表 -----
const REGISTERED_AGENTS = {
  "file-watcher": {
    type: "file-watcher",
    module: "./file-watcher.js",
    description: "监控 data/incoming/ 目录，自动识别文件类型并路由",
    startupPriority: 1,
    autoStart: true,
    routes: {
      // 扩展名 -> orchestrator pipeline 阶段
      ".xlsx": { pipeline: ["asset-import", "fingerprint", "scan", "ai-review", "report"], label: "资产导入+扫描" },
      ".xls": { pipeline: ["asset-import", "fingerprint", "scan", "ai-review", "report"], label: "资产导入+扫描" },
      ".csv": { pipeline: ["asset-import", "fingerprint", "scan", "ai-review", "report"], label: "资产导入+扫描" },
      ".yaml": { pipeline: ["template-import", "template-merge"] },
      ".yml": { pipeline: ["template-import", "template-merge"] },
      ".json": { pipeline: ["template-import", "template-merge"] },
      ".md": { pipeline: ["template-import", "template-merge"] },
      // 所有代码/压缩包 -> POC 转化管线
      "*": { pipeline: ["poc-convert", "template-merge"] }
    }
  },

  "poc-converter": {
    type: "poc-converter",
    module: "./poc-converter.js",
    description: "AI智能识别POC，支持所有编程语言和压缩格式，自动提取元数据",
    startupPriority: 2,
    autoStart: true
  },

  "kali-toolbox": {
    type: "kali-toolbox",
    module: "./kali-toolbox.js",
    description: "封装 Kali 内置工具(nmap/nikto/sqlmap/httpx/subfinder/whatweb/nuclei)，统一输出格式",
    startupPriority: 3,
    autoStart: true
  },

  "scan-executor": {
    type: "scan-executor",
    module: "./scan-executor.js",
    description: "智能扫描引擎：按指纹选工具、分阶段扫描、误报过滤",
    startupPriority: 4,
    autoStart: true,
    dependencies: ["kali-toolbox"]
  },

  "orchestrator": {
    type: "orchestrator",
    module: "./orchestrator.js",
    description: "核心协调层：8阶段管线引擎，统一调度所有智能体",
    startupPriority: 5,
    autoStart: true,
    isPrimary: true  // 主智能体，处理所有兜底路由
  }
};

// ----- 启动器 -----
async function startAllAgents(hubUrl = "ws://localhost:3090") {
  const WebSocket = (await import("ws")).default;
  const started = [];

  // 按优先级排序启动
  const agents = Object.values(REGISTERED_AGENTS)
    .filter(a => a.autoStart)
    .sort((a, b) => a.startupPriority - b.startupPriority);

  for (const agentDef of agents) {
    try {
      console.log(`[Registry] Starting ${agentDef.type}...`);

      // 动态导入模块
      const module = await import(`${agentDef.module}`);

      // 连接到 Hub
      const ws = new WebSocket(hubUrl);

      await new Promise((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error("Connection timeout")), 10000);

        ws.on("open", () => {
          clearTimeout(timeout);
          // 注册智能体
          ws.send(JSON.stringify({
            type: "agent:register",
            agent: {
              type: agentDef.type,
              name: agentDef.type,
              capabilities: module.capabilities || [],
              metadata: {
                description: agentDef.description,
                dependencies: agentDef.dependencies || [],
                isPrimary: agentDef.isPrimary || false,
                routes: agentDef.routes || null
              }
            }
          }));

          started.push({
            type: agentDef.type,
            ws,
            module,
            status: "connecting"
          });

          resolve();
        });

        ws.on("error", (err) => {
          clearTimeout(timeout);
          console.error(`[Registry] ${agentDef.type} WebSocket error: ${err.message}`);
          reject(err);
        });
      });

      // 等待注册确认
      await new Promise((resolve) => {
        ws.once("message", (raw) => {
          try {
            const msg = JSON.parse(raw.toString());
            if (msg.type === "agent:registered") {
              console.log(`[Registry] ${agentDef.type} registered as ${msg.agentId}`);
              const entry = started.find(s => s.type === agentDef.type);
              if (entry) {
                entry.agentId = msg.agentId;
                entry.status = "online";
              }

              // 设置消息处理
              setupAgentHandlers(ws, agentDef.type, module);

              resolve();
            }
          } catch (e) {
            console.error(`[Registry] ${agentDef.type} parse error:`, e.message);
            resolve(); // 继续
          }
        });
      });

      // 如果智能体有文件监控能力，启动它
      if (agentDef.type === "file-watcher" && module.startWatching) {
        module.startWatching(ws);
      }

    } catch (error) {
      console.error(`[Registry] Failed to start ${agentDef.type}: ${error.message}`);
    }
  }

  console.log(`[Registry] Started ${started.filter(s => s.status === "online").length}/${agents.length} agents`);
  return started;
}

// ----- 消息处理器 -----
function setupAgentHandlers(ws, agentType, module) {
  ws.on("message", async (raw) => {
    let msg;
    try { msg = JSON.parse(raw.toString()); }
    catch { return; }

    switch (msg.type) {
      case "task:assign":
        // Hub 分配了任务给本智能体
        if (msg.task && module.handleTask) {
          console.log(`[${agentType}] Task received: ${msg.task.data?.action || msg.task.type}`);
          try {
            const result = await module.handleTask(msg.task);
            ws.send(JSON.stringify({
              type: "task:complete",
              taskId: msg.task.id,
              result
            }));
          } catch (error) {
            ws.send(JSON.stringify({
              type: "task:fail",
              taskId: msg.task.id,
              error: error.message
            }));
          }
        }
        break;

      case "task:progress":
        // 其他智能体的进度更新 - 可以在这里做级联触发
        break;

      case "event:asset:imported":
        // 资产导入完成 -> 自动触发指纹识别和扫描
        if (agentType === "orchestrator" && msg.data?.assetIds?.length) {
          console.log("[Orchestrator] Auto-triggering fingerprint+scan for " + msg.data.assetIds.length + " assets");
          ws.send(JSON.stringify({
            type: "task:submit",
            data: {
              targetType: "orchestrator",
              type: "quick-pipeline",
              data: {
                assetIds: msg.data.assetIds,
                projectName: msg.data.projectName
              }
            }
          }));
        }
        break;

      case "event:poc:converted":
        // POC 转换完成 -> 自动触发模板合并
        if (agentType === "orchestrator") {
          // Orchestrator 可以自动衔接下一阶段
        }
        break;

      case "event:file:detected":
        // File watcher 检测到新文件 -> 自动触发导入
        if (agentType === "orchestrator" && msg.data?.path) {
          const ext = path.extname(msg.data.path).toLowerCase();
          const route = REGISTERED_AGENTS["file-watcher"]?.routes?.[ext] ||
                        REGISTERED_AGENTS["file-watcher"]?.routes?.["*"];

          if (route?.pipeline) {
            console.log(`[Orchestrator] Auto-starting pipeline for ${ext}: ${route.pipeline.join(" -> ")}`);

            // 提交管线到 agent-hub
            ws.send(JSON.stringify({
              type: "task:submit",
              data: {
                targetType: "orchestrator",
                type: "pipeline:execute",
                data: {
                  input: { path: msg.data.path, extension: ext },
                  stages: route.pipeline
                }
              }
            }));
          }
        }
        break;
    }
  });

  // 心跳
  const heartbeat = setInterval(() => {
    if (ws.readyState === 1) {
      ws.send(JSON.stringify({ type: "agent:heartbeat" }));
    }
  }, 15000);

  ws.on("close", () => {
    clearInterval(heartbeat);
    console.log(`[${agentType}] Disconnected from Hub`);
  });
}

// ----- 独立运行模式 -----
async function main() {
  const hubUrl = process.env.HUB_URL || "ws://localhost:3090";
  console.log(`[Registry] Connecting to Hub at ${hubUrl}`);
  console.log(`[Registry] Registered types: ${Object.keys(REGISTERED_AGENTS).join(", ")}`);

  const started = await startAllAgents(hubUrl);

  // 保持进程运行
  process.on("SIGINT", () => {
    console.log("[Registry] Shutting down...");
    for (const agent of started) {
      try { agent.ws.close(); } catch {}
    }
    process.exit(0);
  });

  process.on("SIGTERM", () => {
    console.log("[Registry] Terminating...");
    process.exit(0);
  });
}

// 直接运行时启动所有智能体
if (process.argv[1] && process.argv[1].includes("agent-registry")) {
  main().catch(err => {
    console.error("[Registry] Fatal:", err.message);
    process.exit(1);
  });
}

export { REGISTERED_AGENTS, startAllAgents, setupAgentHandlers };
