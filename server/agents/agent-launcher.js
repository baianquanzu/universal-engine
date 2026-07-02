// Agent Launcher - CLI wrapper
// 一键启动：ue agent start  -> 启动 Agent Hub + 所有智能体
// 分布式启动: 可以每台机器只启动特定智能体

import fs from "node:fs";
import path from "node:path";

const AGENT_DIR = path.resolve("server/agents");

// 启动选项
const launchOptions = {
  hubOnly: false,        // 只启动 Hub
  hubPort: 3090,         // Hub 端口
  agents: [],            // 指定启动哪些智能体（空=全部）
  watchDir: null,        // 文件监控目录
  autoPipeline: true,    // 自动管线（文件检测到后自动执行完整流程）
};

async function launch() {
  console.log("╔═══════════════════════════════════╗");
  console.log("║   Universal Engine Agent Cluster  ║");
  console.log("╚═══════════════════════════════════╝");
  console.log("");

  // 1. 启动 Agent Hub
  console.log("[1/3] Starting Agent Hub...");
  const { default: hubModule } = await import("../agent-hub.js");
  console.log("  Hub: ws://localhost:3090  REST: http://localhost:3090/api/");

  // 2. 如果只启动 Hub，到此为止
  if (launchOptions.hubOnly) {
    console.log("  [Hub-only mode] No agents attached.");
    console.log("  Ready to accept external agent connections.");
    return;
  }

  // 3. 启动所有智能体（通过 agent-registry）
  console.log("[2/3] Starting Agent Registry...");
  const { startAllAgents } = await import("./agent-registry.js");

  const agents = launchOptions.agents?.length
    ? launchOptions.agents
    : null; // null = all registered

  await startAllAgents("ws://localhost:3090");

  console.log("");
  console.log("[3/3] All agents started!");
  console.log("");
  console.log("╔═══════════════════════════════════════════════════╗");
  console.log("║  Agent Cluster Running                            ║");
  console.log("║                                                   ║");
  console.log("║  Hub:    ws://localhost:3090                       ║");
  console.log("║  REST:   http://localhost:3090/api/hub/status      ║");
  console.log("║                                                   ║");
  if (launchOptions.autoPipeline) {
  console.log("║  File Watch: data/incoming/                        ║");
  console.log("║  Pipeline: file → convert → import → scan → report ║");
  }
  console.log("║                                                   ║");
  console.log("║  Commands:                                        ║");
  console.log("║    ue agent status    — 查看智能体状态              ║");
  console.log("║    ue agent stop      — 停止智能体集群              ║");
  console.log("║    curl :3090/api/hub/status — REST查询             ║");
  console.log("╚═══════════════════════════════════════════════════╝");
  console.log("");

  // 保持运行
  process.on("SIGINT", () => {
    console.log("\nShutting down agent cluster...");
    process.exit(0);
  });
}

// CLI entry
if (process.argv[1] && process.argv[1].includes("agent-launcher")) {
  const mode = process.argv[2] || "start";

  if (mode === "start" || mode === "launch") {
    if (process.argv.includes("--hub-only")) launchOptions.hubOnly = true;
    if (process.argv.includes("--port")) {
      const pi = process.argv.indexOf("--port");
      launchOptions.hubPort = Number(process.argv[pi + 1]) || 3090;
    }
    launch().catch(err => {
      console.error("Launch failed:", err.message);
      process.exit(1);
    });
  } else if (mode === "status") {
    fetch("http://localhost:3090/api/hub/status")
      .then(r => r.json())
      .then(s => console.log(JSON.stringify(s, null, 2)))
      .catch(() => console.log("Hub not running"));
  } else {
    console.log("Usage: node agent-launcher.js [start|status]");
    console.log("  start       Launch agent cluster");
    console.log("  start --hub-only   Hub only, no agents");
    console.log("  status      Show cluster status");
  }
}

export { launch, launchOptions };
