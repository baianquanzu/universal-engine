// Universal Engine Agent Hub
// 常驻服务 - 管理智能体集群，消息路由，任务队列

import { createServer } from "node:http";
import { WebSocketServer } from "ws";
import { v4 as uuidv4 } from "uuid";

const PORT = process.env.AGENT_PORT || 3090;

// ----- Agent Registry -----
const agents = new Map();      // agentId -> { id, type, status, registeredAt, lastHeartbeat }
const agentTypes = new Map();  // type -> Set<agentId>
const subscriptions = new Map(); // agentId -> Set<eventType>

// ----- Message Router -----
const pendingRequests = new Map(); // requestId -> { resolve, reject, timeout }

// ----- Task Queue -----
const taskQueue = [];
const taskResults = new Map(); // taskId -> { status, result, error }
let taskCursor = 0;

// ----- Helpers -----
function now() { return new Date().toISOString(); }

function registerAgent(info) {
  const agent = {
    id: info.id || uuidv4(),
    type: info.type,
    name: info.name || info.type,
    status: "online",
    capabilities: info.capabilities || [],
    registeredAt: now(),
    lastHeartbeat: now(),
    metadata: info.metadata || {}
  };
  agents.set(agent.id, agent);

  if (!agentTypes.has(agent.type)) {
    agentTypes.set(agent.type, new Set());
  }
  agentTypes.get(agent.type).add(agent.id);

  // Auto-subscribe to type-specific events
  if (!subscriptions.has(agent.id)) {
    subscriptions.set(agent.id, new Set());
  }
  const sub = subscriptions.get(agent.id);
  for (const cap of agent.capabilities) {
    sub.add(cap);
  }

  broadcast({ type: "agent:registered", agent });
  log(`Agent registered: ${agent.type}/${agent.name} (${agent.id.slice(0, 8)})`);
  return agent;
}

function unregisterAgent(agentId) {
  const agent = agents.get(agentId);
  if (!agent) return;
  
  agent.status = "offline";
  const typeAgents = agentTypes.get(agent.type);
  if (typeAgents) typeAgents.delete(agentId);
  subscriptions.delete(agentId);
  
  // Cancel pending tasks for this agent
  for (const [taskId, task] of taskResults) {
    if (task.agentId === agentId && task.status === "running") {
      task.status = "failed";
      task.error = "Agent went offline";
    }
  }

  broadcast({ type: "agent:offline", agentId, agentType: agent.type });
  log(`Agent offline: ${agent.type}/${agent.name} (${agentId.slice(0, 8)})`);
}

function heartbeat(agentId) {
  const agent = agents.get(agentId);
  if (agent) {
    agent.lastHeartbeat = now();
    agent.status = "online";
  }
}

// ----- Task System -----
function enqueueTask(payload) {
  const task = {
    id: uuidv4(),
    type: payload.type,
    targetAgent: payload.targetAgent || null,
    targetType: payload.targetType || null,
    data: payload.data || {},
    priority: payload.priority || 5,
    status: "queued",
    createdAt: now(),
    startedAt: null,
    completedAt: null,
    timeout: payload.timeout || 300000
  };

  taskQueue.push(task);
  taskQueue.sort((a, b) => a.priority - b.priority); // lower = higher priority
  taskResults.set(task.id, { taskId: task.id, status: "queued", result: null });

  broadcast({ type: "task:queued", task });
  dispatchTasks();
  return task;
}

function dispatchTasks() {
  while (taskCursor < taskQueue.length) {
    const task = taskQueue[taskCursor];
    if (task.status !== "queued") { taskCursor++; continue; }

    let targetIds = [];
    if (task.targetAgent) {
      targetIds = [task.targetAgent];
    } else if (task.targetType && agentTypes.has(task.targetType)) {
      targetIds = [...agentTypes.get(task.targetType)];
    }

    // Find first available agent
    const available = targetIds.filter(id => {
      const a = agents.get(id);
      return a && a.status === "online";
    });

    if (available.length === 0) {
      taskCursor++;
      continue;
    }

    // Assign to first available agent
    const agentId = available[0];
    task.status = "running";
    task.agentId = agentId;
    task.startedAt = now();

    const tr = taskResults.get(task.id);
    if (tr) tr.status = "running";

    // Send to agent
    sendToAgent(agentId, { type: "task:assign", task });
    
    // Set timeout
    setTimeout(() => {
      if (task.status === "running") {
        task.status = "failed";
        task.error = "Task timeout";
        task.completedAt = now();
        const tr2 = taskResults.get(task.id);
        if (tr2) { tr2.status = "failed"; tr2.error = "Task timeout"; }
        broadcast({ type: "task:failed", task });
      }
    }, task.timeout);

    taskCursor = 0; // Reset cursor to check for new tasks
    return;
  }
  taskCursor = 0;
}

function completeTask(taskId, result, error = null) {
  const task = taskQueue.find(t => t.id === taskId);
  if (!task) return;

  task.status = error ? "failed" : "completed";
  task.completedAt = now();
  if (error) task.error = error;

  const tr = taskResults.get(taskId);
  if (tr) {
    tr.status = task.status;
    tr.result = result;
    if (error) tr.error = error;
  }

  broadcast({ type: error ? "task:failed" : "task:completed", task, result });
  dispatchTasks();
}

// ----- WebSocket -----
const server = createServer();
const wss = new WebSocketServer({ server });
const clients = new Map(); // ws -> agentId

function sendToAgent(agentId, message) {
  for (const [ws, id] of clients) {
    if (id === agentId && ws.readyState === 1) {
      ws.send(JSON.stringify(message));
      return;
    }
  }
}

function broadcast(message) {
  const data = JSON.stringify(message);
  for (const [ws] of clients) {
    if (ws.readyState === 1) ws.send(data);
  }
}

function broadcastToType(agentType, message) {
  const typeAgents = agentTypes.get(agentType);
  if (!typeAgents) return;
  const data = JSON.stringify(message);
  for (const [ws, agentId] of clients) {
    if (typeAgents.has(agentId) && ws.readyState === 1) ws.send(data);
  }
}

wss.on("connection", (ws) => {
  const clientId = uuidv4();
  clients.set(ws, null); // Not yet identified

  ws.on("message", (raw) => {
    let msg;
    try { msg = JSON.parse(raw.toString()); }
    catch { return; }

    switch (msg.type) {
      case "agent:register": {
        const agent = registerAgent(msg.agent);
        clients.set(ws, agent.id);
        ws.send(JSON.stringify({
          type: "agent:registered",
          agentId: agent.id,
          hubTime: now()
        }));
        break;
      }

      case "agent:heartbeat": {
        const agentId = clients.get(ws);
        if (agentId) heartbeat(agentId);
        break;
      }

      case "agent:capabilities": {
        const agentId = clients.get(ws);
        if (agentId && msg.capabilities) {
          const agent = agents.get(agentId);
          if (agent) agent.capabilities = msg.capabilities;
          if (!subscriptions.has(agentId)) subscriptions.set(agentId, new Set());
          for (const cap of msg.capabilities) subscriptions.get(agentId).add(cap);
        }
        break;
      }

      case "task:complete": {
        completeTask(msg.taskId, msg.result);
        break;
      }

      case "task:fail": {
        completeTask(msg.taskId, null, msg.error || "Agent reported failure");
        break;
      }

      case "task:progress": {
        broadcast({
          type: "task:progress",
          taskId: msg.taskId,
          progress: msg.progress,
          message: msg.message
        });
        break;
      }

      case "event:publish": {
        const agentId = clients.get(ws);
        const agent = agents.get(agentId);
        broadcast({
          type: "event:" + (msg.event || "custom"),
          source: agent ? `${agent.type}/${agent.name}` : "unknown",
          data: msg.data,
          timestamp: now()
        });
        break;
      }

      // Public API: submit a task from outside
      case "task:submit": {
        const task = enqueueTask(msg);
        ws.send(JSON.stringify({
          type: "task:accepted",
          taskId: task.id,
          position: taskQueue.filter(t => t.status === "queued").indexOf(task)
        }));
        break;
      }

      // Query hub state
      case "hub:status": {
        const status = {
          agents: [...agents.values()].map(a => ({
            id: a.id, type: a.type, name: a.name,
            status: a.status, capabilities: a.capabilities
          })),
          queueSize: taskQueue.filter(t => t.status === "queued").length,
          runningTasks: taskQueue.filter(t => t.status === "running").length,
          completedTasks: taskQueue.filter(t => t.status === "completed").length,
          uptime: process.uptime()
        };
        ws.send(JSON.stringify({ type: "hub:status", status }));
        break;
      }
    }
  });

  ws.on("close", () => {
    const agentId = clients.get(ws);
    if (agentId) unregisterAgent(agentId);
    clients.delete(ws);
  });

  ws.on("error", () => {
    const agentId = clients.get(ws);
    if (agentId) unregisterAgent(agentId);
    clients.delete(ws);
  });
});

// ----- REST API -----
server.on("request", (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  
  if (req.method === "OPTIONS") {
    res.writeHead(204); res.end(); return;
  }

  const url = new URL(req.url, `http://localhost:${PORT}`);

  // GET /api/hub/status
  if (req.method === "GET" && url.pathname === "/api/hub/status") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      agents: [...agents.values()].map(a => ({
        id: a.id, type: a.type, name: a.name,
        status: a.status, capabilities: a.capabilities,
        lastHeartbeat: a.lastHeartbeat
      })),
      queue: {
        pending: taskQueue.filter(t => t.status === "queued").length,
        running: taskQueue.filter(t => t.status === "running").length,
        completed: taskQueue.filter(t => t.status === "completed").length,
        failed: taskQueue.filter(t => t.status === "failed").length
      },
      uptime: process.uptime()
    }));
    return;
  }

  // POST /api/task/submit
  if (req.method === "POST" && url.pathname === "/api/task/submit") {
    let body = "";
    req.on("data", chunk => body += chunk);
    req.on("end", () => {
      try {
        const payload = JSON.parse(body);
        const task = enqueueTask(payload);
        res.writeHead(202, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ accepted: true, taskId: task.id }));
      } catch (e) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }

  // GET /api/task/:id
  if (req.method === "GET" && url.pathname.startsWith("/api/task/")) {
    const taskId = url.pathname.split("/").pop();
    const result = taskResults.get(taskId);
    if (result) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(result));
    } else {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "task not found" }));
    }
    return;
  }

  res.writeHead(404);
  res.end("Not Found");
});

// ----- Heartbeat Monitor -----
setInterval(() => {
  const cutoff = Date.now() - 60000; // 60s timeout
  for (const [id, agent] of agents) {
    if (agent.status === "online" && new Date(agent.lastHeartbeat).getTime() < cutoff) {
      agent.status = "timeout";
      broadcast({ type: "agent:timeout", agentId: id });
      log(`Agent timeout: ${agent.type}/${agent.name}`);
    }
  }
}, 15000);

// ----- Startup -----
function log(msg) {
  console.log(`[Hub ${new Date().toISOString().slice(11, 19)}] ${msg}`);
}

server.listen(PORT, () => {
  log(`Agent Hub listening on ws://localhost:${PORT}`);
  log(`REST API at http://localhost:${PORT}/api/`);
  log(`Agent types: file-watcher, asset-importer, fingerprinter, scan-executor, ai-reviewer, poc-converter, report-builder, kali-toolbox`);
});

export { enqueueTask, broadcast, broadcastToType, agents, agentTypes, sendToAgent };
