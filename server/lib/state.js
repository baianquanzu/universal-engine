import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { v4 as uuidv4 } from "uuid";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const runtimeDir = path.resolve(__dirname, "../../data/runtime");
const stateFile = path.join(runtimeDir, "state.json");

const defaultState = {
  assets: [
    {
      id: uuidv4(),
      name: "Demo WordPress Portal",
      projectName: "Demo Project",
      target: "https://demo-wordpress.local",
      owner: "Blue Team",
      tags: ["demo", "web"],
      status: "new",
      fingerprint: null
    },
    {
      id: uuidv4(),
      name: "Demo Exchange Gateway",
      projectName: "Demo Project",
      target: "https://exchange-demo.local",
      owner: "Messaging Team",
      tags: ["demo", "mail"],
      status: "new",
      fingerprint: null
    }
  ],
  templates: [],
  tasks: [],
  queue: {
    pending: [],
    running: [],
    completed: 0,
    failed: 0,
    canceled: 0
  },
  upstreamLookups: [],
  findings: [],
  reports: [],
  settings: {
    ui: {
      title: "Universal Engine"
    },
    scanning: {
      safeMode: true,
      concurrency: 3,
      maxConcurrentTasks: 2,
      assetConcurrency: 4,
      autoAiReview: true,
      findingsPageSize: 9
    },
    nuclei: {
      enabled: false,
      binaryPath: "nuclei",
      args: ["-rl", "150", "-silent"]
    },
    ai: {
      enabled: false,
      provider: "openai-compatible",
      baseUrl: "https://api.openai.com/v1",
      apiKey: "",
      model: "gpt-4.1-mini",
      temperature: 0.1,
      maxTokens: 600
    }
  }
};

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function mergeDeep(base, override) {
  if (!isPlainObject(base) || !isPlainObject(override)) {
    return override ?? base;
  }

  const result = { ...base };
  for (const [key, value] of Object.entries(override)) {
    result[key] = isPlainObject(value) && isPlainObject(base[key]) ? mergeDeep(base[key], value) : value;
  }
  return result;
}

function ensureRuntime() {
  fs.mkdirSync(runtimeDir, { recursive: true });
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

export function loadState() {
  ensureRuntime();

  if (!fs.existsSync(stateFile)) {
    fs.writeFileSync(stateFile, JSON.stringify(defaultState, null, 2), "utf8");
    return clone(defaultState);
  }

  const raw = fs.readFileSync(stateFile, "utf8");
  const parsed = JSON.parse(raw);
  const merged = mergeDeep(clone(defaultState), parsed);
  merged.assets = (merged.assets || []).map((asset) => ({
    projectName: asset.projectName || "Default Project",
    ...asset
  }));
  merged.findings = (merged.findings || []).map((finding) => ({
    projectName: finding.projectName || "Default Project",
    ...finding
  }));
  return merged;
}

export function saveState(state) {
  ensureRuntime();
  fs.writeFileSync(stateFile, JSON.stringify(state, null, 2), "utf8");
}
