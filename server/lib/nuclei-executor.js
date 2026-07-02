import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import YAML from "yaml";
import { v4 as uuidv4 } from "uuid";

function runProcess(command, args) {
  return new Promise((resolve) => {
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });

    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    child.on("close", (code) => {
      resolve({ code, stdout, stderr });
    });

    child.on("error", (error) => {
      resolve({ code: -1, stdout, stderr: error.message });
    });
  });
}

function buildFindingFromNuclei(asset, fingerprint, template, line) {
  return {
    id: uuidv4(),
    assetId: asset.id,
    assetName: asset.name,
    target: asset.target,
    templateId: template.nucleiId,
    templateName: template.name,
    severity: line.info?.severity || template.severity,
    tags: template.tags,
    fingerprint,
    evidence: [
      `Nuclei template: ${line.templateID || template.nucleiId}`,
      `Matched target: ${line.matched || asset.target}`,
      `Extractor output: ${JSON.stringify(line.extractedResults || [])}`
    ],
    status: "candidate",
    createdAt: new Date().toISOString(),
    aiReview: null
  };
}

export async function runNucleiTemplate(asset, fingerprint, template, nucleiSettings) {
  if (!nucleiSettings.enabled) {
    return { mode: "disabled", findings: [] };
  }

  if (!template?.raw || template.runnable === false) {
    return { mode: "metadata-only", findings: [] };
  }

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "universal-engine-"));
  const templatePath = path.join(tempDir, `${template.nucleiId}.yaml`);

  try {
    fs.writeFileSync(templatePath, YAML.stringify(template.raw), "utf8");

    const args = [
      "-u",
      asset.target,
      "-t",
      templatePath,
      "-jsonl",
      ...(Array.isArray(nucleiSettings.args) ? nucleiSettings.args : [])
    ];

    const result = await runProcess(nucleiSettings.binaryPath || "nuclei", args);
    if (result.code !== 0) {
      return {
        mode: "error",
        findings: [],
        error: result.stderr || `nuclei exited with code ${result.code}`
      };
    }

    const findings = result.stdout
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => JSON.parse(line))
      .map((line) => buildFindingFromNuclei(asset, fingerprint, template, line));

    return { mode: "nuclei", findings };
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}
