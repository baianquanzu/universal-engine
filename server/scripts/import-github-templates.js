import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import AdmZip from "adm-zip";
import { mergeImportedTemplates, parseTemplateDirectory, summarizeTemplateGroups } from "../lib/template-service.js";
import { loadState, saveState } from "../lib/state.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "../..");
const cacheRoot = path.join(repoRoot, "data/runtime/import-cache");
const archivePath = path.join(cacheRoot, "nuclei-templates-main.zip");
const extractRoot = path.join(cacheRoot, "nuclei-templates-expanded");
const repoDir = path.join(extractRoot, "nuclei-templates-main");
const archiveUrl = process.argv[2] || "https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip";

fs.mkdirSync(cacheRoot, { recursive: true });
fs.rmSync(extractRoot, { recursive: true, force: true });

const response = await fetch(archiveUrl, {
  headers: {
    "user-agent": "universal-engine-importer"
  }
});

if (!response.ok) {
  throw new Error(`Archive download failed: ${response.status} ${response.statusText}`);
}

const archiveBuffer = Buffer.from(await response.arrayBuffer());
fs.writeFileSync(archivePath, archiveBuffer);

const zip = new AdmZip(archivePath);
zip.extractAllTo(extractRoot, true);

const state = loadState();
const imported = parseTemplateDirectory("projectdiscovery/nuclei-templates", repoDir);
const uniqueImported = mergeImportedTemplates(state.templates, imported);

state.templates.unshift(...uniqueImported);
saveState(state);

const summary = {
  source: archiveUrl,
  scannedTemplates: imported.length,
  imported: uniqueImported.length,
  skippedDuplicates: imported.length - uniqueImported.length,
  totalTemplates: state.templates.length,
  groups: summarizeTemplateGroups(uniqueImported)
};

console.log(JSON.stringify(summary, null, 2));
