// POC Converter Agent
// 接收任何形式的POC输入，AI智能识别并转化为程序可用的POC模板
// 支持：目录、压缩包、单文件、代码粘贴、GitHub URL

import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { v4 as uuidv4 } from "uuid";
import AdmZip from "adm-zip";

// ----- 支持的所有文件类型 -----
const ALL_SUPPORTED_EXTENSIONS = new Set([
  ".py",".js",".mjs",".cjs",".ts",".rb",".pl",".php",
  ".asp",".aspx",".jsp",".sh",".bash",".zsh",".ps1",".psm1",".bat",".cmd",
  ".c",".h",".cpp",".hpp",".cc",".cs",".java",".go",".rs",".swift",
  ".json",".yaml",".yml",".xml",".toml",".ini",".cfg",".conf",
  ".md",".txt",".rst",".adoc",
  ".zip",".tar.gz",".tgz",".tar",".rar",".7z",
  ".exe",".dll",".bin",".so",".dylib",".jar",".class",".elf",
  ".cargo",".toml",".gradle",".pom",".cmake",
  ".proto",".sql",".http",".har"
]);

// 产品识别规则
const PRODUCT_PATTERNS = [
  [/wordpress|wp-/i, "wordpress"], [/drupal/i, "drupal"], [/joomla/i, "joomla"],
  [/spring|springboot/i, "spring-boot"], [/tomcat/i, "apache-tomcat"],
  [/weblogic/i, "oracle-weblogic"], [/jenkins/i, "jenkins"],
  [/nginx/i, "nginx"], [/apache|httpd/i, "apache"], [/redis/i, "redis"],
  [/elasticsearch|kibana/i, "elasticsearch"], [/mongodb/i, "mongodb"],
  [/mysql|mariadb/i, "mysql"], [/postgresql/i, "postgresql"],
  [/docker/i, "docker"], [/kubernetes|k8s/i, "kubernetes"],
  [/gitlab/i, "gitlab"], [/gitea/i, "gitea"],
  [/django/i, "django"], [/flask/i, "flask"], [/laravel/i, "laravel"],
  [/thinkphp/i, "thinkphp"], [/struts/i, "apache-struts"],
  [/shiro/i, "apache-shiro"], [/fastjson/i, "fastjson"],
  [/log4j/i, "log4j"], [/exchange|owa/i, "microsoft-exchange"],
  [/sharepoint/i, "sharepoint"], [/vmware|vcenter/i, "vmware"],
  [/citrix/i, "citrix"], [/fortinet|fortigate/i, "fortinet"],
  [/palo.?alto/i, "palo-alto"], [/jira|confluence/i, "atlassian"],
  [/phpmyadmin/i, "phpmyadmin"], [/nodejs|node.js/i, "nodejs"],
  [/c-ares/i, "c-ares"], [/libssh/i, "libssh2"], [/curl/i, "curl"],
  [/openssl/i, "openssl"], [/anydesk/i, "anydesk"],
  [/rustdesk/i, "rustdesk"], [/7-?zip/i, "7-zip"],
  [/vlc/i, "vlc"], [/ffmpeg/i, "ffmpeg"],
  [/imagemagick/i, "imagemagick"], [/nmap/i, "nmap"],
  [/openvpn/i, "openvpn"], [/firefox/i, "firefox"],
  [/chrome|chromium/i, "chrome"], [/php/i, "php"],
  [/sqlite/i, "sqlite"], [/gstreamer/i, "gstreamer"],
];

// 框架家族映射
const FAMILY_MAP = {
  "wordpress":"cms","drupal":"cms","joomla":"cms",
  "spring-boot":"java","apache-tomcat":"java","oracle-weblogic":"java",
  "jenkins":"java","apache-struts":"java","apache-shiro":"java","fastjson":"java",
  "thinkphp":"php","laravel":"php","phpmyadmin":"php","php":"php",
  "django":"python","flask":"python",
  "nginx":"middleware","apache":"middleware","redis":"middleware",
  "elasticsearch":"middleware","mongodb":"middleware",
  "docker":"container","kubernetes":"container",
  "microsoft-exchange":"mail","sharepoint":"dotnet",
  "anydesk":"desktop-app","rustdesk":"desktop-app","7-zip":"desktop-app",
  "vlc":"desktop-app","openvpn":"desktop-app","firefox":"browser","chrome":"browser",
  "c-ares":"c-library","libssh2":"c-library","curl":"c-library","openssl":"c-library",
  "ffmpeg":"binary-tool","imagemagick":"binary-tool","nmap":"binary-tool",
  "vmware":"virtualization","citrix":"network-appliance",
  "fortinet":"network-appliance","palo-alto":"network-appliance",
  "gstreamer": "binary-tool", "sqlite": "c-library",
};

function inferProduct(allText, sourceName) {
  const combined = allText + " " + sourceName;
  for (const [regex, product] of PRODUCT_PATTERNS) {
    if (regex.test(combined)) return product;
  }
  return "generic";
}

function inferSeverity(text) {
  const lower = text.toLowerCase();
  if (/critical|rce|remote.code|command.injection|arbitrary.code|pre.auth/i.test(lower)) return "critical";
  if (/high|privilege.escalation|lpe|local.system|auth.bypass|sqli|ssrf|xxe|deserial/i.test(lower)) return "high";
  if (/medium|moderate|xss|csrf|idor|open.redirect/i.test(lower)) return "medium";
  if (/low|notice|info|dos/i.test(lower)) return "low";
  return "high";
}

function inferCategory(text) {
  const lower = text.toLowerCase();
  if (/rce|remote.code|command.injection|arbitrary.code/i.test(lower)) return "remote-code-execution";
  if (/sqli|sql.injection/i.test(lower)) return "sql-injection";
  if (/xss|cross.site.script/i.test(lower)) return "cross-site-scripting";
  if (/ssrf/i.test(lower)) return "ssrf";
  if (/xxe/i.test(lower)) return "xxe-injection";
  if (/lpe|privilege.escalation|elevation/i.test(lower)) return "privilege-escalation";
  if (/auth.bypass|authentication.bypass/i.test(lower)) return "authentication-bypass";
  if (/idor|bola|broken.access/i.test(lower)) return "authorization-bypass";
  if (/path.traversal|lfi|rfi|directory.traversal/i.test(lower)) return "path-traversal";
  if (/deserial/i.test(lower)) return "deserialization";
  if (/csrf/i.test(lower)) return "csrf";
  if (/uaf|use.after.free|memory.corruption|buffer.overflow|heap|oob/i.test(lower)) return "memory-corruption";
  if (/dos|denial.of.service|crash/i.test(lower)) return "denial-of-service";
  if (/information.disclosure|data.exposure/i.test(lower)) return "information-disclosure";
  if (/container.escape|docker.escape|sandbox.escape/i.test(lower)) return "container-escape";
  return "uncategorized";
}

function extractVersion(text) {
  let m = text.match(/(?:version|v\.?)\s*([\d.]+(?:\s*[-–]\s*[\d.]+)?)/i);
  if (!m) m = text.match(/<=?\s*([\d.]+)/);
  if (!m) m = text.match(/([\d]+\.[\d]+(?:\.[\d]+)?)/);
  return m ? (m[1] || m[0]) : "";
}

function parsePocMetadata(sourceName, fileList, readmeContent, codeSnippets) {
  const allText = [sourceName, readmeContent || "", ...codeSnippets].join("\n").slice(0, 15000);
  const lower = allText.toLowerCase();

  const cveMatch = allText.match(/CVE-\d{4}-\d{4,8}/gi) || [];
  const cveIds = [...new Set(cveMatch.map(c => c.toUpperCase()))];

  const product = inferProduct(allText, sourceName);
  const severity = inferSeverity(allText);
  const category = inferCategory(allText);
  const versionRange = extractVersion(allText);
  const frameworkFamily = FAMILY_MAP[product] || "generic";

  const tags = [category, product, "poc"];
  if (cveIds.length) tags.push("cve");

  const nameMatch = (readmeContent || "").match(/^#\s+(.+)$/m);
  const name = nameMatch ? nameMatch[1].trim() : sourceName.replace(/[_-]/g, " ");

  let summary = "";
  const lines = (readmeContent || allText).split("\n").filter(l => l.trim().length > 30);
  summary = lines[1] || lines[0] || `${name} POC`;

  return {
    name, product, severity, category, frameworkFamily,
    cveIds, versionRange: versionRange.slice(0, 80),
    tags: [...new Set(tags)],
    summary: summary.slice(0, 500)
  };
}

// ----- 主转换函数 -----
function convertPocInput(input) {
  const stats = { totalFiles: 0, converted: 0, codeFiles: 0, docFiles: 0, errors: [] };
  let sourceName = input.sourceName || "unknown";
  let fileList = [];
  let readmeContent = "";
  let codeSnippets = [];

  // 类型1: 目录
  if (input.path && fs.existsSync(input.path) && fs.statSync(input.path).isDirectory()) {
    const rootDir = input.path;
    function walkDir(dir, relative) {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        if (entry.name.startsWith(".") || entry.name === "node_modules" || entry.name === ".git") continue;
        const relPath = path.join(relative || "", entry.name);
        if (entry.isDirectory()) {
          walkDir(path.join(dir, entry.name), relPath);
        } else {
          const absPath = path.join(dir, entry.name);
          stats.totalFiles++;
          let content;
          try { content = fs.readFileSync(absPath); }
          catch { continue; }
          const info = { relativePath: relPath, extension: path.extname(entry.name).toLowerCase(), name: entry.name, size: content.length };
          fileList.push(info);
          if (entry.name.toLowerCase() === "readme.md" || entry.name.toLowerCase() === "readme.txt") {
            readmeContent = readmeContent || content.toString("utf8");
            stats.docFiles++;
          } else if ([".yaml",".yml",".json",".md",".txt"].includes(info.extension)) {
            stats.docFiles++;
            codeSnippets.push(content.toString("utf8").slice(0, 3000));
          } else if (ALL_SUPPORTED_EXTENSIONS.has(info.extension)) {
            stats.codeFiles++;
            codeSnippets.push(content.toString("utf8").slice(0, 3000));
          }
        }
      }
    }
    walkDir(rootDir, "");
    sourceName = path.basename(rootDir);
  }
  // 类型2: 压缩包
  else if (input.path && fs.existsSync(input.path) && fs.statSync(input.path).isFile()) {
    const ext = path.extname(input.path).toLowerCase();
    if (ext === ".zip" || input.path.endsWith(".tar.gz") || input.path.endsWith(".tgz")) {
      const tempDir = path.join(os.tmpdir(), "poc-convert-" + uuidv4());
      fs.mkdirSync(tempDir, { recursive: true });
      try {
        if (ext === ".zip") {
          const zip = new AdmZip(input.path);
          for (const entry of zip.getEntries()) {
            if (entry.isDirectory) continue;
            stats.totalFiles++;
            const name = path.basename(entry.entryName);
            const ext2 = path.extname(name).toLowerCase();
            const info = { relativePath: entry.entryName, extension: ext2, name, size: entry.getData().length };
            fileList.push(info);
            if (name.toLowerCase() === "readme.md") {
              readmeContent = readmeContent || entry.getData().toString("utf8");
              stats.docFiles++;
            } else if (ALL_SUPPORTED_EXTENSIONS.has(ext2)) {
              stats.codeFiles++;
              codeSnippets.push(entry.getData().toString("utf8").slice(0, 3000));
            }
          }
        } else {
          const { execSync } = require("node:child_process");
          execSync('tar -xzf "' + input.path + '" -C "' + tempDir + '"', { timeout: 15000 });
          // recurse
          return convertPocInput({ path: tempDir, sourceName: input.sourceName });
        }
      } catch(e) { stats.errors.push(e.message); }
      finally { try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch {} }
    }
    // 单文件
    else {
      stats.totalFiles++;
      const content = fs.readFileSync(input.path);
      const info = { relativePath: path.basename(input.path), extension: ext, name: path.basename(input.path), size: content.length };
      fileList.push(info);
      if ([".md",".txt"].includes(ext)) { readmeContent = content.toString("utf8"); stats.docFiles++; }
      else { codeSnippets.push(content.toString("utf8")); stats.codeFiles++; }
    }
  }
  // 类型3: 粘贴文本
  else if (input.content) {
    stats.totalFiles++;
    sourceName = input.sourceName || "pasted-poc";
    const info = { relativePath: sourceName, extension: input.language ? "." + input.language : ".txt", name: sourceName, size: input.content.length };
    fileList.push(info);
    codeSnippets.push(input.content);
    stats.codeFiles++;
  }

  if (fileList.length === 0) return { templates: [], stats };

  const metadata = parsePocMetadata(sourceName, fileList, readmeContent, codeSnippets);

  const template = {
    id: uuidv4(),
    nucleiId: metadata.cveIds[0] || "poc:" + sourceName.replace(/[^a-zA-Z0-9]/g, "-"),
    sourceName,
    sourceType: "poc",
    importFormat: "poc-converter-agent",
    name: metadata.name,
    severity: metadata.severity,
    tags: metadata.tags,
    product: metadata.product,
    category: metadata.category,
    frameworkFamily: metadata.frameworkFamily,
    classificationLabel: metadata.frameworkFamily + " / " + metadata.category + " / " + metadata.product,
    safe: true,
    runnable: false,
    executionMode: "metadata",
    metadataOnly: true,
    cveIds: metadata.cveIds,
    references: [],
    versionRange: metadata.versionRange,
    summary: metadata.summary,
    raw: {
      type: "poc-package",
      description: "Auto-converted POC: " + metadata.name,
      source: sourceName,
      totalFiles: fileList.length,
      codeFiles: stats.codeFiles,
      docFiles: stats.docFiles,
      files: fileList.map(function(f) { return { relativePath: f.relativePath, extension: f.extension, sizeBytes: f.size }; }),
      readme: readmeContent || "",
      convertedBy: "poc-converter-agent",
      convertedAt: new Date().toISOString()
    }
  };

  stats.converted = 1;
  return { templates: [template], stats };
}

// ----- Agent API -----
export const agentType = "poc-converter";
export const capabilities = ["poc:convert", "poc:import", "poc:classify"];

export async function handleTask(task) {
  try {
    const result = convertPocInput(task.data || {});
    return { success: true, ...result };
  } catch (error) {
    return { success: false, error: error.message, templates: [], stats: { errors: [error.message] } };
  }
}

export function getStatus() {
  return { type: agentType, capabilities, status: "ready" };
}
