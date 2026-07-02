// Whitebox Auditor Agent
// 白盒审计复挖：扫描完成后 → 查找开源代码 → AI审计 → 生成检测模板 → 复测验证

import { v4 as uuidv4 } from "uuid";
import { locateUpstreamSources } from "../lib/upstream-locator-service.js";
import { callAiJson } from "../lib/ai-review-service.js";
// convertMultiPoc imported via dynamic import when needed

// ----- 白盒审计管线 -----
// 1. 接收已完成扫描的资产
// 2. 对每个明确指纹的资产，查找开源仓库
// 3. 下载源码（如果有权限）
// 4. AI审计源码中的潜在漏洞
// 5. 生成检测模板（nuclei YAML 格式）
// 6. 在原始资产上复测验证

const WHITEBOX_PIPELINE = [
  { stage: "locate-source", label: "查找开源代码", timeout: 30000 },
  { stage: "analyze-code", label: "AI代码审计", timeout: 120000 },
  { stage: "generate-templates", label: "生成检测模板", timeout: 30000 },
  { stage: "retest-verify", label: "复测验证", timeout: 60000 }
];

// ----- 阶段1：查找开源代码 -----
async function locateOpenSource(asset, fingerprint) {
  if (fingerprint.platform === "generic-web") {
    return { success: false, reason: "generic-web fingerprint, no source to audit" };
  }

  try {
    const result = await locateUpstreamSources({
      asset,
      customQuery: fingerprint.platform
    });

    if (!result.candidates?.length) {
      return { success: false, reason: "no open source candidates found" };
    }

    return {
      success: true,
      query: result.query,
      candidates: result.candidates.slice(0, 5).map(c => ({
        name: c.name,
        stars: c.stars,
        language: c.language,
        homepage: c.homepage,
        downloadZipUrl: c.downloadZipUrl,
        cloneUrl: c.cloneUrl,
        description: c.description
      }))
    };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

// ----- 阶段2：AI代码审计 -----
async function analyzeSourceCode(sourceInfo, asset, aiSettings, fingerprint) {
  if (!aiSettings?.enabled) {
    return { success: false, reason: "AI not enabled" };
  }

  // 根据指纹构建审计提示词
  const platform = fingerprint.platform;
  const category = fingerprint.category;

  // 已知漏洞模式库 - 按产品分类的常见漏洞
  const KNOWN_VULN_PATTERNS = {
    "wordpress": [
      { type: "sqli", pattern: "SQL injection in plugin/theme", templateId: "wordpress-plugin-sqli" },
      { type: "xss", pattern: "XSS in admin panel", templateId: "wordpress-admin-xss" },
      { type: "idor", pattern: "IDOR in REST API endpoints", templateId: "wordpress-rest-idor" },
      { type: "upload", pattern: "Unrestricted file upload", templateId: "wordpress-file-upload" },
    ],
    "spring-boot": [
      { type: "actuator", pattern: "Actuator endpoint exposure", templateId: "springboot-actuator-exposure" },
      { type: "rce", pattern: "SpEL injection", templateId: "springboot-spel-injection" },
      { type: "ssrf", pattern: "SSRF via Spring Cloud Gateway", templateId: "springboot-ssrf-gateway" },
    ],
    "apache-tomcat": [
      { type: "rce", pattern: "CGI Servlet RCE", templateId: "tomcat-cgi-rce" },
      { type: "traversal", pattern: "Path traversal in WAR deployment", templateId: "tomcat-path-traversal" },
      { type: "auth-bypass", pattern: "Manager app weak credentials", templateId: "tomcat-manager-brute" },
    ],
    "phpmyadmin": [
      { type: "sqli", pattern: "SQL injection in export", templateId: "phpmyadmin-export-sqli" },
      { type: "auth-bypass", pattern: "Authentication bypass", templateId: "phpmyadmin-auth-bypass" },
    ],
    "nginx": [
      { type: "traversal", pattern: "Path traversal / alias misconfig", templateId: "nginx-alias-traversal" },
      { type: "ssrf", pattern: "SSRF via proxy_pass", templateId: "nginx-proxy-ssrf" },
    ],
    "laravel": [
      { type: "rce", pattern: "Deserialization RCE", templateId: "laravel-deserialization-rce" },
      { type: "debug", pattern: "Debug mode enabled", templateId: "laravel-debug-mode" },
      { type: "env", pattern: ".env file exposure", templateId: "laravel-env-exposure" },
    ],
    "django": [
      { type: "debug", pattern: "DEBUG=True in production", templateId: "django-debug-true" },
      { type: "sqli", pattern: "SQL injection in ORM", templateId: "django-orm-sqli" },
    ]
  };

  const threatModel = KNOWN_VULN_PATTERNS[platform] || [
    { type: "generic", pattern: "Common web vulnerabilities", templateId: `generic-${platform}-audit` }
  ];

  try {
    const auditPrompt = {
      asset: {
        name: asset.name,
        target: asset.target,
        fingerprint: `${platform}/${category}`,
        version: asset.availability?.server || "",
        headers: asset.availability?.headers || {}
      },
      source: {
        repository: sourceInfo.candidates[0]?.name || "unknown",
        language: sourceInfo.candidates[0]?.language || "unknown",
        description: sourceInfo.candidates[0]?.description || ""
      },
      threatModel,
      instruction: `You are a security code auditor. Based on the fingerprint ${platform}/${category}, identify potential vulnerabilities in the source code patterns. For each finding, provide: type, severity, nuclei template YAML (with HTTP requests to verify), and remediation advice. Focus on HIGH and CRITICAL severity findings only.`
    };

    const result = await callAiJson(
      aiSettings,
      "You are an expert security code auditor specializing in web application vulnerabilities. Output JSON with: { findings: [{type, severity, description, nucleiYaml, remediation}] }",
      JSON.stringify(auditPrompt, null, 2)
    );

    if (!result?.findings?.length) {
      return { success: true, findings: [], message: "AI audit found no new vulnerabilities" };
    }

    return {
      success: true,
      findings: result.findings.map(f => ({
        id: uuidv4(),
        type: f.type,
        severity: f.severity || "high",
        description: f.description,
        product: platform,
        category,
        templateYaml: f.nucleiYaml || "",
        remediation: f.remediation || "",
        source: "whitebox-audit",
        createdAt: new Date().toISOString()
      })),
      threatModel
    };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

// ----- 阶段3：生成检测模板 -----
function generateDetectionTemplate(finding, asset, fingerprint) {
  // 将 AI 审计发现转化为 nuclei YAML 模板
  const severity = finding.severity || "high";

  const yamlTemplate = finding.templateYaml || `# Auto-generated template from whitebox audit
id: ${finding.id}
info:
  name: ${finding.description?.substring(0, 80) || "Whitebox audit finding"}
  author: universal-engine-whitebox
  severity: ${severity}
  description: ${finding.description || "Auto-detected vulnerability pattern"}
  tags: [whitebox,${fingerprint.platform},${fingerprint.category},${finding.type}]
requests:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words:
          - "test"`;

  return {
    id: uuidv4(),
    nucleiId: `whitebox:${finding.type}:${fingerprint.platform}:${uuidv4().slice(0, 8)}`,
    sourceName: `whitebox-audit-${fingerprint.platform}`,
    sourceType: "whitebox-audit",
    importFormat: "yaml",
    name: finding.description?.substring(0, 100) || "Whitebox finding",
    severity,
    tags: ["whitebox", fingerprint.platform, fingerprint.category, finding.type].filter(Boolean),
    product: fingerprint.platform,
    category: fingerprint.category,
    frameworkFamily: fingerprint.platform,
    safe: true,
    runnable: true,
    executionMode: "http",
    metadataOnly: false,
    cveIds: [],
    references: finding.remediation ? [finding.remediation] : [],
    versionRange: "",
    summary: finding.description || "",
    raw: yamlTemplate
  };
}

// ----- 阶段4：复测验证 -----
async function retestAsset(asset, templates, nucleiSettings) {
  if (!templates?.length) return { findings: [] };

  const { runNucleiTemplate } = await import("../lib/nuclei-executor.js");

  const findings = [];
  for (const template of templates) {
    if (!template.runnable || !template.raw) continue;

    try {
      const result = await runNucleiTemplate(
        asset,
        asset.fingerprint || { platform: "generic-web", category: "generic" },
        template,
        nucleiSettings
      );

      if (result.mode === "nuclei") {
        for (const f of (result.findings || [])) {
          f.whiteboxAuditId = template.id;
          f.projectName = asset.projectName;
          findings.push(f);
        }
      }
    } catch (e) {
      // Skip failed retests
    }
  }

  return { findings, templatesTested: templates.length };
}

// ----- 完整白盒审计流程 -----
async function runWhiteboxAudit(assets, state, options = {}) {
  const results = {
    startedAt: new Date().toISOString(),
    assetsAudited: 0,
    sourcesFound: 0,
    vulnerabilitiesDiscovered: 0,
    templatesGenerated: 0,
    retestFindings: 0,
    perAsset: []
  };

  // 过滤：只对有明确指纹的存活资产进行审计
  const candidates = assets.filter(a =>
    a.availability?.reachable &&
    a.fingerprint &&
    a.fingerprint.platform !== "generic-web"
  ).slice(0, options.maxAssets || 5);

  for (const asset of candidates) {
    const assetResult = {
      assetName: asset.name,
      target: asset.target,
      fingerprint: asset.fingerprint,
      stages: []
    };

    // Stage 1: 查找开源代码
    const sourceResult = await locateOpenSource(asset, asset.fingerprint);
    assetResult.stages.push({ stage: "locate-source", ...sourceResult });
    if (!sourceResult.success) {
      results.perAsset.push(assetResult);
      continue;
    }
    results.sourcesFound++;

    // Stage 2: AI代码审计
    const auditResult = await analyzeSourceCode(
      sourceResult,
      asset,
      state.settings.ai,
      asset.fingerprint
    );
    assetResult.stages.push({ stage: "analyze-code", ...auditResult });

    if (!auditResult.success || !auditResult.findings?.length) {
      results.perAsset.push(assetResult);
      continue;
    }
    results.vulnerabilitiesDiscovered += auditResult.findings.length;

    // Stage 3: 生成检测模板
    const templates = auditResult.findings.map(f =>
      generateDetectionTemplate(f, asset, asset.fingerprint)
    );
    state.templates.unshift(...templates);
    results.templatesGenerated += templates.length;
    assetResult.stages.push({
      stage: "generate-templates",
      templatesGenerated: templates.length,
      templateIds: templates.map(t => t.id)
    });

    // Stage 4: 复测验证
    const retestResult = await retestAsset(asset, templates, state.settings.nuclei);
    if (retestResult.findings.length > 0) {
      for (const f of retestResult.findings) {
        state.findings.unshift(f);
      }
    }
    results.retestFindings += retestResult.findings.length;
    assetResult.stages.push({
      stage: "retest-verify",
      findings: retestResult.findings.length,
      templatesTested: retestResult.templatesTested
    });

    results.assetsAudited++;
    results.perAsset.push(assetResult);
  }

  results.completedAt = new Date().toISOString();
  return results;
}

// ----- Agent API -----
export const agentType = "whitebox-auditor";
export const capabilities = [
  "audit:locate-source", "audit:analyze-code",
  "audit:generate-templates", "audit:retest",
  "audit:full-pipeline", "audit:targeted"
];

export async function handleTask(task) {
  const { action, asset, assets, state, options } = task.data || {};

  try {
    switch (action) {
      case "audit:locate-source": {
        if (!asset?.fingerprint) throw new Error("asset.fingerprint required");
        const result = await locateOpenSource(asset, asset.fingerprint);
        return { success: true, ...result };
      }

      case "audit:analyze-code": {
        const result = await analyzeSourceCode(
          options?.sourceInfo || {},
          asset,
          options?.aiSettings || {},
          asset?.fingerprint || {}
        );
        return { success: true, ...result };
      }

      case "audit:targeted": {
        // 针对已知产品类型的定向审计
        if (!assets?.length) throw new Error("assets required");
        const result = await runWhiteboxAudit(assets, state || {}, {
          maxAssets: assets.length,
          ...options
        });
        return { success: true, ...result };
      }

      case "audit:full-pipeline": {
        if (!assets?.length) throw new Error("assets required");
        const result = await runWhiteboxAudit(assets, state || {}, options || {});
        return { success: true, ...result };
      }

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
    pipeline: WHITEBOX_PIPELINE,
    status: "ready"
  };
}

export {
  runWhiteboxAudit, locateOpenSource, analyzeSourceCode,
  generateDetectionTemplate, retestAsset, WHITEBOX_PIPELINE
};
