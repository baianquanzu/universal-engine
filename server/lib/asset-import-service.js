// Asset Import Service
// 支持：XLSX/CSV拖放导入 + 实时进度条 + AI自动分类 + 智能测活

import { v4 as uuidv4 } from "uuid";
import XLSX from "xlsx";
import { callAiJson } from "./ai-review-service.js";

const urlPattern = /((?:https?:\/\/)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d{2,5})?(?:\/[^\s"'<>]*)?)/gi;
const titlePattern = /<title[^>]*>([\s\S]{0,300}?)<\/title>/i;
const ipPortPattern = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):?(\d{1,5})?$/;

function normalizeWhitespace(value) {
  return `${value ?? ""}`.replace(/\s+/g, " ").trim();
}

function decodeHtmlEntities(value) {
  return value
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
}

function normalizeUrlCandidate(rawValue) {
  const value = normalizeWhitespace(rawValue).replace(/[),.;]+$/g, "");
  if (!value) return null;

  // 处理 "无" 等无效值
  if (/^(无|null|none|n\/a|不适用|未配置|没有)$/i.test(value)) return null;

  // IP:Port 格式
  const ipm = value.match(ipPortPattern);
  if (ipm) {
    const ip = ipm[1];
    const port = ipm[2] || "80";
    return `http://${ip}:${port}`;
  }

  // 域名格式 - 如果已经有协议
  const withProtocol = /^https?:\/\//i.test(value) ? value : `https://${value}`;

  try {
    const parsed = new URL(withProtocol);
    if (!parsed.hostname.includes(".") && !/^\d+\.\d+\.\d+\.\d+$/.test(parsed.hostname)) {
      return null;
    }
    parsed.hash = "";
    return parsed.toString();
  } catch {
    return null;
  }
}

function collectUrlCandidates(rowValues) {
  const found = [];
  for (const value of rowValues) {
    const text = normalizeWhitespace(value);
    if (!text) continue;
    const matches = text.match(urlPattern) || [];
    for (const match of matches) {
      const normalized = normalizeUrlCandidate(match);
      if (normalized) found.push(normalized);
    }
  }
  return [...new Set(found)];
}

function pickNameCandidate(rowValues, matchedUrl) {
  const cleanUrl = normalizeWhitespace(matchedUrl);
  const candidates = rowValues
    .map((value) => normalizeWhitespace(value))
    .filter(Boolean)
    .filter((value) => !value.includes(cleanUrl))
    .filter((value) => !normalizeUrlCandidate(value))
    .sort((left, right) => right.length - left.length);
  return candidates[0] || "";
}

function sheetRowsToCandidates(sheetName, rows) {
  const records = [];
  rows.forEach((row, index) => {
    const rowValues = Array.isArray(row) ? row.map((cell) => normalizeWhitespace(cell)) : [];
    const urls = collectUrlCandidates(rowValues);
    if (!urls.length) return;

    // IP + 端口组合：第一列IP，第二列端口
    if (rowValues.length >= 2) {
      const ipMatch = rowValues[0]?.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
      const portMatch = rowValues[1]?.match(/^(\d{1,5})$/);
      if (ipMatch && portMatch) {
        const ip = ipMatch[1];
        const port = portMatch[1];
        records.push({
          id: uuidv4(),
          target: `http://${ip}:${port}`,
          sourceSheet: sheetName,
          sourceRow: index + 1,
          suggestedName: pickNameCandidate(rowValues.slice(2), `http://${ip}:${port}`),
          rawRow: rowValues
        });
        return;
      }
    }

    for (const url of urls) {
      records.push({
        id: uuidv4(),
        target: url,
        sourceSheet: sheetName,
        sourceRow: index + 1,
        suggestedName: pickNameCandidate(rowValues, url),
        rawRow: rowValues
      });
    }
  });
  return records;
}

// 提取资产候选（支持 callback 进度）
export function extractAssetCandidatesFromBuffer(fileName, buffer, onProgress) {
  const workbook = XLSX.read(buffer, { type: "buffer", dense: true });
  const imported = [];

  for (let i = 0; i < workbook.SheetNames.length; i++) {
    const sheetName = workbook.SheetNames[i];
    const sheet = workbook.Sheets[sheetName];
    const rows = XLSX.utils.sheet_to_json(sheet, {
      header: 1,
      blankrows: false,
      defval: ""
    });

    const records = sheetRowsToCandidates(sheetName, rows);
    imported.push(...records);

    if (onProgress) {
      onProgress({
        stage: "extracting",
        sheet: sheetName,
        sheetIndex: i + 1,
        totalSheets: workbook.SheetNames.length,
        candidatesFound: imported.length,
        rowsProcessed: rows.length
      });
    }
  }

  const uniqueTargets = new Set();
  return imported.filter((record) => {
    const key = record.target.toLowerCase();
    if (uniqueTargets.has(key)) return false;
    uniqueTargets.add(key);
    return true;
  });
}

async function fetchWithTimeout(url, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: {
        "user-agent": "Universal-Engine-Asset-Import/1.0",
        "accept": "text/html,application/json,*/*"
      }
    });
  } finally {
    clearTimeout(timer);
  }
}

function extractTitleFromHtml(html) {
  const match = html.match(titlePattern);
  if (!match) return "";
  return decodeHtmlEntities(normalizeWhitespace(match[1]));
}

// 测活 + 收集页面指纹信息
async function probeAsset(candidate, options = {}) {
  const attempts = [candidate.target];
  if (candidate.target.startsWith("https://")) {
    attempts.push(candidate.target.replace(/^https:\/\//i, "http://"));
  }

  for (const attemptUrl of attempts) {
    try {
      const response = await fetchWithTimeout(attemptUrl, options.timeout || 8000);
      const contentType = response.headers.get("content-type") || "";
      const finalUrl = response.url || attemptUrl;
      const statusCode = response.status;
      const html = contentType.includes("text/html") ? await response.text() : "";
      const title = html ? extractTitleFromHtml(html) : "";
      const reachable = statusCode > 0 && statusCode < 500;

      // 收集响应头指纹
      const headers = {};
      for (const [k, v] of response.headers) {
        headers[k.toLowerCase()] = v;
      }

      return {
        reachable,
        finalUrl,
        httpStatus: statusCode,
        title,
        headers,
        server: headers.server || "",
        poweredBy: headers["x-powered-by"] || "",
        contentType,
        bodySnippet: html ? html.replace(/\s+/g, " ").slice(0, 800) : "",
        checkedAt: new Date().toISOString(),
        error: reachable ? null : `HTTP ${statusCode}`
      };
    } catch (error) {
      // continue to next attempt
    }
  }

  return {
    reachable: false,
    finalUrl: candidate.target,
    httpStatus: 0,
    title: "",
    checkedAt: new Date().toISOString(),
    error: "unreachable"
  };
}

async function mapWithConcurrency(items, limit, worker) {
  const results = new Array(items.length);
  let cursor = 0;
  const runners = Array.from({ length: Math.min(limit, Math.max(1, items.length)) }, async () => {
    while (cursor < items.length) {
      const currentIndex = cursor;
      cursor += 1;
      results[currentIndex] = await worker(items[currentIndex], currentIndex);
    }
  });
  await Promise.all(runners);
  return results;
}

function buildAssetName(candidate, probe) {
  if (probe.title && probe.title.length > 1) return probe.title;
  if (candidate.suggestedName) return candidate.suggestedName;
  try {
    return new URL(probe.finalUrl || candidate.target).hostname;
  } catch {
    return candidate.target.substring(0, 60);
  }
}

// AI 自动业务分类
async function classifyAssetWithAI(asset, aiSettings, onProgress) {
  if (!aiSettings?.enabled) return null;

  try {
    const result = await callAiJson(
      aiSettings,
      "You are an asset classification assistant. Classify web assets by business function. Output JSON with: category (one of: portal,api,admin-console,cms,mail,cdn,monitoring,collaboration,bi,iot,vpn,file-server,database-tool,devops,education,government,telecom,finance,generic), confidence, tags[].",
      JSON.stringify({
        url: asset.target,
        title: asset.availability?.title || "",
        server: asset.availability?.server || "",
        statusCode: asset.availability?.httpStatus || 0,
        bodySnippet: (asset.availability?.bodySnippet || "").slice(0, 300)
      })
    );

    if (result?.category) {
      if (onProgress) onProgress({ type: "ai-classify", asset: asset.name, category: result.category, confidence: result.confidence });
      return {
        businessCategory: result.category,
        businessTags: result.tags || [],
        aiClassificationConfidence: result.confidence || 0
      };
    }
  } catch (e) {
    // AI分类失败不阻断导入流程
  }
  return null;
}

// 增强版资产导入 - 带实时进度 + AI分类
export async function enrichImportedAssets(candidates, options = {}) {
  const owner = normalizeWhitespace(options.owner) || "Import";
  const projectName = normalizeWhitespace(options.projectName) || "Default Project";
  const tags = Array.isArray(options.tags) ? options.tags.filter(Boolean) : [];
  const aiSettings = options.aiSettings || { enabled: false };
  const onProgress = options.onProgress;

  let processed = 0;
  let live = 0;
  let unreachable = 0;
  let errors = 0;

  const results = await mapWithConcurrency(candidates, Number(options.concurrency || 6), async (candidate, index) => {
    // 探活
    const probe = await probeAsset(candidate, { timeout: options.timeout || 8000 });
    processed++;

    if (probe.reachable) live++; else unreachable++;

    // 进度回调
    if (onProgress) {
      onProgress({
        stage: "probing",
        processed,
        total: candidates.length,
        percent: Math.round((processed / candidates.length) * 100),
        current: probe.finalUrl || candidate.target,
        live,
        unreachable,
        errors,
        httpStatus: probe.httpStatus,
        title: probe.title
      });
    }

    const asset = {
      id: uuidv4(),
      name: buildAssetName(candidate, probe),
      projectName,
      target: probe.finalUrl || candidate.target,
      owner,
      tags: [...new Set([...tags, candidate.sourceSheet])],
      status: probe.reachable ? "live" : "unreachable",
      fingerprint: null,
      availability: probe,
      importMeta: {
        sourceSheet: candidate.sourceSheet,
        sourceRow: candidate.sourceRow,
        originalTarget: candidate.target
      },
      aiClassification: null
    };

    return asset;
  });

  // AI 分类阶段（对存活资产）
  if (aiSettings?.enabled && results.some(a => a.status === "live")) {
    if (onProgress) onProgress({ stage: "ai-classifying", message: "AI自动分类中..." });

    const liveAssets = results.filter(a => a.status === "live");
    let classified = 0;

    for (const asset of liveAssets) {
      const classification = await classifyAssetWithAI(asset, aiSettings);
      if (classification) {
        asset.aiClassification = classification;
        asset.tags = [...new Set([...asset.tags, ...(classification.businessTags || [])])];
        classified++;
      }
    }

    if (onProgress) {
      onProgress({
        stage: "ai-classify-done",
        classified,
        total: liveAssets.length
      });
    }
  }

  return results;
}

export function mergeImportedAssets(existingAssets, importedAssets) {
  const seen = new Set(existingAssets.map((asset) => normalizeWhitespace(asset.target).toLowerCase()));
  const uniqueImported = [];
  for (const asset of importedAssets) {
    const key = normalizeWhitespace(asset.target).toLowerCase();
    if (!key || seen.has(key)) continue;
    seen.add(key);
    uniqueImported.push(asset);
  }
  return uniqueImported;
}

// CSV 支持
export function extractAssetCandidatesFromCSV(fileName, text) {
  const lines = text.split(/\r?\n/).filter(Boolean);
  if (!lines.length) return [];

  const headers = lines[0].split(/[,\t;|]/).map(h => normalizeWhitespace(h));
  const rows = lines.slice(1).map(line => {
    const cells = line.split(/[,\t;|]/).map(c => normalizeWhitespace(c));
    const obj = {};
    cells.forEach((c, i) => obj[headers[i] || `col_${i}`] = c);
    return obj;
  });

  return rows.map(row => ({
    id: uuidv4(),
    target: row.url || row.target || row.host || row.domain || Object.values(row).find(v => v?.includes("http")),
    sourceRow: rows.indexOf(row) + 2,
    suggestedName: row.name || row.title || row.description || "",
    rawRow: Object.values(row)
  })).filter(c => c.target);
}
