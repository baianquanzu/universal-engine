import { builtinFingerprintRules, fingerprintLibraryMeta } from "./builtin-fingerprint-library.js";
import { classifyFingerprintWithAi } from "./ai-fingerprint-service.js";

function normalize(value) {
  return `${value ?? ""}`.toLowerCase();
}

async function fetchFingerprintEvidence(target) {
  if (!/^https?:\/\//i.test(`${target || ""}`)) {
    return null;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);

  try {
    const response = await fetch(target, {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: {
        "user-agent": "Universal-Engine-Fingerprint"
      }
    });

    const contentType = response.headers.get("content-type") || "";
    const html = contentType.includes("text/html") ? await response.text() : "";
    const titleMatch = html.match(/<title[^>]*>([\s\S]{0,250}?)<\/title>/i);
    const bodySnippet = html.replace(/\s+/g, " ").slice(0, 800);

    return {
      finalUrl: response.url || target,
      title: titleMatch ? titleMatch[1].trim() : "",
      httpStatus: response.status,
      server: response.headers.get("server") || "",
      poweredBy: response.headers.get("x-powered-by") || "",
      generator: response.headers.get("x-generator") || "",
      bodySnippet
    };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

function collectSignals(asset, liveEvidence) {
  const mergedAvailability = {
    ...(asset.availability || {}),
    ...(liveEvidence || {})
  };

  const signals = {
    target: normalize(mergedAvailability.finalUrl || asset.target),
    name: normalize(asset.name),
    title: normalize(mergedAvailability.title),
    headers: normalize(
      [
        mergedAvailability.server ? `server: ${mergedAvailability.server}` : "",
        mergedAvailability.poweredBy ? `x-powered-by: ${mergedAvailability.poweredBy}` : "",
        mergedAvailability.generator ? `x-generator: ${mergedAvailability.generator}` : ""
      ]
        .filter(Boolean)
        .join(" | ")
    ),
    body: normalize(mergedAvailability.bodySnippet)
  };

  return { signals, mergedAvailability };
}

function matchPatterns(value, patterns = []) {
  return patterns.filter((pattern) => value.includes(normalize(pattern)));
}

function evaluateRule(rule, signals) {
  const hits = [
    ...matchPatterns(signals.target, rule.urlPatterns).map((pattern) => `URL matched "${pattern}"`),
    ...matchPatterns(signals.name, rule.namePatterns).map((pattern) => `Name matched "${pattern}"`),
    ...matchPatterns(signals.title, rule.titlePatterns).map((pattern) => `Title matched "${pattern}"`),
    ...matchPatterns(signals.headers, rule.headerPatterns).map((pattern) => `Header matched "${pattern}"`),
    ...matchPatterns(signals.body, rule.bodyPatterns).map((pattern) => `Body matched "${pattern}"`)
  ];

  if (hits.length < (rule.minMatches || 1)) {
    return null;
  }

  return {
    type: "web",
    platform: rule.platform,
    category: rule.category,
    confidence: Math.min(0.97, rule.confidence + Math.min(hits.length - 1, 3) * 0.02),
    evidence: [
      ...hits,
      `Matched built-in fingerprint rule ${rule.id} from ${rule.source}`
    ],
    source: `builtin:${rule.source}`,
    library: fingerprintLibraryMeta
  };
}

function bestBuiltinFingerprint(signals) {
  return builtinFingerprintRules
    .map((rule) => evaluateRule(rule, signals))
    .filter(Boolean)
    .sort((left, right) => right.confidence - left.confidence)[0];
}

function genericFingerprint() {
  return {
    type: "web",
    platform: "generic-web",
    category: "generic",
    confidence: 0.58,
    evidence: ["No strong fingerprint markers", "Kept in generic web bucket for safe routing"],
    source: "fallback"
  };
}

export async function fingerprintAsset(asset, aiSettings) {
  const liveEvidence = await fetchFingerprintEvidence(asset.target);
  const { signals, mergedAvailability } = collectSignals(asset, liveEvidence);

  if (liveEvidence) {
    asset.availability = {
      ...(asset.availability || {}),
      ...mergedAvailability
    };
  }

  const builtin = bestBuiltinFingerprint(signals);
  const aiSuggestion =
    !builtin || builtin.platform === "generic-web" || builtin.confidence < 0.82
      ? await classifyFingerprintWithAi(aiSettings, asset, {
          target: signals.target,
          title: signals.title,
          headers: signals.headers,
          body: signals.body,
          builtin
        })
      : null;

  if (builtin && aiSuggestion && aiSuggestion.platform === builtin.platform) {
    return {
      ...builtin,
      confidence: Math.min(0.98, Math.max(builtin.confidence, aiSuggestion.confidence) + 0.03),
      evidence: [...builtin.evidence, "AI confirmed the final fingerprint"],
      source: "builtin+ai-confirmed"
    };
  }

  if (aiSuggestion && (!builtin || aiSuggestion.confidence > builtin.confidence + 0.08)) {
    return {
      ...aiSuggestion,
      evidence: aiSuggestion.evidence
    };
  }

  return builtin || genericFingerprint();
}
