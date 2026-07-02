import { callAiJson } from "./ai-review-service.js";

export async function classifyFingerprintWithAi(aiSettings, asset, evidence) {
  if (!aiSettings?.enabled) {
    return null;
  }

  const prompt = JSON.stringify(
    {
      asset: {
        name: asset.name,
        target: asset.target,
        title: asset.availability?.title || "",
        httpStatus: asset.availability?.httpStatus || 0,
        server: asset.availability?.server || "",
        poweredBy: asset.availability?.poweredBy || "",
        bodySnippet: asset.availability?.bodySnippet || ""
      },
      builtinEvidence: evidence
    },
    null,
    2
  );

  try {
    const result = await callAiJson(
      aiSettings,
      "You are a defensive web fingerprint assistant. Identify only the final confirmed platform and category from supplied evidence. If evidence is insufficient, return platform as unknown and confidence below 0.75. Return JSON only with platform, category, confidence.",
      prompt
    );

    if (!result?.platform || !result?.category) {
      return null;
    }

    const normalizedPlatform = `${result.platform}`.trim().toLowerCase().replace(/\s+/g, "-");
    if (!normalizedPlatform || normalizedPlatform === "unknown" || normalizedPlatform === "generic-web") {
      return null;
    }

    const confidence = Math.max(0, Math.min(0.99, Number(result.confidence || 0)));
    if (confidence < 0.82) {
      return null;
    }

    return {
      type: "web",
      platform: normalizedPlatform,
      category: `${result.category}`.trim().toLowerCase().replace(/\s+/g, "-"),
      confidence,
      evidence: [`AI confirmed final fingerprint: ${result.platform} / ${result.category}`],
      source: "ai-confirmed"
    };
  } catch {
    return null;
  }
}
