function sanitizeBaseUrl(baseUrl) {
  return baseUrl.replace(/\/$/, "");
}

async function callOpenAiCompatible(settings, prompt) {
  const response = await fetch(`${sanitizeBaseUrl(settings.baseUrl)}/chat/completions`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${settings.apiKey}`
    },
    body: JSON.stringify({
      model: settings.model,
      temperature: settings.temperature,
      max_tokens: settings.maxTokens,
      response_format: { type: "json_object" },
      messages: [
        {
          role: "system",
          content:
            "You are a defensive security review assistant. Decide only from supplied evidence. Output JSON with verdict, confidence, rationale, remediation."
        },
        {
          role: "user",
          content: prompt
        }
      ]
    })
  });

  const payload = await response.json();
  const content = payload.choices?.[0]?.message?.content ?? "{}";
  return JSON.parse(content);
}

async function callAnthropic(settings, prompt) {
  const response = await fetch(`${sanitizeBaseUrl(settings.baseUrl)}/messages`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": settings.apiKey,
      "anthropic-version": "2023-06-01"
    },
    body: JSON.stringify({
      model: settings.model,
      max_tokens: settings.maxTokens,
      temperature: settings.temperature,
      system:
        "You are a defensive security review assistant. Return JSON only with verdict, confidence, rationale, remediation.",
      messages: [{ role: "user", content: prompt }]
    })
  });

  const payload = await response.json();
  const text = payload.content?.[0]?.text ?? "{}";
  return JSON.parse(text);
}

async function callGemini(settings, prompt) {
  const url = `${sanitizeBaseUrl(settings.baseUrl)}/models/${settings.model}:generateContent?key=${settings.apiKey}`;
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      generationConfig: {
        temperature: settings.temperature,
        maxOutputTokens: settings.maxTokens
      },
      contents: [
        {
          role: "user",
          parts: [
            {
              text:
                "You are a defensive security review assistant. Return JSON only with verdict, confidence, rationale, remediation.\n\n" +
                prompt
            }
          ]
        }
      ]
    })
  });

  const payload = await response.json();
  const text = payload.candidates?.[0]?.content?.parts?.[0]?.text ?? "{}";
  return JSON.parse(text);
}

async function callOllama(settings, prompt) {
  const response = await fetch(`${sanitizeBaseUrl(settings.baseUrl)}/api/generate`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      model: settings.model,
      stream: false,
      format: "json",
      prompt:
        "You are a defensive security review assistant. Return JSON only with verdict, confidence, rationale, remediation.\n\n" +
        prompt
    })
  });

  const payload = await response.json();
  return JSON.parse(payload.response ?? "{}");
}

export async function callAiJson(aiSettings, systemPrompt, prompt) {
  const wrappedPrompt = `${systemPrompt}\n\n${prompt}`;

  if (aiSettings.provider === "deepseek") {
    return callOpenAiCompatible(aiSettings, wrappedPrompt);
  }

  if (aiSettings.provider === "anthropic") {
    return callAnthropic(aiSettings, wrappedPrompt);
  }

  if (aiSettings.provider === "gemini") {
    return callGemini(aiSettings, wrappedPrompt);
  }

  if (aiSettings.provider === "ollama") {
    return callOllama(aiSettings, wrappedPrompt);
  }

  return callOpenAiCompatible(aiSettings, wrappedPrompt);
}

export async function reviewFinding(aiSettings, finding) {
  if (!aiSettings.enabled) {
    return {
      status: "skipped",
      verdict: "not-reviewed",
      confidence: 0,
      rationale: "AI review is disabled in settings.",
      remediation: "Enable a provider to perform evidence-based rechecks."
    };
  }

  const prompt = JSON.stringify(
    {
      asset: {
        name: finding.assetName,
        target: finding.target,
        fingerprint: finding.fingerprint
      },
      template: {
        id: finding.templateId,
        name: finding.templateName,
        severity: finding.severity,
        tags: finding.tags
      },
      evidence: finding.evidence
    },
    null,
    2
  );

  try {
    return {
      status: "complete",
      ...(await callAiJson(
        aiSettings,
        "You are a defensive security review assistant. Decide only from supplied evidence. Output JSON with verdict, confidence, rationale, remediation.",
        prompt
      ))
    };
  } catch (error) {
    return {
      status: "failed",
      verdict: "needs-manual-review",
      confidence: 0.25,
      rationale: `AI review failed: ${error.message}`,
      remediation: "Verify provider settings, then rerun the AI recheck."
    };
  }
}
