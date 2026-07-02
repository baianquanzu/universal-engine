function sanitizeQuery(value) {
  return `${value ?? ""}`.trim();
}

function repoToCandidate(repo, query, asset) {
  return {
    id: `${repo.id}`,
    query,
    assetId: asset?.id ?? null,
    assetName: asset?.name ?? null,
    fingerprint: asset?.fingerprint ?? null,
    source: "github",
    name: repo.full_name,
    homepage: repo.html_url,
    description: repo.description ?? "",
    defaultBranch: repo.default_branch ?? "main",
    stars: repo.stargazers_count ?? 0,
    language: repo.language ?? "unknown",
    downloadZipUrl: `${repo.html_url}/archive/refs/heads/${repo.default_branch ?? "main"}.zip`,
    downloadTarUrl: `${repo.html_url}/archive/refs/heads/${repo.default_branch ?? "main"}.tar.gz`,
    cloneUrl: repo.clone_url,
    topics: repo.topics ?? [],
    rationale: [
      `Matched query: ${query}`,
      `Repository language: ${repo.language ?? "unknown"}`,
      `Stars: ${repo.stargazers_count ?? 0}`
    ],
    createdAt: new Date().toISOString()
  };
}

function candidateScore(repo, query) {
  const normalizedQuery = sanitizeQuery(query).toLowerCase();
  const name = `${repo.name ?? ""}`.toLowerCase();
  const fullName = `${repo.full_name ?? ""}`.toLowerCase();
  const description = `${repo.description ?? ""}`.toLowerCase();
  const topics = (repo.topics ?? []).map((item) => `${item}`.toLowerCase());

  let score = repo.stargazers_count ?? 0;

  if (name === normalizedQuery) {
    score += 500000;
  }
  if (fullName.includes(`/${normalizedQuery}`) || fullName.startsWith(`${normalizedQuery}/`)) {
    score += 250000;
  }
  if (topics.includes(normalizedQuery)) {
    score += 150000;
  }
  if (description.includes(normalizedQuery)) {
    score += 20000;
  }
  if (fullName.includes("awesome") || name.includes("awesome")) {
    score -= 400000;
  }
  if (fullName.includes("public-apis") || fullName.includes("developer-roadmap")) {
    score -= 250000;
  }

  return score;
}

function buildQueries({ asset, customQuery }) {
  const queries = [];
  const normalizedCustom = sanitizeQuery(customQuery);
  if (normalizedCustom) {
    queries.push(normalizedCustom);
  }

  if (asset?.fingerprint?.platform && asset.fingerprint.platform !== "generic-web") {
    queries.push(asset.fingerprint.platform);
  }

  if (asset?.name) {
    queries.push(asset.name);
  }

  return [...new Set(queries.map((item) => sanitizeQuery(item)).filter(Boolean))];
}

async function searchGithubRepositories(rawQuery) {
  const query = sanitizeQuery(rawQuery);
  const searchVariants = [`"${query}" in:name`, `topic:${query}`];
  const allItems = [];

  for (const variant of searchVariants) {
    const url = new URL("https://api.github.com/search/repositories");
    url.searchParams.set("q", variant);
    url.searchParams.set("sort", "stars");
    url.searchParams.set("order", "desc");
    url.searchParams.set("per_page", "5");

    const response = await fetch(url, {
      headers: {
        Accept: "application/vnd.github+json",
        "User-Agent": "universal-engine"
      }
    });

    if (!response.ok) {
      throw new Error(`GitHub search failed with status ${response.status}`);
    }

    const payload = await response.json();
    allItems.push(...(payload.items ?? []));
  }

  const deduped = [];
  const seen = new Set();
  for (const repo of allItems) {
    if (seen.has(repo.full_name)) {
      continue;
    }

    seen.add(repo.full_name);
    deduped.push(repo);
  }

  return deduped;
}

export async function locateUpstreamSources({ asset, customQuery }) {
  const queries = buildQueries({ asset, customQuery });
  if (!queries.length) {
    return {
      query: "",
      candidates: [],
      message: "No usable query could be built from the asset fingerprint."
    };
  }

  const combined = [];
  for (const query of queries) {
    const repos = await searchGithubRepositories(query);
    combined.push(...repos.map((repo) => repoToCandidate(repo, query, asset)));
  }

  const deduped = [];
  const seen = new Set();
  for (const item of combined) {
    if (seen.has(item.name)) {
      continue;
    }

    seen.add(item.name);
    deduped.push(item);
  }

  deduped.sort((left, right) => {
    const leftScore = candidateScore(
      {
        name: left.name.split("/").at(-1),
        full_name: left.name,
        description: left.description,
        stargazers_count: left.stars,
        topics: left.topics
      },
      left.query
    );
    const rightScore = candidateScore(
      {
        name: right.name.split("/").at(-1),
        full_name: right.name,
        description: right.description,
        stargazers_count: right.stars,
        topics: right.topics
      },
      right.query
    );
    return rightScore - leftScore;
  });

  return {
    query: queries[0],
    queries,
    candidates: deduped.slice(0, 8),
    message: deduped.length ? "Upstream candidates located." : "No upstream repository candidates found."
  };
}
