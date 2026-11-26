// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

type SearchScore<T> = {
  item: T;
  score: number;
  matches: Array<{
    field: string;
    score: number;
  }>;
};

export interface FuzzySearchOptions {
  threshold?: number;
  weightedScoring?: Record<string, number>;
  caseSensitive?: boolean;
}

function toSearchableString(value: unknown): string {
  if (value == null) {
    return "";
  }

  if (
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean" ||
    typeof value === "bigint"
  ) {
    return String(value);
  }

  if (value instanceof Date) {
    return value.toISOString();
  }

  if (typeof value === "object") {
    try {
      return JSON.stringify(value);
    } catch {
      return "";
    }
  }

  return "";
}

function getNestedValue(obj: unknown, path: readonly string[]): string {
  let current: unknown = obj;
  const blockedKeys = new Set(["__proto__", "prototype", "constructor"]);

  for (const key of path) {
    if (current == null) {
      return "";
    }

    if (blockedKeys.has(key)) {
      return "";
    }

    const arrayIndex = Number(key);
    if (Array.isArray(current) && Number.isInteger(arrayIndex)) {
      current = current.at(arrayIndex);
      continue;
    }

    if (typeof current === "object") {
      if (!Object.prototype.hasOwnProperty.call(current, key)) {
        return "";
      }
      current = Reflect.get(current, key);
      continue;
    }

    return "";
  }

  return toSearchableString(current);
}

function isURL(value: string): boolean {
  return (
    /^https?:\/\/[^\s]+$/i.test(value) ||
    /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}(\/.*)?$/.test(
      value,
    )
  );
}

type UrlParts = {
  domain: string;
  path: string;
  full: string;
};

function parseURL(url: string): UrlParts {
  const withoutProtocol = url.replace(/^https?:\/\//, "");
  const parts = withoutProtocol.split("/");
  const domain = parts[0] ?? "";
  const path = parts.length > 1 ? parts.slice(1).join("/") : "";

  return { domain, path, full: url };
}

function calculateURLFuzzyScore(
  text: string,
  searchTerm: string,
  searchURLParts: UrlParts,
): number {
  if (!text || !searchTerm) {
    return 0;
  }

  if (isURL(text)) {
    const textURLParts = parseURL(text);

    if (textURLParts.full === searchURLParts.full) return 100;
    if (
      textURLParts.domain === searchURLParts.domain &&
      textURLParts.path === searchURLParts.path
    )
      return 95;
    if (textURLParts.domain === searchURLParts.domain) return 85;
    if (
      textURLParts.domain.includes(searchURLParts.domain) ||
      searchURLParts.domain.includes(textURLParts.domain)
    )
      return 70;
    if (searchURLParts.path && textURLParts.path.includes(searchURLParts.path))
      return 60;
  }

  if (text === searchTerm) {
    return 100;
  }

  let score = 0;
  if (text.includes(searchURLParts.domain)) score += 70;
  if (searchURLParts.path && text.includes(searchURLParts.path)) score += 50;
  if (text.includes("https://") && searchTerm.includes("https://")) score += 5;

  return Math.min(100, Math.max(0, score));
}

function calculateFuzzyScore(text: string, searchTerm: string): number {
  if (!text || !searchTerm) {
    return 0;
  }

  let score = 0;
  if (text === searchTerm) return 100;
  if (text.startsWith(searchTerm)) score += 80;
  if (text.includes(searchTerm)) score += 60;

  let textIndex = 0;
  let termIndex = 0;
  let lastMatchPos = -1;
  let consecutiveMatches = 0;
  const matchPositions: number[] = [];

  while (textIndex < text.length && termIndex < searchTerm.length) {
    if (text[textIndex] === searchTerm[termIndex]) {
      matchPositions.push(textIndex);
      score += 10;

      if (lastMatchPos === textIndex - 1) {
        consecutiveMatches++;
        score += consecutiveMatches * 5;
      } else {
        consecutiveMatches = 0;
      }

      score += Math.max(0, ((text.length - textIndex) / text.length) * 5);
      lastMatchPos = textIndex;
      termIndex++;
    }
    textIndex++;
  }

  if (termIndex < searchTerm.length) {
    score = Math.max(0, score - (searchTerm.length - termIndex) * 15);
  }

  const words = text.split(/[\s-_]+/);
  const firstLetters = words.map((word) => word[0]).join("");
  if (firstLetters.includes(searchTerm)) {
    score += 40;
  }

  const wordBoundaries = new Set<number>([
    0,
    ...text
      .split("")
      .map((char, index) => (/[A-Z\s-_]/.test(char) ? index : -1))
      .filter((index) => index !== -1),
  ]);
  const boundaryMatches = matchPositions.filter((pos) =>
    wordBoundaries.has(pos),
  );
  score += boundaryMatches.length * 10;

  return Math.min(100, Math.max(0, score));
}

export function fuzzySearch<T extends object>(
  term: string,
  data: readonly T[],
  keys: readonly string[] | string,
  options: FuzzySearchOptions = {},
): T[] {
  if (!term || data.length === 0) {
    return [...data];
  }

  const searchKeys = Array.isArray(keys) ? keys : [keys];
  if (searchKeys.length === 0) {
    throw new Error("Search keys must be provided");
  }

  const {
    threshold = 20,
    weightedScoring = {},
    caseSensitive = false,
  } = options;

  const searchTerm = caseSensitive ? term : term.toLowerCase();
  const searchIsURL = isURL(searchTerm);
  const searchURLParts = searchIsURL ? parseURL(searchTerm) : null;

  const results = data
    .map((item): SearchScore<T> => {
      const fieldMatches = searchKeys.map((key) => {
        const keyPath = key.split(".");
        const value = getNestedValue(item, keyPath);
        const fieldValue = caseSensitive ? value : value.toLowerCase();

        const score =
          searchIsURL && searchURLParts
            ? calculateURLFuzzyScore(fieldValue, searchTerm, searchURLParts)
            : calculateFuzzyScore(fieldValue, searchTerm);

        return {
          field: key,
          score: score * (weightedScoring[key] ?? 1),
        };
      });

      const totalScore = fieldMatches.reduce(
        (sum, match) => sum + match.score,
        0,
      );
      const maxPossibleScore = searchKeys.length * 100;
      const normalizedScore = (totalScore / maxPossibleScore) * 100;

      return { item, score: normalizedScore, matches: fieldMatches };
    })
    .filter((result) => result.score >= threshold)
    .sort((a, b) => b.score - a.score);

  return results.map((result) => result.item);
}
