// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { AppSearchItem } from "@/lib/app-search-types";

const normalizeSearchText = (value: string): string =>
  value.toLocaleLowerCase().trim().replace(/\s+/g, " ");

const getEditDistance = (left: string, right: string): number => {
  const previousRow = Array.from(
    { length: right.length + 1 },
    (_, index) => index,
  );

  for (let leftIndex = 1; leftIndex <= left.length; leftIndex += 1) {
    let diagonal = previousRow[0];
    previousRow[0] = leftIndex;

    for (let rightIndex = 1; rightIndex <= right.length; rightIndex += 1) {
      const above = previousRow[rightIndex];
      const substitutionCost =
        left[leftIndex - 1] === right[rightIndex - 1] ? 0 : 1;
      previousRow[rightIndex] = Math.min(
        previousRow[rightIndex] + 1,
        previousRow[rightIndex - 1] + 1,
        diagonal + substitutionCost,
      );
      diagonal = above;
    }
  }

  return previousRow[right.length];
};

const getFuzzyWordScore = (text: string, query: string): number => {
  if (query.length < 4 || query.includes(" ")) {
    return 0;
  }

  const maximumDistance = query.length >= 8 ? 2 : 1;
  const closestDistance = Math.min(
    ...text.split(/[^a-z0-9]+/).map((word) => getEditDistance(word, query)),
  );

  return closestDistance <= maximumDistance ? 300 - closestDistance : 0;
};

const getTextScore = (
  text: string,
  query: string,
  allowFuzzy = true,
): number => {
  const normalizedText = normalizeSearchText(text);
  if (normalizedText === query) return 1_000;
  if (normalizedText.startsWith(query)) return 900;
  if (normalizedText.split(/[^a-z0-9]+/).some((word) => word === query)) {
    return 850;
  }
  if (normalizedText.includes(query)) return 800;
  if (
    normalizedText.split(/[^a-z0-9]+/).some((word) => word.startsWith(query))
  ) {
    return 750;
  }
  return allowFuzzy ? getFuzzyWordScore(normalizedText, query) : 0;
};

const getItemScore = (item: AppSearchItem, query: string): number => {
  const titleScore = getTextScore(item.title, query);
  const keywordScore = Math.max(
    0,
    ...item.keywords.map((keyword) => getTextScore(keyword, query) - 200),
  );
  const descriptionScore = getTextScore(item.description, query, false) - 400;
  const hrefScore = getTextScore(item.href, query, false) - 500;
  return Math.max(titleScore, keywordScore, descriptionScore, hrefScore, 0);
};

export function rankAppSearchItems(
  items: readonly AppSearchItem[],
  query: string,
): AppSearchItem[] {
  const normalizedQuery = normalizeSearchText(query);
  if (!normalizedQuery) return [...items];

  return items
    .map((item, index) => ({
      index,
      item,
      score: getItemScore(item, normalizedQuery),
    }))
    .filter(({ score }) => score > 0)
    .sort((left, right) => right.score - left.score || left.index - right.index)
    .map(({ item }) => item);
}
