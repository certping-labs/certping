// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { fuzzySearch } from "@/lib/fuzzy-search";

type TestItem = {
  id: string;
  name?: string;
  url?: string;
  nested?: { value?: string; tags?: string[] };
  enabled?: boolean;
  meta?: unknown;
};

describe("fuzzySearch", () => {
  const items: TestItem[] = [
    {
      id: "1",
      name: "Alpha Service",
      url: "https://alpha.example.com/path",
      nested: { value: "prod-west", tags: ["api", "core"] },
      enabled: true,
    },
    {
      id: "2",
      name: "Beta Gateway",
      url: "beta.example.com/edge",
      nested: { value: "staging-east", tags: ["edge"] },
      enabled: false,
    },
    {
      id: "3",
      name: "Gamma",
      url: "https://gamma.example.com",
      nested: { value: "qa", tags: ["batch"] },
      meta: new Date("2026-01-01T00:00:00Z"),
    },
  ];

  it("returns original dataset when term is empty", () => {
    expect(fuzzySearch("", items, ["name"])).toEqual(items);
  });

  it("throws when keys are empty", () => {
    expect(() => fuzzySearch("alpha", items, [])).toThrow(
      "Search keys must be provided",
    );
  });

  it("matches nested values and array indexes", () => {
    const result = fuzzySearch("core", items, ["nested.tags.1"], {
      threshold: 1,
    });
    expect(result).toHaveLength(1);
    expect(result[0]?.id).toBe("1");
  });

  it("does not allow prototype traversal in key path", () => {
    const result = fuzzySearch(
      "pollute",
      [{ id: "1", name: "safe" }],
      ["constructor.prototype.injected"],
    );
    expect(result).toEqual([]);
  });

  it("supports URL search scoring and ranks exact domain/path first", () => {
    const result = fuzzySearch(
      "https://alpha.example.com/path",
      items,
      ["url"],
      {
        threshold: 1,
      },
    );
    expect(result[0]?.id).toBe("1");
  });

  it("applies weighted scoring across fields", () => {
    const result = fuzzySearch(
      "gateway",
      [
        { id: "a", name: "Gateway", nested: { value: "low" } },
        { id: "b", name: "Other", nested: { value: "gateway" } },
      ],
      ["name", "nested.value"],
      { threshold: 1, weightedScoring: { name: 3, "nested.value": 1 } },
    );
    expect(result[0]?.id).toBe("a");
  });

  it("supports case sensitive mode", () => {
    const insensitive = fuzzySearch("alpha", items, ["name"], { threshold: 1 });
    const sensitive = fuzzySearch("alpha", items, ["name"], {
      threshold: 1,
      caseSensitive: true,
    });
    expect(insensitive.some((item) => item.id === "1")).toBe(true);
    expect(sensitive.some((item) => item.id === "1")).toBe(false);
  });

  it("handles non-string serializable values", () => {
    const result = fuzzySearch("2026-01-01", items, ["meta"], { threshold: 1 });
    expect(result[0]?.id).toBe("3");
  });
});
