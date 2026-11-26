// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  type ComponentStatus,
  fetchStatus,
  overallOf,
  parseSummary,
  STATUS_TIMEOUT_MS,
  type StatusReport,
} from "@/lib/public-status";
import { STATUS_SOURCES, type StatusSource } from "@/lib/status-sources";

const [platform] = STATUS_SOURCES;
const BASE = "https://api.certping.test";

/**
 * A second source that only these tests know about, so the aggregation
 * across sources stays covered now that the product ships with one.
 */
const search: StatusSource = {
  id: "search",
  path: "/api/v1/public/search-status",
  components: [{ id: "search", name: "Search" }],
};
const BOTH: readonly StatusSource[] = [platform, search];

function summary(components: { id: string; name?: string; status: string }[]) {
  return {
    page: { updated_at: "2026-10-16T12:00:00Z" },
    status: { indicator: "none", description: "All systems operational" },
    components: components.map((c) => ({
      name: c.id,
      updated_at: "2026-10-16T12:00:00Z",
      ...c,
    })),
    incidents: [],
    scheduled_maintenances: [],
  };
}

const ok = (body: unknown) => ({ json: async () => body, status: 200 });

const platformOperational = ok(
  summary([
    { id: "api", status: "operational" },
    { id: "notifications", status: "operational" },
    { id: "certificates", status: "operational" },
  ]),
);

const allOperational = {
  [`${BASE}${platform.path}`]: platformOperational,
  [`${BASE}${search.path}`]: ok(
    summary([{ id: "search", status: "operational" }]),
  ),
};

function answer(responses: Record<string, unknown>) {
  return jest.spyOn(global, "fetch").mockImplementation(async (input) => {
    const response = responses[String(input)];
    if (response instanceof Error) throw response;
    return response as Response;
  });
}

const states = (components: ComponentStatus[]) =>
  Object.fromEntries(components.map((c) => [c.id, c.state]));

describe("STATUS_SOURCES", () => {
  it("reads one platform source with the three remaining services", () => {
    expect(STATUS_SOURCES).toHaveLength(1);
    expect(platform.id).toBe("platform");
    expect(platform.path).toBe("/api/v1/public/status");
    expect(platform.components.map((c) => c.id)).toEqual([
      "api",
      "notifications",
      "certificates",
    ]);
  });
});

describe("parseSummary", () => {
  it("gives the expected components their public names and reported states", () => {
    expect(
      parseSummary(
        summary([
          { id: "api", name: "cert-manager", status: "degraded_performance" },
          { id: "notifications", status: "major_outage" },
          { id: "certificates", status: "partial_outage" },
        ]),
        platform,
      ),
    ).toEqual([
      { id: "api", name: "API and sign-in", state: "degraded_performance" },
      {
        id: "notifications",
        name: "Email notifications",
        state: "major_outage",
      },
      {
        id: "certificates",
        name: "Certificate issuance and renewal",
        state: "partial_outage",
      },
    ]);
  });

  it("reads an unknown status and a missing component as unknown", () => {
    expect(
      states(
        parseSummary(
          summary([
            { id: "api", status: "investigating" },
            { id: "notifications", status: "operational" },
          ]),
          platform,
        ) ?? [],
      ),
    ).toEqual({
      api: "unknown",
      certificates: "unknown",
      notifications: "operational",
    });
  });

  it("leaves out email notifications when the server does not report them (no mail server)", async () => {
    answer({
      [`${BASE}${platform.path}`]: ok(
        summary([
          { id: "api", status: "operational" },
          { id: "certificates", status: "operational" },
        ]),
      ),
    });

    const report = await fetchStatus(BASE);

    expect(report.components.map((c) => c.id)).toEqual(["api", "certificates"]);
    expect(overallOf(report)).toBe("operational");
  });

  it("counts an unknown status from a source it reached as degraded, not unreachable", async () => {
    answer({
      [`${BASE}${platform.path}`]: ok(
        summary([
          { id: "api", status: "operational" },
          { id: "notifications", status: "investigating" },
          { id: "certificates", status: "operational" },
        ]),
      ),
    });

    const report = await fetchStatus(BASE);

    expect(report.reachedEverySource).toBe(true);
    expect(states(report.components).notifications).toBe("unknown");
    expect(overallOf(report)).toBe("degraded");
  });

  it("shows a component it does not expect under the name the document gives", () => {
    const parsed = parseSummary(
      summary([
        { id: "api", status: "operational" },
        { id: "notifications", status: "operational" },
        { id: "certificates", status: "operational" },
        { id: "search", name: "<b>Search</b>", status: "partial_outage" },
      ]),
      platform,
    );
    expect(parsed).toHaveLength(4);
    expect(parsed?.[3]).toEqual({
      id: "search",
      name: "<b>Search</b>",
      state: "partial_outage",
    });
  });

  it.each([
    ["no body", null],
    ["a string", "operational"],
    ["no components", { status: { indicator: "none" } }],
    ["components that are not a list", { components: {} }],
    [
      "a component without a status",
      { components: [{ id: "api", name: "API" }] },
    ],
  ])("refuses %s", (_case, body) => {
    expect(parseSummary(body, platform)).toBeUndefined();
  });
});

describe("fetchStatus", () => {
  it("reads the platform source with no credentials and no headers", async () => {
    const fetchMock = answer(allOperational);

    const report = await fetchStatus(`${BASE}/`);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe(`${BASE}${platform.path}`);
    expect(init?.credentials).toBe("omit");
    expect(init?.headers).toBeUndefined();
    expect(init?.signal).toBeInstanceOf(AbortSignal);
    expect(states(report.components)).toEqual({
      api: "operational",
      certificates: "operational",
      notifications: "operational",
    });
    expect(report.reachedEverySource).toBe(true);
    expect(overallOf(report)).toBe("operational");
  });

  it("reads every source at once and merges their components", async () => {
    const fetchMock = answer(allOperational);

    const report = await fetchStatus(BASE, undefined, BOTH);

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls.map(([url]) => String(url))).toEqual([
      `${BASE}${platform.path}`,
      `${BASE}${search.path}`,
    ]);
    expect(states(report.components)).toEqual({
      api: "operational",
      certificates: "operational",
      notifications: "operational",
      search: "operational",
    });
    expect(report.reachedEverySource).toBe(true);
    expect(overallOf(report)).toBe("operational");
  });

  it.each([
    ["a network failure", new TypeError("Failed to fetch")],
    ["a 503 before the first check", { json: async () => ({}), status: 503 }],
    [
      "a 404 while the endpoint is not deployed",
      { json: async () => ({}), status: 404 },
    ],
    [
      "a body that is not JSON",
      {
        json: async () => {
          throw new SyntaxError("Unexpected token <");
        },
        status: 200,
      },
    ],
    ["a body that is not a summary", ok({ ok: true })],
  ])(
    "shows the platform's components as not responding after %s",
    async (_case, failure) => {
      answer({ [`${BASE}${platform.path}`]: failure });

      const report = await fetchStatus(BASE);

      expect(states(report.components)).toEqual({
        api: "not_responding",
        certificates: "not_responding",
        notifications: "not_responding",
      });
      expect(report.reachedEverySource).toBe(false);
      expect(overallOf(report)).toBe("unreachable");
    },
  );

  it("marks only the failed source's components when another source answers", async () => {
    answer({
      ...allOperational,
      [`${BASE}${platform.path}`]: new TypeError("Failed to fetch"),
    });

    const report = await fetchStatus(BASE, undefined, BOTH);

    expect(states(report.components)).toEqual({
      api: "not_responding",
      certificates: "not_responding",
      notifications: "not_responding",
      search: "operational",
    });
    expect(report.reachedEverySource).toBe(false);
    expect(overallOf(report)).toBe("unreachable");
  });

  it("gives up on a source after the timeout", async () => {
    jest.useFakeTimers();
    const timeout = jest
      .spyOn(AbortSignal, "timeout")
      .mockImplementation((ms) => {
        const controller = new AbortController();
        setTimeout(
          () => controller.abort(new DOMException("timed out", "TimeoutError")),
          ms,
        );
        return controller.signal;
      });
    try {
      jest.spyOn(global, "fetch").mockImplementation((input, init) =>
        String(input).endsWith(search.path)
          ? Promise.resolve(allOperational[`${BASE}${search.path}`] as Response)
          : new Promise((_resolve, reject) => {
              init?.signal?.addEventListener("abort", () =>
                reject(new DOMException("timed out", "TimeoutError")),
              );
            }),
      );
      const pending = fetchStatus(BASE, undefined, BOTH);
      await jest.advanceTimersByTimeAsync(STATUS_TIMEOUT_MS);
      const report = await pending;

      expect(timeout).toHaveBeenCalledWith(STATUS_TIMEOUT_MS);
      expect(STATUS_TIMEOUT_MS).toBe(8000);
      expect(states(report.components).api).toBe("not_responding");
      expect(states(report.components).search).toBe("operational");
    } finally {
      jest.useRealTimers();
    }
  });

  it("reaches nothing without an API address", async () => {
    const fetchMock = jest.spyOn(global, "fetch");

    const report = await fetchStatus("");

    expect(fetchMock).not.toHaveBeenCalled();
    expect(report.components.map((c) => c.id)).toEqual([
      "api",
      "notifications",
      "certificates",
    ]);
    expect(report.components.every((c) => c.state === "not_responding")).toBe(
      true,
    );
  });
});

describe("overallOf", () => {
  const report = (
    reached: boolean,
    ...list: ComponentStatus["state"][]
  ): StatusReport => ({
    checkedAt: new Date(),
    components: list.map((state, i) => ({ id: `c${i}`, name: `C${i}`, state })),
    reachedEverySource: reached,
  });

  it.each([
    [report(true, "operational", "operational"), "operational"],
    [report(true, "operational", "degraded_performance"), "degraded"],
    [report(true, "under_maintenance", "operational"), "maintenance"],
    [report(true, "under_maintenance", "degraded_performance"), "maintenance"],
    [report(true, "unknown", "operational"), "degraded"],
    [report(true, "under_maintenance", "not_responding"), "unreachable"],
    [report(true, "under_maintenance", "major_outage"), "down"],
    [report(true, "partial_outage", "degraded_performance"), "down"],
    [report(true, "major_outage", "operational"), "down"],
    [report(true, "not_responding", "operational"), "unreachable"],
    [report(false, "operational", "operational"), "unreachable"],
    [report(false, "major_outage", "not_responding"), "down"],
  ])("%#: %j is %s", (given, want) => {
    expect(overallOf(given)).toBe(want);
  });
});
