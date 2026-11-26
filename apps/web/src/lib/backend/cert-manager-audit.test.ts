// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

jest.mock("@/lib/api", () => {
  const actual = jest.requireActual("@/lib/api");
  return { ...actual, apiClient: { get: jest.fn() } };
});

import { AxiosError, AxiosHeaders } from "axios";

import { apiClient } from "@/lib/api";
import { isAuditTrailUnavailable } from "@/lib/backend/audit-trail";
import {
  EXPORT_ENDED_EARLY,
  auditFilterParams,
  readCsvRows,
  exportAuditAccessLog,
  exportAuditLogs,
  getAuditAccessActivities,
  getAuditAccessLog,
  getAuditLogs,
  getAuditOptions,
  retryAfterSeconds,
} from "@/lib/backend/cert-manager-audit";
import {
  CERT_MANAGER_AUDIT_CATEGORIES,
  CERT_MANAGER_AUDIT_GOLDEN_PAGE,
  certManagerAuditEntry,
  certManagerAuditPage,
} from "@/test/fixtures/cert-manager-audit";

const mockedGet = (apiClient as unknown as { get: jest.Mock }).get;

const httpError = (
  status: number,
  data: unknown = {},
  headers: Record<string, string> = {},
): AxiosError =>
  new AxiosError("Request failed", "ERR_BAD_REQUEST", undefined, undefined, {
    status,
    statusText: "",
    data,
    headers,
    config: { headers: new AxiosHeaders() },
  });

const blobOf = (body: unknown) =>
  new Blob([JSON.stringify(body)], { type: "application/json" });

beforeEach(() => {
  mockedGet.mockReset();
});

describe("getAuditLogs", () => {
  it("reads cert-manager's golden page, every new field included", async () => {
    mockedGet.mockResolvedValue({ data: CERT_MANAGER_AUDIT_GOLDEN_PAGE });

    const page = await getAuditLogs({ filters: {}, platform: false, size: 4 });

    expect(mockedGet).toHaveBeenCalledWith("/api/v1/audit-logs", {
      params: { size: 4 },
    });
    expect(page.totalElements).toBe(57);
    expect(page.totalCapped).toBe(false);
    expect(page.nextCursor).toBe(CERT_MANAGER_AUDIT_GOLDEN_PAGE.nextCursor);
    expect(page.visibleFrom).toBe("2026-07-09T12:00:00Z");
    const [deleted, roles, locked, refused] = page.content;
    expect(deleted).toMatchObject({
      summary: "Deleted the Azure credential 'prod-dns'",
      actorName: "Alice Admin",
      category: "CREDENTIALS",
      resourceRef: "cred_8f2k",
      userAgent: "Mozilla/5.0",
      featureOff: true,
      requestId: "req-4",
      attributes: { credentialType: "DNS" },
    });
    expect(roles.changes).toEqual([
      { field: "roles", before: "VIEWER", after: "ADMIN" },
    ]);
    expect(locked).toMatchObject({
      actorType: "SYSTEM",
      actorName: "CertPing (automatic)",
      correlationId: "corr-2",
    });
    expect(refused).toMatchObject({
      status: "FAILURE",
      errorCode: "PERMISSION_DENIED",
      reason: "You don't have permission to do this.",
      featureOff: true,
    });
  });

  it("reads a change whose sides were not recorded as null", async () => {
    mockedGet.mockResolvedValue({
      data: certManagerAuditPage([
        certManagerAuditEntry(9003, {
          changes: [{ field: "secret", before: null, after: null }],
          requestedByName: "Bob Builder",
        }),
      ]),
    });

    const page = await getAuditLogs({ filters: {}, platform: false, size: 25 });

    expect(page.content[0].changes).toEqual([
      { field: "secret", before: null, after: null },
    ]);
    expect(page.content[0].requestedByName).toBe("Bob Builder");
  });

  it("sends the filters, the size (at most 100) and the cursor", async () => {
    mockedGet.mockResolvedValue({ data: certManagerAuditPage([]) });

    await getAuditLogs({
      filters: {
        userId: "42",
        category: "CREDENTIALS",
        status: "FAILURE",
        requestId: " req-1 ",
        from: "2026-09-01T00:00:00.000Z",
        to: "2026-09-30T23:59:59.999Z",
        organizationId: "9",
        visibility: "INTERNAL",
      },
      platform: false,
      size: 250,
      cursor: "c2",
    });

    expect(mockedGet).toHaveBeenCalledWith("/api/v1/audit-logs", {
      params: {
        userId: "42",
        category: "CREDENTIALS",
        status: "FAILURE",
        requestId: "req-1",
        from: "2026-09-01T00:00:00.000Z",
        to: "2026-09-30T23:59:59.999Z",
        size: 100,
        cursor: "c2",
      },
    });
  });

  it("turns a date preset into a start relative to now", () => {
    const now = Date.parse("2026-10-10T12:00:00.000Z");

    expect(
      auditFilterParams(
        { range: "7d", from: "2026-01-01T00:00:00Z", actorType: "SYSTEM" },
        false,
        now,
      ),
    ).toEqual({ actorType: "SYSTEM", from: "2026-10-03T12:00:00.000Z" });
    expect(auditFilterParams({ range: "24h" }, false, now)).toEqual({
      from: "2026-10-09T12:00:00.000Z",
    });
  });

  it("reads the platform route with the organization and visibility", async () => {
    mockedGet.mockResolvedValue({ data: certManagerAuditPage([]) });

    await getAuditLogs({
      filters: { organizationId: "9" },
      platform: true,
      size: 25,
    });

    expect(mockedGet).toHaveBeenCalledWith("/api/v1/admin/audit-logs", {
      params: { organizationId: "9", visibility: "CUSTOMER", size: 25 },
    });
  });

  it("reads a missing platform route as not available yet", async () => {
    mockedGet.mockRejectedValue(httpError(404));

    const error = await getAuditLogs({
      filters: {},
      platform: true,
      size: 25,
    }).catch((caught: unknown) => caught);

    expect(isAuditTrailUnavailable(error)).toBe(true);
    expect((error as Error).message).toMatch(/switch into an organization/i);
  });

  it("reads AUDIT_LOGS turned off (423) as not available", async () => {
    mockedGet.mockRejectedValue(httpError(423));

    const error = await getAuditLogs({
      filters: {},
      platform: false,
      size: 25,
    }).catch((caught: unknown) => caught);

    expect(isAuditTrailUnavailable(error)).toBe(true);
    expect((error as Error).message).toMatch(/turned off/);
  });

  it("passes any other failure on as it is", async () => {
    const failure = httpError(503, { code: "QUERY_TIMEOUT" });
    mockedGet.mockRejectedValue(failure);

    await expect(
      getAuditLogs({ filters: {}, platform: false, size: 25 }),
    ).rejects.toBe(failure);
  });

  it("refuses a response that is not a page", async () => {
    mockedGet.mockResolvedValue({ data: { nope: true } });

    await expect(
      getAuditLogs({ filters: {}, platform: false, size: 25 }),
    ).rejects.toThrow("Unexpected audit log response.");
  });
});

describe("getAuditOptions", () => {
  it("offers a customer only the categories that are on", async () => {
    mockedGet.mockResolvedValue({ data: CERT_MANAGER_AUDIT_CATEGORIES });

    await expect(getAuditOptions("categories", false)).resolves.toEqual([
      { value: "ACCESS_CONTROL", label: "Access control" },
      { value: "CREDENTIALS", label: "Credentials" },
    ]);
    expect(mockedGet).toHaveBeenCalledWith("/api/v1/audit-logs/categories");
  });

  it("offers a super admin every category, marking those that are off", async () => {
    mockedGet.mockResolvedValue({ data: CERT_MANAGER_AUDIT_CATEGORIES });

    const categories = await getAuditOptions("categories", true);

    expect(mockedGet).toHaveBeenCalledWith(
      "/api/v1/admin/audit-logs/categories",
    );
    expect(categories).toContainEqual({
      value: "DISCOVERY",
      label: "Discovery (feature off)",
    });
  });

  it("asks for the picked organization's flags on the platform view", async () => {
    mockedGet.mockResolvedValue({ data: CERT_MANAGER_AUDIT_CATEGORIES });

    await getAuditOptions("categories", true, { organizationId: " 7 " });
    await getAuditOptions("categories", false, { organizationId: "7" });

    expect(mockedGet).toHaveBeenNthCalledWith(
      1,
      "/api/v1/admin/audit-logs/categories",
      { params: { organizationId: "7" } },
    );
    // A customer's categories are their own organization's.
    expect(mockedGet).toHaveBeenNthCalledWith(
      2,
      "/api/v1/audit-logs/categories",
    );
  });

  it("offers the members after CertPing (automatic), by name", async () => {
    mockedGet.mockResolvedValue({
      data: [
        { id: 51, email: "bob@acme.test", displayName: "Bob Builder" },
        { id: 42, email: "alice@acme.test", displayName: " " },
      ],
    });

    await expect(getAuditOptions("members", false)).resolves.toEqual([
      { value: "SYSTEM", label: "CertPing (automatic)" },
      { value: "42", label: "alice@acme.test" },
      { value: "51", label: "Bob Builder" },
    ]);
    expect(mockedGet).toHaveBeenCalledWith("/api/v1/users/organization");
  });

  it("still offers CertPing (automatic) to one who may not list members", async () => {
    mockedGet.mockRejectedValue(httpError(403));

    await expect(getAuditOptions("members", false)).resolves.toEqual([
      { value: "SYSTEM", label: "CertPing (automatic)" },
    ]);
  });

  it("offers the organizations by name", async () => {
    mockedGet.mockResolvedValue({
      data: [
        { id: 9, name: "Zeta" },
        { id: 7, name: "Acme" },
      ],
    });

    await expect(getAuditOptions("organizations", true)).resolves.toEqual([
      { value: "7", label: "Acme" },
      { value: "9", label: "Zeta" },
    ]);
  });

  it("reads the action and resource codes of each route", async () => {
    mockedGet.mockResolvedValue({ data: ["DELETE"] });

    await getAuditOptions("actions", false);
    await getAuditOptions("resources", true);

    expect(mockedGet).toHaveBeenNthCalledWith(1, "/api/v1/audit-logs/actions");
    expect(mockedGet).toHaveBeenNthCalledWith(
      2,
      "/api/v1/admin/audit-logs/resources",
    );
  });

  it("offers nothing from a list the server does not serve yet", async () => {
    mockedGet.mockRejectedValue(httpError(404));

    await expect(getAuditOptions("categories", true)).resolves.toEqual([]);
  });
});

describe("exportAuditLogs", () => {
  beforeEach(() => {
    jest.useFakeTimers({ now: new Date("2026-10-10T08:00:00Z") });
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it("asks for the file in the format with the current filters", async () => {
    const blob = new Blob(["timestamp\n"], { type: "text/csv" });
    mockedGet.mockResolvedValue({ data: blob });

    await expect(
      exportAuditLogs(
        { category: "CREDENTIALS", status: "FAILURE" },
        "csv",
        false,
      ),
    ).resolves.toEqual({ blob, fileName: "certping-audit-log-2026-10-10.csv" });
    expect(mockedGet).toHaveBeenCalledWith("/api/v1/audit-logs/export", {
      params: { category: "CREDENTIALS", status: "FAILURE", format: "csv" },
      responseType: "blob",
    });
  });

  it("exports from the platform route for a super admin", async () => {
    mockedGet.mockResolvedValue({ data: new Blob(["[]"]) });

    await exportAuditLogs({ organizationId: "7" }, "json", true);

    expect(mockedGet).toHaveBeenCalledWith("/api/v1/admin/audit-logs/export", {
      params: { organizationId: "7", visibility: "CUSTOMER", format: "json" },
      responseType: "blob",
    });
  });

  it.each([
    ["EXPORT_TOO_LARGE", 400, /More than 10,000 entries match/],
    ["EXPORT_LIMIT", 429, /limit of 10 exports an hour/],
    ["QUERY_TIMEOUT", 503, /The export took too long/],
  ])(
    "says what to do when the export is refused with %s",
    async (code, status, words) => {
      mockedGet.mockRejectedValue(
        httpError(status, blobOf({ code, message: "server words" })),
      );

      await expect(exportAuditLogs({}, "csv", false)).rejects.toThrow(words);
    },
  );

  it.each([
    [
      "EXPORT_NOT_RECORDED",
      503,
      "Couldn't start the export. Try again in a moment.",
    ],
    [
      "EXPORT_BUSY",
      503,
      "Another export is running. Try again in a few seconds.",
    ],
    [
      "EXPORT_IN_PROGRESS",
      429,
      "Another export is running. Try again in a few seconds.",
    ],
  ])("explains %s", async (code, status, words) => {
    mockedGet.mockRejectedValue(httpError(status, blobOf({ code })));

    await expect(exportAuditLogs({}, "csv", false)).rejects.toThrow(words);
  });

  it.each([
    [
      "EXPORT_LIMIT",
      429,
      "1500",
      "You've reached the limit of 10 exports an hour. Try again in about 25 minutes.",
    ],
    [
      "EXPORT_BUSY",
      503,
      "5",
      "Another export is running. Try again in 5 seconds.",
    ],
    [
      "EXPORT_IN_PROGRESS",
      429,
      "60",
      "Another export is running. Try again in about 1 minute.",
    ],
  ])(
    "says when to retry %s from Retry-After",
    async (code, status, retryAfter, words) => {
      mockedGet.mockRejectedValue(
        httpError(status, blobOf({ code }), { "retry-after": retryAfter }),
      );

      await expect(exportAuditLogs({}, "csv", false)).rejects.toThrow(words);
    },
  );

  it("shows the server's words for a coded refusal it has no words of its own for", async () => {
    mockedGet.mockRejectedValue(
      httpError(
        409,
        blobOf({
          code: "EXPORT_SOMETHING_NEW",
          message: "Server's own words.",
        }),
      ),
    );

    await expect(exportAuditLogs({}, "csv", false)).rejects.toThrow(
      "Server's own words.",
    );
  });

  it.each([
    ["a proxy's HTML page", 502, new Blob(["<html>Bad gateway</html>"])],
    ["a raw error string", 504, blobOf({ error: "Gateway Timeout" })],
    [
      "words without a code",
      400,
      blobOf({ message: "from must not be after to" }),
    ],
    ["no body", 502, undefined],
  ])(
    "reads a failure with %s as a plain retry",
    async (_case, status, body) => {
      mockedGet.mockRejectedValue(httpError(status, body));

      const message = await exportAuditLogs({}, "csv", false).then(
        () => "exported",
        (caught: Error) => caught.message,
      );

      expect(message).toBe("Couldn't export the log. Try again.");
      expect(message).not.toMatch(/status code|Gateway|must not/);
    },
  );

  it("names the reference of a failure that has one", async () => {
    mockedGet.mockRejectedValue(
      httpError(502, undefined, { "x-correlation-id": "corr-abc123" }),
    );

    await expect(exportAuditLogs({}, "json", false)).rejects.toThrow(
      "Couldn't export the log. Try again. (Reference: corr-abc123)",
    );
  });

  it("says export is not available until the route exists", async () => {
    mockedGet.mockRejectedValue(httpError(404, blobOf({})));

    await expect(exportAuditLogs({}, "json", false)).rejects.toThrow(
      "Exporting the audit log isn't available yet.",
    );
  });
});

describe("an export cut short", () => {
  const csv = (rows: number) =>
    new Blob(
      [
        "timestamp,summary\r\n" +
          Array.from(
            { length: rows },
            (_, index) => `2026-10-07,"Row ${index}"\r\n`,
          ).join(""),
      ],
      { type: "text/csv" },
    );

  it("keeps a CSV with as many rows as the server counted", async () => {
    mockedGet.mockResolvedValue({
      data: csv(3),
      headers: { "x-audit-export-rows": "3" },
    });

    await expect(exportAuditLogs({}, "csv", false)).resolves.toMatchObject({
      fileName: expect.stringMatching(/\.csv$/),
    });
  });

  it("refuses a CSV with fewer rows than the server counted", async () => {
    mockedGet.mockResolvedValue({
      data: csv(2),
      headers: { "x-audit-export-rows": "3" },
    });

    await expect(exportAuditLogs({}, "csv", false)).rejects.toThrow(
      EXPORT_ENDED_EARLY,
    );
  });

  it("does not check a CSV whose count the browser cannot read", async () => {
    mockedGet.mockResolvedValue({ data: csv(2), headers: {} });

    await expect(exportAuditLogs({}, "csv", false)).resolves.toBeDefined();
  });

  it("refuses a JSON export that does not parse, or is short", async () => {
    mockedGet.mockResolvedValueOnce({
      data: new Blob(['[{"id":1},{"id":2}'], { type: "application/json" }),
      headers: {},
    });
    await expect(exportAuditLogs({}, "json", false)).rejects.toThrow(
      EXPORT_ENDED_EARLY,
    );

    mockedGet.mockResolvedValueOnce({
      data: new Blob(['[{"id":1}]']),
      headers: { "x-audit-export-rows": "2" },
    });
    await expect(exportAuditLogs({}, "json", false)).rejects.toThrow(
      EXPORT_ENDED_EARLY,
    );

    mockedGet.mockResolvedValueOnce({
      data: new Blob(['[{"id":1},{"id":2}]']),
      headers: { "x-audit-export-rows": "2" },
    });
    await expect(exportAuditLogs({}, "json", false)).resolves.toBeDefined();
  });

  it("reads a dropped connection or stream as an export that ended early", async () => {
    mockedGet.mockRejectedValueOnce(
      new AxiosError("Network Error", "ERR_NETWORK"),
    );
    await expect(exportAuditLogs({}, "csv", false)).rejects.toThrow(
      EXPORT_ENDED_EARLY,
    );

    // The body arrived but cannot be read through.
    const unreadable = new Blob(["x"]);
    unreadable.text = () => Promise.reject(new Error("stream reset"));
    mockedGet.mockResolvedValueOnce({
      data: unreadable,
      headers: { "x-audit-export-rows": "1" },
    });
    await expect(exportAuditLogs({}, "csv", false)).rejects.toThrow(
      EXPORT_ENDED_EARLY,
    );
  });

  it("checks the Access export too", async () => {
    mockedGet.mockResolvedValue({
      data: csv(1),
      headers: { "x-audit-export-rows": "4" },
    });

    await expect(exportAuditAccessLog({}, "csv")).rejects.toThrow(
      EXPORT_ENDED_EARLY,
    );
  });

  it("counts CSV rows, line breaks inside quotes included", () => {
    expect(readCsvRows('a,b\r\n1,"two\r\nlines"\r\n2,x\r\n')).toEqual({
      rows: 2,
      complete: true,
    });
    expect(readCsvRows('a,b\r\n1,"say ""hi"""\r\n')).toEqual({
      rows: 1,
      complete: true,
    });
    expect(readCsvRows("a,b\r\n")).toEqual({ rows: 0, complete: true });
    expect(readCsvRows("a,b\r\n2,x")).toEqual({ rows: 0, complete: false });
    expect(readCsvRows('a,b\r\n2,"cut\r\n')).toEqual({
      rows: 0,
      complete: false,
    });
  });

  it.each([
    [
      "mid-way through its last row",
      "timestamp,summary\r\n2026-10-07,a\r\n2026-10-07,b",
    ],
    [
      "inside a final quoted field",
      'timestamp,summary\r\n2026-10-07,a\r\n2026-10-07,"line one\r\nline',
    ],
    [
      "inside a quoted field that ends with a line break",
      'timestamp,summary\r\n2026-10-07,a\r\n2026-10-07,"cut here\r\n',
    ],
  ])(
    "refuses a CSV cut %s (the old line count would have matched)",
    async (_cut, body) => {
      mockedGet.mockResolvedValue({
        data: new Blob([body], { type: "text/csv" }),
        headers: { "x-audit-export-rows": "2" },
      });

      await expect(exportAuditLogs({}, "csv", false)).rejects.toThrow(
        EXPORT_ENDED_EARLY,
      );
    },
  );

  it("keeps a complete CSV whose last field is quoted across lines", async () => {
    mockedGet.mockResolvedValue({
      data: new Blob(
        ['timestamp,summary\r\n2026-10-07,a\r\n2026-10-07,"two\r\nlines"\r\n'],
        { type: "text/csv" },
      ),
      headers: { "x-audit-export-rows": "2" },
    });

    await expect(exportAuditLogs({}, "csv", false)).resolves.toBeDefined();
  });

  it("reads Retry-After as seconds or a date", () => {
    const now = Date.parse("2026-10-10T08:00:00Z");
    expect(retryAfterSeconds("120", now)).toBe(120);
    expect(retryAfterSeconds("Sat, 10 Oct 2026 08:01:30 GMT", now)).toBe(90);
    expect(retryAfterSeconds("soon", now)).toBeUndefined();
    expect(retryAfterSeconds(undefined, now)).toBeUndefined();
  });
});

describe("the Access log", () => {
  it("reads the domains-shaped Access entry", async () => {
    mockedGet.mockResolvedValue({
      data: {
        content: [
          {
            id: 1,
            timestamp: "2026-10-07T10:00:00Z",
            activity: "access.private_key_downloaded",
            target: "www.acme.test",
            status: "SUCCESS",
            actor: "alice@acme.test",
            userId: 42,
            requestId: "req-9",
          },
        ],
        totalElements: 1,
        totalPages: 1,
        totalElementsCapped: false,
        nextCursor: null,
      },
    });

    const page = await getAuditAccessLog({
      filters: { userId: "42" },
      size: 25,
    });

    expect(mockedGet).toHaveBeenCalledWith("/api/v1/audit-logs/access", {
      params: { userId: "42", size: 25 },
    });
    expect(page.content[0]).toMatchObject({
      activity: "access.private_key_downloaded",
      target: "www.acme.test",
      actor: "alice@acme.test",
    });
  });

  it("reads an Access entry in the activity shape too", async () => {
    mockedGet.mockResolvedValue({
      data: certManagerAuditPage([
        certManagerAuditEntry(9004, {
          event: "access.audit_log_exported",
          resourceName: "audit log",
        }),
      ]),
    });

    const page = await getAuditAccessLog({ filters: {}, size: 25 });

    expect(page.content[0]).toMatchObject({
      activity: "access.audit_log_exported",
      target: "audit log",
      actor: "Alice Admin",
      requestId: "req-4",
    });
  });

  it("reads missing Access routes as not available", async () => {
    mockedGet.mockRejectedValue(httpError(404));

    const list = await getAuditAccessLog({ filters: {}, size: 25 }).catch(
      (caught: unknown) => caught,
    );
    const activities = await getAuditAccessActivities().catch(
      (caught: unknown) => caught,
    );

    expect(isAuditTrailUnavailable(list)).toBe(true);
    expect(isAuditTrailUnavailable(activities)).toBe(true);
  });

  it("lists the activities and exports the reads", async () => {
    mockedGet.mockResolvedValueOnce({ data: ["access.audit_log_viewed"] });
    await expect(getAuditAccessActivities()).resolves.toEqual([
      "access.audit_log_viewed",
    ]);

    mockedGet.mockResolvedValueOnce({ data: new Blob(["x"]) });
    const file = await exportAuditAccessLog({ status: "FAILURE" }, "csv");

    expect(file.fileName).toMatch(/^certping-access-log-.*\.csv$/);
    expect(mockedGet).toHaveBeenLastCalledWith(
      "/api/v1/audit-logs/access/export",
      { params: { status: "FAILURE", format: "csv" }, responseType: "blob" },
    );
  });
});
