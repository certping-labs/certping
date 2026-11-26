// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { toast } from "sonner";

import AuditLogsPage from "@/app/(main)/settings/audit-logs/page";
import { useAuth } from "@/hooks/use-auth";
import { saveBlob } from "@/lib/download";
import {
  CERT_MANAGER_AUDIT_GOLDEN_PAGE,
  certManagerAuditEntry,
  certManagerAuditPage,
} from "@/test/fixtures/cert-manager-audit";
import { certManagerAuditHandlers } from "@/test/msw/handlers";
import { server } from "@/test/msw/server";
import type { SsoUser } from "@/types/auth";

let mockSearch = "";
const mockReplace = jest.fn();

jest.mock("next/navigation", () => ({
  useRouter: () => ({ replace: mockReplace }),
  usePathname: () => "/settings/audit-logs",
  useSearchParams: () => new URLSearchParams(mockSearch),
}));
jest.mock("@/hooks/use-auth", () => ({ useAuth: jest.fn() }));
jest.mock("@/lib/download", () => ({ saveBlob: jest.fn() }));
jest.mock("sonner", () => ({
  toast: { error: jest.fn(), success: jest.fn(), dismiss: jest.fn() },
}));

const API = process.env.NEXT_PUBLIC_API_URL as string;

const orgAdmin: SsoUser = {
  id: "42",
  email: "alice@acme.test",
  organizationId: "7",
  organizationName: "Acme",
  roles: ["ORGANIZATION_ADMIN"],
  permissions: ["audit:view", "users:view"],
};

const superAdmin: SsoUser = {
  id: "1",
  email: "ops@certping.test",
  organizationId: null,
  organizationName: null,
  roles: ["SUPER_ADMIN"],
  permissions: ["audit:view"],
};

const signIn = (user: SsoUser, isSuperAdmin = false) =>
  (useAuth as jest.Mock).mockReturnValue({
    user,
    isSuperAdmin,
    isLoading: false,
  });

/** The list requests the page made, as their query parameters. */
const listRequests = (seen: URL[], path = "/api/v1/audit-logs") =>
  seen
    .filter((url) => url.pathname === path)
    .map((url) => Object.fromEntries(url.searchParams));

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <AuditLogsPage />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  mockSearch = "";
  mockReplace.mockReset();
  signIn(orgAdmin);
});

describe("Audit logs page", () => {
  it("shows each event as a sentence with who did it and how it ended", async () => {
    const seen: URL[] = [];
    // The tests' clock reads 2026-01-01T00:00:00Z (setup.node.ts).
    const [first, ...rest] = CERT_MANAGER_AUDIT_GOLDEN_PAGE.content;
    server.use(
      ...certManagerAuditHandlers({
        seen,
        page: {
          ...CERT_MANAGER_AUDIT_GOLDEN_PAGE,
          content: [{ ...first, timestamp: "2025-12-31T23:55:00Z" }, ...rest],
        },
      }),
    );

    renderPage();

    const table = await screen.findByRole("table");
    expect(screen.getByRole("heading", { name: "Audit logs" })).toBeVisible();
    expect(
      within(table)
        .getAllByRole("columnheader")
        .map((header) => header.textContent),
    ).toEqual(["Event", "Actor", "Result", "Request ID", "Time"]);

    const rows = within(table).getAllByRole("row").slice(1);
    const [deleted, , locked, refused] = rows;
    // A member, with the feature since turned off.
    expect(
      within(deleted).getByRole("button", {
        name: "Deleted the Azure credential 'prod-dns'",
      }),
    ).toBeInTheDocument();
    expect(within(deleted).getByText("Feature off")).toBeInTheDocument();
    expect(within(deleted).getByText("Credentials")).toBeInTheDocument();
    expect(within(deleted).getAllByText("Alice Admin").length).toBeGreaterThan(
      0,
    );
    expect(within(deleted).getByText("alice@acme.test")).toBeInTheDocument();
    expect(within(deleted).getByText("Succeeded")).toBeInTheDocument();
    expect(
      within(deleted).getByRole("button", { name: "Copy request ID req-4" }),
    ).toBeInTheDocument();
    const time = deleted.querySelector("time");
    expect(time).toHaveAttribute("dateTime", "2025-12-31T23:55:00Z");
    expect(time?.textContent).toBe("5 minutes ago");
    // The absolute time renders in the runner's zone: 23:55 UTC on 31 Dec is
    // still 2025 west of UTC and already 2026 east of it.
    expect(time?.nextElementSibling?.textContent).toMatch(
      /(Dec 31, 2025|Jan 1, 2026), \d+:\d{2}:00 [AP]M$/,
    );
    // CertPing acting by itself.
    expect(
      within(locked).getAllByText("CertPing (automatic)").length,
    ).toBeGreaterThan(0);
    // A failure, in words the customer can act on, and its code.
    expect(
      within(refused).getByText(
        /Failed: You don't have permission to do this./,
      ),
    ).toBeInTheDocument();
    expect(within(refused).getByText("PERMISSION_DENIED")).toBeInTheDocument();
    expect(within(refused).getByText("Failed")).toBeInTheDocument();
    expect(
      within(refused).getAllByText("Former member").length,
    ).toBeGreaterThan(0);

    expect(listRequests(seen)).toEqual([{ size: "25" }]);
  });

  it("names the member an automatic event acted for, and the platform administrator", async () => {
    server.use(
      ...certManagerAuditHandlers({
        page: certManagerAuditPage([
          certManagerAuditEntry(9002, {
            summary: "Renewed www.acme.test",
            requestedByName: "Bob Builder",
          }),
          certManagerAuditEntry(9004, {
            id: 9010,
            summary: "Viewed the audit log",
            actorType: "USER",
            actorName: "Platform administrator",
            userEmail: null,
            featureOff: false,
          }),
        ]),
      }),
    );

    renderPage();

    const table = await screen.findByRole("table");
    expect(within(table).getByText("requested by Bob Builder")).toBeVisible();
    expect(
      within(table).getAllByText("Platform administrator").length,
    ).toBeGreaterThan(0);
  });

  it("says how far back the log reaches and links to the docs", async () => {
    signIn({ ...orgAdmin, permissions: ["audit:view"] });
    server.use(...certManagerAuditHandlers());

    renderPage();

    const link = within(await screen.findByRole("note")).getByRole("link", {
      name: "Read the docs",
    });
    expect(link.getAttribute("href")).toBe(
      "https://github.com/certping-labs/certping/tree/main/docs",
    );
  });

  it("sends the URL's filters to cert-manager, a preset as a start time", async () => {
    mockSearch =
      "userId=51&category=CREDENTIALS&status=FAILURE&range=7d&requestId=req-1";
    const seen: URL[] = [];
    server.use(...certManagerAuditHandlers({ seen }));
    const before = Date.now();

    renderPage();
    await screen.findByRole("table");

    const [params] = listRequests(seen);
    expect(params).toMatchObject({
      userId: "51",
      category: "CREDENTIALS",
      status: "FAILURE",
      requestId: "req-1",
      size: "25",
    });
    const from = Date.parse(params.from);
    const weekMs = 7 * 24 * 60 * 60 * 1_000;
    expect(from).toBeGreaterThanOrEqual(before - weekMs - 1_000);
    expect(from).toBeLessThanOrEqual(Date.now() - weekMs + 1_000);
  });

  it("filters by CertPing (automatic), a member and a category", async () => {
    server.use(
      ...certManagerAuditHandlers({
        members: [
          { id: 51, email: "bob@acme.test", displayName: "Bob Builder" },
        ],
      }),
    );
    const user = userEvent.setup();

    renderPage();
    await screen.findByRole("table");

    await user.click(
      screen.getByRole("combobox", { name: "Filter by Member" }),
    );
    await user.click(
      await screen.findByRole("option", { name: "CertPing (automatic)" }),
    );
    expect(mockReplace).toHaveBeenLastCalledWith(
      "/settings/audit-logs?actorType=SYSTEM",
    );

    await user.click(
      screen.getByRole("combobox", { name: "Filter by Member" }),
    );
    await user.click(
      await screen.findByRole("option", { name: "Bob Builder" }),
    );
    expect(mockReplace).toHaveBeenLastCalledWith(
      "/settings/audit-logs?userId=51",
    );

    await user.click(
      screen.getByRole("combobox", { name: "Filter by Category" }),
    );
    // Discovery is off for the organization, so it is not offered.
    expect(
      screen.queryByRole("option", { name: /Discovery/ }),
    ).not.toBeInTheDocument();
    await user.click(
      await screen.findByRole("option", { name: "Credentials" }),
    );
    expect(mockReplace).toHaveBeenLastCalledWith(
      "/settings/audit-logs?category=CREDENTIALS",
    );

    await user.click(screen.getByRole("button", { name: /Filter by date/ }));
    await user.click(
      await screen.findByRole("button", { name: "Last 24 hours" }),
    );
    expect(mockReplace).toHaveBeenLastCalledWith(
      "/settings/audit-logs?range=24h",
    );
  });

  it("searches by request ID", async () => {
    server.use(...certManagerAuditHandlers());
    const user = userEvent.setup();

    renderPage();
    await screen.findByRole("table");
    await user.type(
      screen.getByRole("textbox", { name: "Request ID" }),
      "req-3{Enter}",
    );

    expect(mockReplace).toHaveBeenLastCalledWith(
      "/settings/audit-logs?requestId=req-3",
    );
  });

  it("keeps long ids and names inside their cells", async () => {
    const requestId = "req-http-f740c5eb-6e74-4dd4-a321-b3b48b1d6e69";
    server.use(
      ...certManagerAuditHandlers({
        page: certManagerAuditPage([
          certManagerAuditEntry(9004, {
            requestId,
            summary:
              "Deleted the DNS credential 'e2e-dns-namedotcom-1791625595397'",
            actorName: "a-very-long-member-name-without-any-spaces@acme.test",
          }),
        ]),
      }),
    );

    renderPage();

    const table = await screen.findByRole("table");
    // The sentence takes what the sized columns leave; it has no width.
    const eventHeader = within(table).getByRole("columnheader", {
      name: "Event",
    });
    expect(eventHeader.style.width).toBe("");
    expect(table).toHaveClass("table-fixed");
    const summary = within(table).getByRole("button", {
      name: /e2e-dns-namedotcom-1791625595397/,
    });
    expect(summary).toHaveClass("wrap-anywhere");
    // The id is shortened from the middle, whole on hover and when copied.
    const shown = within(table).getByText("req-http-f740…6e69");
    expect(shown).toHaveAttribute("title", requestId);
    expect(
      within(table).getByRole("button", {
        name: `Copy request ID ${requestId}`,
      }),
    ).toBeInTheDocument();
    const actor = within(table).getAllByTitle(
      "a-very-long-member-name-without-any-spaces@acme.test",
    )[0];
    expect(actor).toHaveClass("truncate");
  });

  it("wraps long ids inside the details dialog, each across both columns", async () => {
    const requestId = "req-http-f740c5eb-6e74-4dd4-a321-b3b48b1d6e69";
    const correlationId = "corr-75e60aaf-e053-4dc5-8032-89314153c226";
    server.use(
      ...certManagerAuditHandlers({
        page: certManagerAuditPage([
          certManagerAuditEntry(9004, {
            requestId,
            correlationId,
            resourceName: "e2e-dns-namedotcom-1791625595397",
          }),
        ]),
      }),
    );
    const user = userEvent.setup();

    renderPage();
    await user.click(
      await screen.findByRole("button", {
        name: "Deleted the Azure credential 'prod-dns'",
      }),
    );

    const dialog = await screen.findByRole("dialog");
    for (const [label, value] of [
      ["Request ID", requestId],
      ["Correlation ID", correlationId],
    ]) {
      const field = within(dialog).getByText(label).parentElement!;
      expect(field).toHaveClass("min-w-0", "sm:col-span-2");
      expect(within(field).getByText(value)).toHaveClass("break-all");
    }
    // Every field of the grid may shrink to its track.
    for (const term of within(dialog).getAllByRole("term")) {
      expect(term.parentElement).toHaveClass("min-w-0");
    }
    const resource = within(dialog).getByText("Resource").parentElement!;
    expect(
      within(resource)
        .getByText("e2e-dns-namedotcom-1791625595397")
        .closest("dd"),
    ).toHaveClass("break-all");
    expect(within(resource).getByText("Credential · cred_8f2k")).toBeVisible();
  });

  it("shows how a member signed in, and no empty resource", async () => {
    server.use(
      ...certManagerAuditHandlers({
        page: certManagerAuditPage([
          certManagerAuditEntry(9004, {
            id: 9020,
            event: "auth.signed_in",
            action: "SIGN_IN",
            resource: "AUTH",
            resourceName: null,
            resourceRef: null,
            summary: "Signed in with a password",
            category: "AUTHENTICATION",
            featureOff: false,
            details: '{"attributes":{"method":"PASSWORD"}}',
          }),
          certManagerAuditEntry(9004, {
            id: 9021,
            event: "auth.signed_out",
            action: "SIGN_OUT",
            resource: "AUTH",
            resourceName: null,
            resourceRef: null,
            summary: "Signed out",
            category: "AUTHENTICATION",
            featureOff: false,
            details: null,
          }),
        ]),
      }),
    );
    const user = userEvent.setup();

    renderPage();
    await user.click(
      await screen.findByRole("button", { name: "Signed in with a password" }),
    );

    let dialog = await screen.findByRole("dialog");
    expect(
      within(dialog).getByText("Sign-in method").nextSibling,
    ).toHaveTextContent("Password");
    expect(within(dialog).queryByText("Auth")).not.toBeInTheDocument();
    expect(within(dialog).queryByText("Resource")).not.toBeInTheDocument();
    expect(within(dialog).queryByText("None")).not.toBeInTheDocument();

    await user.keyboard("{Escape}");
    await user.click(await screen.findByRole("button", { name: "Signed out" }));
    dialog = await screen.findByRole("dialog");
    expect(
      within(dialog).queryByText("Sign-in method"),
    ).not.toBeInTheDocument();
    expect(within(dialog).queryByText("Auth")).not.toBeInTheDocument();
  });

  it("opens an event's details: changes, address, browser and ids", async () => {
    server.use(
      ...certManagerAuditHandlers({
        page: certManagerAuditPage([
          certManagerAuditEntry(9003, {
            userAgent:
              "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
            correlationId: "corr-3",
            changes: [
              { field: "roles", before: "VIEWER", after: "ADMIN" },
              { field: "secret", before: null, after: null },
            ],
          }),
        ]),
      }),
    );
    const user = userEvent.setup();

    renderPage();
    await user.click(
      await screen.findByRole("button", {
        name: "Changed Bob Builder's roles",
      }),
    );

    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("203.0.113.7")).toBeInTheDocument();
    expect(within(dialog).getByText("Chrome 129 on macOS")).toBeInTheDocument();
    expect(within(dialog).getByText("Access control")).toBeInTheDocument();
    expect(within(dialog).getByText("Bob Builder")).toBeInTheDocument();
    expect(
      within(dialog).getByRole("button", { name: "Copy request ID req-3" }),
    ).toBeInTheDocument();
    expect(
      within(dialog).getByRole("button", {
        name: "Copy correlation ID corr-3",
      }),
    ).toBeInTheDocument();
    const changes = within(dialog).getByRole("table");
    expect(within(changes).getByText("VIEWER")).toBeInTheDocument();
    expect(within(changes).getAllByText("Changed")).toHaveLength(2);
  });

  it("returns focus to the event that opened its details", async () => {
    server.use(...certManagerAuditHandlers());
    const user = userEvent.setup();

    renderPage();
    const opener = await screen.findByRole("button", {
      name: "Changed Bob Builder's roles",
    });
    opener.focus();
    await user.keyboard("{Enter}");
    expect(await screen.findByRole("dialog")).toBeInTheDocument();

    await user.keyboard("{Escape}");

    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    expect(opener).toHaveFocus();
  });

  it("explains a failure in the details", async () => {
    server.use(
      ...certManagerAuditHandlers({
        page: certManagerAuditPage([certManagerAuditEntry(9001)]),
      }),
    );
    const user = userEvent.setup();

    renderPage();
    await user.click(
      await screen.findByRole("button", {
        name: "Could not add the Azure credential 'staging-dns'",
      }),
    );

    const dialog = await screen.findByRole("dialog");
    expect(
      within(dialog).getByText(/Failed: You don't have permission/),
    ).toBeInTheDocument();
    expect(within(dialog).getByText("Feature off")).toBeInTheDocument();
  });

  it("reads a capped total as 10,000+ and pages on by cursor", async () => {
    const seen: URL[] = [];
    server.use(
      ...certManagerAuditHandlers({
        seen,
        page: certManagerAuditPage([certManagerAuditEntry(9004)], {
          totalElements: 10_000,
          totalPages: 400,
          totalElementsCapped: true,
          nextCursor: "cursor-2",
          last: false,
        }),
      }),
    );
    const user = userEvent.setup();

    renderPage();

    expect(await screen.findByText("10,000+ events")).toBeInTheDocument();
    expect(screen.getByText(/Page 1 of 400\+/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Go to next page" }));
    await waitFor(() =>
      expect(listRequests(seen).at(-1)).toEqual({
        size: "25",
        cursor: "cursor-2",
      }),
    );
  });

  it("says how to reach older events on the last page of a capped count", async () => {
    server.use(
      ...certManagerAuditHandlers({
        page: certManagerAuditPage([certManagerAuditEntry(9004)], {
          totalElements: 10_000,
          totalPages: 400,
          totalElementsCapped: true,
        }),
      }),
    );

    renderPage();

    expect(
      await screen.findByText(
        "Showing the first 10,000 matching events. Narrow the filters or date range to see older ones.",
      ),
    ).toBeInTheDocument();
  });

  it("exports with the current filters and saves the file", async () => {
    mockSearch = "category=CREDENTIALS";
    const seen: URL[] = [];
    server.use(...certManagerAuditHandlers({ seen, b2b: true }));
    const user = userEvent.setup();

    renderPage();
    await screen.findByRole("table");
    await user.click(screen.getByRole("button", { name: /Export/ }));
    await user.click(
      await screen.findByRole("menuitem", { name: "CSV (spreadsheet)" }),
    );

    await waitFor(() =>
      expect(saveBlob).toHaveBeenCalledWith(
        expect.any(Blob),
        expect.stringMatching(/^certping-audit-log-\d{4}-\d{2}-\d{2}\.csv$/),
      ),
    );
    expect(listRequests(seen, "/api/v1/audit-logs/export")).toEqual([
      { category: "CREDENTIALS", format: "csv" },
    ]);
  });

  it("says what to do when an export is too large", async () => {
    // The first handler that matches answers, so the refusal goes first.
    server.use(
      http.get(`${API}/api/v1/audit-logs/export`, () =>
        HttpResponse.json(
          { code: "EXPORT_TOO_LARGE", message: "Too many rows" },
          { status: 400 },
        ),
      ),
      ...certManagerAuditHandlers({ b2b: true }),
    );
    const user = userEvent.setup();

    renderPage();
    await screen.findByRole("table");
    await user.click(screen.getByRole("button", { name: /Export/ }));
    await user.click(await screen.findByRole("menuitem", { name: "JSON" }));

    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith(
        "More than 10,000 entries match. Narrow the filters or date range, then export again.",
        { id: "audit-log-export-error" },
      ),
    );
  });

  it("offers the Access view only once cert-manager serves it", async () => {
    server.use(...certManagerAuditHandlers({ b2b: true }));

    renderPage();

    const views = await screen.findByRole("navigation", {
      name: "Audit log views",
    });
    expect(
      within(views).getByRole("link", { name: "Activity" }),
    ).toHaveAttribute("aria-current", "page");
    expect(within(views).getByRole("link", { name: "Access" })).toHaveAttribute(
      "href",
      "/settings/audit-logs?view=access",
    );
  });

  it("shows the activity log alone before the Access routes exist", async () => {
    const seen: URL[] = [];
    server.use(...certManagerAuditHandlers({ seen }));

    renderPage();
    await screen.findByRole("table");

    await waitFor(() =>
      expect(
        seen.some((url) => url.pathname.endsWith("/access/activities")),
      ).toBe(true),
    );
    expect(
      screen.queryByRole("navigation", { name: "Audit log views" }),
    ).not.toBeInTheDocument();
  });

  it("quotes the request id on the Access tab, and leaves an unnamed read blank", async () => {
    mockSearch = "view=access";
    server.use(
      http.get(`${API}/api/v1/audit-logs/access`, () =>
        HttpResponse.json({
          content: [
            {
              id: 1,
              timestamp: "2025-12-31T23:00:00Z",
              activity: "access.audit_log_viewed",
              target: null,
              status: "SUCCESS",
              actor: "alice@acme.test",
              userId: 42,
              requestId: "req-77",
              correlationId: "corr-77",
            },
          ],
          totalElements: 1,
          totalPages: 1,
          totalElementsCapped: false,
          nextCursor: null,
        }),
      ),
      ...certManagerAuditHandlers({ b2b: true }),
    );
    const user = userEvent.setup();

    renderPage();

    const table = await screen.findByRole("table");
    expect(
      within(table).getByRole("columnheader", { name: "Request ID" }),
    ).toBeInTheDocument();
    expect(within(table).getByText("req-77")).toBeInTheDocument();
    expect(within(table).queryByText("corr-77")).not.toBeInTheDocument();
    expect(within(table).queryByText("None")).not.toBeInTheDocument();

    await user.click(within(table).getByText("Audit log viewed"));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("Request ID")).toBeInTheDocument();
    expect(within(dialog).getByText("req-77")).toBeInTheDocument();
    expect(
      within(dialog).queryByText("Resource or search"),
    ).not.toBeInTheDocument();
    expect(within(dialog).queryByText("None")).not.toBeInTheDocument();
  });

  it("explains a missing Access log when a link opens it early", async () => {
    mockSearch = "view=access";
    server.use(...certManagerAuditHandlers());

    renderPage();

    expect(
      await screen.findByRole("heading", {
        name: "The Access log isn't available yet",
      }),
    ).toBeInTheDocument();
  });

  it("explains the platform view to a super admin before it exists", async () => {
    signIn(superAdmin, true);
    const seen: URL[] = [];
    server.use(...certManagerAuditHandlers({ seen }));

    renderPage();

    expect(
      await screen.findByRole("heading", {
        name: "The audit log isn't available here",
      }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/switch into an organization to read its audit log/i),
    ).toBeInTheDocument();
    expect(listRequests(seen)).toEqual([]);
    expect(listRequests(seen, "/api/v1/admin/audit-logs")).toHaveLength(1);
  });

  it("lets a super admin pick the organization on the platform view", async () => {
    signIn(superAdmin, true);
    const seen: URL[] = [];
    server.use(...certManagerAuditHandlers({ seen, b2b: true }));
    const user = userEvent.setup();

    renderPage();
    await screen.findByRole("table");

    expect(screen.queryByRole("note")).not.toBeInTheDocument();
    await user.click(
      screen.getByRole("combobox", { name: "Filter by Organization" }),
    );
    await user.click(await screen.findByRole("option", { name: "Acme" }));
    expect(mockReplace).toHaveBeenLastCalledWith(
      "/settings/audit-logs?organizationId=7",
    );
    expect(listRequests(seen, "/api/v1/admin/audit-logs")[0]).toEqual({
      visibility: "CUSTOMER",
      size: "25",
    });
  });

  it("reads the picked organization's categories on the platform view", async () => {
    signIn(superAdmin, true);
    mockSearch = "organizationId=7";
    const seen: URL[] = [];
    server.use(...certManagerAuditHandlers({ seen, b2b: true }));

    renderPage();
    await screen.findByRole("table");

    await waitFor(() =>
      expect(listRequests(seen, "/api/v1/admin/audit-logs/categories")).toEqual(
        [{ organizationId: "7" }],
      ),
    );
    expect(listRequests(seen, "/api/v1/admin/audit-logs")[0]).toMatchObject({
      organizationId: "7",
    });
  });

  it("reads nothing for a member without audit:view", () => {
    signIn({ ...orgAdmin, permissions: [] });
    const seen: URL[] = [];
    server.use(...certManagerAuditHandlers({ seen }));

    renderPage();

    expect(
      screen.getByText("You don't have permission to view the audit log."),
    ).toBeInTheDocument();
    expect(listRequests(seen)).toEqual([]);
  });
});
