// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { toast } from "sonner";

import { accessReference } from "@/components/audit-trail/audit-trail-access-columns";
import { AuditTrailAccessPanel } from "@/components/audit-trail/audit-trail-access-panel";
import { AuditTrailPanel } from "@/components/audit-trail/audit-trail-panel";
import { useAuth } from "@/hooks/use-auth";
import type {
  AuditTrailAccessSource,
  AuditTrailSource,
} from "@/lib/audit-trail-source";
import { saveBlob } from "@/lib/download";
import type {
  AuditTrailAccessEntry,
  AuditTrailAccessPage,
  AuditTrailEntry,
  AuditTrailPage,
} from "@/types/audit-trail";

let mockSearch = "";
const mockReplace = jest.fn();

jest.mock("next/navigation", () => ({
  useRouter: () => ({ replace: mockReplace }),
  usePathname: () => "/things/audit",
  useSearchParams: () => new URLSearchParams(mockSearch),
}));

jest.mock("@/hooks/use-auth", () => ({ useAuth: jest.fn() }));
jest.mock("@/lib/download", () => ({ saveBlob: jest.fn() }));
jest.mock("sonner", () => ({
  toast: { error: jest.fn(), success: jest.fn(), dismiss: jest.fn() },
}));

// A source no real service has: its words and codes show the panel uses the
// adapter's, and nothing of the domains'.
const fakeLabel = (code: string) => `«${code.toLowerCase()}»`;

const entry = (overrides: Partial<AuditTrailEntry> = {}): AuditTrailEntry => ({
  id: 1,
  timestamp: "2026-09-25T10:00:00Z",
  action: "WIDGET_SPIN",
  summary: "Spun widget alpha",
  status: "SUCCESS",
  resource: "WIDGET",
  resourceId: 7,
  resourceName: "alpha",
  actorType: "USER",
  actorName: "Ada",
  changes: [],
  attributes: {},
  ...overrides,
});

const pageOf = (
  content: AuditTrailEntry[],
  overrides: Partial<AuditTrailPage> = {},
): AuditTrailPage => ({
  content,
  totalElements: content.length,
  totalPages: 1,
  totalCapped: false,
  ...overrides,
});

const fakeSource = (
  overrides: Partial<AuditTrailSource> = {},
): AuditTrailSource => ({
  queryKeys: { list: ["fake-trail"], options: ["fake-trail-options"] },
  list: jest.fn(async () => pageOf([entry()])),
  options: jest.fn(async (kind) =>
    kind === "actions" ? ["WIDGET_SPIN"] : ["WIDGET"],
  ),
  export: jest.fn(async (_filters, format) => ({
    blob: new Blob(["x"]),
    fileName: `widgets.${format}`,
  })),
  exportErrorToastId: "fake-export-error",
  canView: jest.fn(() => true),
  canLoadOptions: jest.fn(() => true),
  filters: {
    read: (params) => {
      const status = params.get("status") ?? undefined;
      return status ? { status } : {};
    },
    write: (filters) => (filters.status ? `status=${filters.status}` : ""),
    has: (filters) => Boolean(filters.status),
    rangeError: () => undefined,
  },
  codes: { results: ["SUCCESS", "FAILURE"], actorTypes: ["USER"] },
  codeLabel: fakeLabel,
  resourceLabel: (row) => `Widget #${row.resourceId}`,
  resourceHref: (row, platform) =>
    platform ? undefined : `/widgets/${row.resourceId}`,
  relatedLink: (row) => ({
    href: `/widgets/${row.resourceId}`,
    label: `Open widget #${row.resourceId}`,
  }),
  copy: {
    customer: {
      title: "Widget log",
      breadcrumbs: [{ label: "Widgets", href: "/widgets" }],
      subtitle: "Who spun your widgets.",
    },
    platform: {
      title: "All widgets",
      breadcrumbs: [],
      subtitle: "Every organization's widgets.",
    },
    noPermission: "No widget log for you.",
    refresh: "Refresh widgets",
    loading: "Loading widgets",
    loadError: "Couldn't load the widget log",
    empty: {
      title: "No widget events",
      description: "Spins appear here.",
      filteredTitle: "No widget events match",
    },
    endOfList: "No more widgets.",
    total: { one: "spin", other: "spins" },
    exportNoun: "spin",
    resource: "Widget",
    resourceFilter: { label: "Widget name", placeholder: "alpha" },
  },
  views: {
    label: "Widget logs",
    items: [
      { id: "spins", label: "Spins", href: "/things/audit" },
      { id: "reads", label: "Reads", href: "/things/audit?view=reads" },
    ],
  },
  viewId: "spins",
  ...overrides,
});

function renderWith(ui: React.ReactElement) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>,
  );
}

beforeEach(() => {
  mockSearch = "";
  mockReplace.mockReset();
  (useAuth as jest.Mock).mockReturnValue({
    user: { id: "1", organizationId: "5" },
    isSuperAdmin: false,
    isLoading: false,
  });
});

describe("AuditTrailPanel", () => {
  it("shows a source's events in the source's words", async () => {
    const source = fakeSource();

    renderWith(<AuditTrailPanel source={source} />);

    const table = await screen.findByRole("table");
    expect(
      within(table)
        .getAllByRole("columnheader")
        .map((header) => header.textContent),
    ).toEqual(["Time", "Actor", "Action", "Widget", "Result", "Details"]);
    expect(within(table).getByText("«widget_spin»")).toBeInTheDocument();
    expect(within(table).getByText("«success»")).toBeInTheDocument();
    expect(
      within(table).getByRole("link", { name: "Widget #7" }),
    ).toHaveAttribute("href", "/widgets/7");
    expect(screen.getByRole("heading", { name: "Widget log" })).toBeVisible();
    expect(screen.getByText("1 spin")).toBeInTheDocument();
    expect(
      screen.getByRole("navigation", { name: "Widget logs" }),
    ).toBeInTheDocument();
    expect(source.list).toHaveBeenCalledWith({
      filters: {},
      platform: false,
      size: 25,
      cursor: undefined,
    });
    expect(source.options).toHaveBeenCalledWith("actions", false);
    expect(source.options).toHaveBeenCalledWith("resources", false);
  });

  it("asks the source who may look, and reads nothing for one who may not", async () => {
    const source = fakeSource({ canView: jest.fn(() => false) });

    renderWith(<AuditTrailPanel source={source} platform />);

    expect(screen.getByText("No widget log for you.")).toBeInTheDocument();
    expect(source.canView).toHaveBeenCalledWith(
      { id: "1", organizationId: "5" },
      false,
      true,
    );
    expect(source.list).not.toHaveBeenCalled();
    expect(source.options).not.toHaveBeenCalled();
  });

  it("loads no filter options when the source says it cannot", async () => {
    const source = fakeSource({ canLoadOptions: jest.fn(() => false) });

    renderWith(<AuditTrailPanel source={source} />);

    await screen.findByRole("table");
    expect(source.options).not.toHaveBeenCalled();
  });

  it("reads and writes the filters through the source", async () => {
    mockSearch = "status=FAILURE";
    const source = fakeSource({
      list: jest.fn(async () => pageOf([])),
    });
    const user = userEvent.setup();

    renderWith(<AuditTrailPanel source={source} />);

    expect(
      await screen.findByText("No widget events match"),
    ).toBeInTheDocument();
    expect(source.list).toHaveBeenCalledWith(
      expect.objectContaining({ filters: { status: "FAILURE" } }),
    );

    await user.click(screen.getByRole("combobox", { name: "Result" }));
    await user.click(await screen.findByRole("option", { name: "«success»" }));
    expect(mockReplace).toHaveBeenLastCalledWith(
      "/things/audit?status=SUCCESS",
    );

    const clears = screen.getAllByRole("button", { name: /Clear filters/ });
    await user.click(clears[clears.length - 1]);
    expect(mockReplace).toHaveBeenLastCalledWith("/things/audit");
  });

  it("stops at the source's range error without reading", async () => {
    const source = fakeSource({
      filters: {
        ...fakeSource().filters,
        rangeError: () => "Too long a range.",
      },
    });

    renderWith(<AuditTrailPanel source={source} />);

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Too long a range.",
    );
    expect(source.list).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: /Export/ })).toBeDisabled();
  });

  it("pages through the source by cursor and size", async () => {
    const source = fakeSource({
      list: jest.fn(async ({ cursor }) =>
        cursor === "c1"
          ? pageOf([entry({ id: 2, summary: "Spun widget beta" })], {
              totalElements: 2,
              totalPages: 2,
            })
          : pageOf([entry()], {
              nextCursor: "c1",
              totalElements: 2,
              totalPages: 2,
            }),
      ),
    });
    const user = userEvent.setup();

    renderWith(<AuditTrailPanel source={source} />);
    await screen.findByText("Spun widget alpha");

    await user.click(screen.getByRole("button", { name: "Go to next page" }));
    expect(await screen.findByText("Spun widget beta")).toBeInTheDocument();
    expect(source.list).toHaveBeenLastCalledWith(
      expect.objectContaining({ cursor: "c1", size: 25 }),
    );

    await user.click(screen.getByRole("combobox", { name: "Rows per page" }));
    await user.click(await screen.findByRole("option", { name: "50" }));
    await waitFor(() =>
      expect(source.list).toHaveBeenLastCalledWith({
        filters: {},
        platform: false,
        size: 50,
        cursor: undefined,
      }),
    );
  });

  it("exports through the source and saves its file", async () => {
    mockSearch = "status=FAILURE";
    const source = fakeSource();
    const user = userEvent.setup();

    renderWith(<AuditTrailPanel source={source} />);
    await screen.findByRole("table");
    await user.click(screen.getByRole("button", { name: /Export/ }));
    expect(
      await screen.findByText("Every spin the filters match, up to 10,000"),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("menuitem", { name: "JSON" }));

    await waitFor(() =>
      expect(saveBlob).toHaveBeenCalledWith(expect.any(Blob), "widgets.json"),
    );
    expect(source.export).toHaveBeenCalledWith(
      { status: "FAILURE" },
      "json",
      false,
    );
  });

  it("toasts a refused export under the source's toast id", async () => {
    const source = fakeSource({
      export: jest.fn(async () => {
        throw new Error("Too many exports");
      }),
    });
    const user = userEvent.setup();

    renderWith(<AuditTrailPanel source={source} />);
    await screen.findByRole("table");
    await user.click(screen.getByRole("button", { name: /Export/ }));
    await user.click(
      await screen.findByRole("menuitem", { name: "CSV (spreadsheet)" }),
    );

    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith("Too many exports", {
        id: "fake-export-error",
      }),
    );
  });

  it("still says something when an export fails without words", async () => {
    const source = fakeSource({
      export: jest.fn(async () => {
        throw new Error("");
      }),
    });
    const user = userEvent.setup();

    renderWith(<AuditTrailPanel source={source} />);
    await screen.findByRole("table");
    await user.click(screen.getByRole("button", { name: /Export/ }));
    await user.click(await screen.findByRole("menuitem", { name: "JSON" }));

    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith(
        "Couldn't export the log. Try again.",
        { id: "fake-export-error" },
      ),
    );
  });

  it("shows the source's error words and retries", async () => {
    const list = jest
      .fn()
      .mockRejectedValueOnce(new Error("Widget service down"))
      .mockResolvedValue(pageOf([entry()]));
    const source = fakeSource({ list });
    const user = userEvent.setup();

    renderWith(<AuditTrailPanel source={source} />);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Couldn't load the widget log");
    expect(alert).toHaveTextContent("Widget service down");
    await user.click(within(alert).getByRole("button", { name: "Try again" }));
    expect(await screen.findByRole("table")).toBeInTheDocument();
  });

  it("opens a row's details with the source's onward link", async () => {
    const source = fakeSource();
    const user = userEvent.setup();

    renderWith(<AuditTrailPanel source={source} />);
    await user.click(await screen.findByText("Spun widget alpha"));

    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("Widget #7")).toBeInTheDocument();
    expect(
      within(dialog).getByRole("link", { name: "Open widget #7" }),
    ).toHaveAttribute("href", "/widgets/7");
  });

  it("shows the platform view without export or tabs", async () => {
    const source = fakeSource();

    renderWith(<AuditTrailPanel source={source} platform />);

    const table = await screen.findByRole("table");
    expect(
      within(table).getByRole("columnheader", { name: "Organization" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "All widgets" })).toBeVisible();
    expect(
      screen.queryByRole("button", { name: /Export/ }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("navigation", { name: "Widget logs" }),
    ).not.toBeInTheDocument();
    expect(source.list).toHaveBeenCalledWith(
      expect.objectContaining({ platform: true }),
    );
    expect(source.options).toHaveBeenCalledWith("actions", true);
  });
});

const read = (
  overrides: Partial<AuditTrailAccessEntry> = {},
): AuditTrailAccessEntry => ({
  id: 1,
  timestamp: "2026-09-25T10:00:00Z",
  activity: "read.widget_viewed",
  target: "alpha",
  status: "SUCCESS",
  actor: "ada@example.com",
  userId: 12,
  correlationId: "corr-1",
  ...overrides,
});

const accessPageOf = (
  content: AuditTrailAccessEntry[],
): AuditTrailAccessPage => ({
  content,
  totalElements: content.length,
  totalPages: 1,
  totalCapped: false,
});

const fakeAccessSource = (
  overrides: Partial<AuditTrailAccessSource> = {},
): AuditTrailAccessSource => ({
  queryKey: ["fake-reads"],
  list: jest.fn(async () => accessPageOf([read()])),
  activities: jest.fn(async () => ["read.widget_viewed"]),
  export: jest.fn(async (_filters, format) => ({
    blob: new Blob(["x"]),
    fileName: `reads.${format}`,
  })),
  exportErrorToastId: "fake-export-error",
  canView: jest.fn(() => true),
  filters: {
    read: (params) => {
      const userId = params.get("userId") ?? undefined;
      return userId ? { userId } : {};
    },
    write: (filters) =>
      filters.userId ? `view=reads&userId=${filters.userId}` : "view=reads",
    has: (filters) => Boolean(filters.userId),
    rangeError: () => undefined,
  },
  results: ["SUCCESS", "FAILURE"],
  codeLabel: fakeLabel,
  activityLabel: (activity) => activity.replace("read.", "Read: "),
  copy: {
    title: "Widget log",
    breadcrumbs: [{ label: "Widgets", href: "/widgets" }],
    subtitle: "Who read your widgets.",
    noPermission: "No widget reads for you.",
    refresh: "Refresh reads",
    loading: "Loading reads",
    loadError: "Couldn't load the widget log",
    empty: {
      title: "No reads",
      description: "Reads appear here.",
      filteredTitle: "No reads match",
    },
    endOfList: "No more reads.",
    total: { one: "read", other: "reads" },
    exportNoun: "read",
    target: "Widget",
    targetPlaceholder: "alpha",
  },
  views: {
    label: "Widget logs",
    items: [
      { id: "spins", label: "Spins", href: "/things/audit" },
      { id: "reads", label: "Reads", href: "/things/audit?view=reads" },
    ],
  },
  viewId: "reads",
  ...overrides,
});

describe("AuditTrailAccessPanel", () => {
  it("quotes a read's request id, else its correlation id", () => {
    expect(accessReference(read({ requestId: "req-9" }))).toBe("req-9");
    expect(accessReference(read())).toBe("corr-1");
    expect(accessReference(read({ correlationId: undefined }))).toBeUndefined();
  });

  it("shows a source's reads in the source's words", async () => {
    const source = fakeAccessSource();

    renderWith(<AuditTrailAccessPanel source={source} />);

    const table = await screen.findByRole("table");
    expect(
      within(table)
        .getAllByRole("columnheader")
        .map((header) => header.textContent),
    ).toEqual(["Time", "User", "Activity", "Widget", "Result", "Request ID"]);
    expect(within(table).getByText("Read: widget_viewed")).toBeInTheDocument();
    expect(screen.getByText("1 read")).toBeInTheDocument();
    expect(
      within(screen.getByRole("navigation", { name: "Widget logs" })).getByRole(
        "link",
        { name: "Reads" },
      ),
    ).toHaveAttribute("aria-current", "page");
    expect(source.list).toHaveBeenCalledWith({
      filters: {},
      size: 25,
      cursor: undefined,
    });
    expect(source.activities).toHaveBeenCalled();
  });

  it("narrows to a user through the source's filters", async () => {
    const source = fakeAccessSource();
    const user = userEvent.setup();

    renderWith(<AuditTrailAccessPanel source={source} />);
    await user.click(await screen.findByText("Read: widget_viewed"));
    await user.click(
      await screen.findByRole("button", {
        name: "Show this user's activity",
      }),
    );

    expect(mockReplace).toHaveBeenLastCalledWith(
      "/things/audit?view=reads&userId=12",
    );
  });

  it("exports through the source", async () => {
    mockSearch = "userId=12";
    const source = fakeAccessSource();
    const user = userEvent.setup();

    renderWith(<AuditTrailAccessPanel source={source} />);
    await screen.findByRole("table");
    await user.click(screen.getByRole("button", { name: /Export/ }));
    await user.click(
      await screen.findByRole("menuitem", { name: "CSV (spreadsheet)" }),
    );

    await waitFor(() =>
      expect(saveBlob).toHaveBeenCalledWith(expect.any(Blob), "reads.csv"),
    );
    expect(source.export).toHaveBeenCalledWith({ userId: "12" }, "csv");
  });

  it("reads nothing for one the source refuses", () => {
    const source = fakeAccessSource({ canView: jest.fn(() => false) });

    renderWith(<AuditTrailAccessPanel source={source} />);

    expect(screen.getByText("No widget reads for you.")).toBeInTheDocument();
    expect(source.list).not.toHaveBeenCalled();
    expect(source.activities).not.toHaveBeenCalled();
  });
});
