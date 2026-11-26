// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";

import { AuditRetentionCard } from "@/components/settings/audit/audit-retention-card";
import type { AuditRetention } from "@/lib/backend/audit-retention";
import { formatDate, formatDateTime } from "@/lib/utils";
import {
  auditRetentionFixture,
  unconfirmedAuditRetentionFixture,
} from "@/test/fixtures/audit-retention";
import { server } from "@/test/msw/server";

const mockToastSuccess = jest.fn();

jest.mock("sonner", () => ({
  toast: {
    success: (message: string) => mockToastSuccess(message),
    error: jest.fn(),
  },
}));

let mockIsSuperAdmin = true;

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({
    user: { id: "root" },
    isLoading: false,
    isSuperAdmin: mockIsSuperAdmin,
  }),
}));

const RETENTION_URL = `${process.env.NEXT_PUBLIC_API_URL}/api/v1/admin/settings/audit-retention`;
// Date.now is fixed at 2026-01-01T00:00Z (setup.node.ts). An older backend
// without deletionWouldStartAt gets the estimate: 04:30 UTC the next day.
const ESTIMATE = `about ${formatDateTime("2026-01-02T04:30:00.000Z")}`;
const SERVER_START = "2026-01-03T04:30:00Z";
const CAVEAT =
  "After you confirm, raising retention later won't bring back older history into the audit log.";

let stored: AuditRetention;
let puts: unknown[];
let getRequests: number;

function serve(
  get: () => Response | Promise<Response> = () => HttpResponse.json(stored),
  put: (body: { months: number; reason: string }) => Response = (body) => {
    stored = {
      ...stored,
      months: body.months,
      previousMonths: body.months === stored.months ? null : stored.months,
      updatedAt:
        body.months === stored.months
          ? stored.updatedAt
          : "2026-01-01T00:00:00Z",
      confirmed: true,
      confirmedAt: "2026-01-01T00:00:00Z",
      effectiveFrom: "2026-01-02T04:30:00Z",
    };
    return HttpResponse.json(stored);
  },
) {
  server.use(
    http.get(RETENTION_URL, () => {
      getRequests += 1;
      return get();
    }),
    http.put(RETENTION_URL, async ({ request }) => {
      const body = (await request.json()) as { months: number; reason: string };
      puts.push(body);
      return put(body);
    }),
  );
}

beforeEach(() => {
  mockIsSuperAdmin = true;
  mockToastSuccess.mockClear();
  stored = auditRetentionFixture();
  puts = [];
  getRequests = 0;
});

function renderCard() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const view = render(
    <QueryClientProvider client={queryClient}>
      <AuditRetentionCard />
    </QueryClientProvider>,
  );
  return { user: userEvent.setup(), ...view };
}

const statusBanner = async () =>
  within(
    await screen.findByRole("region", { name: "Audit log retention" }),
  ).findByRole("status");

const segment = (name: string) => screen.getByRole("button", { name });

async function fillReason(
  user: ReturnType<typeof userEvent.setup>,
  text: string,
) {
  const reason = screen.getByRole("textbox", { name: "Reason" });
  await user.clear(reason);
  await user.click(reason);
  await user.paste(text);
}

describe("who sees the card", () => {
  it("renders nothing, and asks nothing, for anyone but a super admin", () => {
    mockIsSuperAdmin = false;
    serve();
    const { container } = renderCard();
    expect(container).toBeEmptyDOMElement();
    expect(getRequests).toBe(0);
  });

  it("renders nothing when the API refuses the caller", async () => {
    serve(() => HttpResponse.json({ status: 403 }, { status: 403 }));
    const { container } = renderCard();
    await waitFor(() => expect(getRequests).toBe(1));
    await waitFor(() => expect(container).toBeEmptyDOMElement());
  });

  it("offers a retry when loading fails otherwise", async () => {
    let fail = true;
    serve(() =>
      fail
        ? HttpResponse.json(
            { message: "Database unavailable" },
            { status: 500 },
          )
        : HttpResponse.json(stored),
    );
    const { user } = renderCard();
    expect(
      await screen.findByText("Couldn't load audit retention"),
    ).toBeInTheDocument();
    expect(screen.getByText("Database unavailable")).toBeInTheDocument();

    fail = false;
    await user.click(screen.getByRole("button", { name: "Try again" }));
    expect(await statusBanner()).toHaveTextContent("Confirmed on");
  });
});

describe("status", () => {
  it("waits for confirmation before anything is deleted", async () => {
    stored = unconfirmedAuditRetentionFixture();
    serve();
    renderCard();
    const banner = await statusBanner();
    expect(banner).toHaveTextContent(
      "Automatic deletion is waiting for confirmation",
    );
    expect(
      screen.getByText("Not scheduled until confirmed"),
    ).toBeInTheDocument();
    expect(screen.getAllByText("Never")).toHaveLength(2);
  });

  it("states the confirmation date and cutoff once running", async () => {
    serve();
    renderCard();
    expect(await statusBanner()).toHaveTextContent(
      `Confirmed on ${formatDate("2025-12-20T12:00:00Z")} · Entries older than Jan 1, 2025 (UTC) are deleted daily`,
    );
  });

  it("reports the kill switch", async () => {
    stored = auditRetentionFixture({ automaticDeletionEnabled: false });
    serve();
    renderCard();
    expect(await statusBanner()).toHaveTextContent(
      "Automatic deletion is paused",
    );
  });

  it("shows the period, oldest stored month, effective date and last change", async () => {
    serve();
    renderCard();
    await statusBanner();
    expect(screen.getByText("1 year (about 365 days)")).toBeInTheDocument();
    expect(screen.getByText("January 2023")).toBeInTheDocument();
    expect(
      screen.getByText(
        "Months before January 2025 are deleted at the next deletion run.",
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(formatDateTime("2026-01-02T04:30:00Z")),
    ).toBeInTheDocument();
    expect(
      screen.getAllByText(formatDateTime("2025-12-20T12:00:00Z")),
    ).toHaveLength(2);
    expect(segment("1 year")).toHaveAttribute("aria-pressed", "true");
  });

  it("starts on Custom for a period that isn't a preset", async () => {
    stored = auditRetentionFixture({ months: 18, oldestStoredMonth: null });
    serve();
    renderCard();
    await statusBanner();
    expect(segment("Custom")).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("spinbutton", { name: "Months" })).toHaveValue(18);
    expect(screen.getByText("No entries stored")).toBeInTheDocument();
  });
});

describe("validation", () => {
  it("requires a reason before asking for confirmation", async () => {
    serve();
    const { user } = renderCard();
    await statusBanner();
    await user.click(segment("2 years"));
    await user.click(screen.getByRole("button", { name: "Save and confirm" }));

    expect(screen.getByText("A reason is required.")).toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: "Reason" })).toHaveAttribute(
      "aria-invalid",
      "true",
    );
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
    expect(puts).toHaveLength(0);
  });

  it("counts the reason and refuses more than 500 characters", async () => {
    serve();
    const { user } = renderCard();
    await statusBanner();
    await fillReason(user, "a".repeat(501));
    expect(
      screen.getByText("The reason must be at most 500 characters."),
    ).toBeInTheDocument();
    expect(screen.getByText(/501\/500 characters/)).toBeInTheDocument();
  });

  it.each([
    ["5", "Audit retention must be between 6 and 36 months."],
    ["37", "Audit retention must be between 6 and 36 months."],
    ["6.5", "Enter a whole number of months."],
  ])("refuses a custom %s months inline", async (months, message) => {
    serve();
    const { user } = renderCard();
    await statusBanner();
    await user.click(segment("Custom"));
    const input = screen.getByRole("spinbutton", { name: "Months" });
    await user.type(input, months);

    expect(screen.getByText(message)).toBeInTheDocument();
    expect(input).toHaveAttribute("aria-invalid", "true");
    await fillReason(user, "Contract");
    await user.click(screen.getByRole("button", { name: "Save and confirm" }));
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
  });

  it("asks for a number when Custom is left empty", async () => {
    serve();
    const { user } = renderCard();
    await statusBanner();
    await user.click(segment("Custom"));
    await fillReason(user, "Contract");
    await user.click(screen.getByRole("button", { name: "Save and confirm" }));
    expect(screen.getByText("Enter a number of months.")).toBeInTheDocument();
  });
});

/** Clicks the dialog's action once the fresh GET has landed and enabled it. */
async function confirmWith(
  user: ReturnType<typeof userEvent.setup>,
  name: string,
) {
  const action = await screen.findByRole("button", { name });
  await waitFor(() => expect(action).toBeEnabled());
  await user.click(action);
}

async function openDialog(
  user: ReturnType<typeof userEvent.setup>,
  choice: string | null,
  reason: string,
) {
  await statusBanner();
  if (choice) await user.click(segment(choice));
  await fillReason(user, reason);
  await user.click(screen.getByRole("button", { name: "Save and confirm" }));
  const dialog = await screen.findByRole("alertdialog");
  await waitFor(() =>
    expect(dialog).not.toHaveTextContent("Checking when deletion would start"),
  );
  return dialog;
}

describe("confirmation dialog", () => {
  it("asks the server again and states its deletion date", async () => {
    stored = unconfirmedAuditRetentionFixture({
      deletionWouldStartAt: "2026-01-02T04:30:00Z",
      deletionHeldBy: null,
    });
    // By the time the dialog opens the server's answer has moved on a day.
    let calls = 0;
    serve(() => {
      calls += 1;
      return HttpResponse.json(
        calls === 1
          ? stored
          : { ...stored, deletionWouldStartAt: SERVER_START },
      );
    });
    const { user } = renderCard();
    const dialog = await openDialog(user, null, "Default period");

    expect(getRequests).toBe(2);
    expect(
      within(dialog).getByRole("heading", {
        name: "Confirm 1 year of audit history?",
      }),
    ).toBeInTheDocument();
    expect(dialog).toHaveTextContent(
      `Entries before January 2025 will be permanently deleted no earlier than ${formatDateTime(SERVER_START)}.`,
    );
    expect(dialog).not.toHaveTextContent("about");
    expect(dialog).toHaveTextContent(CAVEAT);
    expect(dialog).toHaveTextContent("Reason: Default period");
    expect(
      within(dialog).getByRole("button", { name: "Confirm 1 year" }),
    ).toBeInTheDocument();
  });

  it("can't be confirmed until the fresh answer arrives", async () => {
    stored = unconfirmedAuditRetentionFixture({
      deletionWouldStartAt: SERVER_START,
      deletionHeldBy: null,
    });
    let release: () => void = () => undefined;
    serve(() =>
      getRequests === 1
        ? HttpResponse.json(stored)
        : new Promise<Response>((resolve) => {
            release = () => resolve(HttpResponse.json(stored));
          }),
    );
    const { user } = renderCard();
    await statusBanner();
    await fillReason(user, "Default period");
    await user.click(screen.getByRole("button", { name: "Save and confirm" }));

    const dialog = await screen.findByRole("alertdialog");
    expect(
      await within(dialog).findByText("Checking when deletion would start…"),
    ).toBeInTheDocument();
    expect(
      within(dialog).getByRole("button", { name: "Confirm 1 year" }),
    ).toBeDisabled();

    release();
    await waitFor(() =>
      expect(
        within(dialog).getByRole("button", { name: "Confirm 1 year" }),
      ).toBeEnabled(),
    );
  });

  it("says when the refresh failed", async () => {
    stored = auditRetentionFixture({ months: 24 });
    serve(() =>
      getRequests === 1
        ? HttpResponse.json(stored)
        : HttpResponse.json({ message: "down" }, { status: 500 }),
    );
    const { user } = renderCard();
    const dialog = await openDialog(user, "6 months", "Trim");
    expect(dialog).toHaveTextContent(
      "Couldn't check the latest schedule; these dates are from when the page loaded.",
    );
  });

  it("labels an older backend's date as an estimate", async () => {
    stored = unconfirmedAuditRetentionFixture();
    serve();
    const { user } = renderCard();
    const dialog = await openDialog(user, null, "Default period");
    expect(dialog).toHaveTextContent(
      `Entries before January 2025 will be permanently deleted no earlier than ${ESTIMATE}.`,
    );
  });

  it("gives no date while automatic deletion is paused", async () => {
    stored = auditRetentionFixture({
      months: 24,
      automaticDeletionEnabled: false,
      deletionWouldStartAt: null,
      deletionHeldBy: "KILL_SWITCH",
    });
    serve();
    const { user } = renderCard();
    const dialog = await openDialog(user, "6 months", "Data minimisation");
    expect(dialog).toHaveTextContent("Shorten audit retention to 6 months?");
    expect(dialog).toHaveTextContent(
      "Entries older than 6 months will be permanently deleted at the first deletion run after automatic deletion resumes.",
    );
    expect(dialog).toHaveTextContent(CAVEAT);
  });

  it("states the irreversible effect of a shortening", async () => {
    stored = auditRetentionFixture({
      months: 24,
      deletionWouldStartAt: SERVER_START,
      deletionHeldBy: null,
    });
    serve();
    const { user } = renderCard();
    const dialog = await openDialog(user, "6 months", "Data minimisation");
    expect(dialog).toHaveTextContent(
      `Entries before July 2025 will be permanently deleted no earlier than ${formatDateTime(SERVER_START)}.`,
    );
  });

  it("says nothing is deleted now when no stored entry is old enough", async () => {
    stored = unconfirmedAuditRetentionFixture({
      oldestStoredMonth: "2025-06",
      deletionWouldStartAt: SERVER_START,
      deletionHeldBy: null,
    });
    serve();
    const { user } = renderCard();
    const dialog = await openDialog(user, null, "Default period");
    expect(dialog).toHaveTextContent(
      `Nothing is deleted now; entries are deleted as they turn 1 year old, starting no earlier than ${formatDateTime(SERVER_START)}.`,
    );
    expect(dialog).not.toHaveTextContent("Entries before");
  });

  it("deletes nothing when lengthening", async () => {
    serve();
    const { user } = renderCard();
    const dialog = await openDialog(user, "3 years", "Contract");
    expect(dialog).toHaveTextContent("Keep audit history for 3 years?");
    expect(dialog).toHaveTextContent("This change deletes nothing");
    expect(dialog).not.toHaveTextContent("permanently deleted");
    expect(dialog).toHaveTextContent(
      "Entries already deleted can't be brought back",
    );
  });

  it("only re-confirms an unchanged period", async () => {
    serve();
    const { user } = renderCard();
    const dialog = await openDialog(user, null, "Annual review");
    expect(dialog).toHaveTextContent("Confirm 1 year again?");
    expect(dialog).not.toHaveTextContent("permanently deleted");
  });

  it("starts a deleting confirmation on Cancel, and Escape saves nothing", async () => {
    stored = auditRetentionFixture({ months: 24 });
    serve();
    const { user } = renderCard();
    const dialog = await openDialog(user, "6 months", "Trim");
    expect(
      within(dialog).getByRole("button", { name: "Keep current setting" }),
    ).toHaveFocus();

    await user.keyboard("{Escape}");
    await waitFor(() =>
      expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument(),
    );
    expect(puts).toHaveLength(0);
  });

  it("saves nothing when cancelled", async () => {
    serve();
    const { user } = renderCard();
    await openDialog(user, "6 months", "Trim");
    await user.click(
      screen.getByRole("button", { name: "Keep current setting" }),
    );
    await waitFor(() =>
      expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument(),
    );
    expect(puts).toHaveLength(0);
  });
});

describe("reason counter", () => {
  it("is part of the field's description and announced politely near the limit", async () => {
    serve();
    const { user } = renderCard();
    await statusBanner();
    const reason = screen.getByRole("textbox", { name: "Reason" });
    const counter = screen.getByText("0/500 characters");
    expect(reason.getAttribute("aria-describedby")).toContain(counter.id);

    const live = document.querySelector('[aria-live="polite"]');
    expect(live).toHaveTextContent("");
    await fillReason(user, "a".repeat(460));
    expect(live).toHaveTextContent("40 characters left");
    await fillReason(user, "a".repeat(499));
    expect(live).toHaveTextContent("1 character left");
    await fillReason(user, "a".repeat(502));
    expect(live).toHaveTextContent("2 characters over the limit");
  });
});

describe("saving", () => {
  it("PUTs the months and the cleaned reason, then shows the confirmed setting", async () => {
    stored = unconfirmedAuditRetentionFixture();
    serve();
    const { user } = renderCard();
    await statusBanner();
    await user.click(segment("3 years"));
    await fillReason(user, "  Customer contract\n requires 3 years ");
    await user.click(screen.getByRole("button", { name: "Save and confirm" }));
    await confirmWith(user, "Confirm 3 years");

    await waitFor(() =>
      expect(puts).toEqual([
        { months: 36, reason: "Customer contract requires 3 years" },
      ]),
    );
    expect(await statusBanner()).toHaveTextContent(
      `Confirmed on ${formatDate("2026-01-01T00:00:00Z")}`,
    );
    // The date shown after saving is the PUT response's effectiveFrom.
    expect(mockToastSuccess).toHaveBeenCalledWith(
      `Audit retention confirmed: 3 years. Applies from ${formatDateTime("2026-01-02T04:30:00Z")}.`,
    );
    expect(screen.getByRole("textbox", { name: "Reason" })).toHaveValue("");
    expect(screen.getByText(/\(from 1 year\)/)).toBeInTheDocument();
  });

  it("PUTs a custom period", async () => {
    serve();
    const { user } = renderCard();
    await statusBanner();
    await user.click(segment("Custom"));
    await user.type(screen.getByRole("spinbutton", { name: "Months" }), "18");
    await fillReason(user, "Regulator asked for 18 months");
    await user.click(screen.getByRole("button", { name: "Save and confirm" }));
    await confirmWith(user, "Save 18 months");
    await waitFor(() =>
      expect(puts).toEqual([
        { months: 18, reason: "Regulator asked for 18 months" },
      ]),
    );
  });

  it("shows the server's range error with its bounds", async () => {
    serve(undefined, () =>
      HttpResponse.json(
        {
          status: 400,
          error: "Bad Request",
          code: "AUDIT_RETENTION_OUT_OF_RANGE",
          message: "Audit retention must be between 6 and 24 months; got 36.",
          minMonths: 6,
          maxMonths: 24,
        },
        { status: 400 },
      ),
    );
    const { user } = renderCard();
    await statusBanner();
    await user.click(segment("3 years"));
    await fillReason(user, "Contract");
    await user.click(screen.getByRole("button", { name: "Save and confirm" }));
    await confirmWith(user, "Save 3 years");

    const alert = await screen.findByText(
      "Audit retention must be between 6 and 24 months; got 36.",
    );
    expect(alert.closest("[role=alert]")).toHaveTextContent(
      "Couldn't save the retention period",
    );
    expect(mockToastSuccess).not.toHaveBeenCalled();
    expect(screen.getByRole("textbox", { name: "Reason" })).toHaveValue(
      "Contract",
    );

    // The inline check now uses the bounds the server answered with.
    await user.click(segment("Custom"));
    await user.type(screen.getByRole("spinbutton", { name: "Months" }), "30");
    expect(screen.getByText("6 to 24 months.")).toBeInTheDocument();
    expect(
      screen.getByText("Audit retention must be between 6 and 24 months."),
    ).toBeInTheDocument();
  });

  it("shows the server's reason validation message", async () => {
    serve(undefined, () =>
      HttpResponse.json(
        {
          status: 400,
          error: "Validation Failed",
          message: "Request validation failed",
          fieldErrors: [{ field: "reason", message: "reason is required" }],
        },
        { status: 400 },
      ),
    );
    const { user } = renderCard();
    await statusBanner();
    await fillReason(user, "Annual review");
    await user.click(screen.getByRole("button", { name: "Save and confirm" }));
    await confirmWith(user, "Confirm");
    expect(await screen.findByText("reason is required")).toBeInTheDocument();
  });
});
