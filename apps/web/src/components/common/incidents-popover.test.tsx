// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { IncidentsPopover } from "@/components/common/incidents-popover";

const markAllRead = jest.fn();
const markRead = jest.fn();

jest.mock("next/navigation", () => ({
  usePathname: () => "/dashboard",
}));

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({ user: { id: "operator-1" } }),
}));

let mockCanManage = true;

jest.mock("@/lib/authz", () => ({
  canViewAlerts: () => true,
  canManageNotifications: () => mockCanManage,
}));

const mockAlerts: Array<Record<string, unknown>> = [];
const mockUnread = { hasUnread: true, hasUnreadProblem: true };
let mockDomainUnavailable = false;
const criticalAlert = {
  id: "alert-1",
  source: "ssl",
  status: "FAILED",
  createdAt: "2026-07-28T00:00:00Z",
  message:
    "The provider could not complete this certificate lifecycle operation.",
  severity: "CRITICAL",
  unread: true,
  domain: "e2e-lifecycle-certificate-with-a-long-name.example.com",
  deploymentTarget: null,
  correlationId: null,
};

jest.mock("@/hooks/incidents", () => ({
  useCanMarkAlertRead: () => () => true,
  useLatestSystemAlerts: () => ({
    data: mockAlerts,
    isLoading: false,
    isError: false,
    domainUnavailable: mockDomainUnavailable,
  }),
  useUnreadAlertSummary: () => mockUnread,
  useMarkAllSystemAlertsAsRead: () => ({
    mutate: markAllRead,
    isPending: false,
  }),
  useMarkSystemAlertAsRead: () => ({
    mutate: markRead,
    isPending: false,
  }),
}));

describe("IncidentsPopover", () => {
  beforeEach(() => {
    mockAlerts.splice(0, mockAlerts.length, criticalAlert);
    Object.assign(mockUnread, { hasUnread: true, hasUnreadProblem: true });
    mockDomainUnavailable = false;
    mockCanManage = true;
  });

  it("contains long alert rows within a responsive popover", async () => {
    const user = userEvent.setup();
    render(<IncidentsPopover />);

    await user.click(screen.getByRole("button", { name: "Open alerts" }));

    const heading = await screen.findByRole("heading", { name: "Alerts" });
    expect(heading.parentElement?.parentElement).toHaveClass(
      "max-w-100",
      "overflow-hidden",
    );

    const alertLink = screen.getByRole("link", {
      name: /e2e-lifecycle-certificate-with-a-long-name/i,
    });
    expect(alertLink).toHaveClass("grid", "overflow-hidden");
    expect(alertLink).toHaveTextContent("Critical");
  });

  it("uses a neutral unread dot when only good news is unread", () => {
    mockUnread.hasUnreadProblem = false;
    render(<IncidentsPopover />);

    const dot = screen.getByTestId("unread-dot");
    expect(dot).toHaveClass("bg-primary");
    expect(dot).not.toHaveClass("bg-destructive");
  });

  it("keeps the red unread dot for unread problems", () => {
    render(<IncidentsPopover />);

    expect(screen.getByTestId("unread-dot")).toHaveClass("bg-destructive");
  });

  it("shows no dot and disables Mark all read when nothing is unread", async () => {
    mockUnread.hasUnread = false;
    mockUnread.hasUnreadProblem = false;
    const user = userEvent.setup();
    render(<IncidentsPopover />);

    expect(screen.queryByTestId("unread-dot")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Open alerts" }));
    expect(
      await screen.findByRole("button", { name: "Mark all read" }),
    ).toBeDisabled();
  });

  it("marks everything read from the badge", async () => {
    const user = userEvent.setup();
    render(<IncidentsPopover />);

    await user.click(screen.getByRole("button", { name: "Open alerts" }));
    await user.click(
      await screen.findByRole("button", { name: "Mark all read" }),
    );

    expect(markAllRead).toHaveBeenCalledTimes(1);
  });

  it("disables Mark all read for a user who cannot mark alerts", async () => {
    mockCanManage = false;
    const user = userEvent.setup();
    render(<IncidentsPopover />);

    expect(screen.getByTestId("unread-dot")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Open alerts" }));
    expect(
      await screen.findByRole("button", { name: "Mark all read" }),
    ).toBeDisabled();
  });
});
