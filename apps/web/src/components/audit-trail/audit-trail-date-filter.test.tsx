// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import {
  AuditTrailDateFilter,
  auditTrailDateLabel,
} from "@/components/audit-trail/audit-trail-date-filter";
import { AUDIT_DATE_PRESETS } from "@/lib/cert-manager-audit-filters";

const NOW = new Date(2026, 9, 10, 12, 0, 0);
// The window starts at noon on July 9th, 90 days back.
const EARLIEST = new Date(2026, 6, 9, 12, 0, 0);

function renderFilter(value = {}) {
  const onChange = jest.fn();
  render(
    <AuditTrailDateFilter
      value={value}
      presets={AUDIT_DATE_PRESETS}
      placeholder="Last 90 days"
      earliest={EARLIEST}
      now={NOW}
      onChange={onChange}
    />,
  );
  return onChange;
}

const goBackMonths = async (
  user: ReturnType<typeof userEvent.setup>,
  n: number,
) => {
  for (let index = 0; index < n; index += 1) {
    await user.click(
      screen.getByRole("button", { name: "Go to previous month" }),
    );
  }
};

describe("AuditTrailDateFilter", () => {
  it("reads the window as its placeholder until something is chosen", () => {
    renderFilter();

    expect(
      screen.getByRole("button", { name: "Filter by date: Last 90 days" }),
    ).toBeInTheDocument();
  });

  it("chooses a preset, and clears for the whole window", async () => {
    const user = userEvent.setup();
    const onChange = renderFilter({ range: "7d" });

    await user.click(
      screen.getByRole("button", { name: "Filter by date: Last 7 days" }),
    );
    expect(screen.getByRole("button", { name: "Last 7 days" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    await user.click(screen.getByRole("button", { name: "Last 30 days" }));
    expect(onChange).toHaveBeenLastCalledWith({ range: "30d" });

    await user.click(screen.getByRole("button", { name: /Filter by date/ }));
    await user.click(screen.getByRole("button", { name: "Last 90 days" }));
    expect(onChange).toHaveBeenLastCalledWith({});
  });

  it("offers no day before the window or after today", async () => {
    const user = userEvent.setup();
    renderFilter();

    await user.click(screen.getByRole("button", { name: /Filter by date/ }));
    expect(
      screen.getByText("The log reaches back to Jul 9, 2026."),
    ).toBeVisible();
    expect(screen.getByRole("gridcell", { name: "11" })).toBeDisabled();
    expect(screen.getByRole("gridcell", { name: "10" })).toBeEnabled();

    await goBackMonths(user, 3);
    expect(screen.getByText("July 2026")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Go to previous month" }),
    ).toBeDisabled();
    expect(screen.getByRole("gridcell", { name: "8" })).toBeDisabled();
    expect(screen.getByRole("gridcell", { name: "9" })).toBeEnabled();
  });

  it("starts a range on the window's first day where the window starts", async () => {
    const user = userEvent.setup();
    const onChange = renderFilter();

    await user.click(screen.getByRole("button", { name: /Filter by date/ }));
    await goBackMonths(user, 3);
    await user.click(screen.getByRole("gridcell", { name: "9" }));

    expect(onChange).toHaveBeenLastCalledWith({
      from: EARLIEST.toISOString(),
      to: new Date(2026, 6, 9, 23, 59, 59, 999).toISOString(),
    });
  });

  it("labels a chosen range by its days", () => {
    expect(
      auditTrailDateLabel(
        {
          from: new Date(2026, 8, 1).toISOString(),
          to: new Date(2026, 8, 3, 23, 59).toISOString(),
        },
        AUDIT_DATE_PRESETS,
      ),
    ).toBe("Sep 1, 2026 – Sep 3, 2026");
    expect(
      auditTrailDateLabel(
        { from: new Date(2026, 8, 1).toISOString() },
        AUDIT_DATE_PRESETS,
      ),
    ).toBe("Since Sep 1, 2026");
    expect(auditTrailDateLabel({}, AUDIT_DATE_PRESETS)).toBeUndefined();
  });
});
