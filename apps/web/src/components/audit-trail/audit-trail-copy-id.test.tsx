// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { AuditTrailCopyId } from "@/components/audit-trail/audit-trail-copy-id";

jest.mock("sonner", () => ({
  toast: { error: jest.fn(), success: jest.fn(), dismiss: jest.fn() },
}));

const LONG_ID = "req-http-f740c5eb-6e74-4dd4-a321-b3b48b1d6e69";

describe("AuditTrailCopyId", () => {
  it("shortens a long id from the middle in a cell, and copies it whole", async () => {
    const user = userEvent.setup();
    render(<AuditTrailCopyId label="request ID" value={LONG_ID} />);

    const shown = screen.getByText("req-http-f740…6e69");
    expect(shown).toHaveAttribute("title", LONG_ID);
    // Clipped to its cell: the text shrinks, the button never does.
    expect(shown).toHaveClass("min-w-0", "truncate");
    expect(shown.parentElement).toHaveClass("flex", "w-full", "min-w-0");
    const button = screen.getByRole("button", {
      name: `Copy request ID ${LONG_ID}`,
    });
    expect(button).toHaveClass("shrink-0");

    await user.click(button);
    await expect(navigator.clipboard.readText()).resolves.toBe(LONG_ID);
  });

  it("shows a short id as it is", () => {
    render(<AuditTrailCopyId label="request ID" value="req-405420498018387" />);

    expect(screen.getByText("req-405420498018387")).toBeInTheDocument();
  });

  it("wraps the whole id in a details field", async () => {
    const user = userEvent.setup();
    render(
      <AuditTrailCopyId label="correlation ID" value={LONG_ID} layout="wrap" />,
    );

    const shown = screen.getByText(LONG_ID);
    expect(shown).toHaveClass("break-all");
    expect(shown.parentElement).toHaveClass("block", "min-w-0");
    await user.click(
      screen.getByRole("button", { name: `Copy correlation ID ${LONG_ID}` }),
    );
    await expect(navigator.clipboard.readText()).resolves.toBe(LONG_ID);
  });
});
