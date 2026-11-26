// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { ViewSwitcher } from "@/components/ui/view-switcher";

describe("ViewSwitcher", () => {
  it("switches view when enabled", async () => {
    const user = userEvent.setup();
    const onValueChange = jest.fn();

    render(<ViewSwitcher value="table" onValueChange={onValueChange} />);

    await user.click(screen.getByRole("button", { name: /Grid/i }));
    expect(onValueChange).toHaveBeenCalledWith("card");
  });

  it("does not switch when disabled", async () => {
    const user = userEvent.setup();
    const onValueChange = jest.fn();

    const { container } = render(
      <ViewSwitcher value="table" onValueChange={onValueChange} disabled />,
    );

    await user.click(screen.getByRole("button", { name: /Grid/i }));
    expect(onValueChange).not.toHaveBeenCalled();
    expect(container.firstChild).toHaveClass("pointer-events-none");
  });

  it("renders showLabels variant", () => {
    render(
      <ViewSwitcher value="card" onValueChange={() => undefined} showLabels />,
    );
    expect(screen.getAllByText(/Table|Grid/).length).toBeGreaterThan(0);
  });

  it("marks the active view as pressed and can show icons only", () => {
    render(
      <ViewSwitcher
        value="card"
        onValueChange={() => undefined}
        showLabels={false}
      />,
    );
    expect(screen.getByRole("button", { name: "Grid" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    expect(screen.getByRole("button", { name: "Table" })).toHaveAttribute(
      "aria-pressed",
      "false",
    );
    expect(screen.queryByText("Grid")).not.toBeInTheDocument();
  });

  it("applies size variants", () => {
    const { rerender, container } = render(
      <ViewSwitcher value="table" onValueChange={() => undefined} size="sm" />,
    );
    expect(container.firstChild).toHaveClass("h-8");

    rerender(
      <ViewSwitcher value="table" onValueChange={() => undefined} size="lg" />,
    );
    expect(container.firstChild).toHaveClass("h-12");
  });
});
