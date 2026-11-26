// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { Sheet, SheetContent } from "@/components/ui/sheet";

describe("Sheet", () => {
  it("renders content and close button when open", async () => {
    const user = userEvent.setup();
    const onOpenChange = jest.fn();

    render(
      <Sheet open onOpenChange={onOpenChange}>
        <SheetContent side="left">
          <div>Sheet body</div>
        </SheetContent>
      </Sheet>,
    );

    expect(await screen.findByText("Sheet body")).toBeInTheDocument();
    const closeButton = screen.getByRole("button", { name: /close/i });
    await user.click(closeButton);
    expect(onOpenChange).toHaveBeenCalled();
  });

  it("uses default side when not provided", async () => {
    render(
      <Sheet open onOpenChange={() => {}}>
        <SheetContent>
          <div>Default side</div>
        </SheetContent>
      </Sheet>,
    );

    expect(await screen.findByText("Default side")).toBeInTheDocument();
  });
});
