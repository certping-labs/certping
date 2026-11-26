// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";

import { Separator } from "@/components/ui/separator";

describe("Separator", () => {
  it("defaults to horizontal orientation styles", () => {
    render(<Separator data-testid="sep" />);
    expect(screen.getByTestId("sep")).toHaveClass("h-px");
    expect(screen.getByTestId("sep")).toHaveClass("w-full");
  });

  it("supports vertical orientation styles", () => {
    render(<Separator data-testid="sep" orientation="vertical" />);
    expect(screen.getByTestId("sep")).toHaveClass("h-full");
    expect(screen.getByTestId("sep")).toHaveClass("w-px");
  });
});
