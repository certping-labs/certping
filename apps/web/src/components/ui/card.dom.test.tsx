// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";

import { Card } from "@/components/ui/card";

describe("Card", () => {
  it("is a flat outlined region with no shadow", () => {
    render(<Card data-testid="card">Certificate health</Card>);

    const card = screen.getByTestId("card");
    expect(card).toHaveClass("border", "border-border", "rounded-xl");
    expect(card.className).not.toMatch(/shadow/);
  });

  it("marks itself so a card nested inside another card can dissolve", () => {
    render(
      <Card data-testid="outer">
        <Card data-testid="inner">Nested</Card>
      </Card>,
    );

    expect(screen.getByTestId("outer")).toHaveAttribute("data-slot", "card");
    expect(screen.getByTestId("inner")).toHaveAttribute("data-slot", "card");
  });

  it("allows an intentional borderless variant", () => {
    render(
      <Card className="border-none" data-testid="card">
        Embedded content
      </Card>,
    );

    expect(screen.getByTestId("card")).toHaveClass("border-none");
  });
});
