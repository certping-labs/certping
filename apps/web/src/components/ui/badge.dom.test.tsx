// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";

import { Badge } from "@/components/ui/badge";

describe("Badge", () => {
  it("renders dot with correct mode precedence and count", () => {
    render(
      <Badge includeDot subVariants="warning" count="3">
        Expiring
      </Badge>,
    );

    expect(screen.getByText("Expiring")).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();
    expect(screen.getByText("3").closest("span")).toHaveClass("bg-muted");
  });

  it("renders destructive count style when variant destructive", () => {
    render(
      <Badge variant="destructive" count="9">
        Alerts
      </Badge>,
    );

    const count = screen.getByText("9");
    expect(count).toBeInTheDocument();
    expect(count.closest("span")).toHaveClass("bg-danger-soft");
  });

  it("supports textOnly appearance and does not render count/dot when absent", () => {
    render(
      <Badge textOnly className="custom">
        Label
      </Badge>,
    );
    const badge = screen.getByText("Label").closest("div");
    expect(badge).toHaveClass("rounded-none");
    expect(badge).toHaveClass("custom");
  });
});
