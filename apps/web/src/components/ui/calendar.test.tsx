// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";

import { Calendar } from "@/components/ui/calendar";

describe("Calendar", () => {
  it("renders month navigation", () => {
    render(
      <Calendar mode="single" selected={new Date("2026-01-01T00:00:00Z")} />,
    );

    expect(
      screen.getByRole("button", { name: /go to previous month/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /go to next month/i }),
    ).toBeInTheDocument();
  });
});
