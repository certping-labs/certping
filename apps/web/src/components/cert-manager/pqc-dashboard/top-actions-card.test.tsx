// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { TopActionsCard } from "./top-actions-card";

const SUMMARY = {
  totalCertificates: 100,
  pqcCompliant: 0,
  deprecated2030: 35,
  disallowed2035: 0,
  unknown: 65,
  highHndlRisk: 35,
};

describe("TopActionsCard", () => {
  it("shows each remediation count and its operational context", () => {
    render(<TopActionsCard summary={SUMMARY} onReviewStatus={jest.fn()} />);

    expect(screen.getByText("Top remediation actions")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /review 2035 disallow queue/i }),
    ).toHaveTextContent("0");
    expect(
      screen.getByRole("button", { name: /plan 2030 migrations/i }),
    ).toHaveTextContent("35");
    expect(
      screen.getByRole("button", { name: /classify unknown algorithms/i }),
    ).toHaveTextContent("65");
    expect(
      screen.getByRole("button", { name: /review pqc-ready inventory/i }),
    ).toHaveTextContent("0");
    expect(
      screen.getByText("Public-key metadata needs classification"),
    ).toBeInTheDocument();
  });

  it("filters the inventory using the selected remediation status", async () => {
    const user = userEvent.setup();
    const onReviewStatus = jest.fn();
    render(
      <TopActionsCard summary={SUMMARY} onReviewStatus={onReviewStatus} />,
    );

    await user.click(
      screen.getByRole("button", { name: /plan 2030 migrations/i }),
    );

    expect(onReviewStatus).toHaveBeenCalledWith("DEPRECATED_2030");
  });
});
