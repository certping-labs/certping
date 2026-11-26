// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";

import { AlgorithmStatusCard } from "./algorithm-status-card";

describe("AlgorithmStatusCard", () => {
  it("renders the complete algorithm distribution instead of only PQC readiness", () => {
    const { container } = render(
      <AlgorithmStatusCard
        summary={{
          totalCertificates: 100,
          pqcCompliant: 0,
          deprecated2030: 35,
          disallowed2035: 0,
          unknown: 65,
          highHndlRisk: 35,
        }}
      />,
    );

    expect(
      screen.getByRole("heading", { name: "Algorithm status" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("img", {
        name: "Algorithm status for 100 certificates",
      }),
    ).toBeInTheDocument();
    expect(screen.getByText("PQC ready").closest("div")).toHaveTextContent(
      "PQC ready0 (0%)",
    );
    expect(screen.getByText("Deprecated").closest("div")).toHaveTextContent(
      "Deprecated35 (35%)",
    );
    expect(screen.getByText("Disallowed").closest("div")).toHaveTextContent(
      "Disallowed0 (0%)",
    );
    expect(screen.getByText("No data").closest("div")).toHaveTextContent(
      "No data65 (65%)",
    );
    expect(container.querySelector("circle.text-warning")).toBeInTheDocument();
    expect(
      container.querySelector("circle.text-muted-foreground"),
    ).toBeInTheDocument();
    expect(container.querySelectorAll("svg circle")).toHaveLength(5);
  });

  it("renders an empty chart safely before inventory data arrives", () => {
    const { container } = render(<AlgorithmStatusCard />);

    expect(
      screen.getByRole("img", {
        name: "Algorithm status for 0 certificates",
      }),
    ).toBeInTheDocument();
    expect(container.querySelectorAll("svg circle")).toHaveLength(1);
  });
});
