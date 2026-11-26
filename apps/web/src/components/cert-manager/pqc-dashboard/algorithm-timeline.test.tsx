// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";

import { AlgorithmTimeline } from "./algorithm-timeline";

describe("AlgorithmTimeline", () => {
  it("renders a fixed year axis, NIST deadlines, and every algorithm status", () => {
    render(
      <AlgorithmTimeline
        isLoading={false}
        groups={[
          {
            algorithm: "RSA",
            count: 35,
            deprecationYear: 2030,
            disallowedYear: 2035,
            keyDetails: "2048-bit",
            quantumStatus: "DEPRECATED_2030",
          },
          {
            algorithm: "Unknown algorithm",
            count: 65,
            deprecationYear: null,
            disallowedYear: null,
            keyDetails: "Key metadata unavailable",
            quantumStatus: "UNKNOWN",
          },
        ]}
      />,
    );

    expect(
      screen.getByRole("heading", {
        name: "Certificate distribution timeline",
      }),
    ).toBeInTheDocument();
    expect(screen.getByText("2024")).toBeInTheDocument();
    expect(screen.getByText("2036+")).toBeInTheDocument();
    expect(screen.getByLabelText("2030 deadline year")).toHaveClass(
      "text-primary",
    );
    expect(screen.getByLabelText("2035 deadline year")).toHaveClass(
      "text-primary",
    );
    expect(screen.getByText("NIST 2030 deadline")).toBeInTheDocument();
    expect(screen.getByText("NIST 2035 deadline")).toBeInTheDocument();
    expect(screen.getByText("RSA")).toBeInTheDocument();
    expect(screen.getByText("Unknown algorithm")).toBeInTheDocument();
  });

  it("renders an actionable empty state when no algorithms are reported", () => {
    render(<AlgorithmTimeline groups={[]} isLoading={false} />);

    expect(screen.getByText("No algorithm inventory yet")).toBeInTheDocument();
    expect(
      screen.getByText(/after the next inventory scan/i),
    ).toBeInTheDocument();
  });
});
