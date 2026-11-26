// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";

import { RenewalForecastPanel } from "./renewal-forecast";
import { buildRenewalForecast } from "@/lib/overview-renewal-forecast";

const NOW = Date.UTC(2026, 9, 25);
const days = (n: number) =>
  new Date(NOW + n * 24 * 60 * 60 * 1000).toISOString();

describe("RenewalForecastPanel", () => {
  it("renders the horizons, twelve week bars and the busiest week", () => {
    const forecast = buildRenewalForecast(
      [
        { domain: "a.example", status: "ACTIVE", validTo: days(3) },
        { domain: "b.example", status: "ACTIVE", validTo: days(20) },
        { domain: "c.example", status: "ACTIVE", validTo: days(19) },
      ],
      NOW,
    );
    render(<RenewalForecastPanel forecast={forecast} />);

    expect(
      screen.getByRole("heading", { name: "Renewal forecast" }),
    ).toBeInTheDocument();
    expect(
      screen.getByTestId("renewal-forecast-weeks").querySelectorAll("li"),
    ).toHaveLength(12);
    expect(
      screen.getByText(/busiest week starts 8 Nov with 2 expiries/i),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: /plan renewals/i }),
    ).toHaveAttribute("href", "/cert-manager/rotation");
    expect(
      screen.getByLabelText(
        /week of 8 Nov: 2 expiries \(b\.example, c\.example\)/i,
      ),
    ).toBeInTheDocument();
  });

  it("explains an empty inventory", () => {
    render(
      <RenewalForecastPanel
        forecast={buildRenewalForecast([], NOW)}
        renewalsHref="/cert-manager"
      />,
    );
    expect(
      screen.getByText(/no certificates with an expiry date yet/i),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: /plan renewals/i }),
    ).toHaveAttribute("href", "/cert-manager");
  });
});
