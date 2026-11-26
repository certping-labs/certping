// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { render, screen } from "@testing-library/react";
import React from "react";

import { ValueSummaryView } from "@/components/overview/value-summary";
import { formatHours, type ValueSummary } from "@/lib/value-summary";

const summary: ValueSummary = {
  days: 365,
  since: "2025-10-27T00:00:00Z",
  issuances: 1,
  renewals: 2,
  scheduledRenewals: 1,
  automatedDeployments: 3,
  renewedBeforeExpiry: 2,
  minutesSaved: 210,
  unmanagedDiscovered: 4,
  unmanagedExpiringSoon: 1,
  assumptions: {
    minutesPerRenewal: 60,
    minutesPerDeployment: 20,
    minutesPerIssuance: 30,
  },
};

describe("ValueSummaryView", () => {
  it("shows hours saved, renewals, deployments and the unmanaged certificates", () => {
    render(<ValueSummaryView summary={summary} isLoading={false} />);
    expect(screen.getByText("What CertPing did for you")).toBeInTheDocument();
    expect(screen.getByText("3.5")).toBeInTheDocument();
    expect(
      screen.getByText(/Discovery found 4 certificates/),
    ).toBeInTheDocument();
    expect(screen.getByText(/1 expiring within 30 days/)).toBeInTheDocument();
    expect(screen.getByText(/60 minutes per renewal/)).toBeInTheDocument();
  });

  it("explains itself before CertPing has done anything", () => {
    render(
      <ValueSummaryView
        summary={{
          ...summary,
          issuances: 0,
          renewals: 0,
          scheduledRenewals: 0,
          automatedDeployments: 0,
          renewedBeforeExpiry: 0,
          minutesSaved: 0,
          unmanagedDiscovered: 0,
          unmanagedExpiringSoon: 0,
        }}
        isLoading={false}
      />,
    );
    expect(
      screen.getByText(/the work it saves shows up here/),
    ).toBeInTheDocument();
    expect(screen.queryByText(/Discovery found/)).not.toBeInTheDocument();
  });
});

describe("ValueSummaryView with fields the server may drop", () => {
  it("hides renewed before expiry when the server does not send it", () => {
    const { renewedBeforeExpiry: _dropped, ...withoutField } = summary;
    void _dropped;
    render(<ValueSummaryView summary={withoutField} isLoading={false} />);
    expect(screen.queryByText("renewed before expiry")).not.toBeInTheDocument();
    expect(
      screen.getByText("renewals started on schedule"),
    ).toBeInTheDocument();
  });

  it("shows renewed before expiry when the server sends a number", () => {
    render(<ValueSummaryView summary={summary} isLoading={false} />);
    expect(screen.getByText("renewed before expiry")).toBeInTheDocument();
  });

  it("does not claim certificates are expiring when the count is missing", () => {
    render(
      <ValueSummaryView
        summary={{ ...summary, unmanagedExpiringSoon: null }}
        isLoading={false}
      />,
    );
    expect(
      screen.getByText(/Discovery found 4 certificates/),
    ).toBeInTheDocument();
    expect(
      screen.queryByText(/expiring within 30 days/),
    ).not.toBeInTheDocument();
  });
});

describe("formatHours", () => {
  it("rounds sensibly", () => {
    expect(formatHours(0)).toBe("0");
    expect(formatHours(60)).toBe("1");
    expect(formatHours(90)).toBe("1.5");
    expect(formatHours(6000)).toBe("100");
  });
});
