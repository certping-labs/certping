// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";
import { GlobeIcon } from "@phosphor-icons/react/dist/ssr";

import { MetricCard } from "@/components/common/metric-card";

describe("MetricCard", () => {
  it("renders compact operational values without changing the card contract", () => {
    render(
      <MetricCard
        title="DNS"
        value="External"
        description="Managed outside CertPing"
        icon={GlobeIcon}
        tone="neutral"
        density="compact"
      />,
    );

    expect(screen.getByText("DNS")).toBeVisible();
    expect(screen.getByText("External")).toHaveClass("text-xl");
    expect(screen.getByText("Managed outside CertPing")).toBeVisible();
  });
});
