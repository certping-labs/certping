// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";

import { FeatureDisabledPage } from "@/components/common/feature-disabled";
import { useAuthStore } from "@/stores/auth-store";
import type { SsoUser } from "@/types/auth";

const baseUser = {
  id: "u1",
  email: "admin@example.com",
  organizationId: "org-1",
  organizationName: "Org",
  roles: ["USER"],
  permissions: [],
  authMethod: "LOCAL",
} as unknown as SsoUser;

const viewer = baseUser;

describe("FeatureDisabledPage", () => {
  afterEach(() => {
    useAuthStore.setState({ user: null });
  });

  it("names the feature from the flag catalogue and uses the agreed copy", () => {
    useAuthStore.setState({ user: viewer });
    render(<FeatureDisabledPage featureKey="DISCOVERY" />);

    expect(
      screen.getByRole("heading", {
        level: 1,
        name: "Certificate discovery isn't available",
      }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        "This feature isn't available. To request access, ask your CertPing administrator.",
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Back to dashboard" }),
    ).toHaveAttribute("href", "/dashboard");
    expect(
      screen.queryByRole("link", { name: /feature flags/i }),
    ).not.toBeInTheDocument();
  });

  it("tells the user to ask their administrator, without a link", () => {
    useAuthStore.setState({ user: viewer });
    render(<FeatureDisabledPage featureKey="ALERTS" />);

    expect(
      screen.getByText(
        "This feature isn't available. To request access, ask your CertPing administrator.",
      ),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: /request access/i }),
    ).not.toBeInTheDocument();
  });

  it("renders a region-sized variant without the dashboard link", () => {
    useAuthStore.setState({ user: viewer });
    render(
      <FeatureDisabledPage
        featureKey="IOT_DEVICE_MANAGEMENT"
        variant="inline"
      />,
    );

    expect(
      screen.getByRole("heading", {
        level: 2,
        name: "Machine Identity isn't available",
      }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("main")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: "Back to dashboard" }),
    ).not.toBeInTheDocument();
  });
});
