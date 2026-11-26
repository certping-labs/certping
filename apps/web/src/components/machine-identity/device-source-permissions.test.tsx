// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";

import { DeviceSourcePermissions } from "@/components/machine-identity/device-source-permissions";

describe("DeviceSourcePermissions", () => {
  it("shows the capability and exact Graph role for granted and missing permissions", () => {
    render(
      <DeviceSourcePermissions
        permissions={[
          {
            name: "DeviceManagementManagedDevices.Read.All",
            granted: true,
          },
          {
            name: "DeviceManagementManagedDevices.PrivilegedOperations.All",
            granted: false,
          },
        ]}
      />,
    );

    expect(screen.getByText("Managed device inventory")).toBeInTheDocument();
    expect(screen.getByText("Device check-in")).toBeInTheDocument();
    expect(screen.getByText("Granted")).toBeInTheDocument();
    expect(screen.getByText("Missing")).toBeInTheDocument();
    expect(
      screen.getByText(
        "DeviceManagementManagedDevices.PrivilegedOperations.All",
      ),
    ).toBeInTheDocument();
  });

  it("explains that health has not reported permissions yet", () => {
    render(<DeviceSourcePermissions permissions={[]} />);
    expect(screen.getByText(/No permission report has arrived/)).toBeVisible();
  });
});
