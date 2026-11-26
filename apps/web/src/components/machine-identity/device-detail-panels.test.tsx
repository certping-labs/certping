// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";

import {
  DeviceIdentityPanels,
  DevicePlatformDataPanels,
  DevicePosturePanels,
} from "@/components/machine-identity/device-detail-panels";
import type { DeviceDetail } from "@/types/machine-identity-backend";

const SPARSE_DEVICE: DeviceDetail = {
  deviceXref: "dev_sparse",
  source: {
    sourceXref: "src_intune",
    provider: "INTUNE",
    sourceCategory: "ENDPOINT_MANAGEMENT",
    connectionProfileRef: "intune-primary",
    displayName: "Contoso Intune",
    description: null,
    configurationMetadata: null,
    syncEnabled: true,
    status: "ACTIVE",
  },
  sourceDeviceId: "native-device-id",
  sourceIdentifiers: null,
  deviceClass: null,
  serialNumber: null,
  deviceName: null,
  manufacturer: null,
  model: null,
  ownership: null,
  status: "REGISTERED",
  archived: false,
  registeredAt: null,
  lastSeenInSourceAt: null,
  decommissionedAt: null,
  endpointPosture: {
    operatingSystem: null,
    osVersion: null,
    complianceState: null,
    complianceStateRaw: null,
    jailbrokenState: null,
    managementAgent: null,
    enrollmentType: null,
    encrypted: null,
    supervised: null,
    mdmEnrolledAt: null,
    mdmLastSyncAt: null,
    vendorAttributes: null,
  },
  connectedThing: null,
  owner: null,
  providerData: null,
  createdAt: "2026-08-27T22:00:51Z",
  updatedAt: "2026-08-27T22:00:51Z",
};

describe("device detail panels", () => {
  it("renders a sparse provider record without assuming identity fields exist", () => {
    render(<DeviceIdentityPanels device={SPARSE_DEVICE} />);

    expect(screen.getByText("Registered")).toBeInTheDocument();
    expect(screen.getByText("native-device-id")).toBeInTheDocument();
  });

  it("explains that Intune never supplies an owner rather than implying missing data", () => {
    render(<DeviceIdentityPanels device={SPARSE_DEVICE} />);

    expect(
      screen.getByText(/does not request user or owner data/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Re-syncing will not change this/i),
    ).toBeInTheDocument();
  });

  it("falls back to the provider name for a source that could report an owner", () => {
    render(
      <DeviceIdentityPanels
        device={{
          ...SPARSE_DEVICE,
          source: { ...SPARSE_DEVICE.source, provider: "JAMF" },
        }}
      />,
    );

    expect(
      screen.getByText(/Jamf Pro has not reported an owner/i),
    ).toBeInTheDocument();
  });

  it("distinguishes unreported posture booleans from a negative answer", () => {
    render(<DevicePosturePanels device={SPARSE_DEVICE} />);

    // null is "we were not told", which must not read as "No".
    expect(screen.getAllByText("Not reported")).toHaveLength(3);
    expect(screen.queryByText("No")).not.toBeInTheDocument();
  });

  it("reports a device that is genuinely not encrypted as No", () => {
    render(
      <DevicePosturePanels
        device={{
          ...SPARSE_DEVICE,
          endpointPosture: {
            ...SPARSE_DEVICE.endpointPosture!,
            encrypted: false,
            supervised: true,
          },
        }}
      />,
    );

    expect(screen.getByText("No")).toBeInTheDocument();
    expect(screen.getByText("Yes")).toBeInTheDocument();
  });

  it("renders provider payloads as attributes instead of a JSON dump", () => {
    render(
      <DevicePlatformDataPanels
        device={{
          ...SPARSE_DEVICE,
          providerData: {
            schemaVersion: 1,
            updatedAt: "2026-08-27T22:00:51Z",
            attributes: { azureAdDeviceId: "aad-123" },
          },
        }}
      />,
    );

    expect(screen.getByText("Azure AD device ID")).toBeInTheDocument();
    expect(screen.getByText("aad-123")).toBeInTheDocument();
    expect(
      screen.getByText("No additional identifiers were reported."),
    ).toBeInTheDocument();
  });
});
