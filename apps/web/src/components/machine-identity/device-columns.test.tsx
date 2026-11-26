// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";
import type { CellContext, ColumnDef } from "@tanstack/react-table";

import {
  buildDeviceColumns,
  DEVICE_DEFAULT_HIDDEN_COLUMNS,
} from "@/components/machine-identity/device-columns";
import type { DeviceListItem } from "@/types/machine-identity-backend";

const DEVICE: DeviceListItem = {
  deviceXref: "dev_1",
  deviceName: "FIN-LAPTOP-04",
  serialNumber: "SN-1234",
  deviceClass: "MANAGED_ENDPOINT",
  operatingSystem: "Windows",
  osVersion: "10.0.22631",
  model: "Latitude 7440",
  ownerUpn: null,
  ownerDisplayName: null,
  complianceState: "NON_COMPLIANT",
  status: "ORPHANED",
  platformDisplayName: "Contoso Intune",
  lastSeenInSourceAt: "2026-08-20T09:00:00Z",
};

const PROVIDER_BY_DISPLAY_NAME = new Map([["Contoso Intune", "INTUNE"]]);

function renderCell(
  columns: ColumnDef<DeviceListItem>[],
  id: string,
  device: DeviceListItem,
) {
  const column = columns.find((candidate) => candidate.id === id);
  if (!column?.cell || typeof column.cell !== "function") {
    throw new Error(`Column ${id} has no cell renderer`);
  }
  const context = { row: { original: device } } as CellContext<
    DeviceListItem,
    unknown
  >;
  return render(<>{column.cell(context)}</>);
}

describe("device inventory columns", () => {
  const columns = buildDeviceColumns({
    providerByDisplayName: PROVIDER_BY_DISPLAY_NAME,
  });

  it("labels the source column by what the API actually sends", () => {
    // `platformDisplayName` is the source's display name, not a platform, so
    // the header used to promise something the payload does not contain.
    const source = columns.find((column) => column.id === "source");
    expect(source?.header).toBe("Source");
  });

  it("shows the vendor mark alongside the source name", () => {
    renderCell(columns, "source", DEVICE);

    expect(screen.getByText("Contoso Intune")).toBeInTheDocument();
    expect(document.querySelector("img")).toBeInTheDocument();
  });

  it("renders a source it cannot resolve without inventing a vendor", () => {
    renderCell(columns, "source", {
      ...DEVICE,
      platformDisplayName: "Some other source",
    });

    expect(screen.getByText("Some other source")).toBeInTheDocument();
    expect(document.querySelector("img")).not.toBeInTheDocument();
  });

  it("colours an orphaned device as a warning", () => {
    renderCell(columns, "status", DEVICE);
    expect(screen.getByText("Orphaned")).toBeInTheDocument();
  });

  it("labels an unreported compliance state instead of showing it as unknown-but-fine", () => {
    renderCell(columns, "compliance", { ...DEVICE, complianceState: null });
    expect(screen.getByText("Not reported")).toBeInTheDocument();
  });

  it("hides the owner column by default because no live connector fills it", () => {
    expect(DEVICE_DEFAULT_HIDDEN_COLUMNS).toContain("owner");
  });
});
