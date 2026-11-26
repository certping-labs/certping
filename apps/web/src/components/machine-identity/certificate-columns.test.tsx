// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";
import type { CellContext } from "@tanstack/react-table";

import { CERTIFICATE_COLUMNS } from "@/components/machine-identity/certificate-columns";
import type {
  CertificateDeviceSummary,
  CertificateListItem,
} from "@/types/machine-identity-backend";

function renderDeviceCell(device: CertificateDeviceSummary | null) {
  const column = CERTIFICATE_COLUMNS.find(
    (candidate) => candidate.id === "device",
  );
  if (!column?.cell || typeof column.cell !== "function") {
    throw new Error("Column device has no cell renderer");
  }
  const context = { row: { original: { device } } } as CellContext<
    CertificateListItem,
    unknown
  >;
  return render(<>{column.cell(context)}</>);
}

describe("certificate inventory device column", () => {
  /**
   * "Unmatched" means "we cannot tell whose credential this is", which is a thing operators chase.
   * An archived device is known — it was taken out of the inventory on purpose — so reporting it as
   * unmatched sends someone hunting a certificate nobody lost.
   */
  it("names an archived device and keeps its link instead of reporting it unmatched", () => {
    renderDeviceCell({
      deviceXref: "dev_1",
      deviceName: "FIN-LAPTOP-04",
      status: "ORPHANED",
      archived: true,
    });

    expect(screen.getByRole("link", { name: "FIN-LAPTOP-04" })).toHaveAttribute(
      "href",
      "/machine-identity/devices/dev_1",
    );
    expect(screen.getByText("(archived)")).toBeInTheDocument();
    expect(screen.queryByText("Unmatched")).not.toBeInTheDocument();
  });

  it("leaves a live device unmarked", () => {
    renderDeviceCell({
      deviceXref: "dev_1",
      deviceName: "FIN-LAPTOP-04",
      status: "REGISTERED",
      archived: false,
    });

    expect(screen.getByText("FIN-LAPTOP-04")).toBeInTheDocument();
    expect(screen.queryByText("(archived)")).not.toBeInTheDocument();
  });

  it("reserves unmatched for a certificate with no device at all", () => {
    renderDeviceCell(null);

    expect(screen.getByText("Unmatched")).toBeInTheDocument();
  });
});
