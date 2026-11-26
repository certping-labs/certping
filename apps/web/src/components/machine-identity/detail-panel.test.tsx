// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import {
  DefinitionList,
  DynamicDataPanel,
} from "@/components/machine-identity/detail-panel";

describe("DefinitionList", () => {
  it("renders one em dash for an absent value, whatever shape the absence takes", () => {
    render(
      <DefinitionList
        items={[
          { label: "Signature hash", value: null },
          { label: "Renewal window", value: undefined },
          { label: "Certificate scope", value: "Device" },
        ]}
      />,
    );

    expect(screen.getAllByText("—")).toHaveLength(2);
    expect(screen.getByText("Device")).toBeInTheDocument();
  });

  it("offers a copy control only where the caller asked for one", () => {
    render(
      <DefinitionList
        items={[
          { label: "Serial number", value: "51AD5C5D", copyable: true },
          { label: "Common name", value: "device-01" },
        ]}
      />,
    );

    expect(
      screen.getByRole("button", { name: "Copy Serial number" }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Copy Common/ })).toBeNull();
  });
});

describe("DynamicDataPanel", () => {
  const SNAPSHOT = {
    id: "695c77b2-88c9-431e-b290-6a7e54ab3655",
    scepServerHosts: "agent.certping.example",
    keyUsage: "keyEncipherment,digitalSignature",
    extendedKeyUsages: [
      { name: "Client Authentication", objectIdentifier: "1.3.6.1.5.5.7.3.2" },
    ],
  };

  it("labels provider fields instead of dumping JSON at the operator", () => {
    render(<DynamicDataPanel title="Provider snapshot" value={SNAPSHOT} />);

    expect(screen.getByText("SCEP server hosts")).toBeInTheDocument();
    expect(screen.getByText("Extended key usages")).toBeInTheDocument();
    expect(screen.getByText("Object identifier")).toBeInTheDocument();
    expect(screen.getByText("Client Authentication")).toBeInTheDocument();
  });

  it("keeps the verbatim payload out of the DOM until it is asked for", async () => {
    render(<DynamicDataPanel title="Provider snapshot" value={SNAPSHOT} />);

    // Serializing a large snapshot on every render costs a page nobody
    // expanded; the disclosure is what pays for it.
    expect(screen.queryByText(/"scepServerHosts"/)).toBeNull();

    await userEvent.click(screen.getByText("Show raw payload"));
    expect(screen.getByText(/"scepServerHosts"/)).toBeInTheDocument();
  });

  it("explains an empty payload rather than rendering an empty panel", () => {
    render(
      <DynamicDataPanel
        title="Issues"
        value={[]}
        emptyMessage="The last health check found no issues."
      />,
    );

    expect(
      screen.getByText("The last health check found no issues."),
    ).toBeInTheDocument();
    expect(screen.queryByText("Show raw payload")).toBeNull();
  });

  it("renders a boolean as a word, not as true/false", () => {
    render(
      <DynamicDataPanel
        title="Health metadata"
        value={{ permissionsValidated: true, entraDevicesReadValidated: false }}
      />,
    );

    expect(screen.getByText("Yes")).toBeInTheDocument();
    expect(screen.getByText("No")).toBeInTheDocument();
  });
});
