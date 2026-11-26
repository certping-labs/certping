// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { CertificateInventoryProgress } from "@/components/cert-manager/certificate-inventory-progress";

describe("CertificateInventoryProgress", () => {
  it("stays hidden after the complete inventory is loaded", () => {
    const { container } = render(
      <CertificateInventoryProgress
        isLoading={false}
        hasError={false}
        loadedItems={200}
        totalItems={200}
        onRetry={jest.fn()}
      />,
    );

    expect(container).toBeEmptyDOMElement();
  });

  it("reports progressive loading with an accessible determinate value", () => {
    render(
      <CertificateInventoryProgress
        isLoading
        hasError={false}
        loadedItems={100}
        totalItems={400}
        onRetry={jest.fn()}
      />,
    );

    expect(screen.getByRole("status")).toHaveTextContent(
      "Loading certificate inventory",
    );
    expect(screen.getByText("100 of 400")).toBeVisible();
    expect(
      screen.getByRole("progressbar", {
        name: "Certificate inventory loading progress",
      }),
    ).toHaveAttribute("aria-valuenow", "25");
  });

  it("reports zero progress before a total is available", () => {
    render(
      <CertificateInventoryProgress
        isLoading
        hasError={false}
        loadedItems={0}
        totalItems={0}
        onRetry={jest.fn()}
      />,
    );

    expect(
      screen.getByRole("progressbar", {
        name: "Certificate inventory loading progress",
      }),
    ).toHaveAttribute("aria-valuenow", "0");
  });

  it("keeps partial results visible and offers a retry", async () => {
    const user = userEvent.setup();
    const onRetry = jest.fn();
    render(
      <CertificateInventoryProgress
        isLoading={false}
        hasError
        loadedItems={100}
        totalItems={1_000}
        onRetry={onRetry}
      />,
    );

    expect(screen.getByRole("alert")).toHaveTextContent(
      "Showing 100 of approximately 1,000 certificates",
    );
    await user.click(screen.getByRole("button", { name: "Retry remaining" }));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });
});
