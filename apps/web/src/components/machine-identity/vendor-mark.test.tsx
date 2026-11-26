// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";

import { VendorMark } from "@/components/machine-identity/vendor-mark";
import {
  CA_PROVIDER_LOGOS,
  PROVIDER_LOGOS,
  vendorMarkSize,
  type VendorLogo,
} from "@/lib/machine-identity/backend-display";

const WORDMARK: VendorLogo = {
  src: "/assets/acme.svg",
  darkSrc: "/assets/acme-dark.svg",
  aspect: 3,
  wordmark: true,
};

describe("VendorMark", () => {
  it("gives a wordmark an accessible name and does not repeat it as text", () => {
    render(<VendorMark logo={WORDMARK} label="Acme" />);

    expect(screen.getByRole("img", { name: "Acme" })).toBeInTheDocument();
    // The asset already spells "Acme"; printing it again beside the mark
    // reads as a duplicated word.
    expect(screen.queryByText("Acme")).not.toBeInTheDocument();
  });

  it("renders a symbol as decorative beside its own text label", () => {
    render(
      <VendorMark logo={PROVIDER_LOGOS.INTUNE} label="Microsoft Intune" />,
    );

    expect(screen.getByText("Microsoft Intune")).toBeInTheDocument();
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
  });

  it("sizes the mark from the asset's own aspect ratio", () => {
    const { container } = render(<VendorMark logo={WORDMARK} label="Acme" />);

    const { width, height } = vendorMarkSize(WORDMARK);
    const image = container.querySelector("img");
    expect(image).toHaveStyle({ width: `${width}px`, height: `${height}px` });
  });

  it("names a wordmark once even when it ships a dark variant", () => {
    // Both a light and a dark file are rendered and CSS picks one. Naming each
    // image would announce the brand twice wherever styles are not computed,
    // and the wrong number of times if the theme rule ever stopped matching -
    // so the name lives on the wrapper.
    const { container } = render(<VendorMark logo={WORDMARK} label="Acme" />);

    expect(container.querySelectorAll("img")).toHaveLength(2);
    expect(screen.getAllByRole("img", { name: "Acme" })).toHaveLength(1);
  });

  it("renders a single file for a mark that reads on both themes", () => {
    // Smallstep's mark reads on both surfaces, so it needs no variant and
    // must not pay for a second request.
    const { container } = render(
      <VendorMark logo={CA_PROVIDER_LOGOS.SMALLSTEP} label="Smallstep" />,
    );

    expect(CA_PROVIDER_LOGOS.SMALLSTEP?.darkSrc).toBeUndefined();
    expect(container.querySelectorAll("img")).toHaveLength(1);
  });

  it("falls back to the vendor name when there is no art", () => {
    render(<VendorMark logo={undefined} label="Cisco" />);

    expect(screen.getByText("Cisco")).toBeInTheDocument();
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
  });

  it("renders nothing in mark-only mode when there is no art", () => {
    const { container } = render(
      <VendorMark logo={undefined} label="Cisco" markOnly />,
    );

    expect(container).toBeEmptyDOMElement();
  });
});
