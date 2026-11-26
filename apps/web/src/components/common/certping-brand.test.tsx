// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";

import { CertPingBrand } from "@/components/common/certping-brand";

describe("CertPingBrand", () => {
  it("uses the scalable SVG symbol and a live-text wordmark with the registered mark", () => {
    const { container } = render(<CertPingBrand surface="dark" />);

    expect(screen.getByRole("img", { name: "CertPing" })).toHaveAttribute(
      "src",
      expect.stringContaining(".svg"),
    );
    expect(container).toHaveTextContent("CertPing®");
    expect(container.querySelector("sup")).toHaveAccessibleName(
      "registered trademark",
    );
    expect(container).not.toHaveTextContent("™");
  });
});
