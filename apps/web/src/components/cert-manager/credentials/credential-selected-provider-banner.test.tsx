// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import { render, screen } from "@testing-library/react";

import { CredentialSelectedProviderBanner } from "@/components/cert-manager/credentials/credential-selected-provider-banner";

describe("CredentialSelectedProviderBanner", () => {
  it("renders docs link with safe target/rel", () => {
    render(
      <CredentialSelectedProviderBanner
        label="AWS ACM"
        description="Example"
        docsUrl="https://example.com/docs"
        providerKey="aws"
        providerApiValue="AWS_ACM"
      />,
    );

    const link = screen.getByRole("link", { name: /docs/i });
    expect(link).toHaveAttribute("href", "https://example.com/docs");
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noreferrer");
  });
});
