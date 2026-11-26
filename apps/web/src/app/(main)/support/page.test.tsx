// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";

import SupportPage from "@/app/(main)/support/page";

jest.mock("@/components/ui/page-header", () => ({
  PageHeader: ({ title }: { title: string }) => (
    <header>
      <h1>{title}</h1>
    </header>
  ),
}));

describe("support page", () => {
  it("shows the support guide with the open edition statement and the sections", () => {
    render(<SupportPage />);

    expect(
      screen.getByText(
        "CertPing OSS is free to self-host. For help deploying CertPing in the cloud, on-premises, or in an enterprise environment, read the docs or open an issue on GitHub.",
      ),
    ).toBeInTheDocument();
    for (const heading of [
      "How to request help",
      "What to include",
      "Cloud deployment support",
      "Self-hosted deployment support",
      "On-premises deployment support",
      "Commercial support",
    ]) {
      expect(screen.getByText(heading)).toBeInTheDocument();
    }
    expect(
      screen.getByRole("link", { name: "CertPing GitHub issues" }),
    ).toHaveAttribute(
      "href",
      "https://github.com/certping-labs/certping/issues",
    );
    expect(
      screen.getByRole("link", { name: "SECURITY.md" }),
    ).toBeInTheDocument();
    expect(screen.queryByText(/support@certping\.com/)).toBeNull();
    expect(
      screen.getByRole("link", { name: "CertPing Enterprise" }),
    ).toHaveAttribute("href", "https://www.certping.com/enterprise/");
    expect(
      screen.queryByRole("link", { name: /sponsor/i }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText(/license key/i)).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /activate|buy|upgrade/i }),
    ).toBeNull();
    expect(screen.queryByRole("link", { name: /open a ticket/i })).toBeNull();
  });
});
