// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { PageHeader } from "@/components/ui/page-header";

const INFO = [
  "Which certificates renew when, and which renewals failed.",
  "Renew one now from its row.",
] as const;

describe("PageHeader info", () => {
  it("explains the page from a keyboard-reachable trigger beside the title", async () => {
    const user = userEvent.setup();
    render(<PageHeader title="Rotation" info={INFO} />);

    await user.tab();

    const trigger = screen.getByRole("button", {
      name: "About Rotation",
    });
    expect(trigger).toHaveFocus();
    const tooltip = await screen.findByRole("tooltip");
    expect(tooltip).toHaveTextContent(INFO.join(""));
  });

  it("closes the explanation on Escape", async () => {
    const user = userEvent.setup();
    render(<PageHeader title="Rotation" info={INFO} />);

    await user.tab();
    await screen.findByRole("tooltip");
    await user.keyboard("{Escape}");

    expect(screen.queryByRole("tooltip")).not.toBeInTheDocument();
  });

  it.each([undefined, []])("shows no trigger without info (%p)", (info) => {
    render(<PageHeader title="Rotation" info={info} />);

    expect(
      screen.queryByRole("button", { name: /about/i }),
    ).not.toBeInTheDocument();
  });
});

describe("PageHeader navigation", () => {
  it("renders breadcrumbs as a labelled trail ending at the current page", () => {
    render(
      <PageHeader
        title="example.com"
        breadcrumbs={[{ label: "Certificates", href: "/cert-manager" }]}
      />,
    );

    const trail = screen.getByRole("navigation", { name: "Breadcrumb" });
    expect(trail).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Certificates" })).toHaveAttribute(
      "href",
      "/cert-manager",
    );
    expect(screen.getAllByText("example.com")[0]).toHaveAttribute(
      "aria-current",
      "page",
    );
  });

  it("shows a back control for backHref when there are no breadcrumbs", () => {
    render(<PageHeader title="Add certificate" backHref="/cert-manager" />);

    expect(screen.getByRole("link", { name: "Back" })).toHaveAttribute(
      "href",
      "/cert-manager",
    );
  });

  it("lets breadcrumbs replace the back control", () => {
    render(
      <PageHeader
        title="Add certificate"
        backHref="/cert-manager"
        breadcrumbs={[{ label: "Certificates", href: "/cert-manager" }]}
      />,
    );

    expect(
      screen.queryByRole("link", { name: "Back" }),
    ).not.toBeInTheDocument();
  });
});
