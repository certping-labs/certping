// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen, within } from "@testing-library/react";

import { AuthCardShell } from "@/components/auth/auth-card-shell";

describe("AuthCardShell", () => {
  it("presents one focused authentication surface", () => {
    render(
      <AuthCardShell
        title="Sign in to CertPing"
        description="Access the certificate control plane."
        footer={<span>Need help?</span>}
      >
        <button type="button">Sign in</button>
      </AuthCardShell>,
    );

    expect(
      screen.getByRole("heading", { name: "Sign in to CertPing" }),
    ).toBeInTheDocument();
    const authSurface = screen.getByRole("region");
    const main = screen.getByRole("main");
    expect(authSurface).not.toHaveClass("dark");
    expect(authSurface).toHaveClass("certping-auth-surface");
    expect(main).not.toHaveClass("items-center");
    expect(authSurface.parentElement).toHaveClass("my-auto");
    expect(
      within(authSurface).getByRole("img", { name: "CertPing" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByText("Secure workspace access"),
    ).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign in" })).toBeInTheDocument();
    expect(screen.getByText("Need help?")).toBeInTheDocument();
    expect(screen.queryByRole("navigation")).not.toBeInTheDocument();
    expect(
      screen.queryByText("Return to your certificate control plane."),
    ).not.toBeInTheDocument();
  });

  it("keeps contextual labels in the same reading axis as the task heading", () => {
    render(
      <AuthCardShell
        eyebrow="Account recovery"
        title="Reset your password"
        description="Request a secure reset link."
      >
        <button type="button">Send link</button>
      </AuthCardShell>,
    );

    const eyebrow = screen.getByText("Account recovery");
    const heading = screen.getByRole("heading", {
      name: "Reset your password",
    });

    expect(
      eyebrow.compareDocumentPosition(heading) &
        Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
  });

  it("shows the open source terms beside the form on wide screens", () => {
    const { container } = render(
      <AuthCardShell title="Sign in" description="Welcome back.">
        <button type="button">Next</button>
      </AuthCardShell>,
    );

    const panel = screen.getByRole("complementary", {
      name: "Certificate lifecycle management you run yourself",
    });
    expect(panel).toHaveClass("hidden", "lg:block");
    expect(within(panel).getByText("Free and open source")).toBeInTheDocument();
    expect(
      within(panel).getByText(/licensed under the Apache License 2.0/),
    ).toBeInTheDocument();
    expect(within(panel).getByText("Provided as is")).toBeInTheDocument();
    expect(container.firstElementChild).toHaveClass("certping-noise");
  });

  it("shows the copyright on every screen size", () => {
    render(
      <AuthCardShell title="Sign in" description="Welcome back.">
        <button type="button">Next</button>
      </AuthCardShell>,
    );

    const notice = screen.getByText(/Seaionl Inc\. CertPing is open source/);
    expect(notice.textContent).toContain(
      `\u00a9 ${new Date().getFullYear()} Seaionl Inc.`,
    );
    expect(screen.getByRole("main")).toContainElement(notice);
  });

  it("has no links to hosted-service pages", () => {
    render(
      <AuthCardShell title="Sign in" description="Welcome back.">
        <button type="button">Next</button>
      </AuthCardShell>,
    );

    for (const name of [
      "Privacy",
      "Terms",
      "Support",
      "Status",
      "Privacy choices",
    ]) {
      expect(screen.queryByRole("link", { name })).not.toBeInTheDocument();
      expect(screen.queryByRole("button", { name })).not.toBeInTheDocument();
    }
  });
});
