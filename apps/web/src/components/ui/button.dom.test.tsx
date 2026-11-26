// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";

import { Button } from "@/components/ui/button";

describe("Button", () => {
  it("renders children when not pending", () => {
    render(<Button>Submit</Button>);
    expect(screen.getByRole("button", { name: "Submit" })).toBeInTheDocument();
  });

  it("renders loading content when pending and uses loadingtext when provided", () => {
    render(
      <Button isPending loadingtext="Saving">
        Submit
      </Button>,
    );
    expect(screen.getByText("Saving")).toBeInTheDocument();
    expect(screen.getByRole("button")).toHaveAttribute("aria-busy", "true");
  });

  it("swaps to the loading label in place and keeps it off the DOM", () => {
    const { rerender } = render(<Button loadingtext="Saving…">Save</Button>);
    const button = screen.getByRole("button", { name: "Save" });

    rerender(
      <Button isPending loadingtext="Saving…">
        Save
      </Button>,
    );

    expect(screen.getByRole("button", { name: "Saving…" })).toBe(button);
    expect(button).not.toHaveAttribute("loadingtext");

    rerender(<Button loadingtext="Saving…">Save</Button>);

    expect(screen.getByRole("button", { name: "Save" })).toBe(button);
    expect(button.querySelector("svg")).toBeNull();
  });

  it("updates a changing label next to an icon", () => {
    const { rerender } = render(
      <Button>
        <svg data-testid="icon" />
        {"Copy"}
      </Button>,
    );

    rerender(
      <Button>
        <svg data-testid="icon" />
        {"Copied"}
      </Button>,
    );

    const button = screen.getByRole("button", { name: "Copied" });
    expect(button).toContainElement(screen.getByTestId("icon"));
  });

  it("keeps a run of text and numbers as one label", () => {
    render(<Button>Show {3} more</Button>);
    expect(
      screen.getByRole("button", { name: "Show 3 more" }).children,
    ).toHaveLength(1);
  });

  it("is a pill-shaped Material Glass primary by default", () => {
    render(<Button>Renew</Button>);
    const button = screen.getByRole("button", { name: "Renew" });
    expect(button).toHaveClass("rounded-full", "mg-btn", "mg-btn-primary");
    expect(button).not.toHaveAttribute("aria-busy");
  });

  it("lets a caller override the shape", () => {
    render(<Button className="rounded-lg">Square</Button>);
    const button = screen.getByRole("button", { name: "Square" });
    expect(button).toHaveClass("rounded-lg");
    expect(button).not.toHaveClass("rounded-full");
  });

  it("supports asChild via Slot", () => {
    render(
      <Button asChild>
        <a href="/x">Go</a>
      </Button>,
    );
    expect(screen.getByRole("link", { name: "Go" })).toHaveAttribute(
      "href",
      "/x",
    );
  });
});
