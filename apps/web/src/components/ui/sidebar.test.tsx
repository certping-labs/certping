// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

let mockIsMobile = false;

jest.mock("@/hooks/use-mobile", () => ({
  useIsMobile: () => mockIsMobile,
}));

import {
  Sidebar,
  SidebarProvider,
  SidebarTrigger,
  useSidebar,
} from "@/components/ui/sidebar";

describe("Sidebar", () => {
  beforeEach(() => {
    mockIsMobile = false;
    document.cookie = "";
  });

  it("throws if useSidebar is used outside SidebarProvider", () => {
    function Probe() {
      useSidebar();
      return null;
    }

    expect(() => render(<Probe />)).toThrow(
      "useSidebar must be used within a SidebarProvider.",
    );
  });

  it("renders collapsible=none as a static sidebar", () => {
    render(
      <SidebarProvider defaultOpen={false}>
        <Sidebar collapsible="none">
          <div>Content</div>
        </Sidebar>
      </SidebarProvider>,
    );

    expect(screen.getByText("Content")).toBeInTheDocument();
  });

  it("toggles desktop sidebar and persists cookie", async () => {
    const user = userEvent.setup();

    render(
      <SidebarProvider defaultOpen>
        <Sidebar>
          <SidebarTrigger />
        </Sidebar>
      </SidebarProvider>,
    );

    await user.click(screen.getByRole("button", { name: /toggle sidebar/i }));
    expect(document.cookie).toContain("sidebar:state=false");
  });

  it("supports controlled open state and calls onOpenChange", async () => {
    const user = userEvent.setup();
    const onOpenChange = jest.fn();

    render(
      <SidebarProvider open={false} onOpenChange={onOpenChange}>
        <Sidebar>
          <div>Content</div>
        </Sidebar>
        <SidebarTrigger />
      </SidebarProvider>,
    );

    await user.click(screen.getByRole("button", { name: /toggle sidebar/i }));
    expect(onOpenChange).toHaveBeenCalledWith(true);
    expect(document.cookie).toContain("sidebar:state=true");
  });

  it("toggles via keyboard shortcut on desktop", async () => {
    render(
      <SidebarProvider defaultOpen>
        <Sidebar>
          <div>Content</div>
        </Sidebar>
      </SidebarProvider>,
    );

    window.dispatchEvent(
      new KeyboardEvent("keydown", { key: "b", metaKey: true }),
    );
    expect(document.cookie).toContain("sidebar:state=false");
  });

  it("renders mobile sidebar using Sheet", async () => {
    mockIsMobile = true;
    const user = userEvent.setup();

    render(
      <SidebarProvider defaultOpen>
        <Sidebar side="left">
          <div>Mobile content</div>
        </Sidebar>
        <SidebarTrigger />
      </SidebarProvider>,
    );

    expect(document.querySelector('[data-mobile="true"]')).toBeNull();

    await user.click(screen.getByRole("button", { name: /toggle sidebar/i }));

    await waitFor(() =>
      expect(document.querySelector('[data-mobile="true"]')).not.toBeNull(),
    );
    expect(await screen.findByText("Mobile content")).toBeInTheDocument();
  });
});
