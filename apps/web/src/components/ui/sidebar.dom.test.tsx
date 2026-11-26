// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import {
  Sidebar,
  SidebarContent,
  SidebarProvider,
  SidebarRail,
  SidebarMenu,
  SidebarMenuAction,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarMenuSkeleton,
  SidebarMenuSub,
  SidebarMenuSubButton,
  SidebarMenuSubItem,
  SidebarTrigger,
  useSidebar,
} from "@/components/ui/sidebar";

let mockIsMobile = false;
jest.mock("@/hooks/use-mobile", () => ({
  useIsMobile: () => mockIsMobile,
}));

describe("Sidebar", () => {
  it("throws when useSidebar is used outside SidebarProvider", () => {
    function Consumer() {
      useSidebar();
      return null;
    }
    expect(() => render(<Consumer />)).toThrow(
      "useSidebar must be used within a SidebarProvider.",
    );
  });

  it("toggles desktop sidebar state and persists cookie", async () => {
    mockIsMobile = false;
    const user = userEvent.setup();

    const { container } = render(
      <SidebarProvider defaultOpen>
        <Sidebar>
          <SidebarContent>Nav</SidebarContent>
        </Sidebar>
        <SidebarTrigger />
      </SidebarProvider>,
    );

    expect(container.querySelector('[data-state="expanded"]')).toBeTruthy();

    const sidebarTrigger = screen.getByRole("button", {
      name: /toggle sidebar/i,
    });
    expect(sidebarTrigger).toHaveClass("size-11", "md:size-8");

    await user.click(sidebarTrigger);

    expect(container.querySelector('[data-state="collapsed"]')).toBeTruthy();
    expect(document.cookie).toContain("sidebar:state=false");
  });

  it("supports collapsible=none layout on desktop", () => {
    mockIsMobile = false;
    render(
      <SidebarProvider defaultOpen>
        <Sidebar collapsible="none">Content</Sidebar>
      </SidebarProvider>,
    );

    expect(screen.getByText("Content")).toBeInTheDocument();
  });

  it("toggles via keyboard shortcut on desktop", async () => {
    mockIsMobile = false;
    const user = userEvent.setup();
    const { container } = render(
      <SidebarProvider defaultOpen>
        <Sidebar>
          <SidebarContent>Nav</SidebarContent>
        </Sidebar>
        <SidebarTrigger />
      </SidebarProvider>,
    );

    expect(container.querySelector('[data-state="expanded"]')).toBeTruthy();
    await user.keyboard("{Meta>}{b}{/Meta}");
    expect(container.querySelector('[data-state="collapsed"]')).toBeTruthy();
  });

  it("toggles via rail click on desktop", async () => {
    mockIsMobile = false;
    const user = userEvent.setup();
    const { container } = render(
      <SidebarProvider defaultOpen>
        <Sidebar>
          <SidebarContent>Nav</SidebarContent>
          <SidebarRail />
        </Sidebar>
      </SidebarProvider>,
    );

    expect(container.querySelector('[data-state="expanded"]')).toBeTruthy();
    await user.click(screen.getByRole("button", { name: /toggle sidebar/i }));
    expect(container.querySelector('[data-state="collapsed"]')).toBeTruthy();
  });

  it("supports controlled open state via props", async () => {
    mockIsMobile = false;
    const user = userEvent.setup();
    const onOpenChange = jest.fn();

    render(
      <SidebarProvider open onOpenChange={onOpenChange}>
        <Sidebar>
          <SidebarContent>Nav</SidebarContent>
        </Sidebar>
        <SidebarTrigger />
      </SidebarProvider>,
    );

    await user.click(screen.getByRole("button", { name: /toggle sidebar/i }));
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it("toggles mobile sidebar via Sheet when mobile", async () => {
    mockIsMobile = true;
    const user = userEvent.setup();

    render(
      <SidebarProvider defaultOpen>
        <Sidebar>
          <SidebarContent>Nav</SidebarContent>
        </Sidebar>
        <SidebarTrigger />
      </SidebarProvider>,
    );

    expect(screen.queryByText("Nav")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /toggle sidebar/i }));
    expect(await screen.findByText("Nav")).toBeInTheDocument();
  });

  it("renders menu variants and tooltip behavior without flake", async () => {
    mockIsMobile = false;
    const user = userEvent.setup();

    const { container } = render(
      <SidebarProvider defaultOpen={false}>
        <Sidebar>
          <SidebarContent>
            <SidebarMenu>
              <SidebarMenuItem>
                <SidebarMenuButton tooltip="Tooltip text">
                  Menu item
                </SidebarMenuButton>
                <SidebarMenuAction showOnHover aria-label="Action">
                  +
                </SidebarMenuAction>
                <SidebarMenuBadge>9</SidebarMenuBadge>
              </SidebarMenuItem>
            </SidebarMenu>
            <SidebarMenuSkeleton showIcon />
            <SidebarMenuSub>
              <SidebarMenuSubItem>
                <SidebarMenuSubButton size="sm" href="/x">
                  Sub item
                </SidebarMenuSubButton>
              </SidebarMenuSubItem>
            </SidebarMenuSub>
          </SidebarContent>
        </Sidebar>
      </SidebarProvider>,
    );

    expect(screen.getByRole("button", { name: /menu item/i })).toHaveClass(
      "h-11",
      "md:h-8",
    );
    expect(screen.getByText("9")).toBeInTheDocument();
    expect(screen.getByText("Sub item")).toHaveAttribute("href", "/x");
    expect(screen.getByText("Sub item")).toHaveClass("h-11", "md:h-7");
    expect(
      document.querySelector('[data-sidebar="menu-skeleton-icon"]'),
    ).toBeTruthy();

    await user.hover(screen.getByRole("button", { name: /menu item/i }));
    await screen.findByRole("tooltip");
    const visualTooltip = screen
      .getAllByText("Tooltip text")
      .find(
        (element) =>
          element.getAttribute("data-slot") === "tooltip-content" &&
          element.classList.contains("bg-foreground"),
      );

    expect(visualTooltip).toBeDefined();
    expect(container.contains(visualTooltip ?? null)).toBe(false);
  });
});
