// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { GlobeIcon, FlowArrowIcon } from "@phosphor-icons/react/dist/ssr";

import { NavSecondary } from "@/components/sidebar/nav-secondary";
import { SidebarProvider } from "@/components/ui/sidebar";

jest.mock("next/navigation", () => ({
  usePathname: () => "/cert-manager/rotation",
}));

jest.mock("@/hooks/use-mobile", () => ({
  useIsMobile: () => false,
}));

describe("NavSecondary", () => {
  afterEach(() => {
    window.localStorage.clear();
  });

  it("keeps the current page and highlighted shortcuts bright while the rest dims", () => {
    const queryClient = new QueryClient();
    const { container } = render(
      <QueryClientProvider client={queryClient}>
        <SidebarProvider>
          <NavSecondary
            groupLabel="Certificate lifecycle"
            emphasis="focus"
            activeUrl="/cert-manager/rotation"
            items={[
              {
                title: "Certificates",
                url: "/cert-manager",
                icon: GlobeIcon,
                highlight: true,
              },
              {
                title: "Rotation",
                url: "/cert-manager/rotation",
                icon: GlobeIcon,
              },
              {
                title: "Deployments",
                url: "/cert-manager/deployments",
                icon: FlowArrowIcon,
              },
            ]}
          />
        </SidebarProvider>
      </QueryClientProvider>,
    );

    const certificates = screen.getByRole("link", { name: "Certificates" });
    expect(certificates).toHaveAttribute("data-highlight", "true");
    expect(certificates).toHaveClass("text-sidebar-foreground");
    expect(screen.getByRole("link", { name: "Rotation" })).toHaveAttribute(
      "data-current",
      "true",
    );
    const deployments = screen.getByRole("link", { name: "Deployments" });
    expect(deployments).not.toHaveAttribute("data-highlight");
    expect(deployments).not.toHaveAttribute("data-current");
    expect(
      container.querySelector('[data-emphasis="focus"]')?.className,
    ).toContain(":opacity-[0.62]");
  });

  it("dims the group but highlights no shortcut outside its module", () => {
    const queryClient = new QueryClient();
    const { container } = render(
      <QueryClientProvider client={queryClient}>
        <SidebarProvider>
          <NavSecondary
            groupLabel="Certificate lifecycle"
            emphasis="recede"
            activeUrl="/dashboard"
            items={[
              {
                title: "Certificates",
                url: "/cert-manager",
                icon: GlobeIcon,
                highlight: true,
              },
            ]}
          />
        </SidebarProvider>
      </QueryClientProvider>,
    );

    expect(
      screen.getByRole("link", { name: "Certificates" }),
    ).not.toHaveAttribute("data-highlight");
    expect(
      container.querySelector('[data-emphasis="recede"]')?.className,
    ).toContain(":opacity-[0.62]");
  });

  it("renders submenu navigation with a single anchor", () => {
    const queryClient = new QueryClient();
    const { container } = render(
      <QueryClientProvider client={queryClient}>
        <SidebarProvider>
          <NavSecondary
            groupLabel=""
            items={[
              {
                title: "Certificate lifecycle",
                icon: GlobeIcon,
                subMenu: [
                  {
                    title: "Rotation",
                    url: "/cert-manager/rotation",
                    icon: GlobeIcon,
                  },
                  {
                    title: "Certificates",
                    url: "/cert-manager",
                    icon: FlowArrowIcon,
                  },
                ],
              },
            ]}
          />
        </SidebarProvider>
      </QueryClientProvider>,
    );

    expect(screen.getByRole("link", { name: "Rotation" })).toHaveAttribute(
      "href",
      "/cert-manager/rotation",
    );
    expect(screen.getByRole("link", { name: "Certificates" })).toHaveClass(
      "text-sidebar-foreground",
    );
    expect(
      screen.getByRole("link", { name: "Rotation" }).querySelector("svg"),
    ).toBeInTheDocument();
    expect(container.querySelector('[data-sidebar="menu-sub"]')).toHaveClass(
      "ml-4",
      "border-l",
      "border-sidebar-border",
      "pl-2",
    );
    expect(container.querySelector("a a")).toBeNull();
  });

  it("does not load deployment data when navigation is only hovered", async () => {
    const user = userEvent.setup();
    const queryClient = new QueryClient();
    render(
      <QueryClientProvider client={queryClient}>
        <SidebarProvider>
          <NavSecondary
            groupLabel=""
            items={[
              {
                title: "Deployments",
                icon: FlowArrowIcon,
                url: "/cert-manager/deployments",
              },
            ]}
          />
        </SidebarProvider>
      </QueryClientProvider>,
    );

    await user.hover(screen.getByRole("link", { name: "Deployments" }));

    expect(queryClient.getQueryCache().getAll()).toHaveLength(0);
  });

  it("keeps group destinations available when the sidebar is collapsed", () => {
    window.localStorage.setItem(
      "sidebar-group-collapsed:Certificate Lifecycle",
      "collapsed",
    );
    const queryClient = new QueryClient();

    render(
      <QueryClientProvider client={queryClient}>
        <SidebarProvider defaultOpen={false}>
          <NavSecondary
            groupLabel="Certificate Lifecycle"
            items={[
              {
                title: "Certificates",
                icon: FlowArrowIcon,
                url: "/cert-manager",
              },
            ]}
          />
        </SidebarProvider>
      </QueryClientProvider>,
    );

    expect(
      screen.getByRole("link", { name: "Certificates" }),
    ).toBeInTheDocument();
  });

  it("keeps long group labels on one line when another section expands", () => {
    const queryClient = new QueryClient();

    render(
      <QueryClientProvider client={queryClient}>
        <SidebarProvider>
          <NavSecondary
            groupLabel="Certificate Lifecycle"
            items={[
              {
                title: "Certificates",
                icon: FlowArrowIcon,
                url: "/cert-manager",
              },
            ]}
          />
        </SidebarProvider>
      </QueryClientProvider>,
    );

    expect(
      screen.getByRole("button", { name: "Certificate Lifecycle" }),
    ).toHaveClass("whitespace-nowrap");
  });
});
