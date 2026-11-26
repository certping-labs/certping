// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { CaretRightIcon } from "@phosphor-icons/react";
import React from "react";
import {
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarMenuSub,
  SidebarMenuSubButton,
  SidebarMenuSubItem,
  useSidebar,
} from "@/components/ui/sidebar";
import { NavGroup, type NavEmphasis } from "./nav-group";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { usePathname } from "next/navigation";
import Link from "next/link";
import { resolveActiveNavUrl } from "@/lib/sidebar-navigation";
import { cn } from "@/lib/utils";
import { useQueryClient } from "@tanstack/react-query";
import { prefetchSSLCertificates } from "@/hooks/prefetch";

export function NavSecondary({
  items,
  groupLabel = "Manage",
  activeUrl: activeUrlProp,
  emphasis,
}: {
  items: {
    title: string;
    url?: string;
    icon: React.ComponentType<React.ComponentProps<"svg">>;
    highlight?: boolean;
    subMenu?: {
      title: string;
      url?: string;
      icon?: React.ComponentType<React.ComponentProps<"svg">>;
      disabled?: boolean;
    }[];
  }[];
  groupLabel?: string;
  activeUrl?: string | null;
  emphasis?: NavEmphasis;
}) {
  const pathName = usePathname();
  const queryClient = useQueryClient();
  const { isMobile, setOpenMobile } = useSidebar();

  const closeSidebarOnMobile = () => {
    if (isMobile) setOpenMobile(false);
  };

  const activeUrl =
    activeUrlProp === undefined
      ? resolveActiveNavUrl(pathName, items)
      : activeUrlProp;
  const isActive = (url?: string) => Boolean(url) && url === activeUrl;
  const isHighlighted = (item: (typeof items)[number]) =>
    emphasis === "focus" && Boolean(item.highlight) && !isActive(item.url);

  const handlePrefetch = (url?: string) => {
    if (!url) return;

    if (url === "/cert-manager") {
      prefetchSSLCertificates(queryClient);
    }
  };

  return (
    <NavGroup groupLabel={groupLabel} emphasis={emphasis}>
      <SidebarMenu>
        {items.map((item, i) => {
          // Item without submenu
          if (!item.subMenu?.length) {
            // If no URL, render as disabled button
            if (!item.url) {
              return (
                <SidebarMenuItem key={item.title}>
                  <div className="w-full">
                    <SidebarMenuButton
                      size="default"
                      className="w-full cursor-not-allowed justify-start text-sm font-medium text-sidebar-muted opacity-60 transition-colors"
                    >
                      <item.icon className="size-4 shrink-0" />
                      <span>{item.title}</span>
                    </SidebarMenuButton>
                  </div>
                </SidebarMenuItem>
              );
            }

            // Regular item with URL
            return (
              <SidebarMenuItem key={`${item.url}-${i}`}>
                <SidebarMenuButton
                  asChild
                  tooltip={item.title}
                  data-current={isActive(item.url) || undefined}
                  data-highlight={isHighlighted(item) || undefined}
                  className={cn(
                    "w-full justify-start text-sm font-medium text-sidebar-foreground transition-colors hover:bg-sidebar-hover hover:text-sidebar-foreground",
                    isHighlighted(item) && "text-sidebar-foreground",
                    isActive(item.url) &&
                      "bg-sidebar-accent text-sidebar-accent-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground",
                  )}
                  onMouseEnter={() => handlePrefetch(item.url)}
                >
                  <Link href={item.url} prefetch onClick={closeSidebarOnMobile}>
                    <item.icon
                      className={cn(
                        "size-4 shrink-0",
                        isActive(item.url)
                          ? "text-sidebar-accent-foreground"
                          : isHighlighted(item)
                            ? "text-sidebar-foreground"
                            : "text-sidebar-muted",
                      )}
                    />
                    <span>{item.title}</span>
                  </Link>
                </SidebarMenuButton>
              </SidebarMenuItem>
            );
          }

          // Handle menu items with submenu
          const hasActiveChild = item.subMenu?.some((subItem) =>
            isActive(subItem.url),
          );

          return (
            <Collapsible
              key={item.title}
              defaultOpen={hasActiveChild}
              className="group/collapsible w-full"
            >
              <SidebarMenuItem>
                <CollapsibleTrigger asChild className="w-full">
                  <SidebarMenuButton
                    className={cn(
                      "w-full justify-start text-sm font-medium transition-colors hover:bg-sidebar-hover hover:text-sidebar-foreground",
                      hasActiveChild
                        ? "bg-sidebar-accent text-sidebar-accent-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
                        : "text-sidebar-foreground",
                    )}
                  >
                    <item.icon
                      className={cn(
                        "size-4 shrink-0",
                        hasActiveChild
                          ? "text-sidebar-accent-foreground"
                          : "text-sidebar-muted",
                      )}
                    />
                    <span>{item.title}</span>
                    <CaretRightIcon className="ml-auto size-4 shrink-0 transition-transform duration-200 group-data-[state=open]/collapsible:rotate-90" />
                  </SidebarMenuButton>
                </CollapsibleTrigger>
                <CollapsibleContent>
                  <SidebarMenuSub className="ml-4 border-l border-sidebar-border pt-1 pl-2">
                    {item.subMenu?.map((subItem) => (
                      <SidebarMenuSubItem key={subItem.title}>
                        {!subItem.url || subItem.disabled ? (
                          <div className="w-full">
                            <SidebarMenuSubButton className="pointer-events-none w-full cursor-not-allowed justify-start text-sm font-medium text-sidebar-muted opacity-60 transition-colors">
                              {subItem.icon && (
                                <subItem.icon className="size-4 shrink-0" />
                              )}
                              <span>{subItem.title}</span>
                            </SidebarMenuSubButton>
                          </div>
                        ) : (
                          <SidebarMenuSubButton
                            asChild
                            className={cn(
                              "w-full justify-start text-sm font-medium text-sidebar-foreground transition-colors hover:bg-sidebar-hover hover:text-sidebar-foreground",
                              isActive(subItem.url)
                                ? "bg-sidebar-accent text-sidebar-accent-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
                                : "",
                            )}
                            onMouseEnter={() => handlePrefetch(subItem.url)}
                          >
                            <Link
                              href={subItem.url}
                              onClick={closeSidebarOnMobile}
                            >
                              {subItem.icon && (
                                <subItem.icon
                                  className={cn(
                                    "size-4 shrink-0",
                                    isActive(subItem.url)
                                      ? "text-sidebar-accent-foreground"
                                      : "text-sidebar-muted",
                                  )}
                                />
                              )}
                              <span>{subItem.title}</span>
                            </Link>
                          </SidebarMenuSubButton>
                        )}
                      </SidebarMenuSubItem>
                    ))}
                  </SidebarMenuSub>
                </CollapsibleContent>
              </SidebarMenuItem>
            </Collapsible>
          );
        })}
      </SidebarMenu>
    </NavGroup>
  );
}
