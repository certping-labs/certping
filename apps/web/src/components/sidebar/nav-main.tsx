// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { CaretRightIcon } from "@phosphor-icons/react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import React from "react";
import { useUnreadAlertSummary } from "@/hooks/incidents";
import { useAuth } from "@/hooks/use-auth";
import { canViewAlerts as userCanViewAlerts } from "@/lib/authz";

import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
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
import { resolveActiveNavUrl } from "@/lib/sidebar-navigation";
import { cn } from "@/lib/utils";

export interface NavMenuProps {
  items: {
    title: string;
    url?: string;
    icon?: React.ComponentType<React.ComponentProps<"svg">>;
    isActive?: boolean;
    /** Highlight only on an exact path match - for parent/landing URLs whose children are separate items. */
    exact?: boolean;
    /**
     * Highlight anywhere under this prefix instead of under `url`. For a single
     * entry that opens a tabbed section: `url` points straight at the first tab
     * the user can see (no redirect hop), while the entry stays highlighted on
     * every tab in the section.
     */
    matchPrefix?: string;
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
}

export function NavMain({
  items,
  groupLabel,
  activeUrl: activeUrlProp,
  emphasis,
}: NavMenuProps) {
  const pathName = usePathname();
  const { user } = useAuth();
  const canViewAlerts = userCanViewAlerts(user);
  const unreadAlerts = useUnreadAlertSummary({ enabled: canViewAlerts });
  const { isMobile, setOpenMobile } = useSidebar();

  const closeSidebarOnMobile = () => {
    if (isMobile) setOpenMobile(false);
  };

  const hasUnreadAlerts = canViewAlerts && unreadAlerts.hasUnread;

  const activeUrl =
    activeUrlProp === undefined
      ? resolveActiveNavUrl(pathName, items)
      : activeUrlProp;
  const isActive = (url?: string) => Boolean(url) && url === activeUrl;

  return (
    <NavGroup groupLabel={groupLabel} emphasis={emphasis}>
      <SidebarMenu>
        {items.map((item, i) => {
          if (!item.subMenu?.length) {
            // If no URL, render as disabled button
            if (!item.url) {
              return (
                <SidebarMenuItem key={item.title}>
                  <div className="w-full">
                    <SidebarMenuButton
                      size="default"
                      className="w-full cursor-not-allowed justify-start text-sm font-medium text-sidebar-muted opacity-60 transition-colors"
                      tooltip={`${item.title} (Disabled)`}
                    >
                      {item.icon && <item.icon className="size-4 shrink-0" />}
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
                  size="default"
                  data-current={isActive(item.url) || undefined}
                  className={cn(
                    "relative w-full justify-start text-sm font-medium text-sidebar-foreground transition-colors hover:bg-sidebar-hover hover:text-sidebar-foreground",
                    isActive(item.url) &&
                      "bg-sidebar-accent text-sidebar-accent-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground",
                  )}
                  tooltip={item.title}
                >
                  <Link href={item.url} prefetch onClick={closeSidebarOnMobile}>
                    {item.icon && (
                      <span
                        className={cn(
                          item.url === "/incidents" &&
                            hasUnreadAlerts &&
                            "relative text-destructive",
                        )}
                      >
                        {item.url === "/incidents" && hasUnreadAlerts && (
                          <span className="absolute left-2 h-1.5 w-1.5 rounded-full bg-destructive"></span>
                        )}
                        <item.icon
                          className={cn(
                            "size-4 shrink-0",
                            item.url === "/incidents" && hasUnreadAlerts
                              ? "text-destructive"
                              : isActive(item.url)
                                ? "text-sidebar-accent-foreground"
                                : "text-sidebar-muted",
                          )}
                        />
                      </span>
                    )}
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
                    tooltip={item.title}
                    className={cn(
                      "w-full justify-start text-sm font-medium transition-colors hover:bg-sidebar-hover hover:text-sidebar-foreground",
                      hasActiveChild
                        ? "bg-sidebar-accent text-sidebar-accent-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
                        : "text-sidebar-foreground",
                      !item.subMenu?.length && "cursor-not-allowed opacity-50",
                    )}
                  >
                    {item.icon && (
                      <item.icon
                        className={cn(
                          "size-4 shrink-0",
                          hasActiveChild
                            ? "text-sidebar-accent-foreground"
                            : "text-sidebar-muted",
                        )}
                      />
                    )}
                    <span>{item.title}</span>
                    <CaretRightIcon className="ml-auto size-4 shrink-0 transition-transform duration-200 group-data-[state=open]/collapsible:rotate-90" />
                  </SidebarMenuButton>
                </CollapsibleTrigger>
                <CollapsibleContent>
                  <SidebarMenuSub className="pt-1">
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
