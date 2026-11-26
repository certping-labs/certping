// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { CaretRightIcon } from "@phosphor-icons/react";
import * as React from "react";

import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import {
  SidebarGroup,
  SidebarGroupLabel,
  useSidebar,
} from "@/components/ui/sidebar";
import { cn } from "@/lib/utils";

const STORAGE_PREFIX = "sidebar-group-collapsed:";

export type NavEmphasis = "default" | "focus" | "recede";

// Dims every item except the current page, highlighted shortcuts and the item under the pointer or keyboard focus.
const recedeClass =
  "**:data-[sidebar=menu-button]:transition-opacity **:data-[sidebar=menu-button]:duration-200 [&_[data-sidebar=menu-button]:not([data-current]):not([data-highlight]):not(:hover):not(:focus-visible)]:opacity-[0.62]";

interface NavGroupProps {
  groupLabel?: string;
  emphasis?: NavEmphasis;
  children: React.ReactNode;
}

export function NavGroup({
  groupLabel,
  emphasis = "default",
  children,
}: NavGroupProps) {
  const emphasisClass = emphasis === "default" ? undefined : recedeClass;
  const { state } = useSidebar();
  const storageKey = groupLabel ? `${STORAGE_PREFIX}${groupLabel}` : undefined;
  const [open, setOpen] = React.useState(true);
  const isNavigationCollapsed = state === "collapsed";
  const isGroupOpen = isNavigationCollapsed || open;

  React.useEffect(() => {
    if (!storageKey) return;

    const stored = window.localStorage.getItem(storageKey);
    if (stored !== null) setOpen(stored !== "collapsed");
  }, [storageKey]);

  const handleOpenChange = (nextOpen: boolean) => {
    if (isNavigationCollapsed) return;

    setOpen(nextOpen);
    if (storageKey) {
      window.localStorage.setItem(
        storageKey,
        nextOpen ? "expanded" : "collapsed",
      );
    }
  };

  if (!groupLabel) {
    return (
      <SidebarGroup
        data-emphasis={emphasis}
        className={cn(
          "py-0.5 group-data-[collapsible=icon]:py-1",
          emphasisClass,
        )}
      >
        {children}
      </SidebarGroup>
    );
  }

  return (
    <Collapsible open={isGroupOpen} onOpenChange={handleOpenChange}>
      <SidebarGroup
        data-emphasis={emphasis}
        className={cn(
          "gap-0.5 border-sidebar-border/60 py-0.5 group-data-[collapsible=icon]:mt-1 group-data-[collapsible=icon]:border-t group-data-[collapsible=icon]:pt-1.5",
          emphasisClass,
        )}
      >
        <SidebarGroupLabel asChild>
          <CollapsibleTrigger
            className={cn(
              "group/section h-6 w-full rounded-md px-3 text-xs font-medium whitespace-nowrap transition-colors group-data-[collapsible=icon]:hidden hover:text-sidebar-foreground",
              emphasis === "focus"
                ? "text-sidebar-foreground"
                : "text-sidebar-muted",
            )}
          >
            <span className="min-w-0 flex-1 text-left">{groupLabel}</span>
            <CaretRightIcon
              className={cn(
                "ml-auto size-3 text-sidebar-muted opacity-0 transition-[transform,opacity] duration-200 group-hover/section:opacity-100",
                open && "rotate-90",
              )}
            />
          </CollapsibleTrigger>
        </SidebarGroupLabel>
        <CollapsibleContent>{children}</CollapsibleContent>
      </SidebarGroup>
    </Collapsible>
  );
}
