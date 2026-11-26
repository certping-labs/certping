// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import * as React from "react";
import * as TabsPrimitive from "@radix-ui/react-tabs";

import { useActiveChildThumb } from "@/hooks/use-sliding-thumb";
import { cn } from "@/lib/utils";

type TabsVariant = "segmented" | "underline";

const TabsVariantContext = React.createContext<TabsVariant>("segmented");

const Tabs = TabsPrimitive.Root;

const tabsListClassName: Record<TabsVariant, string> = {
  segmented:
    "mg-segmented relative inline-flex h-10 items-center justify-center gap-0.5 rounded-full p-1 text-muted-foreground",
  underline:
    "relative flex h-11 w-full items-end justify-start gap-6 overflow-x-auto border-b border-divider text-muted-foreground scrollbar-none",
};

const tabsTriggerClassName: Record<TabsVariant, string> = {
  segmented:
    "relative inline-flex h-8 items-center justify-center gap-1.5 whitespace-nowrap rounded-full px-3.5 text-sm font-medium tracking-[-0.01em] text-muted-foreground transition-colors duration-200 hover:text-foreground focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:pointer-events-none disabled:opacity-50 data-[state=active]:text-foreground [&_svg]:size-4",
  underline:
    "relative inline-flex h-11 items-center gap-1.5 whitespace-nowrap px-0.5 text-sm font-medium text-muted-foreground transition-colors duration-200 hover:text-foreground focus-visible:rounded-md focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:pointer-events-none disabled:opacity-50 data-[state=active]:text-foreground [&_svg]:size-4",
};

const TabsList = React.forwardRef<
  React.ElementRef<typeof TabsPrimitive.List>,
  React.ComponentPropsWithoutRef<typeof TabsPrimitive.List> & {
    variant?: TabsVariant;
  }
>(({ className, variant = "segmented", children, ...props }, ref) => {
  const listRef = React.useRef<HTMLDivElement | null>(null);
  const { moving, thumbStyle } = useActiveChildThumb(listRef);
  const setRefs = React.useCallback(
    (node: HTMLDivElement | null) => {
      listRef.current = node;
      if (typeof ref === "function") ref(node);
      else if (ref) ref.current = node;
    },
    [ref],
  );
  return (
    <TabsVariantContext.Provider value={variant}>
      <TabsPrimitive.List
        ref={setRefs}
        data-variant={variant}
        className={cn(tabsListClassName[variant], className)}
        {...props}
      >
        <span
          aria-hidden
          className={cn(
            variant === "segmented" ? "mg-thumb" : "mg-tab-indicator",
            moving && "is-moving",
          )}
          style={thumbStyle}
        />
        {children}
      </TabsPrimitive.List>
    </TabsVariantContext.Provider>
  );
});
TabsList.displayName = TabsPrimitive.List.displayName;

const TabsTrigger = React.forwardRef<
  React.ElementRef<typeof TabsPrimitive.Trigger>,
  React.ComponentPropsWithoutRef<typeof TabsPrimitive.Trigger>
>(({ className, ...props }, ref) => {
  const variant = React.useContext(TabsVariantContext);
  return (
    <TabsPrimitive.Trigger
      ref={ref}
      className={cn(tabsTriggerClassName[variant], className)}
      {...props}
    />
  );
});
TabsTrigger.displayName = TabsPrimitive.Trigger.displayName;

const TabsContent = React.forwardRef<
  React.ElementRef<typeof TabsPrimitive.Content>,
  React.ComponentPropsWithoutRef<typeof TabsPrimitive.Content>
>(({ className, ...props }, ref) => (
  <TabsPrimitive.Content
    ref={ref}
    className={cn(
      "mt-4 focus-visible:ring-2 focus-visible:ring-brand focus-visible:outline-hidden data-[state=active]:duration-200 data-[state=active]:animate-in data-[state=active]:fade-in-0 motion-reduce:animate-none",
      className,
    )}
    {...props}
  />
));
TabsContent.displayName = TabsPrimitive.Content.displayName;

export {
  Tabs,
  TabsList,
  TabsTrigger,
  TabsContent,
  tabsListClassName,
  tabsTriggerClassName,
};
