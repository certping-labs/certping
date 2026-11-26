// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useState } from "react";
import { Button } from "@/components/ui/button";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { ScrollArea } from "@/components/ui/scroll-area";
import { AlertList } from "./alert-list";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { BellIcon } from "@phosphor-icons/react";
import {
  useMarkAllSystemAlertsAsRead,
  useUnreadAlertSummary,
} from "@/hooks/incidents";
import { useAuth } from "@/hooks/use-auth";
import {
  canManageNotifications,
  canViewAlerts as userCanViewAlerts,
} from "@/lib/authz";
import { cn } from "@/lib/utils";

export function IncidentsPopover() {
  const [openByPath, setOpenByPath] = useState<Record<string, boolean>>({});
  const pathname = usePathname();
  const currentPath = pathname || "/";
  const isOpen = Boolean(openByPath[currentPath]);
  const { user } = useAuth();
  const canViewAlerts = userCanViewAlerts(user);
  const unread = useUnreadAlertSummary({
    enabled: canViewAlerts,
    poll: true,
  });
  const markAllRead = useMarkAllSystemAlertsAsRead();

  const hasUnreadAlerts = canViewAlerts && unread.hasUnread;
  const hasUnreadProblems = unread.hasUnreadProblem;
  const canMarkAll = hasUnreadAlerts && canManageNotifications(user);

  return (
    <Popover
      open={isOpen}
      onOpenChange={(open) => {
        setOpenByPath((previous) => ({
          ...previous,
          [currentPath]: open,
        }));
      }}
    >
      <PopoverTrigger asChild>
        <Button
          aria-label="Open alerts"
          size="iconSm"
          variant="icon"
          className="relative"
        >
          <BellIcon className="size-8" />
          {hasUnreadAlerts && (
            <span className="absolute top-1 right-2 flex h-2 w-2">
              <span
                className={cn(
                  "absolute inline-flex h-full w-full rounded-full opacity-75",
                  hasUnreadProblems ? "bg-destructive/40" : "bg-primary/40",
                )}
              ></span>
              <span
                data-testid="unread-dot"
                className={cn(
                  "relative inline-flex h-2 w-2 rounded-full",
                  hasUnreadProblems ? "bg-destructive" : "bg-primary",
                )}
              ></span>
            </span>
          )}
        </Button>
      </PopoverTrigger>
      <PopoverContent
        align="end"
        collisionPadding={12}
        className="w-[calc(100vw-1rem)] max-w-100 overflow-hidden p-0"
      >
        <div className="flex items-center justify-between border-b px-4 py-3">
          <h2 className="font-semibold">Alerts</h2>
          <Link
            href="/incidents"
            className="text-sm text-primary hover:underline"
          >
            View all
          </Link>
        </div>
        <ScrollArea className="h-[300px]">
          <AlertList onlyUnread limit={10} markReadOnClick />
        </ScrollArea>
        <div className="border-t px-4 py-3">
          <Button
            type="button"
            variant="subtle"
            className={cn(
              "h-auto w-full justify-start px-0",
              !canMarkAll && "text-muted-foreground",
            )}
            disabled={!canMarkAll || markAllRead.isPending}
            isPending={markAllRead.isPending}
            loadingtext="Marking read…"
            onClick={() => markAllRead.mutate()}
          >
            Mark all read
          </Button>
        </div>
      </PopoverContent>
    </Popover>
  );
}
