// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";
import {
  SealCheckIcon,
  LifebuoyIcon,
  SignOutIcon,
} from "@phosphor-icons/react";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { SidebarTrigger } from "../ui/sidebar";
import Link from "next/link";
import { useAuth } from "@/hooks/use-auth";
import { useAgentHealth } from "@/hooks/agent";
import { IncidentsPopover } from "./incidents-popover";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "../ui/alert-dialog";
import { canViewAlerts as userCanViewAlerts } from "@/lib/authz";
import { useIsFeatureEnabled } from "@/hooks/use-feature-flags";
import { ThemeToggle } from "@/components/theme-toggle";
import { AgentHealthNavbarIndicator } from "./agent-health-status";
import { AppSearch } from "./app-search";
import { ToolTipCard } from "./tooltip-card";

export function Navbar() {
  const [confirmLogoutOpen, setConfirmLogoutOpen] = useState(false);
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const auth = useAuth();
  const isAgentHealthEnabled = useIsFeatureEnabled("AGENT_HEALTH_MONITORING");
  const isAlertsEnabled = useIsFeatureEnabled("ALERTS");
  const agentHealthQuery = useAgentHealth();
  const canViewAlerts = userCanViewAlerts(auth.user);
  const initials = (auth.user?.email ?? "").slice(0, 2).toUpperCase() || "CP";

  return (
    <header
      suppressHydrationWarning
      className="sticky top-0 z-30 border-b border-divider certping-app-toolbar"
    >
      <AlertDialog open={confirmLogoutOpen} onOpenChange={setConfirmLogoutOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Log out of CertPing?</AlertDialogTitle>
            <AlertDialogDescription>
              You will need to sign in again to reach this workspace.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Stay signed in</AlertDialogCancel>
            <AlertDialogAction variant="destructive" onClick={auth.logout}>
              Log out
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      <div className="flex h-14 items-center px-3 sm:px-4">
        <div className="flex flex-1 items-center space-x-4">
          <SidebarTrigger className="md:hidden" />
        </div>
        <div className="flex items-center gap-1.5">
          <AppSearch />
          {isAgentHealthEnabled && (
            <AgentHealthNavbarIndicator agentHealth={agentHealthQuery.data} />
          )}
          {isAlertsEnabled && canViewAlerts ? <IncidentsPopover /> : null}
          <ThemeToggle />
          <ToolTipCard value="Support Center">
            <Button size={"iconSm"} variant={"icon"} asChild>
              <Link href="/support" aria-label="Support Center">
                <LifebuoyIcon width={16} height={16} />
              </Link>
            </Button>
          </ToolTipCard>

          <DropdownMenu open={userMenuOpen} onOpenChange={setUserMenuOpen}>
            <DropdownMenuTrigger asChild>
              <button
                type="button"
                aria-label="Account menu"
                className="ml-1 rounded-full outline-hidden transition-transform duration-150 ease-out hover:scale-[1.04] focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:ring-offset-background active:scale-95"
              >
                <Avatar className="h-8 w-8 rounded-full">
                  <AvatarFallback className="rounded-full text-xs font-medium">
                    {initials}
                  </AvatarFallback>
                </Avatar>
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent
              className="min-w-60"
              align="end"
              sideOffset={4}
            >
              <DropdownMenuLabel className="p-0 font-normal">
                <div className="flex items-center gap-2.5 px-2.5 py-2 text-left">
                  <Avatar className="h-7 w-7 rounded-full">
                    <AvatarFallback className="rounded-full text-[11px] font-medium">
                      {initials}
                    </AvatarFallback>
                  </Avatar>
                  <span className="min-w-0 truncate text-sm text-foreground lowercase">
                    {auth.user?.email}
                  </span>
                </div>
              </DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuGroup>
                <Link href="/settings/organization-access?tab=account">
                  <DropdownMenuItem>
                    <SealCheckIcon />
                    Account
                  </DropdownMenuItem>
                </Link>
              </DropdownMenuGroup>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={() => setConfirmLogoutOpen(true)}>
                <SignOutIcon />
                Log out
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
    </header>
  );
}
