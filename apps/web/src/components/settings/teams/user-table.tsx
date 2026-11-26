// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import { ColumnDef } from "@tanstack/react-table";
import { WarningIcon } from "@phosphor-icons/react";

import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import type { UserDto } from "@/types/auth";
import { cn } from "@/lib/utils";

interface UserTableOptions {
  canManage: boolean;
  isSuperAdmin?: boolean;
  currentUserId?: number | string;
  currentUserEmail?: string;
  /** Set while re-enabling a member must wait; shown on the menu item. */
  enableBlockedReason?: string | null;
  onEdit: (user: UserDto) => void;
  onDisable: (user: UserDto) => void;
  onDelete: (user: UserDto) => void;
  /** Clears the member's authenticator-app second factor; shown when set. */
  onResetMfa?: (user: UserDto) => void;
}

const getInitials = (user: UserDto): string => {
  const name = user.displayName || user.username;
  if (name) {
    const parts = name.trim().split(/\s+/);
    if (parts.length >= 2) {
      return `${parts[0][0]}${parts[1][0]}`.toUpperCase();
    }
    return name.slice(0, 2).toUpperCase();
  }
  return user.email.slice(0, 2).toUpperCase();
};

const getDisplayName = (user: UserDto): string =>
  user.displayName || user.username || user.email.split("@")[0];

const AVATAR_COLORS = [
  "bg-muted text-foreground",
  "bg-muted text-foreground",
  "bg-primary/10 text-primary",
  "bg-muted text-foreground",
  "bg-muted text-foreground",
  "bg-primary/10 text-primary",
];

const getAvatarColor = (id: number | string): string => {
  const index =
    Number(String(id).replace(/\D/g, "") || 0) % AVATAR_COLORS.length;
  return AVATAR_COLORS[index];
};

const authMethodLabel = (method: string) =>
  method === "SSO" ? "SSO" : method === "LOCAL" ? "Password" : method;

export const formatRoleName = (role: string): string =>
  role
    .replace(/_/g, " ")
    .toLowerCase()
    .replace(/\b\w/g, (c) => c.toUpperCase());

export const createUserColumns = ({
  canManage,
  isSuperAdmin = false,
  currentUserId,
  currentUserEmail,
  enableBlockedReason = null,
  onEdit,
  onDisable,
  onDelete,
  onResetMfa,
}: UserTableOptions): ColumnDef<UserDto>[] => [
  {
    accessorKey: "displayName",
    header: "Member",
    size: 280,
    cell: ({ row }) => {
      const u = row.original;
      return (
        <div className="flex items-center gap-3">
          <Avatar className="h-8 w-8 shrink-0">
            <AvatarFallback
              className={`text-xs font-medium ${getAvatarColor(u.id)}`}
            >
              {getInitials(u)}
            </AvatarFallback>
          </Avatar>
          <div className="min-w-0">
            <div className="flex items-center gap-1.5">
              <p className="truncate font-medium text-foreground">
                {getDisplayName(u)}
              </p>
              {u.mustChangePassword ? (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <WarningIcon className="h-3.5 w-3.5 shrink-0 status-warning-text" />
                  </TooltipTrigger>
                  <TooltipContent side="top">
                    Must change password on next sign-in
                  </TooltipContent>
                </Tooltip>
              ) : null}
            </div>
            <p className="truncate text-xs text-muted-foreground">{u.email}</p>
          </div>
        </div>
      );
    },
  },
  ...(isSuperAdmin
    ? ([
        {
          accessorKey: "organizationName",
          header: "Organization",
          size: 160,
          cell: ({ row }) => {
            const name = row.original.organizationName;
            return (
              <div>
                {name ? (
                  <Badge variant="secondary" className="text-xs font-normal">
                    {name}
                  </Badge>
                ) : (
                  <span className="text-muted-foreground">-</span>
                )}
              </div>
            );
          },
        },
      ] as ColumnDef<UserDto>[])
    : []),
  {
    accessorKey: "roles",
    header: "Roles",
    size: 220,
    cell: ({ row }) => {
      const roles = row.original.roles ?? [];
      if (roles.length === 0) {
        return <span className="text-muted-foreground">No roles</span>;
      }
      return (
        <div className="flex flex-wrap gap-1">
          {roles.map((role) => (
            <Badge key={role} variant="secondary" textOnly>
              {formatRoleName(role)}
            </Badge>
          ))}
        </div>
      );
    },
  },
  {
    accessorKey: "authMethod",
    header: "Sign-in",
    size: 100,
    cell: ({ row }) => {
      const method = row.original.authMethod ?? "LOCAL";
      return (
        <Badge
          variant={method === "SSO" ? "info" : "secondary"}
          textOnly
          className={cn(
            method === "SSO" ? "text-primary" : "text-secondary-700",
          )}
        >
          {authMethodLabel(method)}
        </Badge>
      );
    },
  },
  {
    accessorKey: "active",
    header: "Status",
    size: 120,
    cell: ({ row }) => {
      const active = row.original.active !== false;
      return (
        <Badge
          variant={active ? "success" : "secondary"}
          textOnly
          // className="text-[11px] font-medium"
        >
          {active ? "Active" : "Disabled"}
        </Badge>
      );
    },
  },
  ...(canManage
    ? ([
        {
          id: "actions",
          header: () => <div className="pr-1 text-right">Actions</div>,
          size: 120,
          cell: ({ row }) => {
            const isCurrentUser =
              (currentUserId !== undefined &&
                String(row.original.id) === String(currentUserId)) ||
              Boolean(
                currentUserEmail &&
                row.original.email.toLowerCase() ===
                  currentUserEmail.toLowerCase(),
              );

            if (isCurrentUser) {
              return null;
            }

            return (
              <div className="flex justify-end pr-1">
                <MemberActionsMenu
                  user={row.original}
                  enableBlockedReason={enableBlockedReason}
                  onEdit={onEdit}
                  onDisable={onDisable}
                  onDelete={onDelete}
                  onResetMfa={onResetMfa}
                />
              </div>
            );
          },
        },
      ] as ColumnDef<UserDto>[])
    : []),
];

function MemberActionsMenu({
  user,
  enableBlockedReason,
  onEdit,
  onDisable,
  onDelete,
  onResetMfa,
}: {
  user: UserDto;
  enableBlockedReason: string | null;
  onEdit: (user: UserDto) => void;
  onDisable: (user: UserDto) => void;
  onDelete: (user: UserDto) => void;
  onResetMfa?: (user: UserDto) => void;
}) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm" className="h-8 px-3">
          Manage
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem onClick={() => onEdit(user)}>
          Edit member
        </DropdownMenuItem>
        {user.active !== false ? (
          <DropdownMenuItem onClick={() => onDisable(user)}>
            Disable member
          </DropdownMenuItem>
        ) : (
          <DropdownMenuItem
            disabled={Boolean(enableBlockedReason)}
            onClick={() => onDisable(user)}
            className="flex-col items-start gap-0.5"
          >
            Enable member
            {enableBlockedReason ? (
              <span className="text-xs font-normal text-muted-foreground">
                {enableBlockedReason}
              </span>
            ) : null}
          </DropdownMenuItem>
        )}
        {onResetMfa && (user.authMethod ?? "LOCAL") === "LOCAL" ? (
          <DropdownMenuItem onClick={() => onResetMfa(user)}>
            Reset two-factor authentication
          </DropdownMenuItem>
        ) : null}
        <DropdownMenuSeparator />
        <DropdownMenuItem
          className="text-destructive focus:text-destructive"
          onClick={() => onDelete(user)}
        >
          Remove member
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

export function MemberCard({
  user,
  isSuperAdmin = false,
  canManage,
  isCurrentUser,
  enableBlockedReason = null,
  onEdit,
  onDisable,
  onDelete,
  onResetMfa,
}: {
  user: UserDto;
  isSuperAdmin?: boolean;
  canManage: boolean;
  isCurrentUser: boolean;
  enableBlockedReason?: string | null;
  onEdit: (user: UserDto) => void;
  onDisable: (user: UserDto) => void;
  onDelete: (user: UserDto) => void;
  onResetMfa?: (user: UserDto) => void;
}) {
  const roles = user.roles ?? [];
  const method = user.authMethod ?? "LOCAL";
  const active = user.active !== false;

  return (
    <div className="min-w-0 space-y-4 rounded-lg border border-border bg-card p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="flex min-w-0 items-center gap-3">
          <Avatar className="h-9 w-9 shrink-0">
            <AvatarFallback
              className={`text-xs font-medium ${getAvatarColor(user.id)}`}
            >
              {getInitials(user)}
            </AvatarFallback>
          </Avatar>
          <div className="min-w-0">
            <div className="flex items-center gap-1.5">
              <p className="truncate font-medium text-foreground">
                {getDisplayName(user)}
              </p>
              {user.mustChangePassword ? (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <WarningIcon className="h-3.5 w-3.5 shrink-0 status-warning-text" />
                  </TooltipTrigger>
                  <TooltipContent side="top">
                    Must change password on next sign-in
                  </TooltipContent>
                </Tooltip>
              ) : null}
            </div>
            <p className="truncate text-xs text-muted-foreground">
              {user.email}
            </p>
          </div>
        </div>
        {canManage && !isCurrentUser ? (
          <MemberActionsMenu
            user={user}
            enableBlockedReason={enableBlockedReason}
            onEdit={onEdit}
            onDisable={onDisable}
            onDelete={onDelete}
            onResetMfa={onResetMfa}
          />
        ) : null}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Badge
          variant={method === "SSO" ? "info" : "secondary"}
          textOnly
          className={cn(
            method === "SSO" ? "text-primary" : "text-secondary-700",
          )}
        >
          {authMethodLabel(method)}
        </Badge>
        <Badge variant={active ? "success" : "secondary"} textOnly>
          {active ? "Active" : "Disabled"}
        </Badge>
        {isSuperAdmin && user.organizationName ? (
          <Badge variant="secondary" className="text-xs font-normal">
            {user.organizationName}
          </Badge>
        ) : null}
      </div>

      <div>
        <p className="mb-1 text-xs text-muted-foreground">Roles</p>
        {roles.length === 0 ? (
          <span className="text-sm text-muted-foreground">No roles</span>
        ) : (
          <div className="flex flex-wrap gap-1">
            {roles.map((role) => (
              <Badge key={role} variant="secondary" textOnly>
                {formatRoleName(role)}
              </Badge>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
