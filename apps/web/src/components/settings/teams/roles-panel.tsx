// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useId, useMemo, useState } from "react";
import {
  CaretDownIcon,
  CircleNotchIcon,
  PlusIcon,
  MagnifyingGlassIcon,
  TrashIcon,
  GearSixIcon,
} from "@phosphor-icons/react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { MultiSelect, type Option } from "@/components/ui/multi-select";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { ViewSwitcher } from "@/components/ui/view-switcher";
import { useResponsiveViewMode } from "@/hooks/use-responsive-view-mode";
import { fuzzySearch } from "@/lib/fuzzy-search";
import type { RoleDto } from "@/types/auth";
import { formatRoleName } from "@/components/settings/teams/user-table";
import { AccessSaveBlockedNote } from "@/components/settings/teams/access-save-blocked-note";

export interface CreateRoleState {
  name: string;
  description: string;
  permissionNames: string[];
}

export interface EditRoleState {
  id: number;
  name: string;
  description: string;
  permissionNames: string[];
}

export interface DeleteRoleState {
  id: number;
  name: string;
}

interface RolesPanelProps {
  canManageRoles: boolean;
  canDeleteRoles: boolean;
  canViewRoles: boolean;
  roles: RoleDto[];
  permissionOptions: Option[];
  isLoading: boolean;
  createRoleState: CreateRoleState;
  editRoleState: EditRoleState | null;
  deleteRoleState: DeleteRoleState | null;
  isCreateOpen: boolean;
  isCreatePending: boolean;
  isUpdatePending: boolean;
  isDeletePending: boolean;
  isRolePermissionsLoading: boolean;
  /** Set while role permission saves must wait; shown beside Save. */
  saveBlockedReason?: string | null;
  onCreateOpenChange: (open: boolean) => void;
  onCreateRoleChange: (state: CreateRoleState) => void;
  onEditRoleChange: (state: EditRoleState) => void;
  onEditRoleOpenChange: (open: boolean) => void;
  onDeleteRoleOpenChange: (open: boolean) => void;
  onCreateRole: () => void;
  onSaveRole: () => void;
  onDeleteRole: () => void;
  onStartEditRole: (role: RoleDto) => void;
  onStartDeleteRole: (role: RoleDto) => void;
}

export function RolesPanel({
  canManageRoles,
  canDeleteRoles,
  canViewRoles,
  roles,
  permissionOptions,
  isLoading,
  createRoleState,
  editRoleState,
  deleteRoleState,
  isCreateOpen,
  isCreatePending,
  isUpdatePending,
  isDeletePending,
  isRolePermissionsLoading,
  saveBlockedReason = null,
  onCreateOpenChange,
  onCreateRoleChange,
  onEditRoleChange,
  onEditRoleOpenChange,
  onDeleteRoleOpenChange,
  onCreateRole,
  onSaveRole,
  onDeleteRole,
  onStartEditRole,
  onStartDeleteRole,
}: RolesPanelProps) {
  // Mobile (<1024px) defaults to the card grid; desktop keeps the table and
  // remembers the user's choice. Mirrors the other list views.
  const [viewMode, setViewMode] = useResponsiveViewMode({
    storageKey: "team-roles_view",
  });
  const [cardSearchTerm, setCardSearchTerm] = useState("");

  const sortedRoles = useMemo(
    () =>
      [...roles].sort((a, b) => {
        if (a.name === "SUPER_ADMIN") return -1;
        if (b.name === "SUPER_ADMIN") return 1;
        return 0;
      }),
    [roles],
  );

  const cardRoles = useMemo(() => {
    const term = cardSearchTerm.trim();
    if (!term) {
      return sortedRoles;
    }
    return fuzzySearch(term, sortedRoles, ["name", "description"]);
  }, [cardSearchTerm, sortedRoles]);

  if (!canManageRoles && !canViewRoles) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Roles</CardTitle>
          <CardDescription>
            You do not have permission to view roles.
          </CardDescription>
        </CardHeader>
      </Card>
    );
  }

  return (
    <>
      <Card>
        <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <CardTitle className="text-lg">Roles & Permissions</CardTitle>
            <CardDescription>
              {canManageRoles
                ? "Create custom roles and manage the permission sets assigned to them."
                : "View roles and their assigned permissions."}
            </CardDescription>
          </div>
          <div className="flex items-center gap-2">
            {!isLoading && roles.length > 0 ? (
              <ViewSwitcher
                value={viewMode}
                onValueChange={setViewMode}
                showLabels={false}
              />
            ) : null}
            {canManageRoles && (
              <CreateRoleDialog
                open={isCreateOpen}
                form={createRoleState}
                permissionOptions={permissionOptions}
                isPending={isCreatePending}
                onOpenChange={onCreateOpenChange}
                onChange={onCreateRoleChange}
                onCreate={onCreateRole}
              />
            )}
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="flex h-32 items-center justify-center">
              <CircleNotchIcon className="h-5 w-5 animate-spin text-muted-foreground" />
            </div>
          ) : roles.length === 0 ? (
            <div className="mx-6 mb-6 rounded-lg border border-dashed p-6 text-sm text-muted-foreground">
              No roles found.
            </div>
          ) : viewMode === "table" ? (
            <>
              <Table>
                <TableHeader>
                  <TableRow className="bg-muted/40 hover:bg-muted/40">
                    <TableHead className="w-[220px] pl-6 font-semibold text-muted-foreground">
                      Role
                    </TableHead>
                    <TableHead className="w-[200px] font-semibold text-muted-foreground">
                      Description
                    </TableHead>
                    <TableHead className="font-semibold text-muted-foreground">
                      Permissions
                    </TableHead>
                    {canManageRoles && (
                      <TableHead className="w-[120px] pr-6 text-right font-semibold text-muted-foreground">
                        Actions
                      </TableHead>
                    )}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {sortedRoles.map((role) => (
                    <RoleRow
                      key={role.id}
                      role={role}
                      canEdit={canManageRoles}
                      canDelete={canDeleteRoles}
                      onEdit={onStartEditRole}
                      onDelete={onStartDeleteRole}
                    />
                  ))}
                </TableBody>
              </Table>
            </>
          ) : (
            <div className="space-y-4 px-6 pb-6">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div className="relative flex-1 sm:max-w-sm">
                  <MagnifyingGlassIcon className="absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                  <Input
                    value={cardSearchTerm}
                    onChange={(event) => setCardSearchTerm(event.target.value)}
                    placeholder="Search roles..."
                    className="pr-3 pl-9"
                    aria-label="Search roles"
                  />
                </div>
              </div>
              {cardRoles.length === 0 ? (
                <div className="rounded-lg border border-border bg-card p-8 text-center text-sm text-muted-foreground">
                  No roles matched your search.
                </div>
              ) : (
                <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
                  {cardRoles.map((role) => (
                    <RoleCard
                      key={role.id}
                      role={role}
                      canEdit={canManageRoles}
                      canDelete={canDeleteRoles}
                      onEdit={onStartEditRole}
                      onDelete={onStartDeleteRole}
                    />
                  ))}
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      <EditRoleDialog
        open={Boolean(editRoleState)}
        role={editRoleState}
        permissionOptions={permissionOptions}
        isPending={isUpdatePending}
        isPermissionsLoading={isRolePermissionsLoading}
        saveBlockedReason={saveBlockedReason}
        onOpenChange={onEditRoleOpenChange}
        onRoleChange={onEditRoleChange}
        onSave={onSaveRole}
      />

      <DeleteRoleDialog
        open={Boolean(deleteRoleState)}
        role={deleteRoleState}
        isPending={isDeletePending}
        onOpenChange={onDeleteRoleOpenChange}
        onDelete={onDeleteRole}
      />
    </>
  );
}

// ---------------------------------------------------------------------------
// Role row
// ---------------------------------------------------------------------------

interface RoleRowProps {
  role: RoleDto;
  canEdit: boolean;
  canDelete: boolean;
  onEdit: (role: RoleDto) => void;
  onDelete: (role: RoleDto) => void;
}

function RoleRow({ role, canEdit, canDelete, onEdit, onDelete }: RoleRowProps) {
  const permissions = role.permissions ?? [];

  return (
    <TableRow className="group align-middle">
      {/* Role name */}
      <TableCell className="py-3 pl-6">
        <span className="font-medium text-foreground">
          {formatRoleName(role.name)}
        </span>
      </TableCell>

      {/* Description */}
      <TableCell className="py-3 text-sm text-muted-foreground">
        {role.description || (
          <span className="text-muted-foreground italic">-</span>
        )}
      </TableCell>

      {/* Permissions - inline badges + popover for overflow */}
      <TableCell className="py-3">
        {permissions.length === 0 ? (
          <span className="text-sm text-muted-foreground italic">
            None assigned
          </span>
        ) : (
          <PermissionsCell permissions={permissions} />
        )}
      </TableCell>

      {/* Actions */}
      {canEdit && (
        <TableCell className="py-3 pr-6 text-right">
          <div className="flex items-center justify-end gap-1">
            <Button
              variant="ghost"
              size="sm"
              className="h-8 gap-1.5 text-xs text-muted-foreground hover:text-foreground"
              onClick={() => onEdit(role)}
            >
              <GearSixIcon className="h-3.5 w-3.5" />
              Edit
            </Button>
            {canDelete && (
              <Button
                variant="ghost"
                size="sm"
                className="h-8 w-8 p-0 text-muted-foreground hover:bg-destructive/10 hover:text-destructive"
                aria-label={`Delete role ${role.name}`}
                onClick={() => onDelete(role)}
              >
                <TrashIcon aria-hidden="true" className="h-3.5 w-3.5" />
              </Button>
            )}
          </div>
        </TableCell>
      )}
    </TableRow>
  );
}

// ---------------------------------------------------------------------------
// Role card (grid view)
// ---------------------------------------------------------------------------

function RoleCard({
  role,
  canEdit,
  canDelete,
  onEdit,
  onDelete,
}: RoleRowProps) {
  const permissions = role.permissions ?? [];

  return (
    <div className="min-w-0 space-y-4 rounded-lg border border-border bg-card p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 space-y-1">
          <p className="truncate font-medium text-foreground">
            {formatRoleName(role.name)}
          </p>
          <p className="text-sm text-muted-foreground">
            {role.description || (
              <span className="text-muted-foreground italic">
                No description
              </span>
            )}
          </p>
        </div>
        {canEdit ? (
          <div className="flex shrink-0 items-center gap-1">
            <Button
              variant="ghost"
              size="sm"
              className="h-8 gap-1.5 text-xs text-muted-foreground hover:text-foreground"
              onClick={() => onEdit(role)}
            >
              <GearSixIcon className="h-3.5 w-3.5" />
              Edit
            </Button>
            {canDelete && (
              <Button
                variant="ghost"
                size="sm"
                className="h-8 w-8 p-0 text-muted-foreground hover:bg-destructive/10 hover:text-destructive"
                aria-label={`Delete role ${role.name}`}
                onClick={() => onDelete(role)}
              >
                <TrashIcon aria-hidden="true" className="h-3.5 w-3.5" />
              </Button>
            )}
          </div>
        ) : null}
      </div>

      <div>
        <p className="mb-1 text-xs text-muted-foreground">Permissions</p>
        {permissions.length === 0 ? (
          <span className="text-sm text-muted-foreground italic">
            None assigned
          </span>
        ) : (
          <PermissionsCell permissions={permissions} />
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Permissions cell - show first N inline, rest in a shadcn-style dropdown
// ---------------------------------------------------------------------------

const INLINE_LIMIT = 3;

function PermissionsCell({ permissions }: { permissions: string[] }) {
  const visible = permissions.slice(0, INLINE_LIMIT);
  const overflow = permissions.length - INLINE_LIMIT;

  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {visible.map((p) => (
        <Badge key={p} variant="secondary" className="text-xs font-normal">
          {p}
        </Badge>
      ))}
      {overflow > 0 && (
        <Popover>
          <PopoverTrigger asChild>
            <Button
              variant="outline"
              size="sm"
              className="h-6 gap-1 rounded-full px-2.5 text-xs font-normal text-muted-foreground hover:text-foreground"
            >
              +{overflow} more
              <CaretDownIcon className="h-3 w-3" />
            </Button>
          </PopoverTrigger>
          <PopoverContent
            align="start"
            side="bottom"
            avoidCollisions
            className="w-56 p-0"
            onWheel={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b px-3 py-2">
              <span className="text-xs font-semibold text-muted-foreground">
                Permissions
              </span>
              <span className="text-xs text-muted-foreground">
                {permissions.length} total
              </span>
            </div>
            <ScrollArea className="h-48">
              <div className="py-1">
                {permissions.map((p) => (
                  <div
                    key={p}
                    className="flex items-center gap-2 px-3 py-1.5 text-sm text-foreground hover:bg-muted"
                  >
                    <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-muted-foreground" />
                    {p}
                  </div>
                ))}
              </div>
            </ScrollArea>
          </PopoverContent>
        </Popover>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Create role Dialog
// ---------------------------------------------------------------------------

interface CreateRoleDialogProps {
  open: boolean;
  form: CreateRoleState;
  permissionOptions: Option[];
  isPending: boolean;
  onOpenChange: (open: boolean) => void;
  onChange: (state: CreateRoleState) => void;
  onCreate: () => void;
}

function CreateRoleDialog({
  open,
  form,
  permissionOptions,
  isPending,
  onOpenChange,
  onChange,
  onCreate,
}: CreateRoleDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogTrigger asChild>
        <Button>
          <PlusIcon className="h-4 w-4" />
          Create role
        </Button>
      </DialogTrigger>
      <DialogContent className="flex max-h-[90vh] flex-col sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Create role</DialogTitle>
          <DialogDescription>
            Define a reusable role and its permission set.
          </DialogDescription>
        </DialogHeader>
        <ScrollArea className="flex-1 pr-4">
          <div className="space-y-4 p-2">
            <div className="space-y-2">
              <Label required>Role Name</Label>
              <Input
                value={form.name}
                onChange={(e) => onChange({ ...form, name: e.target.value })}
                placeholder="e.g. SECURITY_AUDITOR"
              />
            </div>
            <div className="space-y-2">
              <Label>Description</Label>
              <Textarea
                value={form.description}
                onChange={(e) =>
                  onChange({ ...form, description: e.target.value })
                }
                placeholder="Describe what this role is for"
              />
            </div>
            <div className="space-y-2">
              <Label>Permissions</Label>
              <MultiSelect
                options={permissionOptions}
                selected={form.permissionNames}
                onChange={(permissionNames) =>
                  onChange({ ...form, permissionNames })
                }
                placeholder="Select permissions..."
              />
            </div>
          </div>
        </ScrollArea>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={onCreate} disabled={isPending}>
            {isPending ? (
              <CircleNotchIcon className="h-4 w-4 animate-spin" />
            ) : null}
            Create role
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Edit Role Dialog
// ---------------------------------------------------------------------------

interface EditRoleDialogProps {
  open: boolean;
  role: EditRoleState | null;
  permissionOptions: Option[];
  isPending: boolean;
  isPermissionsLoading: boolean;
  saveBlockedReason: string | null;
  onOpenChange: (open: boolean) => void;
  onRoleChange: (state: EditRoleState) => void;
  onSave: () => void;
}

function EditRoleDialog({
  open,
  role,
  permissionOptions,
  isPending,
  isPermissionsLoading,
  saveBlockedReason,
  onOpenChange,
  onRoleChange,
  onSave,
}: EditRoleDialogProps) {
  const saveBlockedId = useId();
  if (!role) return null;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="flex max-h-[90vh] flex-col sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Edit Permissions - {role.name}</DialogTitle>
          <DialogDescription>
            Update the permissions assigned to this role.
          </DialogDescription>
        </DialogHeader>
        <ScrollArea className="flex-1 pr-4">
          <div className="space-y-4 py-2">
            <div className="space-y-2">
              <Label>Role</Label>
              <Input value={role.name} disabled />
            </div>
            <div className="space-y-2">
              <Label>Description</Label>
              <Textarea value={role.description} disabled />
            </div>
            <div className="space-y-2">
              <Label>Permissions</Label>
              <MultiSelect
                options={permissionOptions}
                selected={role.permissionNames}
                onChange={(permissionNames) =>
                  onRoleChange({ ...role, permissionNames })
                }
                placeholder={
                  isPermissionsLoading
                    ? "Loading role permissions..."
                    : "Select permissions..."
                }
              />
            </div>
          </div>
        </ScrollArea>
        <DialogFooter>
          <AccessSaveBlockedNote
            id={saveBlockedId}
            reason={saveBlockedReason}
          />
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            onClick={onSave}
            disabled={isPending || Boolean(saveBlockedReason)}
            aria-describedby={saveBlockedReason ? saveBlockedId : undefined}
          >
            {isPending ? (
              <CircleNotchIcon className="h-4 w-4 animate-spin" />
            ) : null}
            Save
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Delete role Dialog
// ---------------------------------------------------------------------------

interface DeleteRoleDialogProps {
  open: boolean;
  role: DeleteRoleState | null;
  isPending: boolean;
  onOpenChange: (open: boolean) => void;
  onDelete: () => void;
}

function DeleteRoleDialog({
  open,
  role,
  isPending,
  onOpenChange,
  onDelete,
}: DeleteRoleDialogProps) {
  if (!role) return null;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Delete role</DialogTitle>
          <DialogDescription>
            Are you sure you want to delete{" "}
            <span className="font-medium">{role.name}</span>? This cannot be
            undone.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="destructive" onClick={onDelete} disabled={isPending}>
            {isPending ? (
              <CircleNotchIcon className="h-4 w-4 animate-spin" />
            ) : null}
            Delete role
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
