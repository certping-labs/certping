// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useId, useMemo } from "react";
import { useForm, useWatch, type Resolver } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { CircleNotchIcon } from "@phosphor-icons/react";

import { MultiSelect, type Option } from "@/components/ui/multi-select";
import { AccessSaveBlockedNote } from "@/components/settings/teams/access-save-blocked-note";
import { Button } from "@/components/ui/button";
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { RequiredMark } from "@/components/settings/teams/user-dialogs";
import {
  getExtraPermissionNames,
  getRoleProvidedPermissions,
  type RolePermissionsById,
} from "@/lib/member-access";

export interface EditUserState {
  id: number | string;
  displayName: string;
  email: string;
  username: string;
  roleIds: string[];
  active: boolean;
}

export type DirectGrantsState =
  | { status: "loading" }
  | { status: "ready"; permissionNames: string[] }
  | { status: "unavailable" };

const editUserSchema = z.object({
  displayName: z.string().trim().default(""),
  username: z.string().trim().default(""),
  email: z
    .string()
    .trim()
    .min(1, "Email is required")
    .email("Enter a valid email address"),
  roleIds: z.array(z.string()).default([]),
  extraPermissionNames: z.array(z.string()).default([]),
});

export type EditUserValues = z.infer<typeof editUserSchema>;

interface EditUserDialogProps {
  open: boolean;
  user: EditUserState | null;
  directGrants: DirectGrantsState;
  isPending: boolean;
  roleOptions: Option[];
  rolePermissionsById: RolePermissionsById;
  permissionOptions: Option[];
  /** Set while saving must wait; shown beside the disabled Save. */
  saveBlockedReason?: string | null;
  onOpenChange: (open: boolean) => void;
  onSave: (values: EditUserValues) => void | Promise<void>;
}

export function EditUserDialog({
  open,
  user,
  directGrants,
  onOpenChange,
  ...formProps
}: EditUserDialogProps) {
  if (!user) return null;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="flex max-h-[92vh] flex-col sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>Edit member</DialogTitle>
          <DialogDescription>
            Update the member profile, assigned roles, and any permissions
            granted on top of those roles.
          </DialogDescription>
        </DialogHeader>

        {directGrants.status === "loading" ? (
          <EditUserLoading onCancel={() => onOpenChange(false)} />
        ) : (
          <EditUserForm
            key={user.id}
            user={user}
            directGrants={directGrants}
            onCancel={() => onOpenChange(false)}
            {...formProps}
          />
        )}
      </DialogContent>
    </Dialog>
  );
}

function EditUserLoading({ onCancel }: { onCancel: () => void }) {
  return (
    <>
      <div className="space-y-4 p-2" role="status" aria-live="polite">
        <span className="sr-only">Loading member access</span>
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-32 w-full" />
      </div>
      <DialogFooter className="mt-4">
        <Button type="button" variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="button" disabled>
          Save
        </Button>
      </DialogFooter>
    </>
  );
}

interface EditUserFormProps {
  user: EditUserState;
  directGrants: Exclude<DirectGrantsState, { status: "loading" }>;
  isPending: boolean;
  roleOptions: Option[];
  rolePermissionsById: RolePermissionsById;
  permissionOptions: Option[];
  saveBlockedReason?: string | null;
  onCancel: () => void;
  onSave: (values: EditUserValues) => void | Promise<void>;
}

function EditUserForm({
  user,
  directGrants,
  isPending,
  roleOptions,
  rolePermissionsById,
  permissionOptions,
  saveBlockedReason = null,
  onCancel,
  onSave,
}: EditUserFormProps) {
  const saveBlockedId = useId();
  const form = useForm<EditUserValues>({
    resolver: zodResolver(editUserSchema) as Resolver<EditUserValues>,
    mode: "onBlur",
    reValidateMode: "onChange",
    defaultValues: {
      displayName: user.displayName,
      username: user.username,
      email: user.email,
      roleIds: user.roleIds,
      extraPermissionNames:
        directGrants.status === "ready"
          ? getExtraPermissionNames(
              directGrants.permissionNames,
              user.roleIds,
              rolePermissionsById,
            )
          : [],
    },
  });

  const selectedRoleIds = useWatch({ control: form.control, name: "roleIds" });
  const roleProvidedPermissions = useMemo(
    () => getRoleProvidedPermissions(selectedRoleIds, rolePermissionsById),
    [rolePermissionsById, selectedRoleIds],
  );
  const roleProvidedNames = useMemo(
    () => new Set(roleProvidedPermissions.map((permission) => permission.name)),
    [roleProvidedPermissions],
  );
  const extraPermissionOptions = useMemo(
    () =>
      permissionOptions.filter(
        (option) => !roleProvidedNames.has(option.value),
      ),
    [permissionOptions, roleProvidedNames],
  );

  const submit = form.handleSubmit(async (values) => {
    if (saveBlockedReason) return;
    await onSave({
      ...values,
      extraPermissionNames: getExtraPermissionNames(
        values.extraPermissionNames,
        values.roleIds,
        rolePermissionsById,
      ),
    });
  });

  return (
    <Form {...form}>
      <form onSubmit={submit} className="flex flex-1 flex-col overflow-hidden">
        <ScrollArea className="flex-1 pr-4">
          <div className="grid gap-5 p-2 sm:grid-cols-2">
            <FormField
              control={form.control}
              name="displayName"
              render={({ field }) => (
                <FormItem className="sm:col-span-1">
                  <FormLabel>Display Name</FormLabel>
                  <FormControl>
                    <Input placeholder="e.g. Jane Doe" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="username"
              render={({ field }) => (
                <FormItem className="sm:col-span-1">
                  <FormLabel>Username</FormLabel>
                  <FormControl>
                    <Input placeholder="e.g. jane" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="email"
              render={({ field }) => (
                <FormItem className="sm:col-span-2">
                  <FormLabel>
                    Email
                    <RequiredMark />
                  </FormLabel>
                  <FormControl>
                    <Input
                      type="email"
                      autoComplete="off"
                      placeholder="jane@example.com"
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="roleIds"
              render={({ field }) => (
                <FormItem className="sm:col-span-2">
                  <FormLabel>Roles</FormLabel>
                  <FormControl>
                    <MultiSelect
                      options={roleOptions}
                      selected={field.value}
                      onChange={field.onChange}
                      placeholder="Assign roles..."
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <RoleProvidedPermissionList
              permissions={roleProvidedPermissions}
              roleOptions={roleOptions}
              permissionOptions={permissionOptions}
            />

            {directGrants.status === "ready" ? (
              <FormField
                control={form.control}
                name="extraPermissionNames"
                render={({ field }) => (
                  <FormItem className="sm:col-span-2">
                    <FormLabel>Additional permissions</FormLabel>
                    <FormControl>
                      <MultiSelect
                        options={extraPermissionOptions}
                        selected={field.value.filter(
                          (name) => !roleProvidedNames.has(name),
                        )}
                        onChange={(visibleNames) =>
                          field.onChange([
                            ...visibleNames,
                            ...field.value.filter((name) =>
                              roleProvidedNames.has(name),
                            ),
                          ])
                        }
                        placeholder="Add permissions beyond the roles..."
                      />
                    </FormControl>
                    <FormDescription className="text-xs">
                      Granted to this member directly, on top of their roles.
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />
            ) : (
              <div className="space-y-1 sm:col-span-2">
                <p className="text-sm font-medium">Additional permissions</p>
                <p className="text-xs text-muted-foreground">
                  This member&apos;s direct permissions couldn&apos;t be loaded,
                  so saving leaves them unchanged.
                </p>
              </div>
            )}
          </div>
        </ScrollArea>

        <DialogFooter className="mt-4">
          <AccessSaveBlockedNote
            id={saveBlockedId}
            reason={saveBlockedReason}
          />
          <Button type="button" variant="outline" onClick={onCancel}>
            Cancel
          </Button>
          <Button
            type="submit"
            disabled={isPending || Boolean(saveBlockedReason)}
            aria-describedby={saveBlockedReason ? saveBlockedId : undefined}
          >
            {isPending ? (
              <CircleNotchIcon className="h-4 w-4 animate-spin" />
            ) : null}
            Save
          </Button>
        </DialogFooter>
      </form>
    </Form>
  );
}

interface RoleProvidedPermissionListProps {
  permissions: ReturnType<typeof getRoleProvidedPermissions>;
  roleOptions: Option[];
  permissionOptions: Option[];
}

function RoleProvidedPermissionList({
  permissions,
  roleOptions,
  permissionOptions,
}: RoleProvidedPermissionListProps) {
  const headingId = useId();
  const roleLabels = useMemo(
    () => new Map(roleOptions.map((option) => [option.value, option.label])),
    [roleOptions],
  );
  const permissionLabels = useMemo(
    () =>
      new Map(permissionOptions.map((option) => [option.value, option.label])),
    [permissionOptions],
  );

  return (
    <section aria-labelledby={headingId} className="space-y-2 sm:col-span-2">
      <div className="flex items-center justify-between gap-3">
        <h3 id={headingId} className="text-sm font-medium">
          Permissions from roles
        </h3>
        <span className="text-xs text-muted-foreground">
          {permissions.length}{" "}
          {permissions.length === 1 ? "permission" : "permissions"}
        </span>
      </div>
      {permissions.length === 0 ? (
        <p className="rounded-[10px] border border-dashed border-border px-3 py-2 text-xs text-muted-foreground">
          The selected roles don&apos;t grant any permissions.
        </p>
      ) : (
        <ul
          aria-labelledby={headingId}
          tabIndex={0}
          className="max-h-56 divide-y divide-border overflow-y-auto rounded-[10px] border border-border focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-hidden"
        >
          {permissions.map((permission) => {
            const label = permissionLabels.get(permission.name);
            return (
              <li
                key={permission.name}
                className="flex items-start justify-between gap-3 px-3 py-2"
              >
                <div className="min-w-0">
                  <p className="text-sm">{label ?? permission.name}</p>
                  {label && label !== permission.name ? (
                    <p className="truncate font-mono text-xs text-muted-foreground">
                      {permission.name}
                    </p>
                  ) : null}
                </div>
                <span className="shrink-0 text-right text-xs text-muted-foreground">
                  From{" "}
                  {permission.roleIds
                    .map((roleId) => roleLabels.get(roleId) ?? roleId)
                    .join(", ")}
                </span>
              </li>
            );
          })}
        </ul>
      )}
      <p className="text-xs text-muted-foreground">
        These come with the roles above and are removed when a role is removed.
      </p>
    </section>
  );
}
