// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useEffect, useState } from "react";
import { useForm, type Resolver } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import {
  EyeIcon,
  EyeSlashIcon,
  CircleNotchIcon,
  PlusIcon,
} from "@phosphor-icons/react";

import { MultiSelect, type Option } from "@/components/ui/multi-select";
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import type { CreateUserRequest, UpdateUserRequest } from "@/types/auth";

// ---- Invite / Create User Dialog ----

export function RequiredMark() {
  return (
    <span className="ml-1 text-destructive" aria-hidden="true">
      *
    </span>
  );
}

const inviteUserBaseSchema = z.object({
  organizationId: z.string().default(""),
  displayName: z.string().trim().default(""),
  username: z.string().trim().default(""),
  email: z
    .string()
    .trim()
    .min(1, "Email is required")
    .email("Enter a valid email address"),
  roleIds: z.array(z.string()).min(1, "Choose at least one role"),
  password: z.string().min(12, "Password must be at least 12 characters"),
});

export type InviteUserValues = z.infer<typeof inviteUserBaseSchema>;

/**
 * Organization is mandatory when a super admin creates a member, EXCEPT when the new
 * member is themselves being made a super admin - super admins are platform-level and
 * are not tied to an organization (their organization is null). {@link superAdminRoleIds}
 * are the role ids that map to the SUPER_ADMIN role, resolved by the caller.
 */
export const buildInviteUserSchema = (
  isSuperAdmin: boolean,
  superAdminRoleIds: string[] = [],
) =>
  inviteUserBaseSchema.superRefine((value, ctx) => {
    const isCreatingSuperAdmin = value.roleIds.some((roleId) =>
      superAdminRoleIds.includes(roleId),
    );

    if (isSuperAdmin && !isCreatingSuperAdmin && !value.organizationId.trim()) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["organizationId"],
        message: "Select an organization",
      });
    }

    if (
      value.username.trim() &&
      value.password &&
      value.username.trim() === value.password
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["password"],
        message: "Password cannot be the same as the username",
      });
    }
  });

const EMPTY_INVITE_USER_VALUES: InviteUserValues = {
  organizationId: "",
  displayName: "",
  username: "",
  email: "",
  roleIds: [],
  password: "",
};

export interface OrganizationOption {
  value: string;
  label: string;
}

interface InviteUserDialogProps {
  open: boolean;
  canCreate: boolean;
  isSuperAdmin?: boolean;
  /** Role ids that correspond to the SUPER_ADMIN role; used to relax the org requirement. */
  superAdminRoleIds?: string[];
  isPending: boolean;
  roleOptions: Option[];
  organizationOptions?: OrganizationOption[];
  rolesHelpText?: string;
  onOpenChange: (open: boolean) => void;
  onCreate: (values: InviteUserValues) => void | Promise<void>;
}

export function InviteUserDialog({
  open,
  canCreate,
  isSuperAdmin,
  superAdminRoleIds,
  isPending,
  roleOptions,
  organizationOptions,
  rolesHelpText,
  onOpenChange,
  onCreate,
}: InviteUserDialogProps) {
  const [isPasswordVisible, setIsPasswordVisible] = useState(false);
  const form = useForm<InviteUserValues>({
    resolver: zodResolver(
      buildInviteUserSchema(Boolean(isSuperAdmin), superAdminRoleIds ?? []),
    ) as Resolver<InviteUserValues>,
    mode: "onBlur",
    reValidateMode: "onChange",
    defaultValues: EMPTY_INVITE_USER_VALUES,
  });

  // Reset when the dialog opens so a second invite starts clean.
  useEffect(() => {
    if (open) {
      form.reset(EMPTY_INVITE_USER_VALUES);
      setIsPasswordVisible(false);
    }
  }, [open, form]);

  // A super admin can omit the organization when the new member is themselves a super
  // admin (platform-level, no organization). Clear any stale "select an organization"
  // error the moment a super-admin role is chosen.
  const selectedRoleIds = form.watch("roleIds");
  const isCreatingSuperAdmin = (selectedRoleIds ?? []).some((roleId) =>
    (superAdminRoleIds ?? []).includes(roleId),
  );
  useEffect(() => {
    if (isCreatingSuperAdmin) {
      form.clearErrors("organizationId");
    }
  }, [isCreatingSuperAdmin, form]);

  if (!canCreate) return null;

  const submit = form.handleSubmit(async (values) => {
    await onCreate(values);
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogTrigger asChild>
        <Button>
          <PlusIcon className="h-4 w-4" />
          Add member
        </Button>
      </DialogTrigger>
      <DialogContent className="flex max-h-[90vh] flex-col">
        <DialogHeader>
          <DialogTitle>Add member</DialogTitle>
          <DialogDescription>
            Create a new local user account.
          </DialogDescription>
        </DialogHeader>

        <Form {...form}>
          <form
            onSubmit={submit}
            className="flex flex-1 flex-col overflow-hidden"
          >
            <ScrollArea className="flex-1 overflow-y-auto pr-4">
              <div className="space-y-4 p-2">
                {isSuperAdmin ? (
                  <FormField
                    control={form.control}
                    name="organizationId"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>
                          Organization
                          {isCreatingSuperAdmin ? null : <RequiredMark />}
                        </FormLabel>
                        <Select
                          value={field.value}
                          onValueChange={field.onChange}
                        >
                          <FormControl>
                            <SelectTrigger>
                              <SelectValue placeholder="Select an organization..." />
                            </SelectTrigger>
                          </FormControl>
                          <SelectContent>
                            {(organizationOptions ?? []).map((t) => (
                              <SelectItem key={t.value} value={t.value}>
                                {t.label}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                        <FormDescription className="text-xs">
                          {isCreatingSuperAdmin
                            ? "Optional - super admins are platform-level and aren't tied to an organization."
                            : "The organization this member will belong to."}
                        </FormDescription>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                ) : null}

                <FormField
                  control={form.control}
                  name="displayName"
                  render={({ field }) => (
                    <FormItem>
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
                    <FormItem>
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
                    <FormItem>
                      <FormLabel>
                        Email
                        <RequiredMark />
                      </FormLabel>
                      <FormControl>
                        <Input
                          type="email"
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
                    <FormItem>
                      <FormLabel>
                        Roles
                        <RequiredMark />
                      </FormLabel>
                      <FormControl>
                        <MultiSelect
                          options={roleOptions}
                          selected={field.value}
                          onChange={field.onChange}
                          placeholder={
                            roleOptions.length > 0
                              ? "Assign roles..."
                              : "No roles available"
                          }
                        />
                      </FormControl>
                      {rolesHelpText ? (
                        <FormDescription className="text-xs">
                          {rolesHelpText}
                        </FormDescription>
                      ) : null}
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="password"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>
                        Password
                        <RequiredMark />
                      </FormLabel>
                      <FormControl>
                        <div className="relative">
                          <Input
                            type={isPasswordVisible ? "text" : "password"}
                            placeholder="Minimum 12 characters"
                            className="pr-10"
                            {...field}
                          />
                          <Button
                            type="button"
                            variant="ghost"
                            size="icon"
                            className="absolute top-1/2 right-1 h-8 w-8 -translate-y-1/2 text-muted-foreground"
                            aria-label={
                              isPasswordVisible
                                ? "Hide password"
                                : "Show password"
                            }
                            onClick={() =>
                              setIsPasswordVisible((current) => !current)
                            }
                          >
                            {isPasswordVisible ? (
                              <EyeSlashIcon className="h-4 w-4" />
                            ) : (
                              <EyeIcon className="h-4 w-4" />
                            )}
                          </Button>
                        </div>
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>
            </ScrollArea>

            <DialogFooter className="mt-4">
              <Button
                type="button"
                variant="outline"
                onClick={() => onOpenChange(false)}
              >
                Cancel
              </Button>
              <Button
                type="submit"
                disabled={isPending || roleOptions.length === 0}
              >
                {isPending ? (
                  <CircleNotchIcon className="h-4 w-4 animate-spin" />
                ) : null}
                Add member
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}

// ---- Delete User Dialog ----

export interface DeleteUserState {
  id: number | string;
  displayName: string;
}

interface DeleteUserDialogProps {
  open: boolean;
  user: DeleteUserState | null;
  isPending: boolean;
  onOpenChange: (open: boolean) => void;
  onDelete: () => void;
}

export function DeleteUserDialog({
  open,
  user,
  isPending,
  onOpenChange,
  onDelete,
}: DeleteUserDialogProps) {
  if (!user) return null;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Remove member</DialogTitle>
          <DialogDescription>
            Are you sure you want to remove{" "}
            <span className="font-medium">{user.displayName}</span>? This action
            cannot be undone.
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
            Remove
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export type { CreateUserRequest, UpdateUserRequest };
