// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useEffect } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { CircleNotchIcon, PlusIcon } from "@phosphor-icons/react";

import { Button } from "@/components/ui/button";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Switch } from "@/components/ui/switch";

export interface OrganizationDialogState {
  organizationId: string;
  name: string;
  domain: string;
  active: boolean;
}

export interface DeleteOrganizationState {
  organizationId: string;
  organizationName: string;
}

function RequiredMark() {
  return (
    <span className="ml-1 text-destructive" aria-hidden="true">
      *
    </span>
  );
}

const DOMAIN_REGEX =
  /^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

const organizationFormSchema = z.object({
  name: z.string().trim().min(1, "Organization name is required"),
  domain: z
    .string()
    .trim()
    .min(1, "Domain is required")
    .regex(DOMAIN_REGEX, "Enter a valid domain (e.g., acme.com)"),
});

const editOrganizationSchema = organizationFormSchema.extend({
  active: z.boolean(),
});

export type CreateOrganizationValues = z.infer<typeof organizationFormSchema>;
export type EditOrganizationValues = z.infer<typeof editOrganizationSchema>;

const EMPTY_CREATE_VALUES: CreateOrganizationValues = {
  name: "",
  domain: "",
};

// ---- Create organization Dialog ----

interface CreateOrganizationDialogProps {
  open: boolean;
  canCreate: boolean;
  isPending: boolean;
  onOpenChange: (open: boolean) => void;
  onCreate: (values: CreateOrganizationValues) => void | Promise<void>;
}

export function CreateOrganizationDialog({
  open,
  canCreate,
  isPending,
  onOpenChange,
  onCreate,
}: CreateOrganizationDialogProps) {
  const form = useForm<CreateOrganizationValues>({
    resolver: zodResolver(organizationFormSchema),
    mode: "onBlur",
    reValidateMode: "onChange",
    defaultValues: EMPTY_CREATE_VALUES,
  });

  useEffect(() => {
    if (open) {
      form.reset(EMPTY_CREATE_VALUES);
    }
  }, [open, form]);

  if (!canCreate) {
    return null;
  }

  const submit = form.handleSubmit(async (values) => {
    await onCreate(values);
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogTrigger asChild>
        <Button>
          <PlusIcon className="h-4 w-4" />
          Create organization
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Create organization</DialogTitle>
          <DialogDescription>
            Create a new organization workspace.
          </DialogDescription>
        </DialogHeader>

        <Form {...form}>
          <form onSubmit={submit} className="space-y-4 py-2">
            <FormField
              control={form.control}
              name="name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>
                    Organization Name
                    <RequiredMark />
                  </FormLabel>
                  <FormControl>
                    <Input placeholder="e.g. Acme Corporation" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="domain"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>
                    Domain
                    <RequiredMark />
                  </FormLabel>
                  <FormControl>
                    <Input placeholder="e.g. acme.com" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => onOpenChange(false)}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={isPending}>
                {isPending ? (
                  <CircleNotchIcon className="mr-2 h-4 w-4 animate-spin" />
                ) : null}
                Create
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}

interface EditOrganizationDialogProps {
  open: boolean;
  canUpdate: boolean;
  organization: OrganizationDialogState | null;
  isPending: boolean;
  onOpenChange: (open: boolean) => void;
  onSave: (values: EditOrganizationValues) => void | Promise<void>;
}

export function EditOrganizationDialog({
  open,
  canUpdate,
  organization,
  isPending,
  onOpenChange,
  onSave,
}: EditOrganizationDialogProps) {
  const form = useForm<EditOrganizationValues>({
    resolver: zodResolver(editOrganizationSchema),
    mode: "onBlur",
    reValidateMode: "onChange",
    defaultValues: { name: "", domain: "", active: true },
  });

  useEffect(() => {
    if (open && organization) {
      form.reset({
        name: organization.name,
        domain: organization.domain,
        active: organization.active,
      });
    }
  }, [open, organization, form]);

  if (!canUpdate) {
    return null;
  }

  const submit = form.handleSubmit(async (values) => {
    await onSave(values);
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Edit organization</DialogTitle>
          <DialogDescription>
            Update organization details and active status.
          </DialogDescription>
        </DialogHeader>

        <Form {...form}>
          <form onSubmit={submit} className="space-y-4 py-2">
            <FormField
              control={form.control}
              name="name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>
                    Organization Name
                    <RequiredMark />
                  </FormLabel>
                  <FormControl>
                    <Input {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="domain"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>
                    Domain
                    <RequiredMark />
                  </FormLabel>
                  <FormControl>
                    <Input {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="active"
              render={({ field }) => (
                <FormItem className="flex items-center justify-between rounded-lg border px-3 py-2">
                  <Label className="text-sm" htmlFor="organization-active">
                    Active
                  </Label>
                  <FormControl>
                    <Switch
                      id="organization-active"
                      checked={field.value}
                      onCheckedChange={field.onChange}
                    />
                  </FormControl>
                </FormItem>
              )}
            />

            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => onOpenChange(false)}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={isPending}>
                {isPending ? (
                  <CircleNotchIcon className="mr-2 h-4 w-4 animate-spin" />
                ) : null}
                Save Changes
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}

// ---- Delete organization Dialog ----

interface DeleteOrganizationDialogProps {
  open: boolean;
  canDelete: boolean;
  organization: DeleteOrganizationState | null;
  isPending: boolean;
  onOpenChange: (open: boolean) => void;
  onDelete: () => void;
}

export function DeleteOrganizationDialog({
  open,
  canDelete,
  organization,
  isPending,
  onOpenChange,
  onDelete,
}: DeleteOrganizationDialogProps) {
  if (!canDelete) {
    return null;
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!isPending) onOpenChange(next);
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Delete organization</DialogTitle>
          <DialogDescription>
            {organization
              ? `Delete ${organization.organizationName}? Members lose access immediately, and its certificates, integrations and settings are removed. This action cannot be undone.`
              : "Delete this organization?"}
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="destructive" onClick={onDelete} disabled={isPending}>
            {isPending ? (
              <CircleNotchIcon className="mr-2 h-4 w-4 animate-spin" />
            ) : null}
            Delete organization
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
