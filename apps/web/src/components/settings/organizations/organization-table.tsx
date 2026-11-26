// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import { ColumnDef } from "@tanstack/react-table";
import {
  EyeIcon,
  PencilSimpleIcon,
  SignInIcon,
  TrashIcon,
} from "@phosphor-icons/react";
import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import { RowActionsTrigger } from "@/components/ui/row-actions-trigger";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { getOrganizationIdValue } from "@/lib/backend/organizations";
import { getOrganizationDetailHref } from "@/lib/organization-routing";
import { compareDateValues } from "@/lib/table-sorting";
import { formatDate } from "@/lib/utils";
import { Organization } from "@/types/auth";

interface OrganizationTableOptions {
  canUpdate: boolean;
  canDelete: boolean;
  /** The organization the signed-in user works in, to mark it and hide its "Work in" action. */
  currentOrganizationId?: string | number | null;
  onView: (organization: Organization) => void;
  onEdit: (organization: Organization) => void;
  onDelete: (organization: Organization) => void;
  /** Super admin only: make this the organization they work in. */
  onWorkIn?: (organization: Organization) => void;
}

const isCurrent = (
  organization: Organization,
  currentOrganizationId?: string | number | null,
) =>
  currentOrganizationId != null &&
  String(getOrganizationIdValue(organization)) ===
    String(currentOrganizationId);

const formatCreatedDate = (value?: string): string => {
  const formatted = formatDate(value ?? null);
  return formatted === "-" ? "-" : formatted;
};

export const createOrganizationColumns = ({
  canUpdate,
  canDelete,
  currentOrganizationId,
  onView,
  onEdit,
  onDelete,
  onWorkIn,
}: OrganizationTableOptions): ColumnDef<Organization>[] => [
  {
    accessorKey: "name",
    header: "Name",
    cell: ({ row }) => (
      <span className="inline-flex items-center gap-2">
        <Link
          href={getOrganizationDetailHref(row.original)}
          className="font-medium text-foreground transition-colors hover:text-primary"
        >
          {row.original.name}
        </Link>
        {isCurrent(row.original, currentOrganizationId) ? (
          <Badge variant="secondary" textOnly>
            Working here
          </Badge>
        ) : null}
      </span>
    ),
  },
  {
    accessorKey: "domain",
    header: "Domain",
    cell: ({ row }) =>
      row.original.domain ? (
        <span
          className="block max-w-[16rem] truncate"
          title={row.original.domain}
        >
          {row.original.domain}
        </span>
      ) : (
        <span className="text-muted-foreground">-</span>
      ),
  },
  {
    accessorKey: "active",
    header: "Status",
    cell: ({ row }) => (
      <div className="flex justify-start">
        <Badge
          variant={row.original.active !== false ? "success" : "secondary"}
          textOnly
        >
          {row.original.active !== false ? "Active" : "Disabled"}
        </Badge>
      </div>
    ),
  },
  {
    accessorKey: "createdAt",
    header: "Created",
    enableSorting: true,
    sortingFn: (rowA, rowB, columnId) =>
      compareDateValues(rowA.getValue(columnId), rowB.getValue(columnId)),
    cell: ({ row }) => (
      <span className="text-sm text-muted-foreground">
        {formatCreatedDate(row.original.createdAt)}
      </span>
    ),
  },
  {
    id: "actions",
    size: 56,
    header: () => <span className="sr-only">Actions</span>,
    cell: ({ row }) => (
      <div className="flex items-center justify-end">
        <OrganizationActionsMenu
          organization={row.original}
          canUpdate={canUpdate}
          canDelete={canDelete}
          onView={onView}
          onEdit={onEdit}
          onDelete={onDelete}
          onWorkIn={
            onWorkIn && !isCurrent(row.original, currentOrganizationId)
              ? onWorkIn
              : undefined
          }
        />
      </div>
    ),
  },
];

function OrganizationActionsMenu({
  organization,
  canUpdate,
  canDelete,
  onView,
  onEdit,
  onDelete,
  onWorkIn,
}: {
  organization: Organization;
  canUpdate: boolean;
  canDelete: boolean;
  onWorkIn?: (organization: Organization) => void;
  onView: (organization: Organization) => void;
  onEdit: (organization: Organization) => void;
  onDelete: (organization: Organization) => void;
}) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <RowActionsTrigger label={organization.name || "organization"} />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        {onWorkIn ? (
          <DropdownMenuItem onClick={() => onWorkIn(organization)}>
            <SignInIcon className="h-4 w-4" />
            Work in this organization
          </DropdownMenuItem>
        ) : null}
        <DropdownMenuItem onClick={() => onView(organization)}>
          <EyeIcon className="h-4 w-4" />
          View details
        </DropdownMenuItem>
        {canUpdate ? (
          <DropdownMenuItem onClick={() => onEdit(organization)}>
            <PencilSimpleIcon className="h-4 w-4" />
            Edit
          </DropdownMenuItem>
        ) : null}
        {canDelete ? (
          <DropdownMenuItem
            onClick={() => onDelete(organization)}
            className="text-destructive focus:text-destructive"
          >
            <TrashIcon className="h-4 w-4" />
            Delete organization
          </DropdownMenuItem>
        ) : null}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

export function OrganizationCard({
  organization,
  canUpdate,
  canDelete,
  currentOrganizationId,
  onView,
  onEdit,
  onDelete,
  onWorkIn,
}: OrganizationTableOptions & { organization: Organization }) {
  const active = organization.active !== false;
  const current = isCurrent(organization, currentOrganizationId);

  return (
    <div className="min-w-0 space-y-4 rounded-lg border border-border bg-card p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 space-y-1">
          <Link
            href={getOrganizationDetailHref(organization)}
            className="block truncate font-medium text-foreground transition-colors hover:text-primary"
          >
            {organization.name}
          </Link>
          <p className="truncate text-xs text-muted-foreground">
            {organization.domain || "No domain"}
          </p>
        </div>
        <OrganizationActionsMenu
          organization={organization}
          canUpdate={canUpdate}
          canDelete={canDelete}
          onView={onView}
          onEdit={onEdit}
          onDelete={onDelete}
          onWorkIn={onWorkIn && !current ? onWorkIn : undefined}
        />
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Badge variant={active ? "success" : "secondary"} textOnly>
          {active ? "Active" : "Disabled"}
        </Badge>
        {current ? (
          <Badge variant="secondary" textOnly>
            Working here
          </Badge>
        ) : null}
      </div>

      <p className="text-xs text-muted-foreground">
        Created {formatCreatedDate(organization.createdAt)}
      </p>
    </div>
  );
}
