// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { use, useState } from "react";
import { useRouter } from "next/navigation";
import { CircleNotchIcon } from "@phosphor-icons/react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { PageHeader } from "@/components/ui/page-header";
import { Unauthorised } from "@/components/common/unautorised";
import { AgentTokensCard } from "@/components/settings/organizations/agent-tokens-card";
import { useAgentTransport } from "@/hooks/use-deployment-mode";
import { useAuth } from "@/hooks/use-auth";
import {
  getApiErrorMessage,
  getOrganizationIdValue,
  useDeleteOrganization,
  useOrganizationBySlug,
  useUpdateOrganization,
} from "@/hooks/organizations";
import {
  canManageOrganizations,
  canUpdateOrganizations,
  canViewOrganizations,
} from "@/lib/authz";
import { formatDate } from "@/lib/utils";
import { isAccessDeniedError, isNotFoundError } from "@/lib/http-errors";
import { isEnterpriseAppMode } from "@/lib/auth-ui-mode";
import {
  DeleteOrganizationDialog,
  DeleteOrganizationState,
  EditOrganizationDialog,
  OrganizationDialogState,
  type EditOrganizationValues,
} from "@/components/settings/organizations/organization-dialogs";
interface OrganizationDetailPageProps {
  params: Promise<{ slug: string }>;
}

const FIXED_DATA_RETENTION_DAYS = 90;

const toOrganizationDialogState = (
  organization: import("@/types/auth").Organization,
): OrganizationDialogState => ({
  organizationId: getOrganizationIdValue(organization),
  name: organization.name || "",
  domain: organization.domain || "",
  active: organization.active !== false,
});

const formatOrganizationDate = (value?: string): string => {
  const formatted = formatDate(value ?? null);
  return formatted === "-" ? "-" : formatted;
};

export default function OrganizationDetailPage({
  params,
}: OrganizationDetailPageProps) {
  const router = useRouter();
  const { user, isSuperAdmin, isLoading: isLoadingAuth } = useAuth();
  const canViewOrganization = canViewOrganizations(user, isSuperAdmin);
  const agentTransport = useAgentTransport();
  const { slug } = use(params);
  const [editOrganization, setEditOrganization] =
    useState<OrganizationDialogState | null>(null);
  const [deleteOrganizationState, setDeleteOrganizationState] =
    useState<DeleteOrganizationState | null>(null);

  const organizationQuery = useOrganizationBySlug(slug, {
    enabled: canViewOrganization,
  });
  const organization = organizationQuery.data;
  const updateOrganization = useUpdateOrganization();
  const deleteOrganization = useDeleteOrganization();
  if (isLoadingAuth || organizationQuery.isLoading) {
    return (
      <div className="flex h-[60vh] items-center justify-center">
        <CircleNotchIcon className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!canViewOrganization) {
    return (
      <div className="p-6">
        <Unauthorised description="You do not have permission to view organization data." />
      </div>
    );
  }

  if (organizationQuery.error) {
    if (isNotFoundError(organizationQuery.error)) {
      return (
        <div className="p-6">
          <Card className="mx-auto max-w-xl">
            <CardHeader>
              <CardTitle>Organization not found</CardTitle>
              <CardDescription>
                The requested organization could not be loaded.
              </CardDescription>
            </CardHeader>
          </Card>
        </div>
      );
    }

    if (isAccessDeniedError(organizationQuery.error)) {
      return (
        <div className="p-6">
          <Unauthorised description="You do not have permission to view this organization." />
        </div>
      );
    }

    return (
      <div className="p-6">
        <Card className="mx-auto max-w-xl">
          <CardHeader>
            <CardTitle>Unable to load organization</CardTitle>
            <CardDescription>
              The organization service did not answer.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button
              variant="outline"
              isPending={organizationQuery.isFetching}
              onClick={() => void organizationQuery.refetch()}
            >
              Retry
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!organization) return null;

  const canEditOrganization = canUpdateOrganizations(user, isSuperAdmin);
  const canDeleteOrganization = canManageOrganizations(user, isSuperAdmin);

  const handleUpdateOrganization = async (values: EditOrganizationValues) => {
    if (!editOrganization) {
      return;
    }

    try {
      await updateOrganization.mutateAsync({
        organizationId: editOrganization.organizationId,
        payload: {
          name: values.name.trim(),
          domain: values.domain.trim(),
          active: values.active,
        },
      });
      setEditOrganization(null);
      toast.success("Organization updated successfully");
      await organizationQuery.refetch();
    } catch (error) {
      toast.error(getApiErrorMessage(error, "Failed to update organization"));
    }
  };

  const handleDeleteOrganization = async () => {
    if (!deleteOrganizationState) {
      return;
    }

    try {
      await deleteOrganization.mutateAsync(
        deleteOrganizationState.organizationId,
      );
      setDeleteOrganizationState(null);
      toast.success("Organization deleted successfully");
      // useDeleteOrganization already invalidated the organization list, so a client-side
      // navigation shows the list without the deleted organization.
      router.push("/settings/organization-access?tab=organization");
    } catch (error) {
      toast.error(getApiErrorMessage(error, "Failed to delete organization"));
    }
  };

  return (
    <div className="w-full space-y-6 p-6">
      <PageHeader
        title={organization.name}
        breadcrumbs={[
          {
            label: isSuperAdmin ? "Organizations" : "Organization",
            href: "/settings/organization-access?tab=organization",
          },
        ]}
        subtitle="Organization overview."
        actions={
          <div className="flex flex-wrap gap-2">
            {canEditOrganization ? (
              <Button
                variant="outline"
                onClick={() =>
                  setEditOrganization(toOrganizationDialogState(organization))
                }
              >
                Edit organization
              </Button>
            ) : null}
            {canDeleteOrganization ? (
              <Button
                variant="ghost"
                className="text-destructive hover:text-destructive"
                onClick={() =>
                  setDeleteOrganizationState({
                    organizationId: getOrganizationIdValue(organization),
                    organizationName: organization.name,
                  })
                }
              >
                Delete organization
              </Button>
            ) : null}
          </div>
        }
      />

      <div className="grid gap-6 lg:grid-cols-[1.3fr_1fr]">
        <Card>
          <CardHeader>
            <CardTitle>Organization details</CardTitle>
            <CardDescription>
              Core workspace and identity settings.
            </CardDescription>
          </CardHeader>
          <CardContent className="grid gap-5 sm:grid-cols-2">
            <div className="space-y-1">
              <p className="text-sm text-muted-foreground">Name</p>
              <p className="font-medium text-foreground">{organization.name}</p>
            </div>
            <div className="space-y-1">
              <p className="text-sm text-muted-foreground">Status</p>
              <div className="flex flex-wrap items-center gap-2">
                <Badge
                  variant={
                    organization.active !== false ? "success" : "secondary"
                  }
                  textOnly
                >
                  {organization.active !== false ? "Active" : "Disabled"}
                </Badge>
              </div>
            </div>
            <div className="space-y-1">
              <p className="text-sm text-muted-foreground">Domain</p>
              <p className="font-medium text-foreground">
                {organization.domain || "-"}
              </p>
            </div>
            <div className="space-y-1">
              <p className="text-sm text-muted-foreground">Slug</p>
              <p className="font-mono text-sm text-foreground">
                {organization.slug || slug}
              </p>
            </div>
            <div className="space-y-1">
              <p className="text-sm text-muted-foreground">Created</p>
              <p className="text-foreground">
                {formatOrganizationDate(organization.createdAt)}
              </p>
            </div>
            <div className="space-y-1">
              <p className="text-sm text-muted-foreground">Updated</p>
              <p className="text-foreground">
                {formatOrganizationDate(organization.updatedAt)}
              </p>
            </div>
          </CardContent>
        </Card>

        <DataRetentionCard canManage={canEditOrganization} />

        {isEnterpriseAppMode() && agentTransport === "GATEWAY" && (
          <AgentTokensCard
            organizationId={getOrganizationIdValue(organization)}
            canManage={canEditOrganization}
          />
        )}
      </div>

      <EditOrganizationDialog
        open={Boolean(editOrganization)}
        canUpdate={canEditOrganization}
        organization={editOrganization}
        isPending={updateOrganization.isPending}
        onOpenChange={(open) => {
          if (!open) {
            setEditOrganization(null);
          }
        }}
        onSave={handleUpdateOrganization}
      />

      <DeleteOrganizationDialog
        open={Boolean(deleteOrganizationState)}
        canDelete={canDeleteOrganization}
        organization={deleteOrganizationState}
        isPending={deleteOrganization.isPending}
        onOpenChange={(open) => {
          if (!open) {
            setDeleteOrganizationState(null);
          }
        }}
        onDelete={handleDeleteOrganization}
      />
    </div>
  );
}

function DataRetentionCard({ canManage }: { canManage: boolean }) {
  if (!canManage) return null;

  return (
    <Card>
      <CardHeader>
        <CardTitle>Data retention</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        <p className="text-2xl font-semibold text-foreground tabular-nums">
          {FIXED_DATA_RETENTION_DAYS} days
        </p>
        <p className="text-sm text-muted-foreground">
          Removed records are kept for {FIXED_DATA_RETENTION_DAYS} days, then
          deleted for good. The same policy applies to every organization.
        </p>
      </CardContent>
    </Card>
  );
}
