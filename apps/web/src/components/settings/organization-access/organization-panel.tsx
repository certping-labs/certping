// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  BuildingsIcon,
  CircleNotchIcon,
  MagnifyingGlassIcon,
} from "@phosphor-icons/react";
import Link from "next/link";
import { toast } from "sonner";

import {
  createOrganizationColumns,
  OrganizationCard,
} from "@/components/settings/organizations/organization-table";
import { Unauthorised } from "@/components/common/unautorised";
import {
  CreateOrganizationDialog,
  DeleteOrganizationDialog,
  DeleteOrganizationState,
  EditOrganizationDialog,
  OrganizationDialogState,
  type CreateOrganizationValues,
  type EditOrganizationValues,
} from "@/components/settings/organizations/organization-dialogs";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { CustomTable } from "@/components/ui/custom-table";
import { Input } from "@/components/ui/input";
import { PageHeader } from "@/components/ui/page-header";
import { Skeleton } from "@/components/ui/skeleton";
import { ViewSwitcher } from "@/components/ui/view-switcher";
import { useResponsiveViewMode } from "@/hooks/use-responsive-view-mode";
import { fuzzySearch } from "@/lib/fuzzy-search";
import { useAuth } from "@/hooks/use-auth";
import { setWorkingOrganization } from "@/lib/backend/organizations";
import { getPostAuthRoute } from "@/lib/post-auth";
import {
  getApiErrorMessage,
  getOrganizationIdValue,
  useCreateOrganization,
  useDeleteOrganization,
  useOrganizationById,
  useOrganizations,
  useUpdateOrganization,
} from "@/hooks/organizations";
import {
  canManageOrganizations,
  canUpdateOrganizations,
  canViewOrganizations,
} from "@/lib/authz";
import { isAccessDeniedError } from "@/lib/http-errors";
import { getOrganizationDetailHref } from "@/lib/organization-routing";
import { Organization } from "@/types/auth";
import { useRouter } from "next/navigation";

const toOrganizationDialogState = (
  organization: Organization,
): OrganizationDialogState => ({
  organizationId: getOrganizationIdValue(organization),
  name: organization.name || "",
  domain: organization.domain || "",
  active: organization.active !== false,
});

/**
 * The Organization tab: the current organization for an organization admin,
 * or every organization for a super admin (who also creates them here).
 */
export function OrganizationPanel() {
  const {
    user,
    isSuperAdmin,
    isLoading: isLoadingAuth,
    establishSession,
  } = useAuth();
  const router = useRouter();
  const canViewOrganizationSettings = canViewOrganizations(user, isSuperAdmin);
  const canUpdateOrganizationSettings = canUpdateOrganizations(
    user,
    isSuperAdmin,
  );
  const canCreateOrDeleteOrganizations = canManageOrganizations(
    user,
    isSuperAdmin,
  );

  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
  const [editOrganization, setEditOrganization] =
    useState<OrganizationDialogState | null>(null);
  const [deleteOrganizationState, setDeleteOrganizationState] =
    useState<DeleteOrganizationState | null>(null);
  const [accessDeniedByScope, setAccessDeniedByScope] = useState<
    Record<string, boolean>
  >({});
  const [viewMode, setViewMode] = useResponsiveViewMode({
    storageKey: "organizations_view",
  });
  const [cardSearchTerm, setCardSearchTerm] = useState("");
  const accessScopeKey = `${canViewOrganizationSettings ? "1" : "0"}:${user?.id ?? "anon"}`;
  const apiAccessDenied = Boolean(accessDeniedByScope[accessScopeKey]);

  const markApiAccessDenied = useCallback(() => {
    setAccessDeniedByScope((previous) => {
      if (previous[accessScopeKey]) {
        return previous;
      }
      return {
        ...previous,
        [accessScopeKey]: true,
      };
    });
  }, [accessScopeKey]);

  const organizationsQuery = useOrganizations({
    enabled:
      canViewOrganizationSettings &&
      canCreateOrDeleteOrganizations &&
      !apiAccessDenied,
  });
  const currentOrganizationQuery = useOrganizationById(user?.organizationId, {
    enabled:
      canViewOrganizationSettings &&
      !canCreateOrDeleteOrganizations &&
      Boolean(user?.organizationId) &&
      !apiAccessDenied,
  });

  const createOrganization = useCreateOrganization();
  const updateOrganization = useUpdateOrganization();
  const deleteOrganization = useDeleteOrganization();

  const organizations = useMemo<Organization[]>(() => {
    if (canCreateOrDeleteOrganizations) {
      return organizationsQuery.data ?? [];
    }

    return currentOrganizationQuery.data ? [currentOrganizationQuery.data] : [];
  }, [
    canCreateOrDeleteOrganizations,
    currentOrganizationQuery.data,
    organizationsQuery.data,
  ]);

  const cardOrganizations = useMemo(() => {
    const term = cardSearchTerm.trim();
    if (!term) {
      return organizations;
    }
    return fuzzySearch(term, organizations, [
      "name",
      "domain",
      "organizationId",
      "slug",
    ]);
  }, [cardSearchTerm, organizations]);

  const isLoadingOrganizations = canCreateOrDeleteOrganizations
    ? organizationsQuery.isLoading
    : currentOrganizationQuery.isLoading;
  const organizationLoadError = canCreateOrDeleteOrganizations
    ? organizationsQuery.error
    : currentOrganizationQuery.error;

  useEffect(() => {
    if (!canViewOrganizationSettings || !organizationLoadError) {
      return;
    }

    if (isAccessDeniedError(organizationLoadError)) {
      markApiAccessDenied();
    }
  }, [canViewOrganizationSettings, markApiAccessDenied, organizationLoadError]);

  /**
   * Super admin: makes `organization` the one they work in, then refreshes the session so the new
   * tokens carry it and the certificate pages open. Lands on the overview.
   */
  const workInOrganization = useCallback(
    async (organization: Organization, announce = true) => {
      const organizationId = getOrganizationIdValue(organization);
      try {
        const session = await establishSession(
          await setWorkingOrganization(organizationId),
        );
        if (announce) {
          toast.success(`You now work in ${organization.name}.`);
        }
        router.push(getPostAuthRoute(session));
      } catch (error) {
        toast.error(getApiErrorMessage(error, "Could not switch organization"));
      }
    },
    [establishSession, router],
  );

  const handleCreateOrganization = async (values: CreateOrganizationValues) => {
    if (!canCreateOrDeleteOrganizations) {
      toast.error("You do not have permission to create organizations");
      return;
    }

    try {
      const created = await createOrganization.mutateAsync({
        name: values.name.trim(),
        domain: values.domain.trim(),
      });

      setIsCreateDialogOpen(false);
      // A super admin who works in no organization yet gets the one they just made, so the
      // product opens instead of an empty sidebar.
      if (isSuperAdmin && !user?.organizationId && created) {
        toast.success(
          `${created.name} created. Opening it as your working organization.`,
        );
        await workInOrganization(created, false);
        return;
      }
      toast.success("Organization created successfully");
    } catch (error) {
      toast.error(getApiErrorMessage(error, "Failed to create organization"));
    }
  };

  const handleUpdateOrganization = async (values: EditOrganizationValues) => {
    if (!canUpdateOrganizationSettings) {
      toast.error("You do not have permission to update organization settings");
      return;
    }
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
    } catch (error) {
      toast.error(getApiErrorMessage(error, "Failed to update organization"));
    }
  };

  const handleDeleteOrganization = async () => {
    if (!canCreateOrDeleteOrganizations) {
      toast.error("You do not have permission to delete organizations");
      return;
    }
    if (!deleteOrganizationState) {
      return;
    }

    try {
      await deleteOrganization.mutateAsync(
        deleteOrganizationState.organizationId,
      );
      setDeleteOrganizationState(null);
      toast.success("Organization deleted successfully");
    } catch (error) {
      toast.error(getApiErrorMessage(error, "Failed to delete organization"));
    }
  };

  const columns = useMemo(
    () =>
      createOrganizationColumns({
        canUpdate: canUpdateOrganizationSettings,
        canDelete: canCreateOrDeleteOrganizations,
        currentOrganizationId: user?.organizationId ?? null,
        onWorkIn: isSuperAdmin
          ? (org) => void workInOrganization(org)
          : undefined,
        onView: (organization) =>
          router.push(getOrganizationDetailHref(organization)),
        onEdit: (organization) =>
          setEditOrganization(toOrganizationDialogState(organization)),
        onDelete: (organization) =>
          setDeleteOrganizationState({
            organizationId: getOrganizationIdValue(organization),
            organizationName: organization.name,
          }),
      }),
    [
      canCreateOrDeleteOrganizations,
      canUpdateOrganizationSettings,
      isSuperAdmin,
      router,
      user?.organizationId,
      workInOrganization,
    ],
  );

  if (isLoadingAuth) {
    return (
      <div className="p-6">
        <div className="flex h-64 items-center justify-center">
          <CircleNotchIcon className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      </div>
    );
  }

  if (!canViewOrganizationSettings) {
    return (
      <div className="p-6">
        <Unauthorised description="You need organization configuration permission to access organization settings.">
          <Link
            href="/settings/organization-access?tab=account"
            className="inline-flex text-sm font-medium underline-offset-4 hover:underline"
          >
            Go to your account
          </Link>
        </Unauthorised>
      </div>
    );
  }

  if (apiAccessDenied) {
    return (
      <div className="p-6">
        <Unauthorised description="You do not have permission to view organization data." />
      </div>
    );
  }

  return (
    <div className="w-full space-y-6">
      <PageHeader
        level="section"
        title={isSuperAdmin ? "Organizations" : "Organization"}
        subtitle={
          isSuperAdmin
            ? "Manage organization workspaces and organization-level configuration."
            : "Manage your organization workspace and organization-level configuration."
        }
        actions={
          <CreateOrganizationDialog
            open={isCreateDialogOpen}
            canCreate={canCreateOrDeleteOrganizations}
            isPending={createOrganization.isPending}
            onOpenChange={setIsCreateDialogOpen}
            onCreate={handleCreateOrganization}
          />
        }
      />

      {isSuperAdmin && !user?.organizationId ? (
        <Alert data-testid="no-working-organization">
          <BuildingsIcon aria-hidden />
          <AlertTitle>You are not working in an organization yet</AlertTitle>
          <AlertDescription>
            Certificates, discovery, rotation and deployments belong to an
            organization, so the sidebar shows only the platform pages until you
            pick one. Create an organization and it opens for you, or choose
            &quot;Work in this organization&quot; from a row&apos;s menu.
          </AlertDescription>
        </Alert>
      ) : null}

      {organizationLoadError && organizations.length === 0 ? (
        <div
          role="alert"
          className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-danger-border bg-danger-soft px-4 py-3 text-sm text-danger-foreground"
        >
          <span>
            {getApiErrorMessage(
              organizationLoadError,
              "Organizations could not be loaded.",
            )}
          </span>
          <Button
            variant="outline"
            size="sm"
            onClick={() =>
              void (canCreateOrDeleteOrganizations
                ? organizationsQuery.refetch()
                : currentOrganizationQuery.refetch())
            }
          >
            Retry
          </Button>
        </div>
      ) : viewMode === "table" ? (
        <CustomTable
          viewSwitcher={{ value: viewMode, onValueChange: setViewMode }}
          columns={columns}
          data={organizations}
          isLoading={isLoadingOrganizations}
          loadingRowCount={6}
          searchBy={["name", "domain", "organizationId", "slug"]}
          searchPlaceholder={
            isSuperAdmin ? "Search organizations..." : "Search organization..."
          }
          emptyTableMsg={
            isSuperAdmin
              ? "No organizations match. Clear the search or create one."
              : "Your organization could not be found."
          }
          showColumnVisibility={false}
          getRowId={(row) => getOrganizationIdValue(row)}
        />
      ) : (
        <div className="space-y-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="relative flex-1 sm:max-w-sm">
              <MagnifyingGlassIcon className="absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                value={cardSearchTerm}
                onChange={(event) => setCardSearchTerm(event.target.value)}
                placeholder={
                  isSuperAdmin
                    ? "Search organizations..."
                    : "Search organization..."
                }
                className="pr-3 pl-9"
                aria-label="Search organizations"
              />
            </div>
            <ViewSwitcher
              value={viewMode}
              onValueChange={setViewMode}
              showLabels={false}
            />
          </div>
          {isLoadingOrganizations ? (
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
              {Array.from({ length: 6 }).map((_, index) => (
                <Skeleton key={index} className="h-36 w-full rounded-lg" />
              ))}
            </div>
          ) : cardOrganizations.length === 0 ? (
            <div className="rounded-lg border border-border bg-card p-8 text-center text-sm text-muted-foreground">
              {isSuperAdmin
                ? "No organizations match. Clear the search or create one."
                : "Your organization could not be found."}
            </div>
          ) : (
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
              {cardOrganizations.map((organization) => (
                <OrganizationCard
                  key={getOrganizationIdValue(organization)}
                  organization={organization}
                  canUpdate={canUpdateOrganizationSettings}
                  canDelete={canCreateOrDeleteOrganizations}
                  currentOrganizationId={user?.organizationId ?? null}
                  onWorkIn={
                    isSuperAdmin
                      ? (org) => void workInOrganization(org)
                      : undefined
                  }
                  onView={(org) => router.push(getOrganizationDetailHref(org))}
                  onEdit={(org) =>
                    setEditOrganization(toOrganizationDialogState(org))
                  }
                  onDelete={(org) =>
                    setDeleteOrganizationState({
                      organizationId: getOrganizationIdValue(org),
                      organizationName: org.name,
                    })
                  }
                />
              ))}
            </div>
          )}
        </div>
      )}

      <EditOrganizationDialog
        open={Boolean(editOrganization)}
        canUpdate={canUpdateOrganizationSettings}
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
        canDelete={canCreateOrDeleteOrganizations}
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
