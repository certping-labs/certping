// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import Link from "next/link";
import React, { use, useState } from "react";
import { ArchiveIcon, PencilSimpleIcon } from "@phosphor-icons/react";

import {
  DetailPanel,
  DynamicDataPanel,
  PanelMasonry,
} from "@/components/machine-identity/detail-panel";
import { DeviceEventList } from "@/components/machine-identity/device-event-list";
import { ProviderLabel } from "@/components/machine-identity/provider-label";
import { ModuleNotice } from "@/components/machine-identity/module-notice";
import {
  ProfileConfigurationPanel,
  ProfileSyncPanel,
} from "@/components/machine-identity/profile-detail-panels";
import { ProfileForm } from "@/components/machine-identity/profile-form";
import { MachineIdentityQueryErrorState } from "@/components/machine-identity/query-error-state";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/page-header";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  useArchiveCertificateProfile,
  useCertificateProfile,
  useCertificateProfileEvents,
  useUpdateCertificateProfile,
} from "@/hooks/machine-identity/use-certificate-profiles";
import { usePermissions } from "@/hooks/use-permissions";
import { PERMISSIONS } from "@/lib/authz";
import {
  PROFILE_LIFECYCLE_LABELS,
  profileLifecycleVariant,
} from "@/lib/machine-identity/backend-display";
import { formatDateTimeCompact } from "@/lib/utils";

const PROFILES_HREF = "/machine-identity/profiles";

export default function CertificateProfileDetailPage({
  params,
}: {
  params: Promise<{ profileXref: string }>;
}) {
  const { profileXref } = use(params);
  const [isEditing, setIsEditing] = useState(false);
  const profileQuery = useCertificateProfile(profileXref);
  const eventsQuery = useCertificateProfileEvents(profileXref);
  const updateProfile = useUpdateCertificateProfile();
  const archiveProfile = useArchiveCertificateProfile();
  const { can } = usePermissions();
  const canManageProfiles = can(PERMISSIONS.iotCertificateProfileManage);

  if (profileQuery.isLoading) {
    return (
      <div className="space-y-4 p-4 md:p-6">
        <Skeleton className="h-16 w-full max-w-xl" />
        <Skeleton className="h-72 w-full" />
      </div>
    );
  }

  if (profileQuery.error || !profileQuery.data) {
    return (
      <div className="p-4 md:p-6">
        <MachineIdentityQueryErrorState
          error={profileQuery.error}
          title="Unable to load profile"
          description="This certificate profile could not be loaded."
          resourceLabel="certificate profile"
          backHref={PROFILES_HREF}
          backLabel="Back to profiles"
          onRetry={() => void profileQuery.refetch()}
          isRetrying={profileQuery.isFetching}
        />
      </div>
    );
  }

  const profile = profileQuery.data;
  const canEdit = canManageProfiles && profile.controlMode !== "OBSERVED_ONLY";
  /**
   * Archiving is only offered from the one state the backend accepts. Showing
   * it otherwise would be a button whose only outcome is a `409`.
   */
  const canArchive =
    canManageProfiles &&
    profile.providerSyncStatus === "NOT_FOUND" &&
    profile.lifecycleStatus !== "ARCHIVED";

  return (
    <div className="space-y-5 p-4 md:p-6">
      <PageHeader
        title={profile.name}
        breadcrumbs={[
          { label: "Machine Identity" },
          { label: "Profiles", href: PROFILES_HREF },
        ]}
        subtitle={
          <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <ProviderLabel provider={profile.provider} />
            <span aria-hidden="true">·</span>
            <Link
              href={`/integrations/device-sources/${profile.sourceXref}`}
              className="hover:text-foreground hover:underline"
            >
              {profile.sourceDisplayName}
            </Link>
            {profile.description ? (
              <>
                <span aria-hidden="true">·</span>
                <span>{profile.description}</span>
              </>
            ) : null}
          </span>
        }
        badge={{
          label: PROFILE_LIFECYCLE_LABELS[profile.lifecycleStatus],
          variant: profileLifecycleVariant(profile.lifecycleStatus),
        }}
        actions={
          isEditing ? null : (
            <>
              {canArchive ? (
                <AlertDialog>
                  <AlertDialogTrigger asChild>
                    <Button variant="outline" size="sm">
                      <ArchiveIcon className="size-4" aria-hidden="true" />
                      Archive
                    </Button>
                  </AlertDialogTrigger>
                  <AlertDialogContent>
                    <AlertDialogHeader>
                      <AlertDialogTitle>
                        Archive {profile.name}?
                      </AlertDialogTitle>
                      <AlertDialogDescription>
                        {profile.sourceDisplayName} no longer has this profile.
                        Archiving retires it in CertPing and keeps its history,
                        its provider snapshot, and every certificate issued
                        under it. Nothing is deleted, and nothing is sent to the
                        provider.
                      </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                      <AlertDialogCancel>Cancel</AlertDialogCancel>
                      <AlertDialogAction
                        variant="destructive"
                        disabled={archiveProfile.isPending}
                        onClick={() => archiveProfile.mutate(profileXref)}
                      >
                        Archive profile
                      </AlertDialogAction>
                    </AlertDialogFooter>
                  </AlertDialogContent>
                </AlertDialog>
              ) : null}
              {canEdit ? (
                <Button size="sm" onClick={() => setIsEditing(true)}>
                  <PencilSimpleIcon className="size-4" aria-hidden="true" />
                  Edit profile
                </Button>
              ) : null}
            </>
          )
        }
      />

      {profile.controlMode === "OBSERVED_ONLY" ? (
        <ModuleNotice tone="info">
          This profile was discovered in {profile.sourceDisplayName} and is
          owned there. CertPing tracks it read-only; edits must be made in the
          provider.
        </ModuleNotice>
      ) : null}

      {profile.providerSyncStatus === "FAILED" ? (
        <ModuleNotice tone="danger">
          The last change could not be applied in {profile.sourceDisplayName}.
          {profile.providerSyncError ? ` ${profile.providerSyncError}` : ""} The
          desired configuration below is stored in CertPing but is not live.
        </ModuleNotice>
      ) : null}

      {profile.providerSyncStatus === "DRIFTED" ? (
        <ModuleNotice tone="warning">
          {profile.sourceDisplayName} reports a configuration that differs from
          the one CertPing holds. Save the profile again to re-apply it.
        </ModuleNotice>
      ) : null}

      {profile.providerSyncStatus === "NOT_FOUND" ? (
        <ModuleNotice tone="warning">
          A completed discovery could not find this profile in{" "}
          {profile.sourceDisplayName}. Devices will not receive it any more, and
          certificates already issued under it are unaffected. Archive it to
          retire the record.
        </ModuleNotice>
      ) : null}

      {profile.providerSyncStatus === "PENDING" ? (
        <ModuleNotice tone="info">
          A change is on its way to {profile.sourceDisplayName}. This page
          updates once the source confirms it.
        </ModuleNotice>
      ) : null}

      {isEditing ? (
        <ProfileForm
          profile={profile}
          isSubmitting={updateProfile.isPending}
          cancelHref={`${PROFILES_HREF}/${profileXref}`}
          onSubmit={(input, confirmReissuance) =>
            updateProfile.mutate(
              {
                profileXref,
                input: {
                  name: input.name,
                  description: input.description,
                  lifecycleStatus: input.lifecycleStatus,
                  expectedVersion: profile.rowVersion,
                  confirmReissuance,
                  configuration: input.configuration,
                },
              },
              { onSuccess: () => setIsEditing(false) },
            )
          }
        />
      ) : (
        <Tabs defaultValue="details">
          {/* Four triggers are wider than a phone. Scrolling the strip keeps every
              tab reachable; wrapping it would put a two-line control block above
              content that is already tight. */}
          <TabsList variant="underline">
            <TabsTrigger value="details">Details</TabsTrigger>
            <TabsTrigger value="activity">Activity</TabsTrigger>
          </TabsList>

          <TabsContent value="details" className="mt-3">
            <PanelMasonry>
              <ProfileConfigurationPanel profile={profile} />
              <ProfileSyncPanel profile={profile} />
              {profile.providerSnapshot ? (
                <DynamicDataPanel
                  title="Provider snapshot"
                  description={`Last authoritative response from ${profile.sourceDisplayName}, observed ${formatDateTimeCompact(profile.providerSnapshot.providerObservedAt)}.`}
                  value={profile.providerSnapshot.response}
                  emptyMessage="The provider returned no profile body."
                />
              ) : null}
            </PanelMasonry>
          </TabsContent>

          <TabsContent value="activity" className="mt-3">
            <DetailPanel title="Activity" description="Newest first.">
              <DeviceEventList
                events={eventsQuery.data?.content.map((event) => ({
                  eventXref: event.eventXref,
                  eventType: event.eventType,
                  eventStatus: event.eventStatus,
                  eventMessage: null,
                  // Provider-sync events have no actor field on the wire -
                  // they are always system-driven, not agent- or user-initiated.
                  actorSource: "SYSTEM",
                  actorUserId: null,
                  correlationId: event.correlationId,
                  detail: event.detail,
                  occurredAt: event.occurredAt,
                }))}
                isLoading={eventsQuery.isLoading}
                emptyMessage="No activity recorded for this profile."
              />
            </DetailPanel>
          </TabsContent>
        </Tabs>
      )}
    </div>
  );
}
