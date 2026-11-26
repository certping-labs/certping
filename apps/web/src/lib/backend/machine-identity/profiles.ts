// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Certificate profile adapter (real backend, no mock fallback).
 *
 * <p>A profile declares what gets delivered to a device platform: enrollment
 * mechanism, key material, subject/SAN construction, EKUs, validity, and
 * renewal window. `CMS_MANAGED` profiles are created/edited here; profiles
 * discovered from the provider (`OBSERVED_ONLY`) are read-only - the backend
 * rejects updates to them with `409`.
 */
import { apiClient, apiRoutes } from "@/lib/api";
import type {
  CertificateProfilePage,
  CertificateProfileResponse,
  CreateCertificateProfileRequest,
  ProfileDiscoverySyncAcceptedResponse,
  ProfileEventPage,
  ProfileListParams,
  UpdateCertificateProfileRequest,
} from "@/types/machine-identity-backend";
import type { PageRequestParams } from "@/types/pagination";
import { MACHINE_IDENTITY_CONFIG } from "@/lib/machine-identity/config";
import {
  compactParams,
  resolvePageRequest,
  type ResolvedPageRequest,
} from "./transport";

/** Server caps `size` at 100 for this endpoint, tighter than the module default. */
const MAX_PROFILE_PAGE_SIZE = 100;

export interface ResolvedProfileListParams extends ResolvedPageRequest {
  sourceXref?: string;
  lifecycleStatus?: string;
  controlMode?: string;
  providerSyncStatus?: string;
  targetPlatform?: string;
  search?: string;
}

export function resolveProfileListParams(
  params: ProfileListParams = {},
): ResolvedProfileListParams {
  const base = resolvePageRequest({
    ...params,
    sort: params.sort ?? "updatedAt",
    size: Math.min(
      params.size ?? MACHINE_IDENTITY_CONFIG.list.defaultPageSize,
      MAX_PROFILE_PAGE_SIZE,
    ),
  });
  return {
    ...base,
    ...compactParams({
      sourceXref: params.sourceXref,
      lifecycleStatus: params.lifecycleStatus,
      controlMode: params.controlMode,
      providerSyncStatus: params.providerSyncStatus,
      targetPlatform: params.targetPlatform,
      search: params.search?.trim(),
    }),
  };
}

export async function listCertificateProfiles(
  params: ProfileListParams = {},
): Promise<CertificateProfilePage> {
  const resolved = resolveProfileListParams(params);
  const response = await apiClient.get<CertificateProfilePage>(
    apiRoutes.query.machineIdentityProfiles.list,
    { params: resolved },
  );
  return response.data;
}

/** Full detail, including the `providerSnapshot` the list endpoint omits. */
export async function getCertificateProfile(
  profileXref: string,
): Promise<CertificateProfileResponse> {
  const response = await apiClient.get<CertificateProfileResponse>(
    apiRoutes.query.machineIdentityProfiles.detail(profileXref),
  );
  return response.data;
}

export async function listCertificateProfileEvents(
  profileXref: string,
  params: PageRequestParams = {},
): Promise<ProfileEventPage> {
  const resolved = resolvePageRequest(params);
  const response = await apiClient.get<ProfileEventPage>(
    apiRoutes.query.machineIdentityProfiles.events(profileXref),
    { params: resolved },
  );
  return response.data;
}

/**
 * Creates a profile. A `DRAFT` profile is saved without contacting the
 * provider; an `ACTIVE` profile additionally dispatches a native create to
 * the device source and comes back with `providerSyncStatus: "PENDING"`.
 */
export async function createCertificateProfile(
  input: CreateCertificateProfileRequest,
): Promise<CertificateProfileResponse> {
  const response = await apiClient.post<CertificateProfileResponse>(
    apiRoutes.mutation.machineIdentityProfiles.create,
    input,
  );
  return response.data;
}

/**
 * Updates a profile. Throws the underlying axios error on `409` (stale
 * `expectedVersion`, or the profile is `OBSERVED_ONLY`) - callers should
 * inspect `error.response.status` rather than assume success.
 */
export async function updateCertificateProfile(
  profileXref: string,
  input: UpdateCertificateProfileRequest,
): Promise<CertificateProfileResponse> {
  const response = await apiClient.put<CertificateProfileResponse>(
    apiRoutes.mutation.machineIdentityProfiles.update(profileXref),
    input,
  );
  return response.data;
}

/**
 * Archives a profile the provider no longer has. Soft delete: the profile
 * moves to `ARCHIVED` and its certificate history and provider snapshot are
 * kept.
 *
 * <p>Only a profile a completed discovery marked `providerSyncStatus:
 * "NOT_FOUND"` can be archived - anything else is a `409`. Archiving an
 * already-archived profile is a no-op `204`, not an error.
 */
export async function archiveCertificateProfile(
  profileXref: string,
): Promise<void> {
  await apiClient.delete<void>(
    apiRoutes.mutation.machineIdentityProfiles.archive(profileXref),
  );
}

/**
 * Requests provider-side profile discovery for a source. `202 Accepted`:
 * poll source events with `correlationId = requestXref` for completion.
 */
export async function syncSourceProfiles(
  sourceXref: string,
): Promise<ProfileDiscoverySyncAcceptedResponse> {
  const response = await apiClient.post<ProfileDiscoverySyncAcceptedResponse>(
    apiRoutes.mutation.machineIdentityProfiles.sourceProfilesSync(sourceXref),
  );
  return response.data;
}
