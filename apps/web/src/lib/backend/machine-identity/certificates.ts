// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Certificate inventory (real backend, no mock fallback).
 */
import { apiClient, apiRoutes } from "@/lib/api";
import type {
  CertificateDetail,
  CertificateListPage,
  CertificateListParams,
  CreateIotRevocationRequest,
  DeviceEventPage,
  DeviceSyncResponse,
  DeviceSyncSelection,
  IotRevocationResponse,
} from "@/types/machine-identity-backend";
import {
  compactParams,
  resolvePageRequest,
  type ResolvedPageRequest,
} from "./transport";

export interface ResolvedCertificateListParams extends ResolvedPageRequest {
  deviceXref?: string;
  profileXref?: string;
  sourceXref?: string;
  caProvider?: string;
  status?: string;
  renewalState?: string;
  expiringWithinDays?: number;
  q?: string;
}

export function resolveCertificateListParams(
  params: CertificateListParams = {},
): ResolvedCertificateListParams {
  return {
    ...resolvePageRequest({
      ...params,
      sort: params.sort ?? "validTo",
      direction: params.direction ?? "asc",
    }),
    ...compactParams({
      deviceXref: params.deviceXref,
      profileXref: params.profileXref,
      sourceXref: params.sourceXref,
      caProvider: params.caProvider,
      status: params.status,
      renewalState: params.renewalState,
      expiringWithinDays: params.expiringWithinDays,
      q: params.search?.trim(),
    }),
  };
}

/**
 * The `/api/v1/iot/certificates*` endpoints take Spring Data's standard
 * `sort=field,asc|desc` format - there is no separate `direction` param, and
 * one sent alongside `sort` is silently dropped rather than erroring. Builds
 * the wire params from a `ResolvedPageRequest`-shaped object, folding
 * `sort`/`direction` into one combined `sort` value.
 */
function toCertificateWireParams<T extends ResolvedPageRequest>(
  resolved: T,
): Omit<T, "direction"> {
  const { sort, direction, ...rest } = resolved;
  return {
    ...rest,
    ...(sort ? { sort: `${sort},${direction}` } : {}),
  } as Omit<T, "direction">;
}

export async function listCertificates(
  params: CertificateListParams = {},
): Promise<CertificateListPage> {
  const response = await apiClient.get<CertificateListPage>(
    apiRoutes.query.iotDevices.certificates,
    { params: toCertificateWireParams(resolveCertificateListParams(params)) },
  );
  return response.data;
}

export async function getCertificate(
  certificateXref: string,
): Promise<CertificateDetail> {
  const response = await apiClient.get<CertificateDetail>(
    apiRoutes.query.iotDevices.certificate(certificateXref),
  );
  return response.data;
}

/**
 * Requests revocation of one certificate. `202 Accepted`: nothing has reached
 * the CA yet - the operation is stored, the certificate moves to
 * `REVOCATION_PENDING`, and the agent dispatches it, so the certificate itself
 * is what to poll for the outcome.
 *
 * <p>`idempotencyKey` is mandatory and is what makes a retry safe. Replaying
 * the same key with the same body returns the original operation; replaying it
 * with a *different* reason or note is a `409`, so a caller retrying after a
 * network failure must send the key it used the first time, not a fresh one.
 *
 * <p>Other refusals worth distinguishing: `409` when a revocation is already in
 * flight or the certificate is already revoked, and `422` for a CA certificate
 * or a `caProvider` with no revocation path.
 */
export async function revokeCertificate(
  certificateXref: string,
  input: CreateIotRevocationRequest,
  idempotencyKey: string,
): Promise<IotRevocationResponse> {
  const response = await apiClient.post<IotRevocationResponse>(
    apiRoutes.mutation.iotDevices.certificateRevoke(certificateXref),
    input,
    { headers: { "Idempotency-Key": idempotencyKey } },
  );
  return response.data;
}

/**
 * Requests an Intune check-in for one, many, or all eligible devices. The
 * response says which devices were queued and which were skipped before the
 * asynchronous command reached the agent.
 *
 * <p>A queued device has had a command published, not renewed.
 */
export async function requestCertificateDeviceSync(
  selection: DeviceSyncSelection,
): Promise<DeviceSyncResponse> {
  const response = selection.all
    ? await apiClient.post<DeviceSyncResponse>(
        apiRoutes.mutation.iotDevices.certificateNudge,
        undefined,
        { params: { all: true } },
      )
    : await apiClient.post<DeviceSyncResponse>(
        apiRoutes.mutation.iotDevices.certificateNudge,
        { deviceXrefs: selection.deviceXrefs },
      );
  return response.data;
}

export async function getCertificateHistory(
  certificateXref: string,
  params: { page?: number; size?: number } = {},
): Promise<DeviceEventPage> {
  const response = await apiClient.get<DeviceEventPage>(
    apiRoutes.query.iotDevices.certificateHistory(certificateXref),
    { params: toCertificateWireParams(resolvePageRequest(params)) },
  );
  return response.data;
}

/**
 * A device's certificates, same item shape as {@link listCertificates}.
 *
 * <p>Unlike the other certificate endpoints, this one has no server-side
 * default sort - an unsorted call returns Postgres's arbitrary row order.
 * Default to `validTo,asc` (soonest-expiring first) to match the main list.
 */
export async function listDeviceCertificates(
  deviceXref: string,
  params: {
    page?: number;
    size?: number;
    sort?: string;
    direction?: "asc" | "desc";
  } = {},
): Promise<CertificateListPage> {
  const response = await apiClient.get<CertificateListPage>(
    apiRoutes.query.iotDevices.deviceCertificates(deviceXref),
    {
      params: toCertificateWireParams(
        resolvePageRequest({
          ...params,
          sort: params.sort ?? "validTo",
          direction: params.direction ?? "asc",
        }),
      ),
    },
  );
  return response.data;
}
