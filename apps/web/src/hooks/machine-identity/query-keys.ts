// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

/**
 * Query-key factory for the Machine Identity module.
 *
 * <p>Keys are scoped by organization so switching org context cannot serve
 * another tenant's cached rows, and list keys embed the RESOLVED request rather
 * than the raw params. Resolving first means `{}` and `{ page: 0, size: 25 }`
 * land on the same cache entry instead of fetching twice.
 */
import {
  resolveDeviceEventParams,
  resolveDeviceListParams,
} from "@/lib/backend/machine-identity/devices";
import { resolveCertificateListParams } from "@/lib/backend/machine-identity/certificates";
import { resolveProfileListParams } from "@/lib/backend/machine-identity/profiles";
import { resolveDeviceSourceEventParams } from "@/lib/backend/machine-identity/sources";
import { resolvePageRequest } from "@/lib/backend/machine-identity/transport";
import type {
  CertificateListParams,
  DeviceEventListParams,
  DeviceListParams,
  DeviceSourceEventListParams,
  ProfileListParams,
} from "@/types/machine-identity-backend";
import type { PageRequestParams } from "@/types/pagination";

const ROOT = "machine-identity";

type OrganizationScope = string | null | undefined;

const scope = (organizationId: OrganizationScope): string | null =>
  organizationId?.trim() || null;

export const machineIdentityKeys = {
  all: (organizationId: OrganizationScope) =>
    [ROOT, scope(organizationId)] as const,

  summary: (organizationId: OrganizationScope) =>
    [ROOT, scope(organizationId), "summary"] as const,

  devices: (organizationId: OrganizationScope) =>
    [ROOT, scope(organizationId), "devices"] as const,
  deviceList: (
    organizationId: OrganizationScope,
    params: DeviceListParams = {},
  ) =>
    [
      ...machineIdentityKeys.devices(organizationId),
      "list",
      resolveDeviceListParams(params),
    ] as const,
  device: (organizationId: OrganizationScope, deviceXref: string | undefined) =>
    [
      ...machineIdentityKeys.devices(organizationId),
      "detail",
      deviceXref ?? null,
    ] as const,
  deviceEventList: (
    organizationId: OrganizationScope,
    deviceXref: string | undefined,
    params: DeviceEventListParams = {},
  ) =>
    [
      ...machineIdentityKeys.devices(organizationId),
      "events",
      deviceXref ?? null,
      resolveDeviceEventParams(params),
    ] as const,
  deviceCertificateList: (
    organizationId: OrganizationScope,
    deviceXref: string | undefined,
    params: { page?: number; size?: number } = {},
  ) =>
    [
      ...machineIdentityKeys.devices(organizationId),
      "certificates",
      deviceXref ?? null,
      resolvePageRequest(params),
    ] as const,

  certificates: (organizationId: OrganizationScope) =>
    [ROOT, scope(organizationId), "certificates"] as const,
  certificateList: (
    organizationId: OrganizationScope,
    params: CertificateListParams = {},
  ) =>
    [
      ...machineIdentityKeys.certificates(organizationId),
      "list",
      resolveCertificateListParams(params),
    ] as const,
  certificate: (
    organizationId: OrganizationScope,
    certificateXref: string | undefined,
  ) =>
    [
      ...machineIdentityKeys.certificates(organizationId),
      "detail",
      certificateXref ?? null,
    ] as const,
  certificateHistory: (
    organizationId: OrganizationScope,
    certificateXref: string | undefined,
    params: { page?: number; size?: number } = {},
  ) =>
    [
      ...machineIdentityKeys.certificates(organizationId),
      "history",
      certificateXref ?? null,
      resolvePageRequest(params),
    ] as const,

  profiles: (organizationId: OrganizationScope) =>
    [ROOT, scope(organizationId), "profiles"] as const,
  profileList: (
    organizationId: OrganizationScope,
    params: ProfileListParams = {},
  ) =>
    [
      ...machineIdentityKeys.profiles(organizationId),
      "list",
      resolveProfileListParams(params),
    ] as const,
  profile: (
    organizationId: OrganizationScope,
    profileXref: string | undefined,
  ) =>
    [
      ...machineIdentityKeys.profiles(organizationId),
      "detail",
      profileXref ?? null,
    ] as const,
  profileEventList: (
    organizationId: OrganizationScope,
    profileXref: string | undefined,
    params: PageRequestParams = {},
  ) =>
    [
      ...machineIdentityKeys.profiles(organizationId),
      "events",
      profileXref ?? null,
      resolvePageRequest(params),
    ] as const,

  sources: (organizationId: OrganizationScope) =>
    [ROOT, scope(organizationId), "sources"] as const,
  sourceEventList: (
    organizationId: OrganizationScope,
    sourceXref: string | undefined,
    params: DeviceSourceEventListParams = {},
  ) =>
    [
      ...machineIdentityKeys.sources(organizationId),
      "events",
      sourceXref ?? null,
      resolveDeviceSourceEventParams(params),
    ] as const,

  caConnectors: (organizationId: OrganizationScope) =>
    [ROOT, scope(organizationId), "ca-connectors"] as const,
  caConnector: (
    organizationId: OrganizationScope,
    connectorId: string | undefined,
  ) =>
    [
      ...machineIdentityKeys.caConnectors(organizationId),
      "detail",
      connectorId ?? null,
    ] as const,
};
