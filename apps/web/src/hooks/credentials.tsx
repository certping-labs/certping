// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import {
  createDeploymentCredentialReference,
  createDnsCredentialReference,
  deleteCredentialReference,
  getCredentialReference,
  listCredentialReferences,
  updateCredentialReference,
} from "@/lib/backend/credentials";
import { getApiErrorMessage } from "@/lib/backend/common";
import {
  getCredentialReferenceProviderOptions,
  resolveCredentialProviderFromApiValue,
} from "@/lib/credential-providers";
import {
  canCreateCredentials,
  canUpdateCredentials,
  canViewCredentials,
} from "@/lib/authz";
import { useAuthStore } from "@/stores/auth-store";
import { useIsOrgFeatureEnabled } from "@/hooks/use-feature-flags";
import { FEATURE_FLAGS } from "@/lib/feature-flags";
import type {
  AddCredentialPayload,
  CredentialCategory,
  CredentialRecord,
  CredentialStatus,
  UpdateCredentialPayload,
} from "@/types/ssl";
import type {
  CreateCredentialReferenceInput,
  CredentialDeleteResponse,
  CredentialReference,
  CredentialReferenceType,
  CredentialUpdateResponse,
} from "@/types/cert-manager";
import { DISCOVERY_CREDENTIAL_TYPE } from "@/types/cert-manager";
import {
  invalidateAlertQueries,
  invalidateAuditQueries,
  invalidateCredentialQueries,
} from "./query-invalidation";
import { getConditionalRefetchInterval } from "./query-polling";

export const CREDENTIALS_QUERY_KEY = ["credentials"] as const;
export const CREDENTIAL_QUERY_KEY = ["credential"] as const;
const CREDENTIAL_POLL_INTERVAL = 5_000;

type CredentialCategoryInput = CredentialCategory | string;

export interface CreateCredentialReferenceMutationInput extends CreateCredentialReferenceInput {
  type: CredentialReferenceType;
}

export interface UpdateCredentialReferenceMutationInput {
  credentialXref: string;
  secretHandle?: string | null;
  credJson?: string | Record<string, unknown>;
  configJson?: string | Record<string, unknown>;
}

const hashStringToId = (value: string): number =>
  Array.from(value).reduce(
    (hash, char) => (hash * 31 + char.charCodeAt(0)) >>> 0,
    7,
  );

const toReferenceType = (
  category?: CredentialCategoryInput,
): CredentialReferenceType | undefined => {
  const normalized = category?.trim().toLowerCase();
  if (!normalized) {
    return undefined;
  }

  if (normalized.startsWith("dns")) {
    return "DNS";
  }

  if (normalized.startsWith("deployment")) {
    return "DEPLOYMENT";
  }

  return undefined;
};

const toCredentialStatus = (status: string | undefined): CredentialStatus => {
  switch ((status || "").toUpperCase()) {
    case "DELETED":
    case "INACTIVE":
      return "INACTIVE";
    case "PENDING":
    case "PENDING_ROTATION":
      return "PENDING_ROTATION";
    default:
      return "ACTIVE";
  }
};

const isCredentialRotationPending = (
  status: string | null | undefined,
): boolean =>
  ["PENDING", "PENDING_ROTATION"].includes((status || "").trim().toUpperCase());

const toCredentialCategory = (
  type: CredentialReferenceType,
): CredentialCategory => {
  // Read-only discovery credentials must never show up in deploy pickers.
  if (String(type) === DISCOVERY_CREDENTIAL_TYPE) return "discovery_source";
  return type === "DNS" ? "dns_credential" : "deployment_target";
};

const toCredentialRecord = (
  reference: CredentialReference,
): CredentialRecord => {
  const providerOption = getCredentialReferenceProviderOptions(
    reference.type,
  ).find((option) => option.apiValue === reference.provider);
  const providerKey =
    reference.providerKey ||
    resolveCredentialProviderFromApiValue(reference.provider);
  const alias = reference.credentialXref;
  const timestamp =
    reference.updatedAt || reference.createdAt || new Date().toISOString();

  return {
    id: hashStringToId(reference.credentialXref),
    alias,
    credentialXref: reference.credentialXref,
    description: reference.description,
    credentialType:
      reference.provider.toLowerCase() as CredentialRecord["credentialType"],
    type: reference.type,
    provider: providerKey,
    typeName: reference.provider.toLowerCase() as CredentialRecord["typeName"],
    providerName: reference.provider,
    providerDisplayName: providerOption?.label || reference.provider,
    category: toCredentialCategory(reference.type),
    secretHandle: reference.secretHandle ?? undefined,
    configJson:
      typeof reference.configJson === "string"
        ? reference.configJson
        : reference.configJson
          ? JSON.stringify(reference.configJson)
          : undefined,
    targetType: reference.targetType,
    metadata: {},
    createdAt: reference.createdAt || timestamp,
    updatedAt: reference.updatedAt || timestamp,
    nextRotationAt: timestamp,
    rotationInterval: 0,
    version: 1,
    status: toCredentialStatus(reference.status),
    lastError: reference.lastError,
  };
};

const normalizeCreateInput = (
  payload: CreateCredentialReferenceMutationInput | AddCredentialPayload,
): CreateCredentialReferenceMutationInput => {
  if (
    "type" in payload &&
    (payload.type === "DNS" || payload.type === "DEPLOYMENT") &&
    "provider" in payload &&
    typeof payload.provider === "string" &&
    "description" in payload &&
    typeof payload.description === "string"
  ) {
    return payload;
  }

  throw new Error(
    "Raw secret capture is no longer supported. Register a saved credential reference instead.",
  );
};

const normalizeUpdateInput = (
  payload: UpdateCredentialReferenceMutationInput | UpdateCredentialPayload,
): UpdateCredentialReferenceMutationInput => {
  if ("credentialXref" in payload) {
    return payload;
  }

  throw new Error("Only credential reference metadata updates are supported.");
};

interface UseCredentialsOptions {
  enabled?: boolean;
  category?: CredentialCategoryInput;
  pollWhilePending?: boolean;
}

/**
 * Whether "add a credential" entry points may be shown. The add route is
 * gated by CREDENTIALS_MANAGEMENT; a DNS credential also needs
 * DNS_CREDENTIALS and a deployment credential CERTIFICATE_DEPLOYMENT, the
 * flags their create endpoints answer 423 for. Listing existing credentials
 * is not flag-gated server-side, so pickers of existing credentials stay
 * usable.
 */
export function useCanAddCredential(type: CredentialReferenceType): boolean {
  const canCreate = useAuthStore((state) => canCreateCredentials(state.user));
  const isCredentialsOn = useIsOrgFeatureEnabled(
    FEATURE_FLAGS.CREDENTIALS_MANAGEMENT,
  );
  const isTypeOn = useIsOrgFeatureEnabled(
    type === "DNS"
      ? FEATURE_FLAGS.DNS_CREDENTIALS
      : FEATURE_FLAGS.CERTIFICATE_DEPLOYMENT,
  );
  return canCreate && isCredentialsOn && isTypeOn;
}

export function useCredentials(options: UseCredentialsOptions = {}) {
  const { user } = useAuthStore();
  const { enabled = true, category, pollWhilePending = true } = options;
  const type = toReferenceType(category);

  return useQuery({
    queryKey: [...CREDENTIALS_QUERY_KEY, type || "all"],
    enabled: enabled && canViewCredentials(user),
    retry: false,
    refetchOnWindowFocus: false,
    queryFn: async (): Promise<CredentialRecord[]> => {
      const response = await listCredentialReferences(type);
      return response.items.map(toCredentialRecord);
    },
    refetchInterval: pollWhilePending
      ? (query) =>
          getConditionalRefetchInterval(
            query,
            CREDENTIAL_POLL_INTERVAL,
            (credentials) =>
              credentials?.some((credential) =>
                isCredentialRotationPending(credential.status),
              ) ?? false,
          )
      : false,
  });
}

export function useCredentialReference(credentialXref: string | null) {
  const { user } = useAuthStore();
  const normalizedXref = (credentialXref || "").trim();

  return useQuery({
    queryKey: [...CREDENTIAL_QUERY_KEY, normalizedXref || "missing"],
    enabled: Boolean(normalizedXref) && canViewCredentials(user),
    retry: false,
    refetchOnWindowFocus: false,
    queryFn: async (): Promise<CredentialReference> =>
      getCredentialReference(normalizedXref),
    refetchInterval: (query) =>
      getConditionalRefetchInterval(query, CREDENTIAL_POLL_INTERVAL, (data) =>
        isCredentialRotationPending(data?.status),
      ),
  });
}

export function useAddCredential() {
  const queryClient = useQueryClient();

  return useMutation({
    retry: false,
    mutationFn: async (
      payload: CreateCredentialReferenceMutationInput | AddCredentialPayload,
    ): Promise<CredentialReference> => {
      const { user } = useAuthStore.getState();
      if (!canCreateCredentials(user)) {
        throw new Error("You do not have permission to create credentials");
      }

      const normalized = normalizeCreateInput(payload);
      return normalized.type === "DNS"
        ? createDnsCredentialReference(normalized)
        : createDeploymentCredentialReference(normalized);
    },
    onSuccess: async (result) => {
      await Promise.all([
        invalidateCredentialQueries(queryClient),
        invalidateAlertQueries(queryClient),
        invalidateAuditQueries(queryClient),
      ]);
      toast.success(`${result.description} saved`);
    },
    onError: (error) => {
      toast.error(
        getApiErrorMessage(error, "Failed to save credential reference"),
      );
    },
  });
}

export function useUpdateCredential() {
  const queryClient = useQueryClient();

  return useMutation({
    retry: false,
    mutationFn: async (
      payload: UpdateCredentialReferenceMutationInput | UpdateCredentialPayload,
    ): Promise<CredentialUpdateResponse> => {
      const { user } = useAuthStore.getState();
      if (!canUpdateCredentials(user)) {
        throw new Error("You do not have permission to update credentials");
      }

      const normalized = normalizeUpdateInput(payload);
      return updateCredentialReference(normalized.credentialXref, {
        secretHandle: normalized.secretHandle,
        credJson: normalized.credJson,
        configJson: normalized.configJson,
      });
    },
    onSuccess: async (result) => {
      await Promise.all([
        invalidateCredentialQueries(queryClient),
        invalidateAlertQueries(queryClient),
        invalidateAuditQueries(queryClient),
      ]);
      toast.success(result.message || "Credential reference updated");
    },
    onError: (error) => {
      toast.error(
        getApiErrorMessage(error, "Failed to update credential reference"),
      );
    },
  });
}

export function useDeleteCredential() {
  const queryClient = useQueryClient();

  return useMutation({
    retry: false,
    mutationFn: async (
      credentialXref: string,
    ): Promise<CredentialDeleteResponse> => {
      const { user } = useAuthStore.getState();
      if (!canUpdateCredentials(user)) {
        throw new Error("You do not have permission to delete credentials");
      }

      return deleteCredentialReference(credentialXref);
    },
    onSuccess: async (result) => {
      await Promise.all([
        invalidateCredentialQueries(queryClient),
        invalidateAlertQueries(queryClient),
        invalidateAuditQueries(queryClient),
      ]);
      toast.success(result.message || "Credential reference deleted");
    },
    onError: (error) => {
      toast.error(
        getApiErrorMessage(error, "Failed to delete credential reference"),
      );
    },
  });
}
