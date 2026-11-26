// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  createOrganization,
  deleteOrganization,
  getOrganizationById,
  getOrganizationBySlug,
  listOrganizations,
  updateOrganization,
} from "@/lib/backend/organizations";
import type { MessageResponse, Organization } from "@/types/auth";

export { getOrganizationIdValue } from "@/lib/backend/organizations";
export { getApiErrorMessage } from "@/lib/backend/common";

export const ORGANIZATIONS_QUERY_KEY = ["organizations"] as const;

export function useOrganizations(options?: { enabled?: boolean }) {
  return useQuery({
    queryKey: ORGANIZATIONS_QUERY_KEY,
    queryFn: listOrganizations,
    enabled: options?.enabled,
    retry: false,
    refetchOnWindowFocus: false,
  });
}

export function useOrganizationById(
  organizationId?: string | null,
  options?: { enabled?: boolean },
) {
  const normalizedOrganizationId = organizationId
    ? String(organizationId).trim()
    : undefined;

  return useQuery({
    queryKey: [
      ...ORGANIZATIONS_QUERY_KEY,
      "by-id",
      normalizedOrganizationId || "none",
    ],
    queryFn: async (): Promise<Organization> => {
      if (!normalizedOrganizationId) {
        throw new Error("Organization ID is required.");
      }

      return getOrganizationById(normalizedOrganizationId);
    },
    enabled: Boolean(normalizedOrganizationId) && (options?.enabled ?? true),
    retry: false,
    refetchOnWindowFocus: false,
  });
}

export function useOrganizationBySlug(
  slug?: string | null,
  options?: { enabled?: boolean },
) {
  const normalizedSlug = slug ? String(slug).trim() : undefined;

  return useQuery({
    queryKey: [...ORGANIZATIONS_QUERY_KEY, "by-slug", normalizedSlug || "none"],
    queryFn: async (): Promise<Organization> => {
      if (!normalizedSlug) {
        throw new Error("Organization slug is required.");
      }

      return getOrganizationBySlug(normalizedSlug);
    },
    enabled: Boolean(normalizedSlug) && (options?.enabled ?? true),
    retry: false,
    refetchOnWindowFocus: false,
  });
}

export function useCreateOrganization() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: createOrganization,
    onSuccess: async () => {
      await queryClient.invalidateQueries({
        queryKey: ORGANIZATIONS_QUERY_KEY,
      });
    },
  });
}

export function useUpdateOrganization() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({
      organizationId,
      payload,
    }: {
      organizationId: string;
      payload: {
        name: string;
        domain: string;
        active?: boolean;
      };
    }) => updateOrganization(organizationId, payload),
    onSuccess: async () => {
      await queryClient.invalidateQueries({
        queryKey: ORGANIZATIONS_QUERY_KEY,
      });
    },
  });
}

export function useDeleteOrganization() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (organizationId: string): Promise<MessageResponse> =>
      deleteOrganization(organizationId),
    onSuccess: async () => {
      await queryClient.invalidateQueries({
        queryKey: ORGANIZATIONS_QUERY_KEY,
      });
    },
  });
}
