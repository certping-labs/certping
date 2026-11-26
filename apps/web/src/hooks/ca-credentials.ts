// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { getApiErrorMessage } from "@/lib/backend/common";
import {
  createCaCredential,
  listCaCredentials,
  type CaCredential,
} from "@/lib/backend/ca-credentials";
import {
  deleteCaCredential,
  getCertificateAuthorities,
  replaceCaCredentialKey,
  type CertificateAuthority,
} from "@/lib/backend/certificate-authorities";
import { canViewCredentials } from "@/lib/authz";
import { isConflictError } from "@/lib/http-errors";
import { useAuthStore } from "@/stores/auth-store";
import { CREDENTIALS_QUERY_KEY } from "@/hooks/credentials";

/** Prefix shared by every CA query, so one invalidation refreshes them all. */
const CA_QUERY_KEY = [...CREDENTIALS_QUERY_KEY, "CA"] as const;

const caCredentialsKey = (provider: string) =>
  [...CA_QUERY_KEY, provider] as const;

export const CERTIFICATE_AUTHORITIES_QUERY_KEY = [
  ...CA_QUERY_KEY,
  "authorities",
] as const;

export const CA_KEY_IN_USE_MESSAGE =
  "This key is still in use. Move its certificates to another key, then delete it.";

/** The message to show when deleting a CA key fails. */
export const caKeyDeleteErrorMessage = (error: unknown): string =>
  isConflictError(error)
    ? CA_KEY_IN_USE_MESSAGE
    : getApiErrorMessage(error, "Failed to delete the key");

export function useCaCredentials(provider: string, enabled = true) {
  const user = useAuthStore((state) => state.user);
  return useQuery({
    queryKey: caCredentialsKey(provider),
    enabled: enabled && canViewCredentials(user),
    retry: false,
    refetchOnWindowFocus: false,
    queryFn: (): Promise<CaCredential[]> => listCaCredentials(provider),
  });
}

/** Every supported CA with its status. Needs the credential view permission. */
export function useCertificateAuthorities(enabled = true) {
  const user = useAuthStore((state) => state.user);
  return useQuery({
    queryKey: CERTIFICATE_AUTHORITIES_QUERY_KEY,
    enabled: enabled && canViewCredentials(user),
    retry: false,
    refetchOnWindowFocus: false,
    queryFn: (): Promise<CertificateAuthority[]> => getCertificateAuthorities(),
  });
}

export function useAddCaCredential(provider: string) {
  const queryClient = useQueryClient();
  return useMutation({
    retry: false,
    mutationFn: (input: { description: string; apiKey: string }) =>
      createCaCredential({ provider, ...input }),
    onSuccess: async (saved) => {
      await queryClient.invalidateQueries({ queryKey: CA_QUERY_KEY });
      toast.success(`${saved.description} saved`);
    },
    onError: (error) => {
      toast.error(getApiErrorMessage(error, "Failed to save the API key"));
    },
  });
}

export function useReplaceCaCredentialKey() {
  const queryClient = useQueryClient();
  return useMutation({
    retry: false,
    mutationFn: replaceCaCredentialKey,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: CA_QUERY_KEY });
      toast.success("Key replaced");
    },
    onError: (error) => {
      toast.error(getApiErrorMessage(error, "Failed to replace the key"));
    },
  });
}

export function useDeleteCaCredential() {
  const queryClient = useQueryClient();
  return useMutation({
    retry: false,
    mutationFn: deleteCaCredential,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: CA_QUERY_KEY });
      toast.success("Key deleted");
    },
    onError: (error) => {
      toast.error(caKeyDeleteErrorMessage(error));
    },
  });
}
