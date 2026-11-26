// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { syncCertificateCredentialConfig } from "@/lib/backend/domain-credential-config";
import { getApiErrorMessage } from "@/lib/backend/common";
import { canUpdateCredentials } from "@/lib/authz";
import { useAuthStore } from "@/stores/auth-store";
import type {
  SyncCertificateCredentialConfigInput,
  SyncCertificateCredentialConfigResult,
} from "@/types/cert-manager";
import {
  invalidateAlertQueries,
  invalidateAuditQueries,
  invalidateCertificateQueries,
  invalidateCredentialQueries,
  invalidateDeploymentQueries,
} from "./query-invalidation";

export function useSyncCertificateCredentialConfig() {
  const queryClient = useQueryClient();

  return useMutation({
    retry: false,
    mutationFn: async (
      payload: SyncCertificateCredentialConfigInput,
    ): Promise<SyncCertificateCredentialConfigResult> => {
      const { user } = useAuthStore.getState();
      if (!canUpdateCredentials(user)) {
        throw new Error(
          "You do not have permission to manage certificate credential configuration",
        );
      }

      return syncCertificateCredentialConfig(payload);
    },
    onSuccess: async (result, payload) => {
      await Promise.all([
        invalidateCertificateQueries(queryClient),
        invalidateCredentialQueries(queryClient),
        invalidateDeploymentQueries(queryClient),
        invalidateAlertQueries(queryClient),
        invalidateAuditQueries(queryClient),
      ]);

      if (!result.didChange) {
        toast.info(
          `No configuration changes were needed for ${payload.domain}`,
        );
        return;
      }

      toast.success(
        `Updated renewal and deployment settings for ${payload.domain}`,
      );
    },
    onError: (error) => {
      toast.error(
        getApiErrorMessage(
          error,
          "Failed to update certificate renewal and deployment settings",
        ),
      );
    },
  });
}
