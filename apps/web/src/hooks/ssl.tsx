// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  type Query,
  useMutation,
  useQueries,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { toast } from "sonner";

import { apiClient, apiRoutes } from "@/lib/api";
import {
  convertCertificateToAutomated,
  deleteCertificate,
  getCertificateDetailsRecord,
  getCertificateHistory,
  getCertificateTxtRecords,
  issueCertificate,
  issueManualCertificate,
  renewCertificate,
  revokeCertificate,
  validateCertificateDns,
} from "@/lib/backend/certs";
import { getApiErrorMessage } from "@/lib/backend/common";
import { shouldPollCertificateStatus } from "@/lib/cert-manager/certificate-status-polling";
import { useCertificateListQuery } from "@/hooks/use-certificate-list";
import type {
  MarkAlertAsReadRequest,
  MarkAlertAsReadResponse,
  SSLCertificateDetails,
} from "@/types/ssl";
import type {
  CertificateAsyncResponse,
  CertificateHistoryPage,
  CertificateTxtRecord,
  ConvertToAutomatedInput,
  ConvertToAutomatedResponse,
  IssueCertificateInput,
  IssueManualCertificateInput,
} from "@/types/cert-manager";
import {
  invalidateAlertQueries,
  invalidateAuditQueries,
  invalidateCertificateDataQueries,
  invalidateDeploymentQueries,
} from "./query-invalidation";
import { getConditionalRefetchInterval } from "./query-polling";

export const CERTIFICATE_DETAILS_QUERY_KEY = "ssl-cert-details";
export const SSL_ALERTS_QUERY_KEY = "ssl-alerts";
export const CERT_HISTORY_QUERY_KEY = "ssl-cert-history";
export {
  CERTIFICATE_STATUS_QUERY_KEY,
  SSL_LIST_QUERY_KEY,
} from "@/hooks/use-certificate-list";

const FAST_POLL_INTERVAL = 5000;

const shouldPollCertificateHistory = (
  data: CertificateHistoryPage | undefined,
): boolean =>
  Boolean(data?.items.some((item) => shouldPollCertificateStatus(item.status)));

export const useListCertificates = useCertificateListQuery;

export const useGetCertificateDetails = (certificateId: string) =>
  useQuery({
    queryKey: [CERTIFICATE_DETAILS_QUERY_KEY, certificateId],
    enabled: Boolean(certificateId),
    retry: false,
    queryFn: async (): Promise<SSLCertificateDetails> =>
      getCertificateDetailsRecord(certificateId),
    refetchInterval: (query) =>
      getConditionalRefetchInterval(
        query,
        FAST_POLL_INTERVAL,
        (data: SSLCertificateDetails | undefined) =>
          shouldPollCertificateStatus(data?.status),
      ),
  });

export async function getCertificateDetails(
  certificateId: string,
): Promise<SSLCertificateDetails> {
  return getCertificateDetailsRecord(certificateId);
}

export const useIssueCertificateRequest = () => {
  const queryClient = useQueryClient();

  return useMutation({
    retry: false,
    mutationFn: async (
      payload: IssueCertificateInput,
    ): Promise<CertificateAsyncResponse> => issueCertificate(payload),
    onSuccess: async (result) => {
      toast.success(`Certificate request queued for ${result.domain}`);
      await Promise.all([
        invalidateCertificateDataQueries(queryClient),
        invalidateAlertQueries(queryClient),
        invalidateAuditQueries(queryClient),
      ]);
    },
    onError: (error) => {
      toast.error(getApiErrorMessage(error, "Failed to request certificate"));
    },
  });
};

export const useIssueManualCertificateRequest = () => {
  const queryClient = useQueryClient();

  return useMutation({
    retry: false,
    mutationFn: async (
      payload: IssueManualCertificateInput,
    ): Promise<CertificateAsyncResponse> => issueManualCertificate(payload),
    onSuccess: async (result) => {
      toast.success(`Manual issuance started for ${result.domain}`);
      await Promise.all([
        invalidateCertificateDataQueries(queryClient),
        invalidateAlertQueries(queryClient),
        invalidateAuditQueries(queryClient),
      ]);
    },
    onError: (error) => {
      toast.error(
        getApiErrorMessage(
          error,
          "Failed to start manual certificate issuance",
        ),
      );
    },
  });
};

export const useConvertCertificateToAutomated = () => {
  const queryClient = useQueryClient();

  return useMutation({
    retry: false,
    mutationFn: async ({
      certificateXref,
      payload,
    }: {
      certificateXref: string;
      payload: ConvertToAutomatedInput;
    }): Promise<ConvertToAutomatedResponse> =>
      convertCertificateToAutomated(certificateXref, payload),
    onSuccess: async (result) => {
      toast.success(`Automation enabled for ${result.domain}`);
      await Promise.all([
        invalidateCertificateDataQueries(queryClient),
        invalidateDeploymentQueries(queryClient),
        invalidateAlertQueries(queryClient),
        invalidateAuditQueries(queryClient),
      ]);
    },
    onError: (error) => {
      toast.error(
        getApiErrorMessage(
          error,
          "Failed to enable automated renewal for this certificate",
        ),
      );
    },
  });
};

export const useGetTxtRecords = () =>
  useMutation({
    retry: false,
    mutationFn: async ({
      certificateXref,
    }: {
      certificateXref: string;
    }): Promise<CertificateTxtRecord[]> =>
      getCertificateTxtRecords(certificateXref),
    onError: (error) => {
      toast.error(getApiErrorMessage(error, "Failed to load TXT records"));
    },
  });

export const useCompleteDnsChallenge = () => {
  const queryClient = useQueryClient();

  return useMutation({
    retry: false,
    mutationFn: async ({
      certificateXref,
    }: {
      certificateXref: string;
    }): Promise<void> => validateCertificateDns(certificateXref),
    onSuccess: async () => {
      toast.success("DNS validation triggered");
      await Promise.all([
        invalidateCertificateDataQueries(queryClient),
        invalidateAlertQueries(queryClient),
        invalidateAuditQueries(queryClient),
      ]);
    },
    onError: (error) => {
      toast.error(getApiErrorMessage(error, "Failed to validate DNS"));
    },
  });
};

export const useRenewCertificate = () => {
  const queryClient = useQueryClient();

  return useMutation({
    retry: false,
    mutationFn: async ({
      certificateXref,
      deploymentTargets,
    }: {
      certificateXref: string;
      deploymentTargets?: string[];
    }): Promise<CertificateAsyncResponse> =>
      renewCertificate(certificateXref, { deploymentTargets }),
    onSuccess: async (result) => {
      toast.success(`Renewal queued for ${result.domain}`);
      await Promise.all([
        invalidateCertificateDataQueries(queryClient),
        invalidateDeploymentQueries(queryClient),
        invalidateAlertQueries(queryClient),
        invalidateAuditQueries(queryClient),
      ]);
    },
    onError: (error) => {
      toast.error(getApiErrorMessage(error, "Failed to renew certificate"));
    },
  });
};

export const useRevokeCertificate = () => {
  const queryClient = useQueryClient();

  return useMutation({
    retry: false,
    mutationFn: async ({
      certificateXref,
      reason,
    }: {
      certificateXref: string;
      reason?: string;
    }): Promise<CertificateAsyncResponse> =>
      revokeCertificate(certificateXref, reason ? { reason } : undefined),
    onSuccess: async (result) => {
      toast.success(`Revocation queued for ${result.domain}`);
      await Promise.all([
        invalidateCertificateDataQueries(queryClient),
        invalidateAlertQueries(queryClient),
        invalidateAuditQueries(queryClient),
      ]);
    },
    onError: (error) => {
      toast.error(getApiErrorMessage(error, "Failed to revoke certificate"));
    },
  });
};

export const useDeletePendingSSLCertificate = () => {
  const queryClient = useQueryClient();

  return useMutation({
    retry: false,
    mutationFn: async ({
      userDomainCertId,
    }: {
      userDomainCertId: string | number;
    }): Promise<void> => deleteCertificate(userDomainCertId),
    onSuccess: async () => {
      toast.success("Certificate deleted");
      await Promise.all([
        invalidateCertificateDataQueries(queryClient),
        invalidateDeploymentQueries(queryClient),
        invalidateAlertQueries(queryClient),
        invalidateAuditQueries(queryClient),
      ]);
    },
    onError: (error) => {
      toast.error(getApiErrorMessage(error, "Failed to delete certificate"));
    },
  });
};

export const useGetCertificateHistory = (
  udcId: string | number | undefined,
  page = 0,
  size = 20,
  options?: { pollWhile?: boolean },
) =>
  useQuery({
    queryKey: [CERT_HISTORY_QUERY_KEY, udcId, page, size],
    enabled: Boolean(udcId),
    retry: false,
    queryFn: (): Promise<CertificateHistoryPage> =>
      getCertificateHistory({ udcId: String(udcId), page, size }),
    refetchInterval: (query) =>
      getConditionalRefetchInterval(
        query,
        FAST_POLL_INTERVAL,
        (data: CertificateHistoryPage | undefined) =>
          options?.pollWhile || shouldPollCertificateHistory(data),
      ),
  });

export const useCertificateHistories = (
  udcIds: Array<string | number>,
  options?: {
    enabled?: boolean;
    page?: number;
    pollWhilePending?: boolean;
    size?: number;
  },
) => {
  const page = options?.page ?? 0;
  const size = options?.size ?? 20;

  return useQueries({
    queries: udcIds.map((udcId) => ({
      queryKey: [CERT_HISTORY_QUERY_KEY, udcId, page, size],
      enabled: options?.enabled !== false && Boolean(udcId),
      retry: false,
      queryFn: (): Promise<CertificateHistoryPage> =>
        getCertificateHistory({ udcId: String(udcId), page, size }),
      refetchInterval: (query: Query<CertificateHistoryPage>) => {
        if (options?.pollWhilePending === false) {
          return false;
        }
        return getConditionalRefetchInterval(
          query,
          FAST_POLL_INTERVAL,
          shouldPollCertificateHistory,
        );
      },
    })),
  });
};

export const useMarkAlertAsRead = () => {
  const queryClient = useQueryClient();

  return useMutation({
    retry: false,
    mutationFn: async (alertId: number) => {
      const payload: MarkAlertAsReadRequest = { unread: false };
      const response = await apiClient.patch<MarkAlertAsReadResponse>(
        apiRoutes.mutation.ssl.markAlertAsRead(alertId),
        payload,
      );

      if (!response.data.success) {
        throw new Error("Failed to mark alert as read");
      }

      return response.data;
    },
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: [SSL_ALERTS_QUERY_KEY] }),
        invalidateAlertQueries(queryClient),
        invalidateAuditQueries(queryClient),
      ]);
    },
    onError: (error) => {
      toast.error(getApiErrorMessage(error, "Failed to mark alert as read"));
    },
  });
};
