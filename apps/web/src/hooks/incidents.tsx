// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { apiClient, apiRoutes } from "@/lib/api";
import {
  createPagerDutyIncident,
  createServiceNowIncident,
  listIncidentHistory,
} from "@/lib/backend/integrations";
import { getSystemNotifications } from "@/lib/backend/notifications";
import {
  keepPreviousData,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { useCallback } from "react";
import { toast } from "sonner";
import { getErrorMessage } from "@/lib/utils";
import { isTransientRequestError } from "@/lib/http-errors";
import type {
  CreatePagerDutyIncidentPayload,
  CreateServiceNowIncidentPayload,
  IncidentHistoryPage,
} from "@/types/integrations";
import type {
  NotificationFilters,
  NotificationPage,
} from "@/types/notifications";
import { getConditionalRefetchInterval } from "@/hooks/query-polling";
import { useIsFeatureEnabled } from "@/hooks/use-feature-flags";
import { FEATURE_FLAGS } from "@/lib/feature-flags";
import {
  getAlertTypeLabel,
  hasUnreadProblem,
  type AlertSeverity,
  type AlertSource,
  type AlertType,
} from "@/lib/alerts";
import { canManageNotifications } from "@/lib/authz";
import { useAuthStore } from "@/stores/auth-store";

export type IncidentSeverity = AlertSeverity;

export type { AlertSource, AlertType } from "@/lib/alerts";

interface AlertApiRecord {
  id: number;
  alertType: AlertType;
  status: string | null;
  domain: string | null;
  createdAt: string;
  message: string | null;
  correlationId: string | null;
  severity: AlertSeverity;
  unread: boolean | null;
}

interface AlertApiPage {
  alerts: AlertApiRecord[];
}

export interface SystemAlert {
  id: string;
  source: AlertSource;
  alertType: AlertType;
  /** Human label for alertType; what the tables render and what search indexes. */
  typeLabel: string;
  status: string | null;
  createdAt: string;
  message: string | null;
  severity: IncidentSeverity;
  unread: boolean;
  domain: string | null;
  deploymentTarget: string | null;
  /** Per-operation trace id surfaced as a support "Reference ID"; null for legacy/uncorrelated alerts. */
  correlationId: string | null;
}

interface QueryOptions {
  enabled?: boolean;
  poll?: boolean;
}

interface PollingQuery<TData> {
  readonly state: {
    readonly data: TData | undefined;
    readonly error?: unknown;
  };
}

type MarkAlertPayload = Pick<SystemAlert, "id" | "source">;

export const SYSTEM_ALERTS_QUERY_KEY = "system-alerts";
const SSL_ALERTS_QUERY_KEY = [SYSTEM_ALERTS_QUERY_KEY, "ssl"] as const;
export const SYSTEM_NOTIFICATIONS_QUERY_KEY = "system-notifications";
export const ESCALATIONS_QUERY_KEY = "incident-escalations";
const ALERT_POLL_INTERVAL_MS = 10 * 1000;
const MAX_NOTIFICATION_RETRY_DELAY_MS = 30 * 1000;

export const getNotificationRetryDelay = (failureCount: number): number =>
  Math.min(
    ALERT_POLL_INTERVAL_MS * 2 ** failureCount,
    MAX_NOTIFICATION_RETRY_DELAY_MS,
  );

const getOperationalPollingInterval = <TData,>(
  query: PollingQuery<TData>,
  isPollingEnabled: boolean,
): number | false => {
  if (!isPollingEnabled) {
    return false;
  }

  return getConditionalRefetchInterval(
    query,
    ALERT_POLL_INTERVAL_MS,
    () => true,
  );
};

const normalizeAlert = (
  alert: AlertApiRecord,
  source: AlertSource,
): SystemAlert => {
  return {
    id: String(alert.id),
    source,
    alertType: alert.alertType,
    typeLabel: getAlertTypeLabel(alert.alertType),
    status: alert.status ?? "UNKNOWN",
    createdAt: alert.createdAt,
    message: alert.message,
    severity: alert.severity,
    unread: alert.unread ?? false,
    domain: alert.domain,
    deploymentTarget: null,
    correlationId: alert.correlationId,
  };
};

const toSystemAlerts = (
  alerts: AlertApiRecord[],
  source: AlertSource,
): SystemAlert[] => {
  return alerts
    .map((alert) => normalizeAlert(alert, source))
    .sort(
      (left, right) =>
        new Date(right.createdAt).getTime() -
        new Date(left.createdAt).getTime(),
    );
};

const fetchSslAlerts = async (): Promise<SystemAlert[]> => {
  const response = await apiClient.get<AlertApiPage>(
    apiRoutes.query.incidents.sslAlerts,
  );
  return toSystemAlerts(response.data.alerts, "ssl");
};

const useSslAlerts = (options: QueryOptions) => {
  // `/alerts` also answers a session without an organization (its own
  // alerts), so this query does not need one.
  const isFeatureOn = useIsFeatureEnabled(FEATURE_FLAGS.ALERTS);
  return useQuery({
    queryKey: SSL_ALERTS_QUERY_KEY,
    queryFn: fetchSslAlerts,
    enabled: (options.enabled ?? true) && isFeatureOn,
    retry: false,
    staleTime: ALERT_POLL_INTERVAL_MS,
    refetchInterval: (query) =>
      getOperationalPollingInterval(query, options.poll === true),
    refetchIntervalInBackground: false,
  });
};

/** Whether the signed-in user can mark an alert from this source read. */
export const useCanMarkAlertRead = (): ((source: AlertSource) => boolean) => {
  const user = useAuthStore((state) => state.user);
  return useCallback(
    (source: AlertSource): boolean =>
      source === "ssl" && canManageNotifications(user),
    [user],
  );
};

export type SystemAlertsOptions = QueryOptions;

/** The alert feed shown on /incidents. */
export interface LatestSystemAlerts {
  data: SystemAlert[] | undefined;
  isLoading: boolean;
  isError: boolean;
  error: unknown;
}

export type SystemAlertFeed = LatestSystemAlerts;

export const useSystemAlerts = (
  options: SystemAlertsOptions = {},
): SystemAlertFeed => {
  const sslQuery = useSslAlerts(options);
  return {
    data: sslQuery.data,
    isLoading: sslQuery.isLoading,
    isError: sslQuery.isError,
    error: sslQuery.error,
  };
};

export type LatestSystemAlertsOptions = QueryOptions;

/** Every SSL alert, newest first. */
export const useLatestSystemAlerts = (
  options: LatestSystemAlertsOptions = {},
): LatestSystemAlerts => {
  const sslQuery = useSslAlerts(options);
  return {
    data: sslQuery.data,
    isLoading: sslQuery.isLoading,
    isError: sslQuery.isError,
    error: sslQuery.error,
  };
};

/** Finds a `source:id` deep link among every loaded alert, including rows a paged feed holds back. */
export const useFindLoadedAlert = (): ((
  alertKey: string,
) => SystemAlert | undefined) => {
  const queryClient = useQueryClient();
  return useCallback(
    (alertKey: string): SystemAlert | undefined => {
      const [source, id] = alertKey.split(":");
      if (source === "ssl") {
        return queryClient
          .getQueryData<SystemAlert[]>(SSL_ALERTS_QUERY_KEY)
          ?.find((alert) => alert.id === id);
      }
      return undefined;
    },
    [queryClient],
  );
};

export interface UnreadAlertSummary {
  hasUnread: boolean;
  /** Drives the red dot; unread good news alone keeps it neutral. */
  hasUnreadProblem: boolean;
}

export const useUnreadAlertSummary = (
  options: QueryOptions = {},
): UnreadAlertSummary => {
  const sslQuery = useSslAlerts(options);
  return {
    hasUnread: sslQuery.data?.some((alert) => alert.unread) ?? false,
    hasUnreadProblem: hasUnreadProblem(sslQuery.data),
  };
};

export const useSystemNotifications = (
  filters: NotificationFilters = {},
  options: QueryOptions = {},
) =>
  useQuery<NotificationPage>({
    queryKey: [
      SYSTEM_NOTIFICATIONS_QUERY_KEY,
      filters.page ?? null,
      filters.size ?? null,
      filters.status ?? null,
    ],
    enabled: options.enabled ?? true,
    queryFn: () => getSystemNotifications(filters),
    placeholderData: keepPreviousData,
    retry: (_failureCount, error) => isTransientRequestError(error),
    retryDelay: getNotificationRetryDelay,
    staleTime: ALERT_POLL_INTERVAL_MS,
    refetchInterval: (query) =>
      getOperationalPollingInterval(query, options.poll === true),
    refetchIntervalInBackground: false,
  });

export const useIncidentEscalations = (
  params: { page?: number; size?: number } = {},
  options: QueryOptions = {},
) => {
  // Escalations go out through integrations; `/incidents` is gated by INTEGRATIONS.
  const isFeatureOn = useIsFeatureEnabled(FEATURE_FLAGS.INTEGRATIONS);
  return useQuery({
    queryKey: [ESCALATIONS_QUERY_KEY, params.page ?? 0, params.size ?? 50],
    enabled: (options.enabled ?? true) && isFeatureOn,
    queryFn: (): Promise<IncidentHistoryPage> => listIncidentHistory(params),
    retry: false,
    staleTime: ALERT_POLL_INTERVAL_MS,
    refetchOnWindowFocus: true,
  });
};

const markSingleAlertAsRead = async ({
  id,
}: MarkAlertPayload): Promise<void> => {
  await apiClient.patch(apiRoutes.mutation.incidents.markSslAlertAsRead(id), {
    unread: false,
  });
};

export const useMarkSystemAlertAsRead = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationKey: ["mark-system-alert-read"],
    mutationFn: markSingleAlertAsRead,
    onError: (error) => {
      toast.error(getErrorMessage(error, "Failed to mark alert as read"), {
        duration: 6000,
      });
    },
    // A failed mark refetches too: a 404 means the alert is gone and its row should go with it.
    onSettled: async () => {
      await queryClient.invalidateQueries({
        queryKey: [SYSTEM_ALERTS_QUERY_KEY],
        refetchType: "active",
      });
    },
  });
};

const PARTIAL_MARK_ALL_FAILURE = "Some alerts could not be marked as read";

type MarkAllOutcome = "all-read" | "some-unread" | "nothing-unread";

const announceMarkAllOutcome = (outcome: MarkAllOutcome): void => {
  switch (outcome) {
    case "all-read":
      toast.success("All alerts marked as read", { duration: 4000 });
      return;
    case "some-unread":
      toast.warning("Some alerts are still unread. Try again in a moment.", {
        duration: 6000,
      });
      return;
    case "nothing-unread":
      toast.info("No unread alerts to mark", { duration: 4000 });
  }
};

export const useMarkAllSystemAlertsAsRead = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationKey: ["mark-all-system-alerts-read"],
    mutationFn: async (): Promise<MarkAllOutcome> => {
      const sslUnread = (
        queryClient.getQueryData<SystemAlert[]>(SSL_ALERTS_QUERY_KEY) ?? []
      ).filter((alert) => alert.unread);
      const calls = sslUnread.map((alert) =>
        markSingleAlertAsRead(alert).then(() => true),
      );
      if (calls.length === 0) {
        return "nothing-unread";
      }

      const results = await Promise.allSettled(calls);
      await queryClient.invalidateQueries({
        queryKey: [SYSTEM_ALERTS_QUERY_KEY],
        refetchType: "active",
      });

      const failures = results.filter(
        (result): result is PromiseRejectedResult =>
          result.status === "rejected",
      );
      if (failures.length === results.length) {
        throw failures[0].reason;
      }
      if (failures.length > 0) {
        throw new Error(PARTIAL_MARK_ALL_FAILURE);
      }
      const allRead = results.every(
        (result) => result.status === "fulfilled" && result.value,
      );
      return allRead ? "all-read" : "some-unread";
    },
    onSuccess: announceMarkAllOutcome,
    onError: (error) => {
      toast.error(getErrorMessage(error, "Failed to mark all alerts as read"), {
        duration: 6000,
      });
    },
  });
};

export const useCreatePagerDutyIncident = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationKey: ["create-pagerduty-incident"],
    mutationFn: (payload: CreatePagerDutyIncidentPayload) =>
      createPagerDutyIncident(payload),
    onSuccess: (response) => {
      toast.success(response.message || "PagerDuty incident created");
    },
    onSettled: async () => {
      await queryClient.invalidateQueries({
        queryKey: [ESCALATIONS_QUERY_KEY],
      });
    },
    onError: (error) => {
      toast.error(
        getErrorMessage(error, "Failed to create PagerDuty incident"),
        { duration: 6000 },
      );
    },
  });
};

export const useCreateServiceNowIncident = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationKey: ["create-servicenow-incident"],
    mutationFn: (payload: CreateServiceNowIncidentPayload) =>
      createServiceNowIncident(payload),
    onSuccess: (response) => {
      toast.success(
        response.number
          ? `ServiceNow incident ${response.number} created`
          : "ServiceNow incident created",
      );
    },
    onSettled: async () => {
      await queryClient.invalidateQueries({
        queryKey: [ESCALATIONS_QUERY_KEY],
      });
    },
    onError: (error) => {
      toast.error(
        getErrorMessage(error, "Failed to create ServiceNow incident"),
        { duration: 6000 },
      );
    },
  });
};
