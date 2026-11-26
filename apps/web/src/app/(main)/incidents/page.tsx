// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { EnvelopeOpenIcon, ShieldWarningIcon } from "@phosphor-icons/react";
import { toast } from "sonner";

import {
  buildEscalationDraft,
  escalationActor,
  indexUserEmails,
  NO_ESCALATIONS,
} from "@/components/incidents/alert-presentation";
import { EscalateIncidentDialog } from "@/components/incidents/escalate-incident-dialog";
import {
  AlertGrid,
  EscalationGrid,
} from "@/components/incidents/incident-cards";
import {
  createAlertColumns,
  createEscalationColumns,
  type AlertActions,
} from "@/components/incidents/incident-columns";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { CustomTable } from "@/components/ui/custom-table";
import { PageHeader } from "@/components/ui/page-header";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  useCanMarkAlertRead,
  useFindLoadedAlert,
  useIncidentEscalations,
  useMarkAllSystemAlertsAsRead,
  useMarkSystemAlertAsRead,
  useSystemAlerts,
  useUnreadAlertSummary,
  type SystemAlert,
} from "@/hooks/incidents";
import { useAuth } from "@/hooks/use-auth";
import { useIsFeatureEnabled } from "@/hooks/use-feature-flags";
import { useResponsiveViewMode } from "@/hooks/use-responsive-view-mode";
import { useListUsers } from "@/hooks/users";
import { getAlertKey } from "@/lib/alerts";
import {
  canCreateIncidents,
  canManageNotifications,
  canViewIncidents,
} from "@/lib/authz";
import { FEATURE_FLAGS } from "@/lib/feature-flags";
import { isAccessDeniedError } from "@/lib/http-errors";
import { cn, getErrorMessage } from "@/lib/utils";
import type { IncidentHistoryItem } from "@/types/integrations";
import { AlertDetailsDialog } from "./alert-details-dialog";

type IncidentTab = "ALERTS" | "escalations";

const ALERT_SEARCH_KEYS = [
  "status",
  "severity",
  "typeLabel",
  "domain",
  "deploymentTarget",
  "message",
];

const ESCALATION_SEARCH_KEYS = [
  "summary",
  "externalReference",
  "externalIncidentId",
  "provider",
];

const isIncidentTab = (value: string | null): value is IncidentTab =>
  value === "ALERTS" || value === "escalations";

const ALERT_FILTERS = [
  {
    id: "severity",
    type: "select" as const,
    placeholder: "Filter by severity",
    options: [
      { label: "All severities", value: "all" },
      { label: "Critical", value: "CRITICAL" },
      { label: "Warning", value: "WARNING" },
      { label: "Info", value: "INFO" },
    ],
  },
  {
    id: "unread",
    type: "select" as const,
    placeholder: "Filter by read status",
    options: [
      { label: "Read and unread", value: "all" },
      { label: "Unread", value: "true" },
      { label: "Read", value: "false" },
    ],
  },
];

const ESCALATION_FILTERS = [
  {
    id: "provider",
    type: "select" as const,
    placeholder: "Filter by provider",
    options: [
      { label: "All providers", value: "all" },
      { label: "PagerDuty", value: "PAGERDUTY" },
      { label: "ServiceNow", value: "SERVICENOW_ITSM" },
    ],
  },
];

const HIDDEN_ALERT_COLUMNS = ["unread", "source"];
const getEscalationRowId = (row: IncidentHistoryItem) => String(row.id);

function AccessRestricted({ subject }: { subject: string }) {
  return (
    <Alert variant="warning" className="mx-auto max-w-md">
      <ShieldWarningIcon aria-hidden />
      <AlertTitle>Access restricted</AlertTitle>
      <AlertDescription>
        You do not have permission to view {subject}.
      </AlertDescription>
    </Alert>
  );
}

const TableLoadingSkeleton = () => (
  <div className="space-y-3 rounded-[10px] border border-border bg-card p-4">
    <Skeleton className="h-9 w-full max-w-sm" />
    <div className="space-y-2">
      {Array.from({ length: 5 }).map((_, index) => (
        <Skeleton className="h-10 w-full" key={index} />
      ))}
    </div>
  </div>
);

export default function IncidentsPage() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const tabParam = searchParams.get("tab");
  const alertParam = searchParams.get("alert");
  const escalationAlertParam = searchParams.get("alertId");
  const { user, isLoading: isLoadingAuth } = useAuth();
  const usersQuery = useListUsers();
  const canViewAlerts = canViewIncidents(user);
  const canMarkAlertsRead = canManageNotifications(user);
  // Escalations go out through integrations, so they exist only while
  // INTEGRATIONS is on; alerts never depend on it.
  const isIntegrationsEnabled = useIsFeatureEnabled(FEATURE_FLAGS.INTEGRATIONS);
  const canViewEscalations = canViewAlerts && isIntegrationsEnabled;
  const canEscalateIncidents =
    canCreateIncidents(user) && isIntegrationsEnabled;
  const canMarkSource = useCanMarkAlertRead();
  const canMarkAlert = useCallback(
    (alert: SystemAlert): boolean => canMarkSource(alert.source),
    [canMarkSource],
  );
  const canEscalateAlert = useCallback(
    (): boolean => canEscalateIncidents,
    [canEscalateIncidents],
  );

  const activeTab: IncidentTab =
    isIncidentTab(tabParam) && (tabParam === "ALERTS" || canViewEscalations)
      ? tabParam
      : "ALERTS";
  const [selectedAlert, setSelectedAlert] = useState<SystemAlert | null>(null);
  const [escalationAlert, setEscalationAlert] = useState<SystemAlert | null>(
    null,
  );

  const [alertsViewMode, setAlertsViewMode] = useResponsiveViewMode({
    storageKey: "incidents-alerts_view",
  });
  const [escalationsViewMode, setEscalationsViewMode] = useResponsiveViewMode({
    storageKey: "incidents-escalations_view",
  });

  const alertsQuery = useSystemAlerts({ enabled: canViewAlerts });
  const unreadAlerts = useUnreadAlertSummary({ enabled: canViewAlerts });
  const escalationsQuery = useIncidentEscalations(
    {},
    { enabled: canViewEscalations },
  );
  const markAlertMutation = useMarkSystemAlertAsRead();
  const markAllAlertsMutation = useMarkAllSystemAlertsAsRead();

  const findLoadedAlert = useFindLoadedAlert();
  const linkedAlert =
    alertParam && alertsQuery.data ? findLoadedAlert(alertParam) : null;
  const dialogAlert =
    selectedAlert ?? (linkedAlert && alertParam ? linkedAlert : null);

  useEffect(() => {
    if (!canViewAlerts) return;
    if (alertsQuery.isError && !isAccessDeniedError(alertsQuery.error)) {
      toast.error(getErrorMessage(alertsQuery.error, "Failed to load alerts"), {
        id: "incidents-alerts-load-error",
        duration: 7000,
      });
    }
  }, [alertsQuery.error, alertsQuery.isError, canViewAlerts]);

  useEffect(() => {
    if (!canViewEscalations) return;
    if (
      escalationsQuery.isError &&
      !isAccessDeniedError(escalationsQuery.error)
    ) {
      toast.error(
        getErrorMessage(
          escalationsQuery.error,
          "Failed to load incident escalations",
        ),
        { id: "incidents-escalations-load-error", duration: 7000 },
      );
    }
  }, [canViewEscalations, escalationsQuery.error, escalationsQuery.isError]);

  const escalationsByAlertId = useMemo(() => {
    const byAlert = new Map<number, IncidentHistoryItem[]>();
    for (const incident of escalationsQuery.data?.items ?? []) {
      if (incident.alertId == null) continue;
      const collection = byAlert.get(incident.alertId) ?? [];
      collection.push(incident);
      byAlert.set(incident.alertId, collection);
    }
    return byAlert;
  }, [escalationsQuery.data]);

  const getAlertEscalations = useCallback(
    (alert: SystemAlert): IncidentHistoryItem[] =>
      alert.source === "ssl"
        ? (escalationsByAlertId.get(Number.parseInt(alert.id, 10)) ??
          NO_ESCALATIONS)
        : NO_ESCALATIONS,
    [escalationsByAlertId],
  );

  const selectedEscalationAlertId = escalationAlertParam
    ? Number.parseInt(escalationAlertParam, 10)
    : null;

  const visibleEscalations = useMemo(() => {
    const items = escalationsQuery.data?.items ?? NO_ESCALATIONS;
    if (!selectedEscalationAlertId) return items;
    return items.filter(
      (incident) => incident.alertId === selectedEscalationAlertId,
    );
  }, [escalationsQuery.data, selectedEscalationAlertId]);

  const replaceParams = useCallback(
    (update: (params: URLSearchParams) => void): void => {
      const nextParams = new URLSearchParams(searchParams.toString());
      update(nextParams);
      const query = nextParams.toString();
      router.replace(query ? `${pathname}?${query}` : pathname);
    },
    [pathname, router, searchParams],
  );

  const handleTabChange = (nextTab: string): void => {
    if (!isIncidentTab(nextTab)) return;
    replaceParams((params) => {
      params.set("tab", nextTab);
      if (nextTab !== "escalations") params.delete("alertId");
    });
  };

  const openAlertDialog = useCallback(
    (alert: SystemAlert): void => {
      replaceParams((params) => {
        params.set("tab", "ALERTS");
        params.set("alert", getAlertKey(alert));
      });
      setSelectedAlert(alert);
    },
    [replaceParams],
  );

  const closeAlertDialog = useCallback((): void => {
    replaceParams((params) => params.delete("alert"));
    setSelectedAlert(null);
  }, [replaceParams]);

  const openEscalationDialog = useCallback(
    (alert: SystemAlert): void => {
      if (canEscalateAlert()) setEscalationAlert(alert);
    },
    [canEscalateAlert],
  );

  const openEscalationsForAlert = useCallback(
    (alertId: number): void => {
      replaceParams((params) => {
        params.set("tab", "escalations");
        params.set("alertId", String(alertId));
        params.delete("alert");
      });
      setSelectedAlert(null);
    },
    [replaceParams],
  );

  const clearEscalationFilter = useCallback((): void => {
    replaceParams((params) => {
      params.delete("alertId");
      params.set("tab", "escalations");
    });
  }, [replaceParams]);

  const { mutate: markAlertRead, isPending: isMarkingAlert } =
    markAlertMutation;
  const handleMarkAlertAsRead = useCallback(
    (alert: SystemAlert): void => {
      if (!canMarkAlert(alert)) return;
      markAlertRead(
        { id: alert.id, source: alert.source },
        {
          onSuccess: () =>
            setSelectedAlert((previous) =>
              previous ? { ...previous, unread: false } : previous,
            ),
        },
      );
    },
    [canMarkAlert, markAlertRead],
  );

  const alertActions = useMemo<AlertActions>(
    () => ({
      escalationCount: (alert) => getAlertEscalations(alert).length,
      canMarkRead: canMarkAlert,
      canEscalate: canEscalateAlert,
      isMarking: isMarkingAlert,
      onOpen: openAlertDialog,
      onMarkRead: handleMarkAlertAsRead,
      onEscalate: openEscalationDialog,
      onViewEscalations: openEscalationsForAlert,
    }),
    [
      canEscalateAlert,
      canMarkAlert,
      getAlertEscalations,
      handleMarkAlertAsRead,
      isMarkingAlert,
      openAlertDialog,
      openEscalationDialog,
      openEscalationsForAlert,
    ],
  );
  const alertColumns = useMemo(
    () => createAlertColumns(alertActions),
    [alertActions],
  );
  const renderAlertGrid = useCallback(
    (alerts: SystemAlert[]) => (
      <AlertGrid alerts={alerts} actions={alertActions} />
    ),
    [alertActions],
  );

  const userEmails = useMemo(
    () => indexUserEmails(usersQuery.data),
    [usersQuery.data],
  );
  const actorFor = useCallback(
    (incident: IncidentHistoryItem) => escalationActor(incident, userEmails),
    [userEmails],
  );
  const escalationColumns = useMemo(
    () => createEscalationColumns(actorFor),
    [actorFor],
  );
  const renderEscalationGrid = useCallback(
    (incidents: IncidentHistoryItem[]) => (
      <EscalationGrid incidents={incidents} actorFor={actorFor} />
    ),
    [actorFor],
  );
  const escalationDraft = useMemo(
    () => buildEscalationDraft(escalationAlert),
    [escalationAlert],
  );

  if (isLoadingAuth) {
    return (
      <div className="flex h-[60vh] items-center justify-center">
        <Skeleton className="h-8 w-8 rounded-full" />
      </div>
    );
  }

  if (!canViewAlerts || isAccessDeniedError(alertsQuery.error)) {
    return (
      <div className="p-6">
        <AccessRestricted subject="alerts and escalations" />
      </div>
    );
  }

  return (
    <>
      <div className="w-full space-y-6 p-4 sm:p-6">
        <PageHeader
          title="Incidents"
          subtitle={
            canViewEscalations
              ? "Alerts from your certificates, and the incidents escalated from them."
              : "Alerts from your certificates."
          }
          actions={
            canMarkAlertsRead && unreadAlerts.hasUnread ? (
              <Button
                size="sm"
                variant="outline"
                disabled={markAllAlertsMutation.isPending}
                onClick={() => markAllAlertsMutation.mutate()}
              >
                <EnvelopeOpenIcon aria-hidden />
                Mark all as read
              </Button>
            ) : null
          }
        />

        <Tabs
          value={activeTab}
          onValueChange={handleTabChange}
          className="space-y-5"
        >
          <TabsList variant="underline">
            <TabsTrigger value="ALERTS" className="gap-2">
              Alerts
              {unreadAlerts.hasUnread ? (
                <span
                  aria-label={
                    unreadAlerts.hasUnreadProblem
                      ? "Unread problems"
                      : "Unread alerts"
                  }
                  className={cn(
                    "inline-flex size-2 rounded-full",
                    unreadAlerts.hasUnreadProblem
                      ? "bg-destructive"
                      : "bg-primary",
                  )}
                />
              ) : null}
            </TabsTrigger>
            {canViewEscalations ? (
              <TabsTrigger value="escalations">Escalations</TabsTrigger>
            ) : null}
          </TabsList>

          <TabsContent value="ALERTS" className="space-y-4">
            {alertsQuery.isLoading ? (
              <TableLoadingSkeleton />
            ) : (
              <CustomTable
                viewSwitcher={{
                  value: alertsViewMode,
                  onValueChange: setAlertsViewMode,
                }}
                renderGrid={renderAlertGrid}
                columns={alertColumns}
                data={alertsQuery.data ?? []}
                searchBy={ALERT_SEARCH_KEYS}
                searchPlaceholder="Search incidents..."
                emptyTableMsg="No incidents found."
                showColumnVisibility={false}
                defaultHiddenColumns={HIDDEN_ALERT_COLUMNS}
                denseRows
                filters={ALERT_FILTERS}
                getRowId={getAlertKey}
                onRowClick={openAlertDialog}
              />
            )}
          </TabsContent>

          <TabsContent value="escalations" className="space-y-4">
            {selectedEscalationAlertId ? (
              <Alert variant="info">
                <AlertDescription className="flex flex-wrap items-center justify-between gap-3">
                  Showing escalations for alert {selectedEscalationAlertId}.
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={clearEscalationFilter}
                  >
                    Show all escalations
                  </Button>
                </AlertDescription>
              </Alert>
            ) : null}
            {isAccessDeniedError(escalationsQuery.error) ? (
              <AccessRestricted subject="escalations" />
            ) : escalationsQuery.isError ? (
              <Alert variant="warning">
                <AlertTitle>Escalations unavailable</AlertTitle>
                <AlertDescription className="space-y-3">
                  <p>
                    The escalation service is unavailable. Alerts keep working;
                    retry escalations when the service recovers.
                  </p>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => void escalationsQuery.refetch()}
                  >
                    Retry
                  </Button>
                </AlertDescription>
              </Alert>
            ) : escalationsQuery.isLoading ? (
              <TableLoadingSkeleton />
            ) : (
              <CustomTable
                viewSwitcher={{
                  value: escalationsViewMode,
                  onValueChange: setEscalationsViewMode,
                }}
                renderGrid={renderEscalationGrid}
                columns={escalationColumns}
                data={visibleEscalations}
                searchBy={ESCALATION_SEARCH_KEYS}
                searchPlaceholder="Search escalations..."
                emptyTableMsg="No escalations found."
                showColumnVisibility={false}
                denseRows
                filters={ESCALATION_FILTERS}
                getRowId={getEscalationRowId}
              />
            )}
          </TabsContent>
        </Tabs>
      </div>

      <AlertDetailsDialog
        alert={dialogAlert}
        isOpen={Boolean(dialogAlert)}
        canEscalate={dialogAlert ? canEscalateAlert() : false}
        canMarkAsRead={dialogAlert ? canMarkAlert(dialogAlert) : false}
        hasEscalations={
          dialogAlert ? getAlertEscalations(dialogAlert).length > 0 : false
        }
        isMarkingAsRead={isMarkingAlert}
        onClose={closeAlertDialog}
        onEscalate={openEscalationDialog}
        onMarkAsRead={handleMarkAlertAsRead}
        onViewEscalations={(alert) =>
          openEscalationsForAlert(Number.parseInt(alert.id, 10))
        }
      />

      <EscalateIncidentDialog
        open={Boolean(escalationAlert)}
        onOpenChange={(open) => {
          if (!open) setEscalationAlert(null);
        }}
        initialDraft={escalationDraft}
      />
    </>
  );
}
