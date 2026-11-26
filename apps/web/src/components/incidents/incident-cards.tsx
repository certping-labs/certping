// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { ArrowSquareOutIcon } from "@phosphor-icons/react/dist/ssr";

import { AlertStatusBadge } from "@/app/(main)/incidents/alert-status-badge";
import {
  formatIncidentDateTime,
  getAlertMessage,
  getAlertTarget,
  getEscalationReference,
  getProviderLabel,
  SeverityBadge,
} from "@/components/incidents/alert-presentation";
import {
  AlertRowActions,
  type AlertActions,
} from "@/components/incidents/incident-columns";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import type { SystemAlert } from "@/hooks/incidents";
import { getAlertKey, getAlertTypeLabel } from "@/lib/alerts";
import type { IncidentHistoryItem } from "@/types/integrations";

function EmptyGrid({ message }: { message: string }) {
  return (
    <p className="rounded-xl border border-dashed border-border px-6 py-10 text-center text-sm text-muted-foreground">
      {message}
    </p>
  );
}

const AlertCard = React.memo(function AlertCard({
  alert,
  actions,
}: {
  alert: SystemAlert;
  actions: AlertActions;
}) {
  const escalations = actions.escalationCount(alert);
  return (
    <article className="flex min-w-0 flex-col gap-3 rounded-xl border border-border bg-card p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 space-y-0.5">
          <button
            type="button"
            onClick={() => actions.onOpen(alert)}
            className="max-w-full truncate rounded-sm text-left font-medium text-foreground underline-offset-4 hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-hidden"
          >
            {getAlertTarget(alert)}
          </button>
          <p className="text-xs text-muted-foreground">
            {getAlertTypeLabel(alert.alertType)}
          </p>
        </div>
        <SeverityBadge severity={alert.severity} />
      </div>
      <p className="line-clamp-2 text-sm text-muted-foreground">
        {getAlertMessage(alert)}
      </p>
      <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
        {alert.status ? <AlertStatusBadge status={alert.status} /> : null}
        {escalations > 0 ? (
          <Badge variant="info" textOnly>
            {escalations} escalation{escalations === 1 ? "" : "s"}
          </Badge>
        ) : null}
        {alert.unread ? (
          <Badge variant="secondary" textOnly>
            Unread
          </Badge>
        ) : null}
        <span className="ml-auto">
          {formatIncidentDateTime(alert.createdAt)}
        </span>
      </div>
      <AlertRowActions alert={alert} actions={actions} layout="card" />
    </article>
  );
});

export function AlertGrid({
  alerts,
  actions,
}: {
  alerts: SystemAlert[];
  actions: AlertActions;
}) {
  if (alerts.length === 0) return <EmptyGrid message="No incidents found." />;
  return (
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
      {alerts.map((alert) => (
        <AlertCard key={getAlertKey(alert)} alert={alert} actions={actions} />
      ))}
    </div>
  );
}

const EscalationCard = React.memo(function EscalationCard({
  incident,
  actor,
}: {
  incident: IncidentHistoryItem;
  actor: string;
}) {
  return (
    <article className="flex min-w-0 flex-col gap-3 rounded-xl border border-border bg-card p-4">
      <div className="flex items-start justify-between gap-3">
        <p className="min-w-0 flex-1 font-medium text-foreground">
          {incident.summary || "No summary"}
        </p>
        <Badge variant="secondary" textOnly>
          {getProviderLabel(incident.provider)}
        </Badge>
      </div>
      <dl className="grid grid-cols-2 gap-3 text-sm">
        <div className="min-w-0">
          <dt className="text-xs text-muted-foreground">Reference</dt>
          <dd className="mt-1 truncate font-mono text-[13px] text-foreground">
            {getEscalationReference(incident)}
          </dd>
        </div>
        <div className="min-w-0">
          <dt className="text-xs text-muted-foreground">Raised by</dt>
          <dd className="mt-1 truncate text-foreground">{actor}</dd>
        </div>
        <div className="col-span-2 min-w-0">
          <dt className="text-xs text-muted-foreground">Raised</dt>
          <dd className="mt-1 text-foreground">
            {formatIncidentDateTime(incident.createdAt)}
          </dd>
        </div>
      </dl>
      {incident.externalUrl ? (
        <Button variant="outline" size="sm" asChild>
          <a href={incident.externalUrl} rel="noreferrer" target="_blank">
            <ArrowSquareOutIcon aria-hidden />
            Open in {getProviderLabel(incident.provider)}
          </a>
        </Button>
      ) : null}
    </article>
  );
});

export function EscalationGrid({
  incidents,
  actorFor,
}: {
  incidents: IncidentHistoryItem[];
  actorFor: (incident: IncidentHistoryItem) => string;
}) {
  if (incidents.length === 0) {
    return <EmptyGrid message="No escalations found." />;
  }
  return (
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
      {incidents.map((incident) => (
        <EscalationCard
          key={incident.id}
          incident={incident}
          actor={actorFor(incident)}
        />
      ))}
    </div>
  );
}
