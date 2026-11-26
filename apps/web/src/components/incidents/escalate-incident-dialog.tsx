// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useEffect, useMemo, useState } from "react";
import { WarningIcon } from "@phosphor-icons/react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import {
  useCreatePagerDutyIncident,
  useCreateServiceNowIncident,
} from "@/hooks/incidents";
import { useListIntegrations } from "@/hooks/integrations";
import type {
  CreatePagerDutyIncidentPayload,
  CreateServiceNowIncidentPayload,
  PagerDutySeverity,
  ServiceNowPriority,
} from "@/types/integrations";

export interface IncidentEscalationDraft {
  alertId: number;
  title: string;
  description: string;
  severity: PagerDutySeverity;
  source: string;
  dedupKey?: string;
}

const INITIAL_DRAFT: IncidentEscalationDraft = {
  alertId: 0,
  title: "",
  description: "",
  severity: "ERROR",
  source: "certping/frontend",
};

const toServiceNowPriority = (
  severity: PagerDutySeverity,
): ServiceNowPriority => {
  if (severity === "CRITICAL" || severity === "ERROR") {
    return "HIGH";
  }
  if (severity === "WARNING") {
    return "MEDIUM";
  }
  return "LOW";
};

export function EscalateIncidentDialog({
  open,
  onOpenChange,
  initialDraft,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  initialDraft: IncidentEscalationDraft;
}) {
  const [draft, setDraft] = useState<IncidentEscalationDraft>(INITIAL_DRAFT);
  const [sendPagerDuty, setSendPagerDuty] = useState(true);
  const [sendServiceNow, setSendServiceNow] = useState(false);

  const integrationsQuery = useListIntegrations({ enabled: open });
  const createPagerDuty = useCreatePagerDutyIncident();
  const createServiceNow = useCreateServiceNowIncident();

  const activeProviders = useMemo(() => {
    const providers = new Set<string>();
    for (const integration of integrationsQuery.data ?? []) {
      if (integration.status === "ACTIVE" && !integration.deletedAt) {
        providers.add(integration.provider);
      }
    }
    return providers;
  }, [integrationsQuery.data]);

  const hasPagerDuty = activeProviders.has("PAGERDUTY");
  const hasServiceNow = activeProviders.has("SERVICENOW_ITSM");

  useEffect(() => {
    if (!open) {
      return;
    }

    setDraft({
      ...INITIAL_DRAFT,
      ...initialDraft,
      title: initialDraft.title.trim(),
      description: initialDraft.description.trim(),
      source: initialDraft.source.trim() || INITIAL_DRAFT.source,
    });
    setSendPagerDuty(hasPagerDuty);
    setSendServiceNow(false);
  }, [hasPagerDuty, initialDraft, open]);

  const isSubmitting = createPagerDuty.isPending || createServiceNow.isPending;

  const submit = async () => {
    if (!draft.title.trim()) {
      toast.error("Incident title is required.");
      return;
    }

    if (!Number.isFinite(draft.alertId) || draft.alertId <= 0) {
      toast.error("A valid alert is required for escalation.");
      return;
    }

    if (!sendPagerDuty && !sendServiceNow) {
      toast.error("Select at least one destination.");
      return;
    }

    const pagerDutyPayload: CreatePagerDutyIncidentPayload = {
      alertId: draft.alertId,
      title: draft.title.trim(),
      source: draft.source.trim() || INITIAL_DRAFT.source,
      severity: draft.severity,
      dedupKey: draft.dedupKey?.trim() || undefined,
      customDetails: draft.description.trim()
        ? { description: draft.description.trim() }
        : undefined,
    };

    const serviceNowPayload: CreateServiceNowIncidentPayload = {
      alertId: draft.alertId,
      shortDescription: draft.title.trim(),
      description: draft.description.trim() || undefined,
      impact: toServiceNowPriority(draft.severity),
      urgency: toServiceNowPriority(draft.severity),
    };

    const actions: Promise<unknown>[] = [];

    if (sendPagerDuty) {
      actions.push(createPagerDuty.mutateAsync(pagerDutyPayload));
    }

    if (sendServiceNow) {
      actions.push(createServiceNow.mutateAsync(serviceNowPayload));
    }

    await Promise.all(actions);
    onOpenChange(false);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <WarningIcon className="h-5 w-5 status-warning-text" />
            Escalate Incident
          </DialogTitle>
          <DialogDescription>
            Send this failure to PagerDuty, ServiceNow, or both.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-5">
          <div className="space-y-2">
            <Label required htmlFor="incident-title">
              Incident title
            </Label>
            <Input
              id="incident-title"
              value={draft.title}
              onChange={(event) =>
                setDraft((previous) => ({
                  ...previous,
                  title: event.target.value,
                }))
              }
              placeholder="Describe the incident"
              required
            />
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label required>Severity</Label>
              <Select
                value={draft.severity}
                onValueChange={(value: PagerDutySeverity) =>
                  setDraft((previous) => ({
                    ...previous,
                    severity: value,
                  }))
                }
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select severity" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="CRITICAL">Critical</SelectItem>
                  <SelectItem value="ERROR">Error</SelectItem>
                  <SelectItem value="WARNING">Warning</SelectItem>
                  <SelectItem value="INFO">Info</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label htmlFor="incident-source">Source</Label>
              <Input
                id="incident-source"
                value={draft.source}
                onChange={(event) =>
                  setDraft((previous) => ({
                    ...previous,
                    source: event.target.value,
                  }))
                }
                placeholder="certping/frontend"
              />
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="incident-description">Description</Label>
            <Textarea
              id="incident-description"
              value={draft.description}
              onChange={(event) =>
                setDraft((previous) => ({
                  ...previous,
                  description: event.target.value,
                }))
              }
              placeholder="Add details for responders"
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="incident-dedup-key">Dedup key</Label>
            <Input
              id="incident-dedup-key"
              value={draft.dedupKey ?? ""}
              onChange={(event) =>
                setDraft((previous) => ({
                  ...previous,
                  dedupKey: event.target.value,
                }))
              }
              placeholder="Optional"
            />
          </div>

          <div className="space-y-3 rounded-lg border bg-muted/35 p-3">
            <Label required>Escalate to</Label>
            <div className="flex flex-wrap items-center gap-4">
              <label className="flex items-center gap-2 text-sm">
                <Checkbox
                  checked={sendPagerDuty}
                  disabled={!hasPagerDuty}
                  onCheckedChange={(checked) =>
                    setSendPagerDuty(checked === true)
                  }
                />
                PagerDuty
                {!hasPagerDuty ? (
                  <Badge variant="warning" textOnly>
                    Not connected
                  </Badge>
                ) : null}
              </label>
              <label className="flex items-center gap-2 text-sm">
                <Checkbox
                  checked={sendServiceNow}
                  disabled={!hasServiceNow}
                  onCheckedChange={(checked) =>
                    setSendServiceNow(checked === true)
                  }
                />
                ServiceNow
                {!hasServiceNow ? (
                  <Badge variant="warning" textOnly>
                    Not connected
                  </Badge>
                ) : null}
              </label>
            </div>
          </div>
        </div>

        <DialogFooter>
          <Button
            type="button"
            variant="outline"
            disabled={isSubmitting}
            onClick={() => onOpenChange(false)}
          >
            Cancel
          </Button>
          <Button type="button" isPending={isSubmitting} onClick={submit}>
            Create incident
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
