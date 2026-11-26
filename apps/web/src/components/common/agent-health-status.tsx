// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import Link from "next/link";
import React from "react";
import {
  RobotIcon,
  CircleNotchIcon,
  PencilSimpleIcon,
} from "@phosphor-icons/react";
import type { Icon as PhosphorIcon } from "@phosphor-icons/react";

import type { AgentHealth, AgentOverallStatus } from "@/hooks/agent";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";

type AgentHealthTone = "healthy" | "unhealthy" | "unknown";

interface AgentHealthViewModel {
  badgeLabel: string;
  detail: string;
  icon: PhosphorIcon;
  status: AgentHealthTone;
  badgeClassName: string;
  containerClassName: string;
}

const UNKNOWN_DETAIL = "No agent heartbeat has been received yet.";
const UNHEALTHY_DETAIL =
  "The agent is not responding or reported an unhealthy state.";

const toAgentHealthTone = (status?: AgentOverallStatus): AgentHealthTone => {
  if (status === "HEALTHY") {
    return "healthy";
  }
  if (status === "UNHEALTHY") {
    return "unhealthy";
  }
  return "unknown";
};

export const getAgentHealthViewModel = (
  agentHealth?: AgentHealth | null,
): AgentHealthViewModel => {
  if (!agentHealth) {
    return {
      badgeLabel: "Checking",
      detail: "Checking agent status...",
      icon: CircleNotchIcon,
      status: "unknown",
      badgeClassName: "status-warning",
      containerClassName: "border-border surface-muted text-foreground",
    };
  }

  const status = toAgentHealthTone(agentHealth.overallStatus);

  if (status === "healthy") {
    return {
      badgeLabel: "Healthy",
      detail: "The agent is connected and reporting health data.",
      icon: RobotIcon,
      status,
      badgeClassName: "status-success",
      containerClassName:
        "border-success-border bg-success-soft text-foreground",
    };
  }

  if (status === "unhealthy") {
    return {
      badgeLabel: "Action needed",
      detail: agentHealth.failureReason ?? UNHEALTHY_DETAIL,
      icon: RobotIcon,
      status,
      badgeClassName: "status-danger",
      containerClassName: "border-danger-border bg-danger-soft text-foreground",
    };
  }

  return {
    badgeLabel: "Unknown",
    detail: agentHealth.failureReason ?? UNKNOWN_DETAIL,
    icon: RobotIcon,
    status,
    badgeClassName: "status-warning",
    containerClassName: "border-warning-border bg-warning-soft text-foreground",
  };
};

const formatHeartbeatCadence = (minutes?: number): string => {
  if (!minutes || !Number.isFinite(minutes)) {
    return "Not configured";
  }

  return minutes === 1 ? "Every minute" : `Every ${minutes} minutes`;
};

export function AgentHealthNavbarIndicator({
  agentHealth,
}: {
  agentHealth?: AgentHealth | null;
}) {
  const model = getAgentHealthViewModel(agentHealth);

  if (!agentHealth || model.status === "healthy") {
    return null;
  }

  const Icon = model.icon;

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Link
          href="/dashboard"
          className={cn(
            "inline-flex h-9 items-center gap-2 rounded-full px-3 text-xs font-semibold transition-colors",
            model.containerClassName,
          )}
        >
          <span className="flex size-5 items-center justify-center rounded-full bg-background/70">
            <Icon
              className={cn(
                "size-3.5",
                !agentHealth && "animate-spin",
                model.status === "unknown" && "animate-pulse",
              )}
            />
          </span>
        </Link>
      </TooltipTrigger>
      <TooltipContent side="bottom" className="max-w-64 text-center text-xs">
        {model.detail}
      </TooltipContent>
    </Tooltip>
  );
}

export function AgentHealthSummaryCard({
  agentHealth,
  cadenceMinutes,
  editingCadence,
  cadenceInput,
  isSavingCadence,
  onCadenceInputChange,
  onEditCadence,
  onCancelCadence,
  onSaveCadence,
}: {
  agentHealth?: AgentHealth | null;
  cadenceMinutes?: number;
  editingCadence: boolean;
  cadenceInput: string;
  isSavingCadence: boolean;
  onCadenceInputChange: (value: string) => void;
  onEditCadence: () => void;
  onCancelCadence: () => void;
  onSaveCadence: () => void;
}) {
  const model = getAgentHealthViewModel(agentHealth);
  const Icon = model.icon;

  return (
    <div
      className={cn(
        "rounded-xl border px-4 py-4 transition-colors",
        model.containerClassName,
      )}
    >
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-start gap-3">
          <div className="mt-0.5 flex size-10 shrink-0 items-center justify-center rounded-[10px] bg-background/70">
            <Icon
              className={cn(
                "size-5",
                !agentHealth && "animate-spin",
                model.status === "unknown" && agentHealth && "animate-pulse",
              )}
            />
          </div>
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <p className="text-sm font-semibold">Agent heartbeat</p>
              <Badge variant="outline" className={model.badgeClassName}>
                {model.badgeLabel}
              </Badge>
            </div>
            <p className="text-[12px] leading-5 text-current/80">
              {model.detail}
            </p>
          </div>
        </div>
      </div>

      <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-current/10 pt-3">
        {editingCadence ? (
          <div className="flex w-full flex-wrap items-center justify-between gap-2">
            <Input
              type="number"
              min={1}
              max={60}
              aria-label="Check cadence in minutes"
              value={cadenceInput}
              onChange={(event) => onCadenceInputChange(event.target.value)}
              className="h-8 w-24 bg-background/80 text-sm"
            />
            <span className="text-[12px] text-current/75">minutes (1-60)</span>
            <div className="flex justify-end gap-2">
              <Button
                size="sm"
                className="h-8 px-3 text-xs"
                disabled={isSavingCadence}
                onClick={onSaveCadence}
              >
                Save
              </Button>
              <Button
                size="sm"
                variant="outline"
                className="h-8 px-3 text-xs"
                disabled={isSavingCadence}
                onClick={onCancelCadence}
              >
                Cancel
              </Button>
            </div>
          </div>
        ) : (
          <>
            <div className="space-y-0.5">
              <p className="text-xs font-medium text-current/70">
                Heartbeat cadence
              </p>
              <p className="text-sm font-medium">
                {formatHeartbeatCadence(cadenceMinutes)}
              </p>
            </div>
            <Button
              type="button"
              size="sm"
              variant="outline"
              className="gap-2 bg-background/70"
              onClick={onEditCadence}
            >
              <PencilSimpleIcon className="size-3.5" />
              Adjust cadence
            </Button>
          </>
        )}
      </div>
    </div>
  );
}
