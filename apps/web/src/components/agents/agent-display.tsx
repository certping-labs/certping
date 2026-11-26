// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { formatDistanceToNow } from "date-fns";

import { Badge, type BadgeProps } from "@/components/ui/badge";
import {
  AGENT_STATUS_LABELS,
  agentStatusKey,
  type Agent,
  type AgentStatusKey,
} from "@/lib/backend/agents";
import { isAgentTokenExpired } from "@/lib/backend/agent-tokens";
import { formatDate } from "@/lib/utils";

const STATUS_VARIANTS: Record<AgentStatusKey, BadgeProps["variant"]> = {
  ONLINE: "success",
  OFFLINE: "warning",
  NEVER_SEEN: "secondary",
  REVOKED: "destructive",
};

export function AgentStatusPill({
  agent,
}: {
  agent: Pick<Agent, "revoked" | "status">;
}) {
  const key = agentStatusKey(agent);
  return (
    <Badge variant={STATUS_VARIANTS[key]} data-status={key}>
      {AGENT_STATUS_LABELS[key]}
    </Badge>
  );
}

/** "3 minutes ago", or "Never" when the agent has not connected. */
export function formatLastSeen(value: string | null | undefined): string {
  if (!value) return "Never";
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return "Never";
  return formatDistanceToNow(date, { addSuffix: true });
}

export function formatTokenExpiry(
  agent: Pick<Agent, "tokenExpiresAt">,
): string {
  if (!agent.tokenExpiresAt) return "Never";
  const date = formatDate(agent.tokenExpiresAt);
  return isAgentTokenExpired({ expiresAt: agent.tokenExpiresAt })
    ? `Expired ${date}`
    : date;
}

export function BundledTag() {
  return (
    <Badge variant="outline" title="Runs next to the server on this install">
      Bundled
    </Badge>
  );
}
