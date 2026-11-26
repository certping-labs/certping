// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import Link from "next/link";
import React, { useState } from "react";

import { AgentHealthSummaryCard } from "@/components/common/agent-health-status";
import { useAuth } from "@/hooks/use-auth";
import { canManageAgents } from "@/lib/authz";
import { Card } from "@/components/ui/card";
import { DetailSection } from "@/components/ui/detail-list";
import {
  useAgentHealth,
  useAgentHealthCadence,
  useUpdateAgentHealthCadence,
} from "@/hooks/agent";

const MIN_CADENCE = 1;
const MAX_CADENCE = 60;
const DEFAULT_CADENCE = 5;

export function AgentsCard() {
  const { user, isSuperAdmin } = useAuth();
  const agentHealth = useAgentHealth({ enabled: true });
  const cadence = useAgentHealthCadence({ enabled: true });
  const updateCadence = useUpdateAgentHealthCadence();
  const [isEditing, setIsEditing] = useState(false);
  const [draft, setDraft] = useState("");

  return (
    <Card>
      <DetailSection
        title="Agents"
        description="Whether your agents are connected and how often they check in"
        action={
          canManageAgents(user, isSuperAdmin) ? (
            <Link
              href="/agents"
              className="text-sm font-medium text-brand hover:underline"
            >
              View agents
            </Link>
          ) : null
        }
      >
        <AgentHealthSummaryCard
          agentHealth={agentHealth.data}
          cadenceMinutes={cadence.data?.heartbeatCadenceMinutes}
          editingCadence={isEditing}
          cadenceInput={draft}
          isSavingCadence={updateCadence.isPending}
          onCadenceInputChange={setDraft}
          onEditCadence={() => {
            setDraft(
              String(cadence.data?.heartbeatCadenceMinutes ?? DEFAULT_CADENCE),
            );
            setIsEditing(true);
          }}
          onCancelCadence={() => setIsEditing(false)}
          onSaveCadence={async () => {
            const value = Number.parseInt(draft, 10);
            if (
              !Number.isFinite(value) ||
              value < MIN_CADENCE ||
              value > MAX_CADENCE
            ) {
              return;
            }
            await updateCadence.mutateAsync(value);
            setIsEditing(false);
          }}
        />
      </DetailSection>
    </Card>
  );
}
