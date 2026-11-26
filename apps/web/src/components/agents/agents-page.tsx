// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useState } from "react";
import { CircleNotchIcon, PlusIcon } from "@phosphor-icons/react";

import { AddAgentSheet } from "@/components/agents/add-agent-sheet";
import { AgentDetailsSheet } from "@/components/agents/agent-details-sheet";
import {
  AgentStatusPill,
  BundledTag,
  formatLastSeen,
  formatTokenExpiry,
} from "@/components/agents/agent-display";
import { Unauthorised } from "@/components/common/unautorised";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { PageHeader } from "@/components/ui/page-header";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useAgents } from "@/hooks/agents";
import { useAuth } from "@/hooks/use-auth";
import { canManageAgents } from "@/lib/authz";
import { secretStoreLabel, type Agent } from "@/lib/backend/agents";

const COLUMNS = [
  "Name",
  "Status",
  "Last seen",
  "Version",
  "Host",
  "Secret store",
  "Token expires",
];

function EmptyState({ onAdd }: { onAdd: () => void }) {
  return (
    <Card className="mx-auto max-w-xl space-y-4 p-6 text-center">
      <h2 className="text-base font-semibold">No agents yet</h2>
      <p className="text-sm text-muted-foreground">
        An agent is a small program you run in your own network. It finds,
        renews and deploys certificates there, and connects to CertPing over
        outbound HTTPS.
      </p>
      <Button type="button" onClick={onAdd} className="gap-2">
        <PlusIcon className="h-4 w-4" />
        Add agent
      </Button>
    </Card>
  );
}

function AgentsTable({
  agents,
  onOpen,
}: {
  agents: Agent[];
  onOpen: (agent: Agent) => void;
}) {
  return (
    <Card className="overflow-x-auto">
      <Table>
        <TableHeader>
          <TableRow>
            {COLUMNS.map((column) => (
              <TableHead key={column}>{column}</TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {agents.map((agent) => (
            <TableRow
              key={agent.agentId}
              data-testid={`agent-row-${agent.agentId}`}
              className="cursor-pointer"
              onClick={() => onOpen(agent)}
            >
              <TableCell>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    className="font-medium text-foreground hover:underline"
                    onClick={(event) => {
                      event.stopPropagation();
                      onOpen(agent);
                    }}
                  >
                    {agent.name}
                  </button>
                  {agent.bundled ? <BundledTag /> : null}
                </div>
              </TableCell>
              <TableCell>
                <AgentStatusPill agent={agent} />
              </TableCell>
              <TableCell className="whitespace-nowrap">
                {formatLastSeen(agent.lastSeenAt)}
              </TableCell>
              <TableCell>{agent.version ?? "-"}</TableCell>
              <TableCell className="max-w-48 truncate">
                {agent.hostname ?? "-"}
              </TableCell>
              <TableCell className="whitespace-nowrap">
                {agent.secretStore ? secretStoreLabel(agent.secretStore) : "-"}
              </TableCell>
              <TableCell className="whitespace-nowrap">
                {formatTokenExpiry(agent)}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Card>
  );
}

export function AgentsPage() {
  const { user, isSuperAdmin, isLoading: isLoadingAuth } = useAuth();
  const canView = canManageAgents(user, isSuperAdmin);
  const agentsQuery = useAgents({ enabled: canView });
  const [selectedId, setSelectedId] = useState<Agent["agentId"] | null>(null);
  const [adding, setAdding] = useState(false);

  if (isLoadingAuth) {
    return (
      <div className="flex h-[60vh] items-center justify-center">
        <CircleNotchIcon className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!canView) {
    return (
      <div className="p-6">
        <Unauthorised description="You do not have permission to manage agents." />
      </div>
    );
  }

  const agents = agentsQuery.data ?? [];
  const selected =
    selectedId === null
      ? null
      : (agents.find((agent) => agent.agentId === selectedId) ?? null);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Agents"
        subtitle="Agents run in your network and do the certificate work there."
        actions={
          agents.length > 0 ? (
            <Button
              type="button"
              onClick={() => setAdding(true)}
              className="gap-2"
            >
              <PlusIcon className="h-4 w-4" />
              Add agent
            </Button>
          ) : undefined
        }
      />

      {agentsQuery.isLoading ? (
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <CircleNotchIcon className="h-4 w-4 animate-spin" />
          Loading agents...
        </div>
      ) : agentsQuery.error ? (
        <p className="text-sm text-destructive">Could not load agents.</p>
      ) : agents.length === 0 ? (
        <EmptyState onAdd={() => setAdding(true)} />
      ) : (
        <AgentsTable
          agents={agents}
          onOpen={(agent) => setSelectedId(agent.agentId)}
        />
      )}

      <AgentDetailsSheet
        agent={selected}
        open={selected !== null}
        onOpenChange={(open) => {
          if (!open) setSelectedId(null);
        }}
        canManage={canView}
      />
      <AddAgentSheet open={adding} onOpenChange={setAdding} />
    </div>
  );
}
