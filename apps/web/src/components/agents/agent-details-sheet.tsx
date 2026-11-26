// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useEffect, useState } from "react";
import { CircleNotchIcon } from "@phosphor-icons/react";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import {
  AgentStatusPill,
  BundledTag,
  formatLastSeen,
  formatTokenExpiry,
} from "@/components/agents/agent-display";
import { BetaBadge } from "@/components/common/beta-badge";
import { RevokeAgentTokenDialog } from "@/components/settings/organizations/agent-tokens-card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { useRevokeAgentToken } from "@/hooks/agent-tokens";
import {
  AGENTS_QUERY_KEY,
  useAgent,
  useDeepHealthCheck,
  useStartAgentHealthCheck,
} from "@/hooks/agents";
import {
  AGENT_DOCS,
  AGENT_SETTING_ENV,
  acmeEnvironmentLabel,
  secretStoreLabel,
  type Agent,
} from "@/lib/backend/agents";
import { formatProviderLabel } from "@/lib/credential-providers";
import {
  BETA_INTEGRATION_DESCRIPTION,
  isBetaIntegration,
  type IntegrationKind,
} from "@/lib/integration-maturity";

const NOT_REPORTED = "Not reported";
const HEALTH_CHECK_TIMEOUT_MS = 60_000;

function SettingRow({
  label,
  value,
  env,
}: {
  label: string;
  value: React.ReactNode;
  env?: string;
}) {
  return (
    <div className="grid grid-cols-1 gap-1 py-2 sm:grid-cols-[10rem_1fr] sm:gap-3">
      <dt className="text-sm text-muted-foreground">{label}</dt>
      <dd className="min-w-0 space-y-1 text-sm">
        <div className="wrap-break-word">{value}</div>
        {env ? (
          <p className="text-xs text-muted-foreground">
            <code className="rounded bg-muted px-1 py-0.5 font-mono">
              {env}
            </code>{" "}
            <a
              href={AGENT_DOCS.configuration}
              target="_blank"
              rel="noreferrer"
              className="underline-offset-2 hover:underline"
            >
              Set on the agent
            </a>
          </p>
        ) : null}
      </dd>
    </div>
  );
}

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="space-y-1">
      <h3 className="text-sm font-semibold text-foreground">{title}</h3>
      <dl className="divide-y divide-border">{children}</dl>
    </section>
  );
}

const yesNo = (value: boolean | null, yes: string, no: string) =>
  value === null || value === undefined ? NOT_REPORTED : value ? yes : no;

function ProviderTags({
  kind,
  values,
}: {
  kind: IntegrationKind;
  values: string[] | undefined;
}) {
  if (!values || values.length === 0) {
    return <span className="text-muted-foreground">None</span>;
  }
  return (
    <ul className="flex flex-wrap gap-1.5">
      {values.map((value) => {
        const beta = isBetaIntegration(kind, value);
        const label = formatProviderLabel(value);
        return (
          <li key={value}>
            <Badge
              variant="outline"
              className="gap-1"
              title={beta ? BETA_INTEGRATION_DESCRIPTION : undefined}
            >
              {label}
              {beta ? <BetaBadge /> : null}
            </Badge>
          </li>
        );
      })}
    </ul>
  );
}

const DEEP_CHECK_OUTCOME: Record<string, { label: string; className: string }> =
  {
    SUCCESS: { label: "Passed", className: "status-success-text" },
    PARTIAL: { label: "Problems found", className: "status-warning-text" },
    FAILED: { label: "Failed", className: "status-danger-text" },
    TIMED_OUT: { label: "Timed out", className: "status-danger-text" },
  };

const SHOWN_PROBLEMS = 5;

function HealthCheckResult({ deepCheckId }: { deepCheckId: string }) {
  const [timedOut, setTimedOut] = useState(false);
  const { check, metrics, done } = useDeepHealthCheck(deepCheckId, !timedOut);

  useEffect(() => {
    const timer = setTimeout(() => setTimedOut(true), HEALTH_CHECK_TIMEOUT_MS);
    return () => clearTimeout(timer);
  }, []);

  if (done && check.data) {
    const outcome = DEEP_CHECK_OUTCOME[check.data.status];
    const results = metrics.data ?? [];
    const problems = results.filter((m) => m.status !== "PASS");
    return (
      <div
        role="status"
        className="space-y-2 rounded border border-border p-3 text-sm"
      >
        <div className="flex items-center gap-2">
          <Badge variant="outline" textOnly className={outcome.className}>
            {outcome.label}
          </Badge>
          {results.length > 0 ? (
            <span>
              {results.length - problems.length} of {results.length} checks
              passed.
            </span>
          ) : check.data.errorMessage ? (
            <span>{check.data.errorMessage}</span>
          ) : null}
        </div>
        {problems.length > 0 ? (
          <ul className="list-disc space-y-1 pl-5 text-muted-foreground">
            {problems.slice(0, SHOWN_PROBLEMS).map((m) => (
              <li key={m.metricKey} className="break-all">
                {m.metricName ?? m.metricKey}
                {m.path ? `: ${m.path}` : ""}
              </li>
            ))}
            {problems.length > SHOWN_PROBLEMS ? (
              <li>{problems.length - SHOWN_PROBLEMS} more</li>
            ) : null}
          </ul>
        ) : null}
      </div>
    );
  }
  if (timedOut) {
    return (
      <p role="status" className="text-sm text-muted-foreground">
        No result yet. The agent may be busy or offline. Try again in a minute.
      </p>
    );
  }
  return (
    <p
      role="status"
      className="flex items-center gap-2 text-sm text-muted-foreground"
    >
      <CircleNotchIcon className="h-4 w-4 animate-spin" />
      Running health check...
    </p>
  );
}

/** The agent's token id, which revoking uses. The agent id is the token id. */
const tokenIdOf = (agent: Agent): number | null => {
  const id = Number(agent.agentId);
  return Number.isInteger(id) && id > 0 ? id : null;
};

export function AgentDetailsSheet({
  agent: listedAgent,
  open,
  onOpenChange,
  canManage,
}: {
  agent: Agent | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  canManage: boolean;
}) {
  const queryClient = useQueryClient();
  const detail = useAgent(listedAgent?.agentId, { enabled: open });
  const agent = detail.data ?? listedAgent;
  const startHealthCheck = useStartAgentHealthCheck();
  const revokeToken = useRevokeAgentToken();
  const [confirmingRevoke, setConfirmingRevoke] = useState(false);
  const [healthCheckId, setHealthCheckId] = useState<string | null>(null);

  useEffect(() => {
    if (!open) {
      setHealthCheckId(null);
      setConfirmingRevoke(false);
    }
  }, [open]);

  if (!agent) return null;

  const tokenId = tokenIdOf(agent);
  const canRevoke = canManage && !agent.revoked && tokenId !== null;

  const runHealthCheck = async () => {
    try {
      const response = await startHealthCheck.mutateAsync(agent.agentId);
      if (!response?.deepCheckId) {
        toast.error("Could not start the health check");
        return;
      }
      setHealthCheckId(response.deepCheckId);
    } catch {
      toast.error("Could not start the health check");
    }
  };

  const revoke = async () => {
    setConfirmingRevoke(false);
    if (tokenId === null) return;
    try {
      await revokeToken.mutateAsync(tokenId);
      await queryClient.invalidateQueries({ queryKey: AGENTS_QUERY_KEY });
      toast.success("Agent token revoked");
    } catch {
      toast.error("Could not revoke the agent token");
    }
  };

  const acme = agent.acme;

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="w-full overflow-y-auto sm:max-w-xl">
        <SheetHeader className="space-y-2 pr-8 text-left">
          <SheetTitle className="flex flex-wrap items-center gap-2">
            {agent.name}
            {agent.bundled ? <BundledTag /> : null}
            <AgentStatusPill agent={agent} />
          </SheetTitle>
          <SheetDescription>
            Token <span className="font-mono">{agent.tokenPrefix}...</span>
            {" · "}expires {formatTokenExpiry(agent).toLowerCase()}
          </SheetDescription>
        </SheetHeader>

        <div className="mt-4 flex flex-wrap gap-2">
          <Button
            type="button"
            size="sm"
            onClick={runHealthCheck}
            disabled={agent.revoked || startHealthCheck.isPending}
          >
            {startHealthCheck.isPending ? (
              <CircleNotchIcon className="h-4 w-4 animate-spin" />
            ) : null}
            Run health check
          </Button>
          {canRevoke ? (
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() => setConfirmingRevoke(true)}
              disabled={revokeToken.isPending}
            >
              Revoke token
            </Button>
          ) : null}
          <RevokeAgentTokenDialog
            tokenName={confirmingRevoke ? agent.name : null}
            onCancel={() => setConfirmingRevoke(false)}
            onConfirm={revoke}
          />
        </div>

        <p className="mt-2 text-xs text-muted-foreground">
          Health checks go to the organization&apos;s queue, so any of its
          agents may answer.
        </p>

        {healthCheckId !== null ? (
          <div className="mt-3">
            <HealthCheckResult
              key={healthCheckId}
              deepCheckId={healthCheckId}
            />
          </div>
        ) : null}

        <div className="mt-6 space-y-6">
          <Section title="Connection">
            <SettingRow
              label="Status"
              value={<AgentStatusPill agent={agent} />}
            />
            <SettingRow
              label="Last seen"
              value={formatLastSeen(agent.lastSeenAt)}
            />
            <SettingRow label="Host" value={agent.hostname ?? NOT_REPORTED} />
            <SettingRow label="OS" value={agent.os ?? NOT_REPORTED} />
            <SettingRow
              label="Java"
              value={agent.javaVersion ?? NOT_REPORTED}
            />
            <SettingRow label="Version" value={agent.version ?? NOT_REPORTED} />
            <SettingRow
              label="Proxy"
              value={yesNo(agent.proxyConfigured, "Set", "Not set")}
              env={AGENT_SETTING_ENV.proxy}
            />
          </Section>

          <Section title="Settings">
            <SettingRow
              label="Secret store"
              value={secretStoreLabel(agent.secretStore)}
              env={AGENT_SETTING_ENV.secretStore}
            />
            <SettingRow
              label="Jobs at once"
              value={agent.maxConcurrentJobs ?? NOT_REPORTED}
              env={AGENT_SETTING_ENV.maxConcurrentJobs}
            />
            <SettingRow
              label="ACME CA"
              value={
                acme ? (
                  <span className="flex flex-wrap items-center gap-2">
                    <Badge variant="secondary">
                      {acmeEnvironmentLabel(acme.environment)}
                    </Badge>
                    <span className="font-mono text-xs break-all">
                      {acme.directoryUrl}
                    </span>
                  </span>
                ) : (
                  NOT_REPORTED
                )
              }
              env={AGENT_SETTING_ENV.acmeDirectoryUrl}
            />
            <SettingRow
              label="Account email"
              value={acme ? acme.contactEmail || "Not set" : NOT_REPORTED}
              env={AGENT_SETTING_ENV.acmeAccountEmail}
            />
            <SettingRow
              label="GlobalSign"
              value={yesNo(agent.globalsignConfigured, "Set up", "Not set up")}
              env={AGENT_SETTING_ENV.globalsign}
            />
          </Section>

          <Section title="Can do">
            <SettingRow
              label="Deployment targets"
              value={
                <ProviderTags
                  kind="DEPLOYMENT"
                  values={agent.capabilities?.deploymentTargets}
                />
              }
            />
            <SettingRow
              label="Discovery targets"
              value={
                <ProviderTags
                  kind="DISCOVERY"
                  values={agent.capabilities?.discoveryTargets}
                />
              }
            />
            <SettingRow
              label="DNS providers"
              value={
                <ProviderTags
                  kind="DNS"
                  values={agent.capabilities?.dnsProviders}
                />
              }
            />
          </Section>

          <p className="text-xs text-muted-foreground">
            Settings are read from the agent. To change one, set its environment
            variable on the agent and restart it. See{" "}
            <a
              href={AGENT_DOCS.configuration}
              target="_blank"
              rel="noreferrer"
              className="text-brand underline-offset-2 hover:underline"
            >
              Configuration
            </a>{" "}
            and{" "}
            <a
              href={AGENT_DOCS.agents}
              target="_blank"
              rel="noreferrer"
              className="text-brand underline-offset-2 hover:underline"
            >
              Agents
            </a>
            .
          </p>
        </div>
      </SheetContent>
    </Sheet>
  );
}
