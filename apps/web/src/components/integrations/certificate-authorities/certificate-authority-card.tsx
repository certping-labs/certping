// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";

import { BetaBadge } from "@/components/common/beta-badge";
import {
  DigiCertKeys,
  type DigiCertKeyPermissions,
} from "@/components/integrations/certificate-authorities/digicert-keys";
import { Badge } from "@/components/ui/badge";
import {
  certificateAuthorityDocsHref,
  type AcmeEnvironment,
  type CertificateAuthority,
  type CertificateAuthorityAgent,
  type CertificateAuthorityStatus,
} from "@/lib/backend/certificate-authorities";
import {
  BETA_INTEGRATION_DESCRIPTION,
  isBetaIntegration,
} from "@/lib/integration-maturity";
import { EXTERNAL_LINK_PROPS } from "@/lib/support-links";
import { formatDate, formatDateTimeCompact } from "@/lib/utils";

const STATUS_PILL: Record<
  CertificateAuthorityStatus,
  { label: string; variant: "success" | "secondary" | "info" }
> = {
  CONFIGURED: { label: "Configured", variant: "success" },
  NOT_CONFIGURED: { label: "Not configured", variant: "secondary" },
  UNKNOWN: { label: "Waiting for an agent report", variant: "info" },
};

const ENVIRONMENT_LABEL: Record<AcmeEnvironment, string> = {
  PRODUCTION: "Production",
  STAGING: "Staging",
  CUSTOM: "Custom ACME CA",
};

/** The server's maturity wins; the local list covers an older server. */
function isBeta(authority: CertificateAuthority): boolean {
  return authority.maturity
    ? authority.maturity === "BETA"
    : isBetaIntegration("CA", authority.id);
}

function statusPill(status: CertificateAuthorityStatus) {
  return STATUS_PILL[status] ?? STATUS_PILL.UNKNOWN;
}

export function CertificateAuthorityCard({
  authority,
  permissions,
}: {
  authority: CertificateAuthority;
  permissions: DigiCertKeyPermissions;
}) {
  const pill = statusPill(authority.status);
  const docsHref = authority.docsPath
    ? certificateAuthorityDocsHref(authority.docsPath)
    : null;

  return (
    <article
      aria-labelledby={`ca-${authority.id}-name`}
      data-testid={`ca-card-${authority.id}`}
      className="space-y-4 rounded-lg border border-border bg-card p-4"
    >
      <header className="space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <h3
            id={`ca-${authority.id}-name`}
            className="text-base font-semibold text-foreground"
          >
            {authority.name}
          </h3>
          {isBeta(authority) ? (
            <>
              <BetaBadge />
              <span className="sr-only">{BETA_INTEGRATION_DESCRIPTION}</span>
            </>
          ) : null}
          <Badge variant={pill.variant} className="ml-auto">
            {pill.label}
          </Badge>
        </div>
        <p className="text-xs text-muted-foreground">
          {authority.configuredWhere === "ORGANIZATION"
            ? "Saved in this organization"
            : "Set on agent"}
        </p>
      </header>

      {authority.kind === "ACME" ? (
        <AcmeBody authority={authority} docsHref={docsHref} />
      ) : authority.configuredWhere === "ORGANIZATION" ? (
        <div className="space-y-3">
          <DigiCertKeys
            credentials={authority.credentials ?? []}
            permissions={permissions}
          />
          {docsHref ? <DocsLink href={docsHref} label="Setup docs" /> : null}
        </div>
      ) : (
        <AgentConfiguredBody authority={authority} docsHref={docsHref} />
      )}
    </article>
  );
}

function DocsLink({ href, label }: { href: string; label: string }) {
  return (
    <a
      href={href}
      {...EXTERNAL_LINK_PROPS}
      className="inline-block text-sm font-medium text-primary underline-offset-4 hover:underline"
    >
      {label}
    </a>
  );
}

function Row({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="grid gap-1 py-2 sm:grid-cols-[9rem_minmax(0,1fr)] sm:gap-3">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="min-w-0 text-sm wrap-break-word text-foreground">
        {children}
      </dd>
    </div>
  );
}

function Muted({ children }: { children: React.ReactNode }) {
  return <span className="text-muted-foreground">{children}</span>;
}

function AgentHeading({ agent }: { agent: CertificateAuthorityAgent }) {
  return (
    <div className="flex flex-wrap items-baseline justify-between gap-2">
      <h4 className="text-sm font-medium text-foreground">{agent.agentName}</h4>
      <span className="text-xs text-muted-foreground">
        {agent.lastSeenAt
          ? `Last report ${formatDateTimeCompact(agent.lastSeenAt)}`
          : "No report yet"}
      </span>
    </div>
  );
}

function NoAgents() {
  return (
    <p className="text-sm text-muted-foreground">
      No agent has reported yet. Start an agent to see its settings here.
    </p>
  );
}

function AcmeBody({
  authority,
  docsHref,
}: {
  authority: CertificateAuthority;
  docsHref: string | null;
}) {
  const agents = authority.agents ?? [];

  return (
    <div className="space-y-3">
      {agents.length === 0 ? <NoAgents /> : null}
      {agents.map((agent) => (
        <section
          key={agent.agentId}
          className="space-y-1 rounded-md border border-border p-3"
        >
          <AgentHeading agent={agent} />
          {agent.acme ? (
            <dl className="divide-y divide-border">
              <Row label="CA address">
                <span className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-xs break-all">
                    {agent.acme.directoryUrl}
                  </span>
                  <Badge variant="secondary">
                    {ENVIRONMENT_LABEL[agent.acme.environment] ??
                      ENVIRONMENT_LABEL.CUSTOM}
                  </Badge>
                </span>
              </Row>
              <Row label="Account email">
                {agent.acme.contactEmail ? (
                  agent.acme.contactEmail
                ) : (
                  <Muted>
                    No email set: set ACME_ACCOUNT_EMAIL on the agent
                  </Muted>
                )}
              </Row>
              <Row label="Account URL">
                {agent.acme.accountUrl ? (
                  <span className="font-mono text-xs break-all">
                    {agent.acme.accountUrl}
                  </span>
                ) : (
                  <Muted>
                    No account yet: created on the first certificate order
                  </Muted>
                )}
              </Row>
              <Row label="Key type">
                {agent.acme.keyType ?? <Muted>Not created yet</Muted>}
              </Row>
              <Row label="Created">
                {agent.acme.createdAt ? (
                  formatDate(agent.acme.createdAt)
                ) : (
                  <Muted>Not created yet</Muted>
                )}
              </Row>
              <Row label="Account key">Key kept by agent {agent.agentName}</Row>
            </dl>
          ) : (
            <p className="text-sm text-muted-foreground">
              This agent has not reported an ACME account.
            </p>
          )}
        </section>
      ))}
      <p className="text-xs text-muted-foreground">
        The account key stays in the agent&apos;s secret store. CertPing never
        shows it.
      </p>
      {docsHref ? <DocsLink href={docsHref} label="How to change" /> : null}
    </div>
  );
}

function AgentConfiguredBody({
  authority,
  docsHref,
}: {
  authority: CertificateAuthority;
  docsHref: string | null;
}) {
  const agents = authority.agents ?? [];

  return (
    <div className="space-y-3">
      {agents.length === 0 ? (
        <NoAgents />
      ) : (
        <ul className="divide-y divide-border rounded-md border border-border">
          {agents.map((agent) => (
            <li
              key={agent.agentId}
              className="flex flex-wrap items-center justify-between gap-2 p-3"
            >
              <span className="min-w-0">
                <span className="block text-sm font-medium text-foreground">
                  {agent.agentName}
                </span>
                {/* An agent's status changes only with its next heartbeat, e.g. after a restart with new settings. */}
                {agent.lastSeenAt ? (
                  <span className="block text-xs text-muted-foreground">
                    As reported {formatDateTimeCompact(agent.lastSeenAt)}
                  </span>
                ) : null}
              </span>
              <Badge variant={agent.configured ? "success" : "secondary"}>
                {agent.configured ? "Configured" : "Not configured"}
              </Badge>
            </li>
          ))}
        </ul>
      )}
      {authority.status !== "CONFIGURED" ? (
        <p className="text-sm text-muted-foreground">
          Set on the agent with environment variables.
        </p>
      ) : null}
      {docsHref ? <DocsLink href={docsHref} label="Setup docs" /> : null}
    </div>
  );
}
