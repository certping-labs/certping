// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import * as React from "react";
import {
  WarningIcon,
  CaretDownIcon,
  FileCodeIcon,
  StackIcon,
  TreeStructureIcon,
  PathIcon,
  HardDrivesIcon,
} from "@phosphor-icons/react";

import {
  compactValue,
  formatUsageType,
  getKubernetesImpactValues,
  getKubernetesWarnings,
  getUsageServices,
  getUsageWorkloads,
} from "@/components/cert-manager/discovery/discovered-cert-detail-helpers";
import {
  DetailRows,
  DetailSection,
  EmptyDetailText,
  ValueList,
} from "@/components/cert-manager/discovery/discovered-cert-detail-primitives";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type {
  KubernetesDiscoveryData,
  KubernetesUsage,
} from "@/types/discovery";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";

function KubernetesWarningPanel({ data }: { data: KubernetesDiscoveryData }) {
  const warnings = getKubernetesWarnings(data);

  if (warnings.length === 0) return null;

  return (
    <Alert className="border-warning-100 bg-warning-50/70">
      <WarningIcon className="h-4 w-4 text-warning" />
      <AlertDescription>
        <div className="font-medium text-foreground">
          Kubernetes scan context is incomplete
        </div>
        <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-muted-foreground">
          {warnings.map((warning) => (
            <li key={warning}>{warning}</li>
          ))}
        </ul>
      </AlertDescription>
    </Alert>
  );
}

function UsageFieldDetails({ usage }: { usage: KubernetesUsage }) {
  return (
    <DetailRows
      items={[
        {
          label: "Reference",
          value: compactValue(usage.fieldPath),
          mono: true,
        },
        {
          label: "API version",
          value: compactValue(usage.apiVersion),
          mono: true,
        },
        { label: "UID", value: compactValue(usage.uid), mono: true },
      ]}
    />
  );
}

function UsageCount({ label, count }: { label: string; count: number }) {
  return (
    <div className="flex items-center gap-1.5 rounded-full border border-border bg-primary-50 px-2.5 py-1 text-xs">
      <span className="font-medium text-foreground">{count}</span>
      <span className="text-muted-foreground">{label}</span>
    </div>
  );
}

function UsageDependencyColumn({
  title,
  icon: Icon,
  values,
  emptyLabel,
}: {
  title: string;
  icon: React.ComponentType<{ className?: string }>;
  values: readonly string[];
  emptyLabel: string;
}) {
  return (
    <div className="min-w-0 rounded-lg border border-border bg-card p-4">
      <div className="mb-3 flex items-center justify-between gap-3">
        <div className="flex min-w-0 items-center gap-2">
          <Icon className="size-4 shrink-0 text-primary" aria-hidden="true" />
          <h4 className="truncate text-sm font-semibold text-foreground">
            {title}
          </h4>
        </div>
        <Badge variant="outline" className="shrink-0 font-mono">
          {values.length}
        </Badge>
      </div>
      <ValueList values={values} emptyLabel={emptyLabel} />
    </div>
  );
}

export function KubernetesUsageRow({
  usage,
  index,
}: {
  usage: KubernetesUsage;
  index: number;
}) {
  const [isOpen, setIsOpen] = React.useState(false);

  const resourceName =
    usage.namespace && usage.name
      ? `${usage.namespace}/${usage.name}`
      : compactValue(usage.name);

  const services = getUsageServices(usage);
  const workloads = getUsageWorkloads(usage);

  const hasWorkloadNotes = usage.affectedWorkloads?.some(
    (w) => w.containers.length > 0 || Boolean(w.referencePath),
  );

  return (
    <Collapsible open={isOpen} onOpenChange={setIsOpen}>
      <div
        className={cn(
          "overflow-hidden rounded-lg border bg-background transition-colors",
          isOpen ? "border-border" : "border-border/70 hover:border-border",
        )}
      >
        <CollapsibleTrigger className="w-full text-left">
          <div
            className={cn(
              "flex w-full flex-col gap-4 p-4 transition-colors lg:flex-row lg:items-center lg:justify-between",
              isOpen ? "bg-muted/30" : "hover:bg-muted/20",
            )}
          >
            <div className="flex min-w-0 items-start gap-3">
              <div className="flex min-w-0 flex-col gap-2">
                <div className="flex flex-wrap items-center gap-2">
                  <p className="truncate text-sm font-semibold text-foreground">
                    {usage.kind ?? `Usage path ${index + 1}`}
                  </p>
                  <Badge variant="info" className="capitalize">
                    {formatUsageType(usage.usageType)}
                  </Badge>
                </div>
                {usage.confidence ? (
                  <span className="flex items-center justify-start gap-2 text-sm">
                    Confidence
                    <Badge variant="info" className="">
                      {usage.confidence}
                    </Badge>
                  </span>
                ) : null}
                <p
                  className="mt-1 truncate font-mono text-sm text-muted-foreground"
                  title={resourceName}
                >
                  {resourceName}
                </p>
              </div>
            </div>

            <div className="flex shrink-0 flex-wrap items-center gap-2 lg:justify-end">
              <UsageCount label="hostnames" count={usage.hostnames.length} />
              <UsageCount label="services" count={services.length} />
              <UsageCount label="workloads" count={workloads.length} />
              <CaretDownIcon
                className={cn(
                  "ml-1 size-5 shrink-0 text-muted-foreground transition-transform duration-200",
                  isOpen && "rotate-180",
                )}
                aria-hidden="true"
              />
            </div>
          </div>
        </CollapsibleTrigger>

        <CollapsibleContent>
          <div className="space-y-4 border-t border-border bg-background p-4">
            <div className="grid gap-3 xl:grid-cols-3">
              <UsageDependencyColumn
                title="Hostnames"
                icon={PathIcon}
                values={usage.hostnames}
                emptyLabel="No hostnames reported."
              />
              <UsageDependencyColumn
                title="Services"
                icon={TreeStructureIcon}
                values={services}
                emptyLabel="No backend services reported."
              />
              <UsageDependencyColumn
                title="Workloads"
                icon={StackIcon}
                values={workloads}
                emptyLabel="No affected workloads reported."
              />
            </div>

            <div className="rounded-lg border border-border bg-card p-4">
              <h4 className="mb-3 flex items-center gap-2 text-sm font-semibold text-foreground">
                <FileCodeIcon className="size-4 text-primary" />
                Reference fields
              </h4>
              <UsageFieldDetails usage={usage} />
            </div>

            {hasWorkloadNotes && (
              <div className="rounded-lg border border-border bg-card p-4">
                <h4 className="mb-3 flex items-center gap-2 text-sm font-semibold text-foreground">
                  <StackIcon className="size-4 text-primary" />
                  Workload notes
                </h4>
                <div className="grid gap-3 lg:grid-cols-2 xl:grid-cols-3">
                  {usage.affectedWorkloads.map((workload) => (
                    <div
                      key={`${workload.namespace}-${workload.name}`}
                      className="rounded-md border border-border bg-muted/40 p-3"
                    >
                      <p className="truncate font-mono text-xs font-medium text-foreground">
                        {workload.namespace}/{workload.name}
                      </p>

                      {workload.containers?.length > 0 && (
                        <p className="mt-2 text-xs text-muted-foreground">
                          <span className="font-medium text-foreground">
                            Containers:
                          </span>{" "}
                          {workload.containers.join(", ")}
                        </p>
                      )}

                      {workload.referencePath && (
                        <p className="mt-1 text-xs text-muted-foreground">
                          <span className="font-medium text-foreground">
                            Via:
                          </span>{" "}
                          {workload.referencePath}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </CollapsibleContent>
      </div>
    </Collapsible>
  );
}

export function KubernetesUsageTable({
  data,
}: {
  data: KubernetesDiscoveryData;
}) {
  const emptyUsageLabel = data.usageComplete
    ? "Unused in scanned scope."
    : "Usage discovery is incomplete; do not treat this certificate as unused.";

  if (!data.usages || data.usages.length === 0) {
    return (
      <div className="flex items-center justify-center rounded-xl border border-dashed bg-muted/10 p-8">
        <EmptyDetailText>{emptyUsageLabel}</EmptyDetailText>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      {data.usages.map((usage, index) => (
        <KubernetesUsageRow
          key={usage.uid ?? `${usage.namespace}-${usage.name}-${index}`}
          usage={usage}
          index={index}
        />
      ))}
    </div>
  );
}

export function KubernetesImpactSummary({
  data,
}: {
  data: KubernetesDiscoveryData;
}) {
  const impactValues = getKubernetesImpactValues(data);
  const impact = data.impact;

  const categories = [
    {
      id: "hostnames",
      label: "Hostnames",
      items: impactValues.affectedHostnames,
      emptyLabel: "No affected hostnames reported.",
    },
    {
      id: "services",
      label: "Services",
      items: impactValues.affectedServices,
      emptyLabel: "No affected services reported.",
    },
    {
      id: "workloads",
      label: "Workloads",
      items: impactValues.affectedWorkloads,
      emptyLabel: "No affected workloads reported.",
    },
  ];

  return (
    <DetailSection
      title="Kubernetes impact"
      description={
        impact?.summary ??
        "Discovery mapped this certificate to Kubernetes traffic and workload dependencies."
      }
    >
      {/* Meta Header */}
      <div className="mt-4 flex items-center justify-between rounded-md border bg-muted/40 px-4 py-3">
        <span className="text-sm font-medium text-foreground">
          TLS Configuration
        </span>
        <Badge variant={impact?.externallyServed ? "default" : "secondary"}>
          {impact?.externallyServed ? "Externally Served" : "Internal Only"}
        </Badge>
      </div>

      <Accordion type="multiple" className="mt-2 w-full">
        {categories.map(({ id, label, items, emptyLabel }) => (
          <AccordionItem key={id} value={id}>
            <AccordionTrigger className="group rounded-md px-2 transition-colors hover:bg-muted/30 hover:no-underline">
              <div className="flex flex-1 items-center gap-4 text-left text-sm">
                <span className="w-24 font-medium text-foreground">
                  {label}
                </span>
                <Badge variant="outline" className="w-fit font-mono text-xs">
                  {items.length}
                </Badge>

                <span className="hidden flex-1 truncate pr-4 font-normal text-muted-foreground group-data-[state=open]:hidden sm:block">
                  {items.length > 0 ? items.join(", ") : emptyLabel}
                </span>
              </div>
            </AccordionTrigger>

            <AccordionContent className="px-2 pt-2 pb-4">
              <ValueList values={items} emptyLabel={emptyLabel} />
            </AccordionContent>
          </AccordionItem>
        ))}
      </Accordion>
    </DetailSection>
  );
}

export function KubernetesSourcePanel({
  data,
}: {
  data: KubernetesDiscoveryData;
}) {
  const source = data.source;

  return (
    <DetailSection title="Kubernetes source">
      <div className="mb-3 flex items-center gap-2 text-sm text-muted-foreground">
        <HardDrivesIcon className="h-4 w-4 text-primary" aria-hidden="true" />
        <span className="font-mono text-xs">
          {compactValue(data.clusterName)}
        </span>
      </div>
      <DetailRows
        items={[
          {
            label: "Scan status",
            value:
              data.usageComplete && data.impactComplete
                ? "Complete"
                : "Partial",
          },
          {
            label: "Secret",
            value:
              source?.namespace && source?.name
                ? `${source.namespace}/${source.name}`
                : compactValue(source?.name),
            mono: true,
          },
          { label: "Kind", value: compactValue(source?.kind) },
          { label: "Type", value: compactValue(source?.type), mono: true },
          {
            label: "Fingerprint",
            value: compactValue(source?.fingerprintSha256),
            mono: true,
          },
        ]}
      />
    </DetailSection>
  );
}

export function KubernetesDiscoveryPanel({
  data,
}: {
  data: KubernetesDiscoveryData;
}) {
  return (
    <div className="space-y-4">
      <KubernetesWarningPanel data={data} />
      <KubernetesImpactSummary data={data} />
      <DetailSection
        title={`Kubernetes usage paths (${data.usages.length})`}
        description="Routes, hostnames, services, and workloads that depend on this certificate."
      >
        <KubernetesUsageTable data={data} />
      </DetailSection>
    </div>
  );
}
