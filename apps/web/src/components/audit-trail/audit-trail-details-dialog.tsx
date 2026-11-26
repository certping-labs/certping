// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { type ReactNode, useEffect, useRef } from "react";
import Link from "next/link";
import { XCircleIcon } from "@phosphor-icons/react";

import {
  EventTime,
  FeatureOffBadge,
  ResultBadge,
  actorLabel,
  relativeTime,
  requestLine,
  sourceActorDetail,
} from "@/components/audit-trail/audit-trail-columns";
import { AuditTrailCopyId } from "@/components/audit-trail/audit-trail-copy-id";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import type {
  AuditTrailDetailField,
  AuditTrailSource,
} from "@/lib/audit-trail-source";
import {
  auditChangeFieldLabel,
  auditChangeValueLabel,
} from "@/lib/cert-manager-audit-filters";
import { cn } from "@/lib/utils";
import type { AuditTrailEntry } from "@/types/audit-trail";

interface AuditTrailDetailsDialogProps {
  source: Pick<
    AuditTrailSource,
    | "codeLabel"
    | "resourceLabel"
    | "relatedLink"
    | "failureLine"
    | "actorDetail"
    | "formatUserAgent"
    | "categoryLabel"
    | "separateReferences"
    | "resourceField"
    | "detailFields"
  >;
  entry: AuditTrailEntry | null;
  /** The platform view names both ids; a customer quotes one reference. */
  platform?: boolean;
  onClose: () => void;
}

function ReferenceFields({
  entry,
  platform,
  separate,
}: {
  entry: AuditTrailEntry;
  platform: boolean;
  /** Name both ids, each with a copy button. */
  separate: boolean;
}) {
  if (separate) {
    return (
      <>
        <Field label="Request ID" wide>
          {entry.requestId ? (
            <AuditTrailCopyId
              label="request ID"
              value={entry.requestId}
              layout="wrap"
            />
          ) : (
            <NotRecorded />
          )}
        </Field>
        <Field label="Correlation ID" wide>
          {entry.correlationId ? (
            <AuditTrailCopyId
              label="correlation ID"
              value={entry.correlationId}
              layout="wrap"
            />
          ) : (
            <NotRecorded />
          )}
        </Field>
      </>
    );
  }
  if (!platform) {
    const referenceId = entry.correlationId || entry.requestId;
    return referenceId ? (
      <Field label="Reference ID" mono>
        {referenceId}
      </Field>
    ) : null;
  }
  return (
    <>
      {entry.correlationId ? (
        <Field label="Correlation ID" mono>
          {entry.correlationId}
        </Field>
      ) : null}
      {entry.requestId ? (
        <Field label="Request ID" mono>
          {entry.requestId}
        </Field>
      ) : null}
    </>
  );
}

export function Field({
  label,
  children,
  mono = false,
  wide = false,
}: {
  label: string;
  children: ReactNode;
  mono?: boolean;
  /** Spans both columns, e.g. for an id too long to read in half the width. */
  wide?: boolean;
}) {
  // min-w-0 lets the grid track, not the value, decide the width; a long
  // value then breaks inside its cell instead of running into the next.
  return (
    <div className={cn("min-w-0 space-y-1", wide && "sm:col-span-2")}>
      <dt className="text-xs font-semibold text-muted-foreground">{label}</dt>
      <dd
        className={
          mono
            ? "font-mono text-[13px] break-all text-foreground"
            : "text-sm wrap-anywhere wrap-break-word text-foreground"
        }
      >
        {children}
      </dd>
    </div>
  );
}

/**
 * What a row is about, as the source says it; by default its kind as the
 * label and its name (or "None") as the value.
 */
const resourceFieldOf = (
  source: Pick<AuditTrailSource, "resourceLabel" | "resourceField">,
  entry: AuditTrailEntry,
): AuditTrailDetailField | undefined => {
  if (source.resourceField) {
    return source.resourceField(entry);
  }
  return {
    label: source.resourceLabel(entry),
    value: entry.resourceName ?? "None",
    detail:
      entry.resourceRef && entry.resourceRef !== entry.resourceName
        ? entry.resourceRef
        : undefined,
  };
};

function NotRecorded() {
  return <span className="text-sm text-muted-foreground">Not recorded</span>;
}

/** A change's side; one not recorded (a secret) only says it changed. */
function ChangeValue({
  field,
  value,
}: {
  field: string;
  value: string | null;
}) {
  if (value === null) {
    return (
      <span className="font-sans text-muted-foreground italic">Changed</span>
    );
  }
  return <>{auditChangeValueLabel(field, value) || "Empty"}</>;
}

function ChangesTable({ entry }: { entry: AuditTrailEntry }) {
  return (
    <section aria-labelledby="audit-trail-changes" className="space-y-2">
      <h3
        id="audit-trail-changes"
        className="text-xs font-semibold text-muted-foreground"
      >
        Changes
      </h3>
      <div className="overflow-x-auto rounded-(--certping-radius-md) border border-border">
        <table className="w-full text-left text-sm">
          <thead className="bg-muted/40 text-xs text-muted-foreground">
            <tr>
              <th scope="col" className="px-3 py-2 font-semibold">
                Field
              </th>
              <th scope="col" className="px-3 py-2 font-semibold">
                Before
              </th>
              <th scope="col" className="px-3 py-2 font-semibold">
                After
              </th>
            </tr>
          </thead>
          <tbody>
            {entry.changes.map((change) => (
              <tr key={change.field} className="border-t border-border">
                <th scope="row" className="px-3 py-2 font-medium">
                  {auditChangeFieldLabel(change.field)}
                </th>
                <td className="px-3 py-2 font-mono text-[13px] break-all text-muted-foreground">
                  <ChangeValue field={change.field} value={change.before} />
                </td>
                <td className="px-3 py-2 font-mono text-[13px] break-all">
                  <ChangeValue field={change.field} value={change.after} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function StatusGuidance({
  explanation,
  whatToDo,
}: {
  explanation?: string;
  whatToDo?: string;
}) {
  return (
    <dl className="space-y-3 rounded-(--certping-radius-md) border border-border bg-muted/30 p-4">
      {explanation ? <Field label="What happened">{explanation}</Field> : null}
      {whatToDo ? <Field label="What to do">{whatToDo}</Field> : null}
    </dl>
  );
}

export function AuditTrailDetailsDialog({
  source,
  entry,
  platform = false,
  onClose,
}: AuditTrailDetailsDialogProps) {
  const { codeLabel } = source;
  // The entry stays known while the dialog animates closed, when `entry` is
  // already null, so focus can go back to the row that opened it.
  const openedId = useRef<number | null>(null);
  useEffect(() => {
    if (entry) {
      openedId.current = entry.id;
    }
  }, [entry]);
  const returnFocus = (event: Event) => {
    const opener = document.querySelector<HTMLElement>(
      `[data-audit-trail-open="${openedId.current}"]`,
    );
    if (opener) {
      event.preventDefault();
      opener.focus();
    }
  };
  const related = entry ? source.relatedLink?.(entry, platform) : undefined;
  const failure = entry ? source.failureLine?.(entry) : undefined;
  const detail = entry ? sourceActorDetail(source, entry) : undefined;
  const resource = entry ? resourceFieldOf(source, entry) : undefined;
  const extraFields = entry ? (source.detailFields?.(entry) ?? []) : [];
  return (
    <Dialog open={entry !== null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent
        className="max-h-[90vh] overflow-y-auto sm:max-w-2xl"
        onCloseAutoFocus={returnFocus}
      >
        {entry ? (
          <>
            <DialogHeader>
              <DialogTitle className="pr-6 wrap-anywhere">
                {entry.summary}
              </DialogTitle>
              {/* A div, not Radix's p: the badge is a div, which a p cannot hold. */}
              <DialogDescription asChild>
                <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                  <EventTime value={entry.timestamp} />
                  <span aria-hidden>·</span>
                  <span>{relativeTime(entry.timestamp)}</span>
                  {entry.featureOff ? <FeatureOffBadge /> : null}
                </div>
              </DialogDescription>
            </DialogHeader>

            {failure ? (
              <Alert variant="destructive" role="note">
                <XCircleIcon aria-hidden weight="fill" />
                <AlertDescription>
                  {failure}
                  {entry.errorCode ? (
                    <span className="ml-2 font-mono text-xs">
                      {entry.errorCode}
                    </span>
                  ) : null}
                </AlertDescription>
              </Alert>
            ) : null}

            <dl className="grid gap-4 sm:grid-cols-2">
              <Field label="Result">
                <span className="flex flex-wrap items-center gap-2">
                  <ResultBadge status={entry.status} codeLabel={codeLabel} />
                  {entry.errorCode ? (
                    <span className="font-mono text-[13px] text-muted-foreground">
                      {entry.errorCode}
                    </span>
                  ) : null}
                </span>
              </Field>
              <Field label="Action">{codeLabel(entry.action)}</Field>
              <Field label="Actor">
                {actorLabel(entry, codeLabel)}
                {detail ? (
                  <span className="block text-xs text-muted-foreground">
                    {detail}
                  </span>
                ) : null}
              </Field>
              {resource ? (
                <Field label={resource.label} mono>
                  {resource.value}
                  {resource.detail ? (
                    <span className="block font-sans text-xs text-muted-foreground">
                      {resource.detail}
                    </span>
                  ) : null}
                </Field>
              ) : null}
              {entry.category ? (
                <Field label="Category">
                  {source.categoryLabel?.(entry.category) ??
                    codeLabel(entry.category)}
                </Field>
              ) : null}
              {extraFields.map((field) => (
                <Field key={field.label} label={field.label} mono={field.mono}>
                  {field.value}
                </Field>
              ))}
              {entry.organizationName ? (
                <Field label="Organization">{entry.organizationName}</Field>
              ) : null}
              <Field label="IP address" mono>
                {entry.ipAddress ?? "Not recorded"}
              </Field>
              <ReferenceFields
                entry={entry}
                platform={platform}
                separate={Boolean(source.separateReferences)}
              />
              {entry.event ? (
                <Field label="Event" mono>
                  {entry.event}
                </Field>
              ) : null}
              {entry.visibility ? (
                <Field label="Visibility">{codeLabel(entry.visibility)}</Field>
              ) : null}
              {entry.request ? (
                <Field label="Request" mono>
                  {requestLine(entry)}
                </Field>
              ) : null}
              {entry.traceId ? (
                <Field label="Trace ID" mono>
                  {entry.traceId}
                </Field>
              ) : null}
              {entry.userAgent ? (
                source.formatUserAgent ? (
                  <Field label="Browser">
                    <span title={entry.userAgent}>
                      {source.formatUserAgent(entry.userAgent)}
                    </span>
                  </Field>
                ) : (
                  <Field label="User agent" mono>
                    {entry.userAgent}
                  </Field>
                )
              ) : null}
            </dl>

            {entry.attributes.explanation || entry.attributes.whatToDo ? (
              <StatusGuidance
                explanation={entry.attributes.explanation}
                whatToDo={entry.attributes.whatToDo}
              />
            ) : null}

            {entry.changes.length > 0 ? <ChangesTable entry={entry} /> : null}

            {related ? (
              <div className="flex justify-end">
                <Button asChild size="sm">
                  <Link href={related.href}>{related.label}</Link>
                </Button>
              </div>
            ) : null}
          </>
        ) : null}
      </DialogContent>
    </Dialog>
  );
}
