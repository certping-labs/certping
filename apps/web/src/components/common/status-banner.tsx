// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useState } from "react";
import { WarningIcon, XIcon } from "@phosphor-icons/react";

import { usePublicStatus } from "@/hooks/use-public-status";
import { useNetworkStatusStore } from "@/lib/network-status";
import type { ComponentState, ComponentStatus } from "@/lib/public-status";
import { QUEUED_COMPONENTS } from "@/lib/status-sources";

export const STATUS_PAGE_URL = "/health/";
const DISMISSED_KEY = "certping.status-banner.dismissed";

const SUBJECT: Record<string, { name: string; plural: boolean }> = {
  api: { name: "Sign-in and the API", plural: true },
  notifications: { name: "Email notifications", plural: true },
  certificates: { name: "Certificate issuance and renewal", plural: false },
};

const isDown = (state: ComponentState) =>
  state === "major_outage" || state === "partial_outage";

function sentence(component: ComponentStatus): string {
  const subject = SUBJECT[component.id] ?? {
    name: component.name,
    plural: false,
  };
  const be = subject.plural ? "are" : "is";
  const queued = QUEUED_COMPONENTS.includes(component.id);
  if (queued) return `${subject.name} ${be} delayed.`;
  if (isDown(component.state)) return `${subject.name} ${be} down.`;
  if (component.state === "under_maintenance") {
    return `${subject.name} ${be} under maintenance.`;
  }
  if (component.state === "unknown") {
    return `${subject.name} may not be working normally.`;
  }
  return `${subject.name} ${be} slower than usual.`;
}

/** What the banner says about these components, or nothing when all is well. */
export function statusMessage(components: ComponentStatus[]): string | null {
  const affected = components.filter((c) => c.state !== "operational");
  if (affected.length === 0) return null;
  const reached = affected.filter((c) => c.state !== "not_responding");
  const parts = reached.map(sentence);
  if (
    reached.some((c) => isDown(c.state) && QUEUED_COMPONENTS.includes(c.id))
  ) {
    parts.push("Work is queued and resumes when the service recovers.");
  }
  if (reached.length < affected.length) {
    parts.push("We could not reach some CertPing services.");
  }
  return parts.join(" ");
}

const incidentKey = (components: ComponentStatus[]) =>
  components
    .filter((c) => c.state !== "operational")
    .map((c) => `${c.id}:${c.state}`)
    .sort()
    .join(",");

function readDismissed(): string | null {
  try {
    return window.sessionStorage.getItem(DISMISSED_KEY);
  } catch {
    return null;
  }
}

function writeDismissed(key: string) {
  try {
    window.sessionStorage.setItem(DISMISSED_KEY, key);
  } catch {
    // Without storage the dismissal lasts until the page reloads.
  }
}

export function StatusBanner() {
  const report = usePublicStatus();
  const offline = useNetworkStatusStore(
    (state) => state.issue?.source === "browser",
  );
  const [dismissed, setDismissed] = useState<string | null>(readDismissed);

  if (!report || offline) return null;
  const message = statusMessage(report.components);
  const key = incidentKey(report.components);
  if (!message || dismissed === key) return null;

  const dismiss = () => {
    writeDismissed(key);
    setDismissed(key);
  };

  return (
    <div
      className="flex items-start gap-3 border-b border-warning-border bg-warning-soft px-4 py-3 text-sm text-foreground sm:px-6"
      role="status"
    >
      <WarningIcon
        aria-hidden
        className="mt-0.5 size-4 shrink-0 text-warning-foreground"
        weight="fill"
      />
      <p className="min-w-0 flex-1 leading-6">
        {message}{" "}
        <a
          className="font-medium text-primary underline-offset-4 hover:underline focus-visible:rounded-sm focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:outline-hidden"
          href={STATUS_PAGE_URL}
          rel="noopener"
          target="_blank"
        >
          View status
        </a>
      </p>
      <button
        aria-label="Dismiss the status notice"
        className="-my-2 grid size-11 shrink-0 place-items-center rounded-[10px] text-muted-foreground transition-colors hover:bg-warning-border/40 hover:text-foreground focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:outline-hidden sm:my-0 sm:size-8"
        onClick={dismiss}
        type="button"
      >
        <XIcon aria-hidden className="size-4" />
      </button>
    </div>
  );
}
