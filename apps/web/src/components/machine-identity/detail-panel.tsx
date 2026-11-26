// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import { CaretRightIcon, CopyIcon } from "@phosphor-icons/react";

import { humanizeKey } from "@/lib/machine-identity/display";
import { cn, copyToClipboard } from "@/lib/utils";

/**
 * Detail-page building blocks shared by every Machine Identity detail surface
 * (device, certificate, profile, policy, connector). Each page used to carry
 * its own copy of these; they live here so the panels stay visually identical.
 */

interface DetailPanelProps {
  title: string;
  /** One-line qualifier under the title, e.g. "Newest first." */
  description?: string;
  /** Right-aligned header slot for a count badge or a small action. */
  headerAccessory?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}

export function DetailPanel({
  title,
  description,
  headerAccessory,
  children,
  className,
}: DetailPanelProps) {
  return (
    <section
      className={cn(
        "overflow-hidden rounded-lg border border-border bg-card",
        className,
      )}
    >
      <header className="flex flex-wrap items-center justify-between gap-x-3 gap-y-2 border-b border-border surface-muted px-4 py-2.5">
        <div className="min-w-0 flex-1 basis-48">
          <h2 className="text-sm font-semibold text-foreground">{title}</h2>
          {description ? (
            <p className="text-xs text-muted-foreground">{description}</p>
          ) : null}
        </div>
        {headerAccessory ?? null}
      </header>
      {children}
    </section>
  );
}

/**
 * Balanced multi-column stack for detail panels.
 *
 * <p>A CSS grid of two fixed columns leaves whichever column runs out first as
 * dead white space - on the certificate and connector pages that was several
 * hundred pixels of nothing beside a column that kept going. Panel heights
 * here are entirely data-dependent (a provider snapshot may be four rows or
 * forty), so the columns are balanced by the browser instead of assigned by
 * hand, and each panel is kept whole.
 */
export function PanelMasonry({
  children,
  columns = 2,
  className,
}: {
  children: React.ReactNode;
  columns?: 2 | 3;
  className?: string;
}) {
  return (
    <div
      className={cn(
        // `-mb-4` absorbs the trailing margin the last panel in the tallest
        // column contributes, so the section below sits at the page's own
        // rhythm rather than one gap lower.
        "-mb-4 gap-4 *:mb-4 *:break-inside-avoid",
        columns === 3 ? "md:columns-2 xl:columns-3" : "lg:columns-2",
        className,
      )}
    >
      {children}
    </div>
  );
}

export interface DetailRowItem {
  label: string;
  value?: string | null;
  /** Rendered instead of {@link value} when the cell needs markup. */
  node?: React.ReactNode;
  /** Identifiers, DNs, and fingerprints render in a monospace cell. */
  monospace?: boolean;
  /** Adds a copy button; only meaningful together with {@link value}. */
  copyable?: boolean;
}

export function DetailRow({
  label,
  value,
  node,
  monospace,
  copyable,
}: DetailRowItem) {
  return (
    <div className="grid gap-x-3 gap-y-1 px-4 py-2.5 sm:grid-cols-[9.5rem_minmax(0,1fr)]">
      <dt className="text-xs leading-5 text-muted-foreground">{label}</dt>
      <dd
        className={cn(
          "flex min-w-0 items-start gap-2",
          monospace ? "font-mono text-xs leading-5" : "text-sm",
        )}
      >
        {/*
          `wrap-break-word` first, `anywhere` only as the fallback: `break-all`
          used to chop distinguished names mid-token ("...1jj7t / i3"), which
          made a copy-pasted DN unreadable.
        */}
        <span className="min-w-0 wrap-anywhere wrap-break-word">
          {node ?? value ?? <span className="text-muted-foreground">—</span>}
        </span>
        {copyable && value ? (
          <button
            type="button"
            onClick={() => copyToClipboard(value)}
            className="mt-0.5 shrink-0 rounded-sm text-muted-foreground transition-colors hover:text-foreground focus-visible:ring-2 focus-visible:ring-brand focus-visible:outline-hidden"
            aria-label={`Copy ${label}`}
          >
            <CopyIcon className="size-3.5" aria-hidden="true" />
          </button>
        ) : null}
      </dd>
    </div>
  );
}

/** Renders a label/value list; pairs with {@link DetailPanel} as its body. */
export function DefinitionList({ items }: { items: DetailRowItem[] }) {
  return (
    <dl className="divide-y divide-border">
      {items.map((item, index) => (
        <DetailRow key={`${item.label}-${index}`} {...item} />
      ))}
    </dl>
  );
}

/**
 * Quiet message for a panel with nothing to show.
 *
 * <p>Defaults to a compact, left-aligned line: a one-sentence explanation
 * centred in eight rows of padding reads as a broken panel rather than as a
 * deliberate answer. `centered` is kept for panels whose emptiness is the
 * whole point (an empty table body, a certificate with no SANs).
 */
export function DetailEmptyState({
  message,
  centered = false,
}: {
  message: string;
  centered?: boolean;
}) {
  return (
    <p
      className={cn(
        "text-sm text-muted-foreground",
        centered ? "px-6 py-10 text-center" : "px-4 py-3",
      )}
    >
      {message}
    </p>
  );
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isEmptyDynamicValue(value: unknown): boolean {
  if (value === null || value === undefined) return true;
  if (Array.isArray(value)) return value.length === 0;
  if (isPlainObject(value)) return Object.keys(value).length === 0;
  return false;
}

/**
 * Identifier-shaped strings (GUIDs, fingerprints, hostnames, Graph type names)
 * are compared character by character, so they get a monospace cell. Prose
 * does not.
 */
const IDENTIFIER_PATTERN = /^[A-Za-z0-9@#][A-Za-z0-9:._@#/+-]{15,}$/;

function isIdentifierLike(value: string): boolean {
  return !value.includes(" ") && IDENTIFIER_PATTERN.test(value);
}

/**
 * Renders a value of unknown, provider-defined shape (a CA connector's opaque
 * `product`/`profiles`/`issues` payloads, Intune's device attributes) as
 * labelled rows instead of a raw JSON dump - without assuming any field names.
 *
 * <p>Labels and values share one left-aligned grid. Right-aligning the values
 * against left-aligned labels left a ragged gutter down the middle of every
 * provider panel, and pushed long values (`#microsoft.graph.macOSScepCertificateProfile`,
 * a nested EKU record) off the right edge of the card.
 */
export function DynamicValue({ value }: { value: unknown }) {
  if (value === null || value === undefined) {
    return <span className="text-muted-foreground">—</span>;
  }
  if (typeof value === "boolean") {
    return <span>{value ? "Yes" : "No"}</span>;
  }
  if (Array.isArray(value)) {
    if (value.length === 0) {
      return <span className="text-muted-foreground">—</span>;
    }
    if (!value.some((item) => isPlainObject(item))) {
      return (
        <span className="wrap-anywhere wrap-break-word">
          {value.map((item) => String(item)).join(", ")}
        </span>
      );
    }
    return (
      <div className="space-y-2">
        {value.map((item, index) => (
          <div
            key={index}
            className="overflow-hidden rounded-md border border-border surface-muted px-3 py-2"
          >
            <DynamicValue value={item} />
          </div>
        ))}
      </div>
    );
  }
  if (isPlainObject(value)) {
    const entries = Object.entries(value).filter(
      ([, entryValue]) => !isEmptyDynamicValue(entryValue),
    );
    if (entries.length === 0) {
      return <span className="text-muted-foreground">—</span>;
    }
    return (
      <dl className="space-y-1.5">
        {entries.map(([key, entryValue]) => (
          <div
            key={key}
            className="grid gap-x-3 text-sm sm:grid-cols-[minmax(0,10rem)_minmax(0,1fr)]"
          >
            <dt className="text-xs leading-5 text-muted-foreground">
              {humanizeKey(key)}
            </dt>
            <dd className="min-w-0">
              <DynamicValue value={entryValue} />
            </dd>
          </div>
        ))}
      </dl>
    );
  }

  const text = String(value);
  return (
    <span
      className={cn(
        "wrap-anywhere wrap-break-word",
        isIdentifierLike(text) && "font-mono text-xs",
      )}
    >
      {text}
    </span>
  );
}

/**
 * A detail panel for a value whose shape is defined by an external provider,
 * not by CertPing (a CA connector's health-report payloads, Intune's device
 * attributes, a profile's provider snapshot). Renders labelled key/value pairs
 * instead of a `JSON.stringify` dump, and keeps the exact payload one
 * disclosure away for support work.
 */
export function DynamicDataPanel({
  title,
  description,
  value,
  emptyMessage = "Nothing reported.",
  showRaw = true,
  className,
}: {
  title: string;
  description?: string;
  value: unknown;
  emptyMessage?: string;
  /** Offer the verbatim payload behind a disclosure. */
  showRaw?: boolean;
  className?: string;
}) {
  return (
    <DetailPanel title={title} description={description} className={className}>
      {isEmptyDynamicValue(value) ? (
        <DetailEmptyState message={emptyMessage} />
      ) : (
        <>
          <div className="px-4 py-3">
            <DynamicValue value={value} />
          </div>
          {showRaw ? <RawPayloadDisclosure value={value} /> : null}
        </>
      )}
    </DetailPanel>
  );
}

/**
 * The verbatim payload, collapsed by default.
 *
 * <p>Serializing is deferred until the disclosure is actually opened, so a
 * large provider snapshot costs nothing on a page nobody expanded. Built on a
 * native `<details>` so it stays keyboard accessible and works before hydration.
 */
function RawPayloadDisclosure({ value }: { value: unknown }) {
  const [isOpen, setIsOpen] = React.useState(false);

  return (
    <details
      className="group border-t border-border"
      onToggle={(event) => setIsOpen(event.currentTarget.open)}
    >
      <summary className="flex cursor-pointer list-none items-center gap-1.5 px-4 py-2 text-xs font-medium text-muted-foreground transition-colors hover:text-foreground focus-visible:ring-2 focus-visible:ring-brand focus-visible:outline-hidden">
        <CaretRightIcon
          className="size-3.5 transition-transform group-open:rotate-90"
          aria-hidden="true"
        />
        <span className="group-open:hidden">Show raw payload</span>
        <span className="hidden group-open:inline">Hide raw payload</span>
      </summary>
      {isOpen ? (
        <pre className="max-h-72 overflow-auto border-t border-border surface-muted px-4 py-3 font-mono text-xs leading-5 text-muted-foreground">
          {JSON.stringify(value, null, 2)}
        </pre>
      ) : null}
    </details>
  );
}
