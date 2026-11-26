// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useEffect, useState } from "react";
import { create } from "zustand";

import {
  type ComponentState,
  type ComponentStatus,
  fetchStatus,
  type StatusReport,
} from "@/lib/public-status";
import { STATUS_SOURCES, type StatusSource } from "@/lib/status-sources";

export const STATUS_POLL_MS = 60_000;
export const RECHECK_AFTER_MS = 30_000;
/** A source is shown as not responding only after this many failed reads in a row. */
export const FAILED_READS_TO_SHOW = 2;

export interface SourceMemory {
  failures: number;
  components: ComponentStatus[];
}

const failed = (components: ComponentStatus[]) =>
  components.every((component) => component.state === "not_responding");

/*
 * One failed read of a source from the browser is often the browser's own
 * hop (a proxy, a waking laptop), not CertPing: until a second failed read in
 * a row, the source keeps its last answer, or says nothing.
 */
export function debounceFailedSources(
  report: StatusReport,
  memory: Map<string, SourceMemory>,
  sources: readonly StatusSource[] = STATUS_SOURCES,
): StatusReport {
  const shown: ComponentStatus[] = [];
  for (const source of sources) {
    const ids = new Set(source.components.map((c) => c.id));
    const read = report.components.filter((c) => ids.has(c.id));
    const remembered = memory.get(source.id);
    if (!failed(read)) {
      memory.set(source.id, { failures: 0, components: read });
      shown.push(...read);
      continue;
    }
    const failures = (remembered?.failures ?? 0) + 1;
    memory.set(source.id, {
      failures,
      components: remembered?.components ?? [],
    });
    shown.push(
      ...(failures >= FAILED_READS_TO_SHOW
        ? read
        : (remembered?.components ?? [])),
    );
  }
  const known = new Set(sources.flatMap((s) => s.components.map((c) => c.id)));
  shown.push(...report.components.filter((c) => !known.has(c.id)));
  return { ...report, components: shown };
}

/** The latest report the status banner read, so other screens can use it without polling again. */
export const usePublicStatusStore = create<{ report: StatusReport | null }>(
  () => ({ report: null }),
);

/** A component's latest state, or undefined before the first check or when it isn't reported. */
export function useComponentState(id: string): ComponentState | undefined {
  return usePublicStatusStore(
    (state) => state.report?.components.find((c) => c.id === id)?.state,
  );
}

/*
 * CertPing's public status, checked at once and every STATUS_POLL_MS while
 * the tab is visible and the browser is online. A hidden tab stops; showing
 * it again checks at once unless the last check finished under
 * RECHECK_AFTER_MS ago. An answer that arrives once the browser is offline is
 * dropped: it says nothing about CertPing.
 */
export function usePublicStatus(): StatusReport | null {
  const [report, setReport] = useState<StatusReport | null>(null);

  useEffect(() => {
    let timer: ReturnType<typeof setInterval> | undefined;
    let controller: AbortController | undefined;
    let finishedAt = Number.NEGATIVE_INFINITY;
    const memory = new Map<string, SourceMemory>();

    const check = async () => {
      if (!navigator.onLine) return;
      controller?.abort();
      const current = new AbortController();
      controller = current;
      const next = await fetchStatus(undefined, current.signal);
      if (current.signal.aborted || !navigator.onLine) return;
      finishedAt = Date.now();
      const shown = debounceFailedSources(next, memory);
      setReport(shown);
      usePublicStatusStore.setState({ report: shown });
    };
    const stop = () => {
      clearInterval(timer);
      timer = undefined;
      controller?.abort();
    };
    const start = () => {
      stop();
      if (Date.now() - finishedAt >= RECHECK_AFTER_MS) void check();
      timer = setInterval(() => void check(), STATUS_POLL_MS);
    };
    const onVisibility = () =>
      document.visibilityState === "visible" ? start() : stop();
    const onOnline = () => {
      if (document.visibilityState === "visible") void check();
    };

    if (document.visibilityState === "visible") start();
    document.addEventListener("visibilitychange", onVisibility);
    window.addEventListener("online", onOnline);
    return () => {
      stop();
      document.removeEventListener("visibilitychange", onVisibility);
      window.removeEventListener("online", onOnline);
    };
  }, []);

  return report;
}
