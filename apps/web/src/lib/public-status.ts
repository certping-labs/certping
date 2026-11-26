// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { apiBaseUrl } from "@/lib/api-base-url";
import { z } from "zod";

import { STATUS_SOURCES, type StatusSource } from "@/lib/status-sources";

export const STATUS_TIMEOUT_MS = 8000;

export type ComponentState =
  | "operational"
  | "degraded_performance"
  | "partial_outage"
  | "major_outage"
  | "under_maintenance"
  | "unknown"
  | "not_responding";

export interface ComponentStatus {
  id: string;
  name: string;
  state: ComponentState;
}

export interface StatusReport {
  components: ComponentStatus[];
  reachedEverySource: boolean;
  checkedAt: Date;
}

export type Overall =
  "operational" | "degraded" | "maintenance" | "down" | "unreachable";

const REPORTED_STATES = [
  "operational",
  "degraded_performance",
  "partial_outage",
  "major_outage",
  "under_maintenance",
] as const;

const summarySchema = z.object({
  components: z.array(
    z.object({
      id: z.string(),
      name: z.string(),
      status: z.string(),
    }),
  ),
});

const stateOf = (status: string | undefined): ComponentState =>
  status !== undefined &&
  (REPORTED_STATES as readonly string[]).includes(status)
    ? (status as ComponentState)
    : "unknown";

const notResponding = (source: StatusSource): ComponentStatus[] =>
  source.components.map(({ id, name }) => ({
    id,
    name,
    state: "not_responding",
  }));

/**
 * The source's components from a summary body: its expected ones under their
 * public names, then any others it reports. A status it does not know, or an
 * expected component it leaves out, is unknown, except an optional one, which
 * is not shown (the installation does not run it). Undefined when the body is
 * not a summary.
 */
export function parseSummary(
  body: unknown,
  source: StatusSource,
): ComponentStatus[] | undefined {
  const parsed = summarySchema.safeParse(body);
  if (!parsed.success) return undefined;
  const reported = new Map(
    parsed.data.components.map((component) => [component.id, component]),
  );
  const expected = source.components
    .filter(({ id, optional }) => !optional || reported.has(id))
    .map(({ id, name }) => ({
      id,
      name,
      state: stateOf(reported.get(id)?.status),
    }));
  const others = parsed.data.components
    .filter((c) => !source.components.some(({ id }) => id === c.id))
    .map((c) => ({ id: c.id, name: c.name, state: stateOf(c.status) }));
  return [...expected, ...others];
}

const timeoutSignal = (signal?: AbortSignal) => {
  const timeout = AbortSignal.timeout(STATUS_TIMEOUT_MS);
  return signal && typeof AbortSignal.any === "function"
    ? AbortSignal.any([signal, timeout])
    : timeout;
};

async function readSource(
  baseUrl: string,
  source: StatusSource,
  signal?: AbortSignal,
): Promise<ComponentStatus[] | undefined> {
  try {
    const response = await fetch(`${baseUrl}${source.path}`, {
      cache: "no-cache",
      credentials: "omit",
      signal: timeoutSignal(signal),
    });
    if (response.status !== 200) return undefined;
    return parseSummary(await response.json(), source);
  } catch {
    return undefined;
  }
}

/** Every source read at once; a source that fails reports its components as not responding. */
export async function fetchStatus(
  baseUrl = apiBaseUrl(),
  signal?: AbortSignal,
  sources: readonly StatusSource[] = STATUS_SOURCES,
): Promise<StatusReport> {
  const base = (baseUrl ?? "").replace(/\/+$/, "");
  const read = await Promise.all(
    sources.map((source) =>
      base ? readSource(base, source, signal) : Promise.resolve(undefined),
    ),
  );
  return {
    checkedAt: new Date(),
    components: read.flatMap(
      (components, index) => components ?? notResponding(sources[index]),
    ),
    reachedEverySource: read.every((components) => components !== undefined),
  };
}

export function overallOf(report: StatusReport): Overall {
  const states = report.components.map((c) => c.state);
  if (states.some((s) => s === "major_outage" || s === "partial_outage")) {
    return "down";
  }
  if (!report.reachedEverySource || states.includes("not_responding")) {
    return "unreachable";
  }
  if (states.includes("under_maintenance")) return "maintenance";
  if (states.every((s) => s === "operational")) return "operational";
  return "degraded";
}
