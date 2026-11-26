// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useMemo, useState } from "react";
import { keepPreviousData, useMutation, useQuery } from "@tanstack/react-query";

import { toast } from "sonner";

import type {
  AuditTrailAccessSource,
  AuditTrailFilterField,
  AuditTrailOption,
  AuditTrailOptionKind,
  AuditTrailOptionScope,
  AuditTrailSource,
} from "@/lib/audit-trail-source";
import { saveBlob } from "@/lib/download";
import type {
  AuditTrailAccessFilters,
  AuditTrailAccessPage,
  AuditTrailExport,
  AuditTrailExportFormat,
  AuditTrailFilters,
  AuditTrailPage,
} from "@/types/audit-trail";

const EXPORT_FAILED_FALLBACK = "Couldn't export the log. Try again.";

/** Which page is shown, and the cursor that fetched each page visited so far. */
interface CursorTrail {
  key: string;
  page: number;
  cursors: readonly (string | undefined)[];
}

/** One keyset-paged list as a table pages through it. */
export interface CursorPagesResult<TPage> {
  data?: TPage;
  isLoading: boolean;
  isFetching: boolean;
  isError: boolean;
  error: Error | null;
  refetch: () => void;
  page: number;
  canGoNext: boolean;
  goToFirstPage: () => void;
  goToPreviousPage: () => void;
  goToNextPage: () => void;
}

interface UseCursorPagesOptions<TPage> {
  queryKey: readonly unknown[];
  /** Everything but the cursor that decides the rows: a change starts again. */
  key: string;
  fetchPage: (cursor: string | undefined) => Promise<TPage>;
  enabled: boolean;
}

const firstPage = (key: string): CursorTrail => ({
  key,
  page: 0,
  cursors: [undefined],
});

/**
 * Pages through a list the server pages by keyset. It refuses a page number,
 * so this keeps the cursor of every page visited: next follows the current
 * page's `nextCursor`, previous and first reuse a kept cursor. A change of
 * `key` starts again from the first page.
 */
export function useCursorPages<TPage extends { nextCursor?: string }>({
  queryKey,
  key,
  fetchPage,
  enabled,
}: UseCursorPagesOptions<TPage>): CursorPagesResult<TPage> {
  const [trail, setTrail] = useState<CursorTrail>(() => firstPage(key));
  // Reset during render, as React recommends for state derived from props:
  // kept, the old trail would reopen a later page when the filters change back.
  if (trail.key !== key) {
    setTrail(firstPage(key));
  }
  const current = trail.key === key ? trail : firstPage(key);
  const cursor = current.cursors[current.page];

  const query = useQuery({
    queryKey: [...queryKey, key, cursor ?? null],
    queryFn: () => fetchPage(cursor),
    enabled,
    retry: false,
    staleTime: 30_000,
    refetchOnWindowFocus: false,
    placeholderData: keepPreviousData,
  });

  const nextCursor = query.isPlaceholderData
    ? undefined
    : query.data?.nextCursor;

  return {
    data: query.data,
    isLoading: query.isLoading,
    isFetching: query.isFetching,
    isError: query.isError,
    error: query.error,
    refetch: () => void query.refetch(),
    page: current.page,
    canGoNext: nextCursor !== undefined,
    goToFirstPage: () => setTrail({ ...current, page: 0 }),
    goToPreviousPage: () =>
      setTrail({ ...current, page: Math.max(0, current.page - 1) }),
    goToNextPage: () => {
      if (nextCursor === undefined) {
        return;
      }
      const cursors = [
        ...current.cursors.slice(0, current.page + 1),
        nextCursor,
      ];
      setTrail({ key, page: current.page + 1, cursors });
    },
  };
}

/**
 * Downloads an export and tells the user when the server refuses it. One toast
 * id, so a repeated refusal replaces the last instead of stacking.
 */
export function useLogExport<TFilters>(
  exportLog: (
    filters: TFilters,
    format: AuditTrailExportFormat,
  ) => Promise<AuditTrailExport>,
  toastId = "domain-log-export-error",
) {
  return useMutation({
    mutationFn: ({
      filters,
      format,
    }: {
      filters: TFilters;
      format: AuditTrailExportFormat;
    }) => exportLog(filters, format),
    onSuccess: ({ blob, fileName }) => saveBlob(blob, fileName),
    // Every failure says something, even one that arrives without words.
    onError: (error: Error) =>
      toast.error(error.message || EXPORT_FAILED_FALLBACK, { id: toastId }),
  });
}

interface UseAuditTrailLogsOptions {
  filters: AuditTrailFilters;
  platform: boolean;
  size: number;
  enabled: boolean;
}

/** A source's events, a page at a time. */
export function useAuditTrailLogs(
  source: Pick<AuditTrailSource, "queryKeys" | "list">,
  { filters, platform, size, enabled }: UseAuditTrailLogsOptions,
): CursorPagesResult<AuditTrailPage> {
  return useCursorPages({
    queryKey: source.queryKeys.list,
    key: JSON.stringify([filters, platform, size]),
    fetchPage: (cursor) => source.list({ filters, platform, size, cursor }),
    enabled,
  });
}

/** One list a filter offers; the source's codes and choices as they came. */
export function useAuditTrailOptions(
  source: Pick<AuditTrailSource, "queryKeys" | "options">,
  kind: AuditTrailOptionKind,
  platform: boolean,
  enabled: boolean,
  scope?: AuditTrailOptionScope,
) {
  const organizationId = scope?.organizationId;
  return useQuery({
    queryKey: [
      ...source.queryKeys.options,
      kind,
      platform,
      ...(organizationId ? [organizationId] : []),
    ],
    queryFn: () =>
      organizationId
        ? source.options(kind, platform, { organizationId })
        : source.options(kind, platform),
    enabled,
    retry: false,
    staleTime: 5 * 60 * 1_000,
    refetchOnWindowFocus: false,
  });
}

/** The lists a panel's filters offer, by kind; a list not yet read is absent. */
export type AuditTrailOptionLists = Partial<
  Record<AuditTrailOptionKind, readonly AuditTrailOption[]>
>;

/**
 * Reads only the lists the bar shows: the classic bar's (`fields` undefined)
 * actions and resources, or the lists the source's fields name.
 */
export function useAuditTrailFilterOptions(
  source: Pick<AuditTrailSource, "queryKeys" | "options">,
  {
    fields,
    platform,
    enabled,
    organizationId,
  }: {
    fields: readonly AuditTrailFilterField[] | undefined;
    platform: boolean;
    enabled: boolean;
    /** The organization picked on the platform view; categories follow its flags. */
    organizationId?: string;
  },
): AuditTrailOptionLists {
  const classic = fields === undefined;
  const shows = (field: AuditTrailFilterField) =>
    enabled && Boolean(fields?.includes(field));
  const actions = useAuditTrailOptions(
    source,
    "actions",
    platform,
    enabled && classic,
  );
  const resources = useAuditTrailOptions(
    source,
    "resources",
    platform,
    enabled && classic,
  );
  const categories = useAuditTrailOptions(
    source,
    "categories",
    platform,
    shows("category"),
    platform ? { organizationId } : undefined,
  );
  const members = useAuditTrailOptions(
    source,
    "members",
    platform,
    shows("member"),
  );
  const organizations = useAuditTrailOptions(
    source,
    "organizations",
    platform,
    shows("organization"),
  );
  return useMemo(
    () => ({
      actions: actions.data,
      resources: resources.data,
      categories: categories.data,
      members: members.data,
      organizations: organizations.data,
    }),
    [
      actions.data,
      resources.data,
      categories.data,
      members.data,
      organizations.data,
    ],
  );
}

export const useAuditTrailExport = (
  source: Pick<AuditTrailSource, "export" | "exportErrorToastId">,
  platform: boolean,
) =>
  useLogExport(
    (filters: AuditTrailFilters, format: AuditTrailExportFormat) =>
      source.export(filters, format, platform),
    source.exportErrorToastId,
  );

interface UseAuditTrailAccessLogOptions {
  filters: AuditTrailAccessFilters;
  size: number;
  enabled: boolean;
}

/** A source's reads, a page at a time. */
export function useAuditTrailAccessLog(
  source: Pick<AuditTrailAccessSource, "queryKey" | "list">,
  { filters, size, enabled }: UseAuditTrailAccessLogOptions,
): CursorPagesResult<AuditTrailAccessPage> {
  return useCursorPages({
    queryKey: source.queryKey,
    key: JSON.stringify([filters, size]),
    fetchPage: (cursor) => source.list({ filters, size, cursor }),
    enabled,
  });
}

export function useAuditTrailAccessActivities(
  source: Pick<AuditTrailAccessSource, "queryKey" | "activities">,
  enabled: boolean,
) {
  return useQuery({
    queryKey: [...source.queryKey, "activities"],
    queryFn: source.activities,
    enabled,
    retry: false,
    staleTime: 5 * 60 * 1_000,
    refetchOnWindowFocus: false,
  });
}

export const useAuditTrailAccessExport = (
  source: Pick<AuditTrailAccessSource, "export" | "exportErrorToastId">,
) => useLogExport(source.export, source.exportErrorToastId);
