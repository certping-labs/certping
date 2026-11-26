// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useCallback, useMemo, useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { ArrowsClockwiseIcon } from "@phosphor-icons/react";

import {
  AUDIT_TRAIL_TABLE_MIN_WIDTH_CLASS,
  createAuditTrailColumns,
} from "@/components/audit-trail/audit-trail-columns";
import { AuditTrailDetailsDialog } from "@/components/audit-trail/audit-trail-details-dialog";
import { AuditTrailExportMenu } from "@/components/audit-trail/audit-trail-export-menu";
import { AuditTrailFieldFilterBar } from "@/components/audit-trail/audit-trail-field-filters";
import { AuditTrailFilterBar } from "@/components/audit-trail/audit-trail-filters";
import {
  AuditTrailPagination,
  auditTrailTotalLabel,
} from "@/components/audit-trail/audit-trail-pagination";
import {
  AuditTrailEmptyState,
  AuditTrailErrorState,
  AuditTrailLoadingState,
  AuditTrailNoticeLine,
  AuditTrailUnavailableState,
} from "@/components/audit-trail/audit-trail-states";
import { AuditTrailViewTabs } from "@/components/audit-trail/audit-trail-view-tabs";
import { Button } from "@/components/ui/button";
import { CustomTable } from "@/components/ui/custom-table";
import { PageHeader } from "@/components/ui/page-header";
import {
  useAuditTrailExport,
  useAuditTrailFilterOptions,
  useAuditTrailLogs,
} from "@/hooks/audit-trail";
import { useAuth } from "@/hooks/use-auth";
import type {
  AuditTrailFilterField,
  AuditTrailOption,
  AuditTrailSource,
} from "@/lib/audit-trail-source";
import { isAuditTrailUnavailable } from "@/lib/backend/audit-trail";
import { cn, getErrorMessage } from "@/lib/utils";
import type { AuditTrailEntry, AuditTrailFilters } from "@/types/audit-trail";

const DEFAULT_PAGE_SIZE = 25;
const NO_OPTIONS: readonly string[] = [];
const NO_FIELDS: readonly AuditTrailFilterField[] = [];
const HOUR_MS = 60 * 60 * 1_000;
const DEFAULT_UNAVAILABLE = {
  title: "This log isn't available",
  description: "It can't be read here yet. Try again later.",
};

const codesOf = (options: readonly AuditTrailOption[] | undefined) =>
  options
    ? options.filter((option): option is string => typeof option === "string")
    : NO_OPTIONS;

interface AuditTrailPanelProps {
  /** The service whose trail this shows; keep it stable across renders. */
  source: AuditTrailSource;
  /** The super admin's view of every organization. */
  platform?: boolean;
  /**
   * Shows the source's view tabs; the view switcher turns them off while the
   * other view's route is not known to exist.
   */
  showViews?: boolean;
}

const getRowId = (entry: { id: number }): string => String(entry.id);

/** An audit trail's events: what changed, who did it, and whether it worked. */
export function AuditTrailPanel({
  source,
  platform = false,
  showViews = true,
}: AuditTrailPanelProps) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const { user, isSuperAdmin, isLoading: isLoadingAuth } = useAuth();
  const canView = source.canView(user, isSuperAdmin, platform);
  const { copy } = source;
  const header = platform ? copy.platform : copy.customer;

  const queryString = searchParams.toString();
  const filters = useMemo(
    () => source.filters.read(new URLSearchParams(queryString), platform),
    [platform, queryString, source],
  );
  const rangeError = source.filters.rangeError(filters, platform);
  const [pageSize, setPageSize] = useState(DEFAULT_PAGE_SIZE);
  const [selected, setSelected] = useState<AuditTrailEntry | null>(null);

  const logs = useAuditTrailLogs(source, {
    filters,
    platform,
    size: pageSize,
    enabled: canView && !isLoadingAuth && !rangeError,
  });
  const fields = source.filterFields
    ? source.filterFields[platform ? "platform" : "customer"]
    : NO_FIELDS;
  const classicFilters = !source.filterFields;
  const options = useAuditTrailFilterOptions(source, {
    fields: source.filterFields ? fields : undefined,
    platform,
    enabled: canView && source.canLoadOptions(user, platform),
    organizationId: filters.organizationId,
  });
  const columns = useMemo(
    () => createAuditTrailColumns(source, platform, setSelected),
    [platform, source],
  );
  const exportLogs = useAuditTrailExport(source, platform);
  const canExport = !platform || Boolean(source.exportsPlatform);
  // Before the first page says where the window starts, the default preset's.
  const [openedAt] = useState(() => Date.now());
  const windowHours = platform
    ? undefined
    : source.datePresets?.find((preset) => preset.default)?.hours;

  const setFilters = useCallback(
    (next: AuditTrailFilters) => {
      const query = source.filters.write(next, platform);
      router.replace(query ? `${pathname}?${query}` : pathname);
    },
    [pathname, platform, router, source],
  );
  const clearFilters = useCallback(() => setFilters({}), [setFilters]);

  if (!isLoadingAuth && !canView) {
    return (
      <div className="p-4 sm:p-6">
        <PageHeader
          title={header.title}
          breadcrumbs={[...header.breadcrumbs]}
          subtitle={copy.noPermission}
        />
      </div>
    );
  }

  const page = logs.data;
  const visibleFrom = page?.visibleFrom
    ? new Date(page.visibleFrom)
    : windowHours
      ? new Date(openedAt - windowHours * HOUR_MS)
      : undefined;
  const notice = source.notice?.({ user, platform, page });
  const unavailable = logs.isError && isAuditTrailUnavailable(logs.error);
  let content: React.ReactNode;
  if (rangeError) {
    content = null;
  } else if (isLoadingAuth || logs.isLoading) {
    content = <AuditTrailLoadingState label={copy.loading} />;
  } else if (unavailable) {
    const words = copy.unavailable ?? DEFAULT_UNAVAILABLE;
    content = (
      <AuditTrailUnavailableState
        title={words.title}
        description={logs.error?.message || words.description}
      />
    );
  } else if (logs.isError || !page) {
    content = (
      <AuditTrailErrorState
        title={copy.loadError}
        message={getErrorMessage(
          logs.error,
          "Check your connection and try again.",
        )}
        retrying={logs.isFetching}
        onRetry={logs.refetch}
      />
    );
  } else if (page.content.length === 0 && logs.page === 0) {
    content = (
      <AuditTrailEmptyState
        filtered={source.filters.has(filters)}
        onClearFilters={clearFilters}
        copy={copy.empty}
      />
    );
  } else {
    content = (
      <div
        aria-busy={logs.isFetching}
        className={cn(
          "overflow-hidden rounded-(--certping-radius-md) transition-opacity",
          logs.isFetching && "opacity-60",
        )}
      >
        <CustomTable
          columns={columns}
          data={page.content}
          getRowId={getRowId}
          onRowClick={setSelected}
          showColumnVisibility={false}
          showPagination={false}
          denseRows
          tableElementClassName={
            source.columns
              ? "w-full"
              : cn(AUDIT_TRAIL_TABLE_MIN_WIDTH_CLASS, "table-fixed")
          }
          emptyTableMsg={copy.endOfList}
        />
        <AuditTrailPagination
          totalLabel={auditTrailTotalLabel(page, copy.total, copy.totalCapped)}
          page={logs.page}
          totalPages={page.totalPages}
          totalCapped={page.totalCapped}
          pageSize={pageSize}
          canGoNext={logs.canGoNext}
          disabled={logs.isFetching}
          onFirstPage={logs.goToFirstPage}
          onPreviousPage={logs.goToPreviousPage}
          onNextPage={logs.goToNextPage}
          onPageSizeChange={setPageSize}
        />
        {copy.cappedHint &&
        page.totalCapped &&
        !logs.canGoNext &&
        page.content.length > 0 ? (
          <p className="border-t border-divider px-4 py-3 text-sm text-muted-foreground">
            {copy.cappedHint(page.totalElements.toLocaleString())}
          </p>
        ) : null}
      </div>
    );
  }

  return (
    <div className="space-y-5 overflow-x-hidden p-4 sm:p-6">
      <PageHeader
        title={header.title}
        breadcrumbs={[...header.breadcrumbs]}
        subtitle={header.subtitle}
        info={header.info}
        actions={
          <>
            <Button
              variant="icon"
              size="icon"
              aria-label={copy.refresh}
              title={copy.refresh}
              onClick={logs.refetch}
              disabled={logs.isFetching || Boolean(rangeError)}
            >
              <ArrowsClockwiseIcon
                className={cn(logs.isFetching && "animate-spin")}
              />
            </Button>
            {canExport ? (
              <AuditTrailExportMenu
                noun={copy.exportNoun}
                disabled={!canView || Boolean(rangeError) || unavailable}
                isExporting={exportLogs.isPending}
                onExport={(format) => exportLogs.mutate({ filters, format })}
              />
            ) : null}
          </>
        }
      />

      {platform || !source.views || !showViews ? null : (
        <AuditTrailViewTabs views={source.views} view={source.viewId} />
      )}

      {classicFilters ? (
        <AuditTrailFilterBar
          source={source}
          filters={filters}
          actions={codesOf(options.actions)}
          resources={codesOf(options.resources)}
          platform={platform}
          rangeError={rangeError}
          onChange={setFilters}
        />
      ) : (
        <AuditTrailFieldFilterBar
          source={source}
          fields={fields}
          filters={filters}
          options={options}
          visibleFrom={visibleFrom}
          rangeError={rangeError}
          onChange={setFilters}
        />
      )}

      {notice ? <AuditTrailNoticeLine notice={notice} /> : null}

      {content}

      <AuditTrailDetailsDialog
        source={source}
        entry={selected}
        platform={platform}
        onClose={() => setSelected(null)}
      />
    </div>
  );
}
