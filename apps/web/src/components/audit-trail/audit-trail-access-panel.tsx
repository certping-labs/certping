// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useCallback, useMemo, useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { ArrowsClockwiseIcon } from "@phosphor-icons/react";

import { createAuditTrailAccessColumns } from "@/components/audit-trail/audit-trail-access-columns";
import { AuditTrailAccessDetailsDialog } from "@/components/audit-trail/audit-trail-access-details-dialog";
import { AuditTrailAccessFilterBar } from "@/components/audit-trail/audit-trail-access-filters";
import { AUDIT_TRAIL_TABLE_MIN_WIDTH_CLASS } from "@/components/audit-trail/audit-trail-columns";
import { AuditTrailExportMenu } from "@/components/audit-trail/audit-trail-export-menu";
import {
  AuditTrailPagination,
  auditTrailTotalLabel,
} from "@/components/audit-trail/audit-trail-pagination";
import {
  AuditTrailEmptyState,
  AuditTrailErrorState,
  AuditTrailLoadingState,
  AuditTrailUnavailableState,
} from "@/components/audit-trail/audit-trail-states";
import { AuditTrailViewTabs } from "@/components/audit-trail/audit-trail-view-tabs";
import { Button } from "@/components/ui/button";
import { CustomTable } from "@/components/ui/custom-table";
import { PageHeader } from "@/components/ui/page-header";
import {
  useAuditTrailAccessActivities,
  useAuditTrailAccessExport,
  useAuditTrailAccessLog,
} from "@/hooks/audit-trail";
import { useAuth } from "@/hooks/use-auth";
import type { AuditTrailAccessSource } from "@/lib/audit-trail-source";
import { isAuditTrailUnavailable } from "@/lib/backend/audit-trail";
import { cn, getErrorMessage } from "@/lib/utils";
import type {
  AuditTrailAccessEntry,
  AuditTrailAccessFilters,
} from "@/types/audit-trail";

const DEFAULT_PAGE_SIZE = 25;
const NO_ACTIVITIES: readonly string[] = [];

const getRowId = (entry: AuditTrailAccessEntry): string => String(entry.id);

interface AuditTrailAccessPanelProps {
  /** The service whose reads this shows; keep it stable across renders. */
  source: AuditTrailAccessSource;
  /** Shows the source's view tabs. */
  showViews?: boolean;
}

/** Who searched, viewed and exported the subject's data. */
export function AuditTrailAccessPanel({
  source,
  showViews = true,
}: AuditTrailAccessPanelProps) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const { user, isLoading: isLoadingAuth } = useAuth();
  const canView = source.canView(user);
  const { copy } = source;
  const breadcrumbs = [...copy.breadcrumbs];

  const queryString = searchParams.toString();
  const filters = useMemo(
    () => source.filters.read(new URLSearchParams(queryString)),
    [queryString, source],
  );
  const rangeError = source.filters.rangeError(filters);
  const [pageSize, setPageSize] = useState(DEFAULT_PAGE_SIZE);
  const [selected, setSelected] = useState<AuditTrailAccessEntry | null>(null);

  const enabled = canView && !isLoadingAuth;
  const log = useAuditTrailAccessLog(source, {
    filters,
    size: pageSize,
    enabled: enabled && !rangeError,
  });
  const activities = useAuditTrailAccessActivities(source, enabled);
  const columns = useMemo(
    () => createAuditTrailAccessColumns(source),
    [source],
  );
  const exportLog = useAuditTrailAccessExport(source);

  const setFilters = useCallback(
    (next: AuditTrailAccessFilters) =>
      router.replace(`${pathname}?${source.filters.write(next)}`),
    [pathname, router, source],
  );
  const showUser = (userId: number) => {
    setSelected(null);
    setFilters({ ...filters, userId: String(userId) });
  };

  if (!isLoadingAuth && !canView) {
    return (
      <div className="p-4 sm:p-6">
        <PageHeader
          title={copy.title}
          breadcrumbs={breadcrumbs}
          subtitle={copy.noPermission}
        />
      </div>
    );
  }

  const page = log.data;
  const unavailable = log.isError && isAuditTrailUnavailable(log.error);
  let content: React.ReactNode;
  if (rangeError) {
    content = null;
  } else if (isLoadingAuth || log.isLoading) {
    content = <AuditTrailLoadingState label={copy.loading} />;
  } else if (unavailable && copy.unavailable) {
    content = (
      <AuditTrailUnavailableState
        title={copy.unavailable.title}
        description={log.error?.message || copy.unavailable.description}
      />
    );
  } else if (log.isError || !page) {
    content = (
      <AuditTrailErrorState
        title={copy.loadError}
        message={getErrorMessage(
          log.error,
          "Check your connection and try again.",
        )}
        retrying={log.isFetching}
        onRetry={log.refetch}
      />
    );
  } else if (page.content.length === 0 && log.page === 0) {
    content = (
      <AuditTrailEmptyState
        filtered={source.filters.has(filters)}
        onClearFilters={() => setFilters({})}
        copy={copy.empty}
      />
    );
  } else {
    content = (
      <div
        aria-busy={log.isFetching}
        className={cn(
          "overflow-hidden rounded-(--certping-radius-md) transition-opacity",
          log.isFetching && "opacity-60",
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
          tableElementClassName={cn(
            AUDIT_TRAIL_TABLE_MIN_WIDTH_CLASS,
            "table-fixed",
          )}
          emptyTableMsg={copy.endOfList}
        />
        <AuditTrailPagination
          totalLabel={auditTrailTotalLabel(page, copy.total, copy.totalCapped)}
          page={log.page}
          totalPages={page.totalPages}
          totalCapped={page.totalCapped}
          pageSize={pageSize}
          canGoNext={log.canGoNext}
          disabled={log.isFetching}
          onFirstPage={log.goToFirstPage}
          onPreviousPage={log.goToPreviousPage}
          onNextPage={log.goToNextPage}
          onPageSizeChange={setPageSize}
        />
      </div>
    );
  }

  return (
    <div className="space-y-5 overflow-x-hidden p-4 sm:p-6">
      <PageHeader
        title={copy.title}
        breadcrumbs={breadcrumbs}
        subtitle={copy.subtitle}
        info={copy.info}
        actions={
          <>
            <Button
              variant="icon"
              size="icon"
              aria-label={copy.refresh}
              title={copy.refresh}
              onClick={log.refetch}
              disabled={!enabled || log.isFetching || Boolean(rangeError)}
            >
              <ArrowsClockwiseIcon
                className={cn(log.isFetching && "animate-spin")}
              />
            </Button>
            <AuditTrailExportMenu
              noun={copy.exportNoun}
              disabled={!enabled || Boolean(rangeError)}
              isExporting={exportLog.isPending}
              onExport={(format) => exportLog.mutate({ filters, format })}
            />
          </>
        }
      />

      {source.views && showViews ? (
        <AuditTrailViewTabs views={source.views} view={source.viewId} />
      ) : null}

      <AuditTrailAccessFilterBar
        source={source}
        filters={filters}
        activities={activities.data ?? NO_ACTIVITIES}
        rangeError={rangeError}
        onChange={setFilters}
      />

      {content}

      <AuditTrailAccessDetailsDialog
        source={source}
        entry={selected}
        onClose={() => setSelected(null)}
        onShowUser={showUser}
      />
    </div>
  );
}
