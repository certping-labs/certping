// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useCallback, useLayoutEffect, useMemo, useRef } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";

import {
  areCertificateTableFiltersEqual,
  buildCertificateDashboardQueryString,
  readCertificateTableFilters,
} from "@/lib/cert-manager/certificate-dashboard-helpers";

/**
 * The certificate list's filters, with the URL as their only source of truth.
 *
 * `tableFilters` is read from the search params and keeps its identity while
 * their contents stay the same, so the table re-syncs only on a real change
 * (a link, back/forward). `replaceTableFilters` writes a user's change back,
 * and only when it differs from the URL: the table echoes every URL change it
 * receives, and that echo must never become a navigation of its own.
 *
 * `replaceTableFilters` is stable across renders. It reads the router, path
 * and params of the latest commit, so the table's report effect never re-runs
 * just because a new URL arrived before the table caught up with it; that
 * re-run would report the stale filters and send the URL back.
 */
export function useCertificateTableUrlFilters() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const filtersKey = JSON.stringify(readCertificateTableFilters(searchParams));
  const tableFilters = useMemo(
    () => JSON.parse(filtersKey) as Record<string, string>,
    [filtersKey],
  );

  const latest = useRef({ router, pathname, searchParams });
  // A layout effect lands before any child's passive effect reports filters.
  useLayoutEffect(() => {
    latest.current = { router, pathname, searchParams };
  });

  const replaceTableFilters = useCallback(
    (filterValues: Record<string, string>) => {
      const current = latest.current;
      if (
        areCertificateTableFiltersEqual(
          readCertificateTableFilters(current.searchParams),
          filterValues,
        )
      ) {
        return;
      }
      const nextQuery = buildCertificateDashboardQueryString({
        currentSearchParams: new URLSearchParams(
          current.searchParams.toString(),
        ),
        filterState: filterValues,
      });
      current.router.replace(
        nextQuery ? `${current.pathname}?${nextQuery}` : current.pathname,
        { scroll: false },
      );
    },
    [],
  );

  /** Sets one filter ("all" clears it) and keeps the others the URL holds. */
  const setTableFilter = useCallback(
    (filterId: string, value: string) => {
      replaceTableFilters({
        ...readCertificateTableFilters(latest.current.searchParams),
        [filterId]: value === "all" ? "" : value,
      });
    },
    [replaceTableFilters],
  );

  return { tableFilters, replaceTableFilters, setTableFilter };
}
