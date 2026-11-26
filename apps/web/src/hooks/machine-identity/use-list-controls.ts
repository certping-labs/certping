// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";

import { MACHINE_IDENTITY_CONFIG } from "@/lib/machine-identity/config";

const SEARCH_DEBOUNCE_MS = 300;

/**
 * Filter values arrive from the URL, so they are untrusted input. Every legal
 * value is an enum constant, an ID, a vendor-reported name (which may contain
 * spaces, e.g. "Windows 10"), or a small number, so anything outside this
 * shape is dropped rather than rendered into filter chips.
 */
const SAFE_PARAM_PATTERN = /^[\w.:+\- ]{1,64}$/;

const SEARCH_PARAM_KEY = "search";

/**
 * List state shared by every Machine Identity table: debounced search, a
 * filter bag, and zero-based pagination.
 *
 * <p>Filters initialize from the URL query string and write back to it, so a
 * dashboard tile can deep-link into a pre-filtered inventory and an operator
 * can share the filtered view - the same tile-equals-filtered-list contract
 * Venafi and Keyfactor dashboards use. The URL only carries values that differ
 * from the page's defaults, and only after the user (or a tile) changes
 * something, so plain navigation never rewrites the address bar.
 *
 * <p>Changing a filter or the search term resets to page 0. Without that, a
 * user sitting on page 7 who narrows the results lands on an empty page and
 * reads it as "no matches".
 */
export function useListControls<
  TFilters extends Record<string, string | undefined>,
>(initialFilters: TFilters) {
  const searchParams = useSearchParams();
  const pathname = usePathname();
  const router = useRouter();

  // Callers may pass the initial-filter object inline, so pin the first
  // render's value: it is the set of recognized keys and their defaults.
  const defaultFiltersRef = useRef(initialFilters);

  const [searchInput, setSearchInput] = useState(
    () => searchParams.get(SEARCH_PARAM_KEY) ?? "",
  );
  const [debouncedSearch, setDebouncedSearch] = useState(searchInput);
  const [filters, setFilters] = useState<TFilters>(() => {
    const merged = { ...initialFilters };
    for (const key of Object.keys(merged)) {
      const fromUrl = searchParams.get(key);
      if (fromUrl && SAFE_PARAM_PATTERN.test(fromUrl)) {
        merged[key as keyof TFilters] = fromUrl as TFilters[keyof TFilters];
      }
    }
    return merged;
  });
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(
    MACHINE_IDENTITY_CONFIG.list.defaultPageSize as number,
  );

  // Skip the reset on mount so the first render does not fire a redundant
  // state update before any query has run.
  const isFirstSearchSync = useRef(true);
  // URL writes start with the first user-driven change; landing on a deep link
  // must not immediately rewrite the address bar.
  const hasUserChangedState = useRef(false);

  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedSearch(searchInput.trim());
    }, SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [searchInput]);

  useEffect(() => {
    if (isFirstSearchSync.current) {
      isFirstSearchSync.current = false;
      return;
    }
    setPage(0);
  }, [debouncedSearch]);

  useEffect(() => {
    if (!hasUserChangedState.current) return;

    const params = new URLSearchParams();
    if (debouncedSearch) {
      params.set(SEARCH_PARAM_KEY, debouncedSearch);
    }
    for (const [key, value] of Object.entries(filters)) {
      if (value !== undefined && value !== defaultFiltersRef.current[key]) {
        params.set(key, value);
      }
    }
    const query = params.toString();
    router.replace(query ? `${pathname}?${query}` : pathname, {
      scroll: false,
    });
  }, [debouncedSearch, filters, pathname, router]);

  const updateSearchInput = useCallback((value: string) => {
    hasUserChangedState.current = true;
    setSearchInput(value);
  }, []);

  const setFilter = useCallback(
    (key: keyof TFilters, value: string | undefined) => {
      hasUserChangedState.current = true;
      setFilters((current) => ({ ...current, [key]: value }));
      setPage(0);
    },
    [],
  );

  const changePageSize = useCallback((size: number) => {
    setPageSize(size);
    setPage(0);
  }, []);

  return useMemo(
    () => ({
      searchInput,
      setSearchInput: updateSearchInput,
      search: debouncedSearch || undefined,
      filters,
      setFilter,
      page,
      setPage,
      pageSize,
      setPageSize: changePageSize,
    }),
    [
      searchInput,
      updateSearchInput,
      debouncedSearch,
      filters,
      setFilter,
      page,
      pageSize,
      changePageSize,
    ],
  );
}
