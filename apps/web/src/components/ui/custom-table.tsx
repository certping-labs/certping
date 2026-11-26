// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import * as React from "react";
import {
  ColumnDef,
  ColumnFiltersState,
  SortingState,
  type Table as TanstackTable,
  VisibilityState,
  RowSelectionState,
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
  ColumnResizeMode,
} from "@tanstack/react-table";
import { DateRange } from "react-day-picker";
import { format } from "date-fns";

import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  GearSixIcon,
  CalendarDotsIcon,
  XIcon,
  TrashIcon,
  MagnifyingGlassIcon,
  ArrowsDownUpIcon,
  ArrowDownIcon,
  ArrowUpIcon,
  TrayIcon,
  CircleNotchIcon,
} from "@phosphor-icons/react";
import { DataTablePagination } from "./pagination";
import {
  filterChipActiveClassName,
  filterChipClassName,
  filterChipIdleClassName,
  FilterSelectChip,
} from "@/components/ui/filter-select-chip";
import { ServerPagination } from "@/components/ui/server-pagination";
import { Calendar } from "@/components/ui/calendar";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { cn } from "@/lib/utils";
import { Checkbox } from "@/components/ui/checkbox";
import { fuzzySearch } from "@/lib/fuzzy-search";
import { Skeleton } from "@/components/ui/skeleton";
import { ViewSwitcher, type ViewMode } from "@/components/ui/view-switcher";

export type FilterType = "text" | "select" | "date" | "date-range";

/**
 * Server-driven pagination state for tables whose data source pages on the
 * backend (zero-based, mirroring the Spring page envelope). When provided,
 * the table treats `data` as one already-sliced page: client-side pagination
 * is disabled and the footer renders the shared {@link ServerPagination}
 * controls instead.
 */
export interface ServerPaginationConfig {
  page: number;
  totalPages: number;
  pageSize: number;
  totalElements: number;
  /** `totalElements` is a lower bound: shown as "10,000+" and "400+". */
  totalCapped?: boolean;
  pageSizeOptions?: readonly number[];
  /** Disables the controls while the next page is being fetched. */
  disabled?: boolean;
  onPageChange: (page: number) => void;
  onPageSizeChange: (size: number) => void;
}

export interface ColumnFilter {
  id: string;
  type: FilterType;
  options?: { label: string; value: string }[];
  placeholder?: string;
  label?: string;
}

// Bulk actions see only selected rows in the current filtered result; a selected
// row that stops being selectable (it is being deleted, say) drops out.
function getSelectableSelection<TData>(table: TanstackTable<TData>): TData[] {
  return table
    .getFilteredSelectedRowModel()
    .rows.filter((row) => row.getCanSelect())
    .map((row) => row.original);
}

const EMPTY_ROW_SELECTION: RowSelectionState = {};

interface BulkAction<TData> {
  /** A function label names the selected count itself, so no count badge is added. */
  label: string | ((selectedCount: number, selectedRows: TData[]) => string);
  icon?: React.ComponentType<{ className?: string }>;
  onClick: (selectedRows: TData[]) => void;
  variant?: "default" | "destructive";
  disabled?: boolean;
}

/** Selects a set of rows in one click, picked from the current filtered result. */
interface SelectionShortcut<TData> {
  label: string;
  pickRows: (filteredRows: TData[]) => TData[];
}

interface DataTableProps<TData, TValue> {
  columns: ColumnDef<TData, TValue>[];
  data: TData[];
  isLoading?: boolean;
  loadingRowCount?: number;
  searchBy?: string | string[];
  searchPlaceholder?: string;
  selectable?: boolean;
  canSelectRow?: (row: TData) => boolean;
  onRowSelect?: (selectedRows: TData[]) => void;
  /** Accessible name of a row's checkbox ("Select example.com"). */
  getRowSelectionLabel?: (row: TData) => string;
  /**
   * Controlled selection, keyed by row id. Pass both to own the selection (to clear it
   * after an action, say); it still resets itself when the search or a filter changes.
   */
  rowSelection?: RowSelectionState;
  onRowSelectionChange?: (rowSelection: RowSelectionState) => void;
  selectionShortcuts?: SelectionShortcut<TData>[];
  /**
   * While set, selection shortcuts and bulk actions are disabled and this message shows
   * beside them ("Loading all certificates…", say). Row checkboxes stay usable.
   */
  selectionActionsPendingMessage?: string;
  onRowClick?: (row: TData) => void;
  /**
   * The user is likely to open this row next: the pointer rested on it or focus moved into it.
   * Lets a list warm the detail read before the click.
   */
  onRowIntent?: (row: TData) => void;
  emptyTableMsg?: string;
  emptyState?: React.ReactNode;
  className?: string;
  showColumnVisibility?: boolean;
  showPagination?: boolean;
  pageSize?: number;
  serverPagination?: ServerPaginationConfig;
  resizable?: boolean;
  filters?: ColumnFilter[];
  bulkActions?: BulkAction<TData>[];
  getRowId?: (row: TData) => string;
  title?: string;
  tableHeaderClassName?: string;
  tableClassName?: string;
  tableElementClassName?: string;
  defaultHiddenColumns?: string[];
  denseRows?: boolean;
  defaultSearchTerm?: string;
  defaultFilterValues?: Record<string, string>;
  onSearchTermChange?: (searchTerm: string) => void;
  onFilterValuesChange?: (filterValues: Record<string, string>) => void;
  manualFiltering?: boolean;
  /**
   * Content rendered at the start of the toolbar row, sharing it with the
   * column-visibility control. Lets a page put its own filter controls on the
   * same line as the table's own, instead of stacking two half-empty rows.
   */
  toolbarLeading?: React.ReactNode;
  toolbarFilters?: React.ReactNode;
  /**
   * Render mode for the body. "table" (default) renders the standard table.
   * "grid" renders {@link renderGrid} instead, while still sharing the same
   * data, filtering, and pagination footer.
   */
  viewMode?: "table" | "grid";
  viewSwitcher?: {
    value: ViewMode;
    onValueChange: (value: ViewMode) => void;
  };
  /**
   * Custom renderer for the current page's rows, used when `viewMode` is "grid".
   * Receives the rows for the active page (already paginated).
   */
  renderGrid?: (rows: TData[]) => React.ReactNode;
}

// Passing the pointer over a row on the way elsewhere is not intent; resting on it is.
const ROW_HOVER_INTENT_MS = 100;

type RowWithUnread = {
  unread?: boolean;
};

const SEARCH_CHANGE_NOTIFY_DELAY_MS = 250;

// The pseudo-element grows the 18px box to a 44px touch target without moving it.
const SELECTION_CHECKBOX_CLASS_NAME =
  "relative translate-y-[2px] before:absolute before:inset-[-13px] before:content-['']";

// The pseudo-element grows the 40px default button to a 44px touch target.
const SELECTION_SHORTCUT_CLASS_NAME =
  "relative before:absolute before:-inset-y-0.5 before:inset-x-0 before:content-['']";

function hasUnreadFlag(value: unknown): value is RowWithUnread {
  return typeof value === "object" && value !== null && "unread" in value;
}

function SortIndicator({ direction }: { direction: false | "asc" | "desc" }) {
  if (direction === "asc") {
    return <ArrowUpIcon className="h-3.5 w-3.5 text-foreground" />;
  }

  if (direction === "desc") {
    return <ArrowDownIcon className="h-3.5 w-3.5 text-foreground" />;
  }

  return (
    <ArrowsDownUpIcon className="h-3.5 w-3.5 text-muted-foreground/50 opacity-0 transition-opacity group-hover/sort:opacity-100" />
  );
}

export function CustomTable<TData extends object, TValue>({
  columns,
  data,
  isLoading = false,
  loadingRowCount,
  searchBy,
  searchPlaceholder,
  selectable = false,
  canSelectRow,
  onRowSelect,
  getRowSelectionLabel,
  rowSelection: controlledRowSelection,
  onRowSelectionChange,
  selectionShortcuts = [],
  selectionActionsPendingMessage,
  onRowClick,
  onRowIntent,
  emptyTableMsg = "No results found.",
  emptyState,
  className,
  showColumnVisibility = false,
  showPagination = true,
  pageSize = 10,
  serverPagination,
  resizable = false,
  filters = [],
  bulkActions = [],
  getRowId,
  title,
  tableHeaderClassName,
  tableClassName,
  tableElementClassName,
  defaultHiddenColumns = [],
  denseRows = false,
  defaultSearchTerm = "",
  defaultFilterValues,
  onSearchTermChange,
  onFilterValuesChange,
  manualFiltering = false,
  toolbarLeading,
  toolbarFilters,
  viewMode = "table",
  renderGrid,
  viewSwitcher,
}: DataTableProps<TData, TValue>) {
  const selectionPendingStatusDomId = React.useId();
  const [sorting, setSorting] = React.useState<SortingState>([]);
  const hoverIntentTimer =
    React.useRef<ReturnType<typeof setTimeout>>(undefined);
  const cancelHoverIntent = React.useCallback(() => {
    clearTimeout(hoverIntentTimer.current);
  }, []);
  React.useEffect(() => cancelHoverIntent, [cancelHoverIntent]);
  const [columnFilters, setColumnFilters] = React.useState<ColumnFiltersState>(
    () =>
      Object.entries(defaultFilterValues ?? {}).map(([id, value]) => ({
        id,
        value,
      })),
  );
  const [columnVisibility, setColumnVisibility] =
    React.useState<VisibilityState>(() => {
      const hiddenState: VisibilityState = {};
      defaultHiddenColumns.forEach((columnId) => {
        hiddenState[columnId] = false;
      });
      return hiddenState;
    });
  const [uncontrolledRowSelection, setUncontrolledRowSelection] =
    React.useState<RowSelectionState>(EMPTY_ROW_SELECTION);
  const rowSelection = controlledRowSelection ?? uncontrolledRowSelection;
  const [searchTerm, setSearchTerm] = React.useState(defaultSearchTerm);
  const deferredSearchTerm = React.useDeferredValue(searchTerm);
  const [columnResizeMode] = React.useState<ColumnResizeMode>("onChange");
  const [dateRanges, setDateRanges] = React.useState<{
    [key: string]: DateRange | undefined;
  }>({});
  const filteredData = React.useMemo(() => {
    if (manualFiltering) {
      return data;
    }

    if (deferredSearchTerm && searchBy) {
      const searchKeys = Array.isArray(searchBy) ? searchBy : [searchBy];
      return fuzzySearch(deferredSearchTerm, data, searchKeys);
    }
    return data;
  }, [deferredSearchTerm, manualFiltering, searchBy, data]);

  // Add selection column if selectable is true
  const columnsWithSelection = React.useMemo(() => {
    if (!selectable) return columns;

    const selectionColumn: ColumnDef<TData, TValue> = {
      id: "select",
      header: ({ table }) => (
        <Checkbox
          checked={
            table.getIsAllPageRowsSelected() ||
            (table.getIsSomePageRowsSelected() && "indeterminate")
          }
          onCheckedChange={(value) => table.toggleAllPageRowsSelected(!!value)}
          aria-label="Select all on this page"
          className={SELECTION_CHECKBOX_CLASS_NAME}
        />
      ),
      cell: ({ row }) => (
        <Checkbox
          checked={row.getIsSelected()}
          disabled={!row.getCanSelect()}
          onCheckedChange={(value) => row.toggleSelected(!!value)}
          aria-label={getRowSelectionLabel?.(row.original) ?? "Select row"}
          className={SELECTION_CHECKBOX_CLASS_NAME}
        />
      ),
      enableSorting: false,
      enableHiding: false,
      size: 40,
    };

    return [selectionColumn, ...columns];
  }, [columns, getRowSelectionLabel, selectable]);
  const table = useReactTable({
    data: filteredData,
    columns: columnsWithSelection,
    defaultColumn: {
      enableSorting: false,
    },
    getCoreRowModel: getCoreRowModel(),
    getPaginationRowModel:
      showPagination && !serverPagination ? getPaginationRowModel() : undefined,
    manualPagination: Boolean(serverPagination),
    pageCount: serverPagination?.totalPages,
    onSortingChange: setSorting,
    getSortedRowModel: getSortedRowModel(),
    onColumnFiltersChange: (updater) => {
      setColumnFilters(updater);
      clearRowSelection();
    },
    getFilteredRowModel: getFilteredRowModel(),
    manualFiltering,
    onColumnVisibilityChange: setColumnVisibility,
    onRowSelectionChange: (updater) =>
      updateRowSelection(
        typeof updater === "function" ? updater(rowSelection) : updater,
      ),
    enableRowSelection: canSelectRow
      ? (row) => canSelectRow(row.original)
      : true,
    getRowId: getRowId,
    state: {
      sorting,
      columnFilters,
      columnVisibility,
      rowSelection,
    },
    columnResizeMode: resizable ? columnResizeMode : undefined,
    initialState: {
      ...(showPagination
        ? {
            pagination: {
              pageSize,
            },
          }
        : {}),
    },
  });

  // The selection can still hold ids of rows that left the data (deleted, or hidden
  // by search); `table.getRow` throws on those, so look rows up without it.
  function updateRowSelection(next: RowSelectionState) {
    if (onRowSelectionChange) {
      onRowSelectionChange(next);
    } else {
      setUncontrolledRowSelection(next);
    }
    if (!onRowSelect) return;
    const rowsById = table.getCoreRowModel().rowsById;
    const selected: TData[] = [];
    for (const [id, isSelected] of Object.entries(next)) {
      const row = isSelected ? rowsById[id] : undefined;
      if (row?.getCanSelect()) selected.push(row.original);
    }
    onRowSelect(selected);
  }

  // A selection made under one search or filter never carries into another.
  function clearRowSelection() {
    if (Object.keys(rowSelection).length > 0) {
      updateRowSelection(EMPTY_ROW_SELECTION);
    }
  }
  // The re-sync effects below run on prop changes; they read the latest clear.
  const clearRowSelectionRef = React.useRef(clearRowSelection);
  React.useLayoutEffect(() => {
    clearRowSelectionRef.current = clearRowSelection;
  });

  const changeSearchTerm = (value: string) => {
    setSearchTerm(value);
    clearRowSelection();
  };

  const selectRows = (rowsToSelect: TData[]) => {
    const picked = new Set(rowsToSelect);
    const next: RowSelectionState = {};
    for (const row of table.getFilteredRowModel().rows) {
      if (row.getCanSelect() && picked.has(row.original)) {
        next[row.id] = true;
      }
    }
    updateRowSelection(next);
  };

  const skeletonRows = Math.max(
    1,
    loadingRowCount ?? (showPagination ? pageSize : 8),
  );

  const handleFilterChange = (columnId: string, value: string) => {
    if (value === "all") {
      table.getColumn(columnId)?.setFilterValue(undefined);
    } else {
      table.getColumn(columnId)?.setFilterValue(value);
    }
  };

  const handleDateRangeChange = (
    columnId: string,
    range: DateRange | undefined,
  ) => {
    setDateRanges((prev) => ({ ...prev, [columnId]: range }));
    if (range?.from) {
      table.getColumn(columnId)?.setFilterValue(range);
    } else {
      table.getColumn(columnId)?.setFilterValue(undefined);
    }
  };

  const clearFilters = () => {
    setColumnFilters([]);
    setDateRanges({});
    setSearchTerm("");
    clearRowSelection();
  };

  const resolveFilterLabel = (filter: ColumnFilter) =>
    filter.label || filter.placeholder || filter.id;

  const activeFilterBadges = React.useMemo(
    () =>
      filters
        .map((filter) => {
          const rawValue = columnFilters.find(
            (columnFilter) => columnFilter.id === filter.id,
          )?.value;
          if (!rawValue) {
            return null;
          }

          let value: string | null = null;
          if (filter.type === "select") {
            value =
              filter.options?.find((option) => option.value === rawValue)
                ?.label ?? String(rawValue);
          } else if (filter.type === "date" || filter.type === "date-range") {
            const range = dateRanges[filter.id];
            if (range?.from) {
              value = range.to
                ? `${format(range.from, "LLL dd, y")} - ${format(range.to, "LLL dd, y")}`
                : format(range.from, "LLL dd, y");
            }
          } else {
            value = String(rawValue);
          }

          if (!value) {
            return null;
          }
          return {
            id: filter.id,
            label: resolveFilterLabel(filter),
            value,
          };
        })
        .filter((item): item is { id: string; label: string; value: string } =>
          Boolean(item),
        ),
    [filters, dateRanges, columnFilters],
  );

  React.useEffect(() => {
    setSearchTerm(defaultSearchTerm);
    clearRowSelectionRef.current();
  }, [defaultSearchTerm]);

  React.useEffect(() => {
    setColumnFilters(
      Object.entries(defaultFilterValues ?? {}).map(([id, value]) => ({
        id,
        value,
      })),
    );
    clearRowSelectionRef.current();
  }, [defaultFilterValues]);

  React.useEffect(() => {
    if (!onSearchTermChange) {
      return;
    }

    const timeoutId = window.setTimeout(() => {
      onSearchTermChange(deferredSearchTerm.trim());
    }, SEARCH_CHANGE_NOTIFY_DELAY_MS);

    return () => window.clearTimeout(timeoutId);
  }, [deferredSearchTerm, onSearchTermChange]);

  React.useEffect(() => {
    if (!onFilterValuesChange) {
      return;
    }

    const nextValues = columnFilters.reduce<Record<string, string>>(
      (accumulator, filter) => {
        if (typeof filter.value === "string" && filter.value.trim() !== "") {
          accumulator[filter.id] = filter.value;
        }
        return accumulator;
      },
      {},
    );
    onFilterValuesChange(nextValues);
  }, [columnFilters, onFilterValuesChange]);

  const clearFilter = (columnId: string) => {
    table.getColumn(columnId)?.setFilterValue(undefined);
    setDateRanges((current) => {
      const next = { ...current };
      delete next[columnId];
      return next;
    });
  };

  const formatRange = (range: DateRange | undefined, single: boolean) => {
    if (!range?.from) return null;
    if (single || !range.to) return format(range.from, "d LLL y");
    return `${format(range.from, "d LLL")} - ${format(range.to, "d LLL y")}`;
  };

  const renderFilterChips = () =>
    filters.map((filter) => {
      const label = resolveFilterLabel(filter);

      if (filter.type === "select" && Array.isArray(filter.options)) {
        return (
          <FilterSelectChip
            key={filter.id}
            label={label}
            value={
              (table.getColumn(filter.id)?.getFilterValue() as string) || "all"
            }
            options={filter.options}
            onValueChange={(value) => handleFilterChange(filter.id, value)}
          />
        );
      }

      if (filter.type === "date" || filter.type === "date-range") {
        const single = filter.type === "date";
        const range = dateRanges[filter.id];
        const value = formatRange(range, single);
        return (
          <div key={filter.id} className="flex items-center">
            <Popover>
              <PopoverTrigger asChild>
                <button
                  type="button"
                  aria-label={`Filter by ${label}`}
                  className={cn(
                    filterChipClassName,
                    value
                      ? cn(filterChipActiveClassName, "rounded-r-none pr-2")
                      : filterChipIdleClassName,
                  )}
                >
                  <CalendarDotsIcon className="h-3.5 w-3.5 text-muted-foreground" />
                  <span className="text-muted-foreground">{label}</span>
                  {value ? (
                    <span className="font-medium text-foreground">{value}</span>
                  ) : null}
                </button>
              </PopoverTrigger>
              <PopoverContent
                className="w-auto p-0"
                align="start"
                onInteractOutside={(e) => {
                  e.preventDefault();
                }}
              >
                {single ? (
                  <Calendar
                    mode="single"
                    selected={range?.from}
                    onSelect={(date) =>
                      handleDateRangeChange(filter.id, {
                        from: date,
                        to: date,
                      })
                    }
                    initialFocus
                  />
                ) : (
                  <Calendar
                    mode="range"
                    selected={range}
                    onSelect={(next) => handleDateRangeChange(filter.id, next)}
                    initialFocus
                  />
                )}
              </PopoverContent>
            </Popover>
            {value ? (
              <button
                type="button"
                onClick={() => clearFilter(filter.id)}
                aria-label={`Clear ${label} filter`}
                className="inline-flex h-8 items-center rounded-r-full border border-l-0 border-border bg-secondary pr-2.5 pl-1.5 text-muted-foreground transition-colors hover:text-foreground focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:ring-offset-background focus-visible:outline-hidden"
              >
                <XIcon className="h-3.5 w-3.5" />
              </button>
            ) : null}
          </div>
        );
      }

      return null;
    });

  const selectedRows = getSelectableSelection(table);
  const hasSelectedRows = selectedRows.length > 0;
  const filteredRowOriginals = selectable
    ? table.getFilteredRowModel().rows.map((row) => row.original)
    : [];
  const availableSelectionShortcuts = selectionShortcuts
    .map((shortcut) => ({
      label: shortcut.label,
      rows: shortcut.pickRows(filteredRowOriginals),
    }))
    .filter((shortcut) => shortcut.rows.length > 0);
  const hasSelectionActions =
    availableSelectionShortcuts.length > 0 ||
    (selectable && hasSelectedRows && bulkActions.length > 0);
  const isSelectionActionPending = Boolean(selectionActionsPendingMessage);
  const selectionPendingStatusId = isSelectionActionPending
    ? selectionPendingStatusDomId
    : undefined;
  const isGridView =
    (viewSwitcher ? viewSwitcher.value === "card" : viewMode === "grid") &&
    Boolean(renderGrid);

  // Shared pagination footer for both the table and grid bodies. `roundingClass`
  // differs: "rounded-b-lg" when fused to the bottom of the table card, a full
  // bordered bar when it sits on its own under a grid.
  const renderPaginationFooter = (roundingClass: string) => {
    if (serverPagination) {
      return (
        <ServerPagination
          page={serverPagination.page}
          totalPages={serverPagination.totalPages}
          pageSize={serverPagination.pageSize}
          totalElements={serverPagination.totalElements}
          totalCapped={serverPagination.totalCapped}
          disabled={serverPagination.disabled}
          pageSizeOptions={serverPagination.pageSizeOptions}
          onPageChange={serverPagination.onPageChange}
          onPageSizeChange={serverPagination.onPageSizeChange}
        />
      );
    }
    return showPagination ? (
      <div
        className={cn(
          "flex flex-col gap-3 border-t border-divider px-4 py-3 sm:flex-row sm:items-center sm:justify-between sm:py-2.5",
          roundingClass,
        )}
      >
        <div className="min-w-0 text-sm text-muted-foreground sm:flex-1">
          {selectable ? (
            <>
              {table.getFilteredSelectedRowModel().rows.length} of{" "}
              {table.getFilteredRowModel().rows.length} row(s) selected.
            </>
          ) : (
            <>
              Showing {table.getRowModel().rows.length} of{" "}
              {table.getFilteredRowModel().rows.length} entries
            </>
          )}
        </div>
        <DataTablePagination table={table} />
      </div>
    ) : null;
  };

  const hasActiveFilters = activeFilterBadges.length > 0;
  const showToolbar =
    Boolean(toolbarLeading) ||
    Boolean(toolbarFilters) ||
    Boolean(searchBy) ||
    filters.length > 0 ||
    showColumnVisibility ||
    Boolean(viewSwitcher) ||
    hasSelectionActions;
  const rows = table.getRowModel().rows;
  const isFilteredEmpty =
    !isLoading &&
    rows.length === 0 &&
    (hasActiveFilters || Boolean(searchTerm));

  return (
    <div className={cn("space-y-3", className)}>
      {title ? (
        <div className="text-[15px] font-semibold tracking-[-0.015em] text-foreground">
          {title}
        </div>
      ) : null}

      {showToolbar ? (
        <div className="flex flex-wrap items-center gap-2">
          {toolbarLeading}
          {searchBy ? (
            <div className="relative w-full sm:w-72">
              <MagnifyingGlassIcon className="pointer-events-none absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder={searchPlaceholder || "Search..."}
                aria-label={searchPlaceholder || "Search"}
                value={searchTerm}
                onChange={(e) => changeSearchTerm(e.target.value)}
                className="h-9 pr-8 pl-9"
              />
              {searchTerm ? (
                <button
                  type="button"
                  onClick={() => changeSearchTerm("")}
                  aria-label="Clear search"
                  className="absolute top-1/2 right-2 inline-flex size-5 -translate-y-1/2 items-center justify-center rounded-full text-muted-foreground transition-colors hover:bg-secondary hover:text-foreground"
                >
                  <XIcon className="h-3.5 w-3.5" />
                </button>
              ) : null}
            </div>
          ) : null}

          {renderFilterChips()}
          {toolbarFilters}

          {hasActiveFilters ? (
            <Button
              variant="ghost"
              size="sm"
              onClick={clearFilters}
              className="h-8 px-2.5"
            >
              Clear filters
            </Button>
          ) : null}

          {availableSelectionShortcuts.map((shortcut) => (
            <Button
              key={shortcut.label}
              variant="outline"
              className={SELECTION_SHORTCUT_CLASS_NAME}
              disabled={isSelectionActionPending}
              aria-describedby={selectionPendingStatusId}
              onClick={() => selectRows(shortcut.rows)}
            >
              {shortcut.label}
            </Button>
          ))}

          {selectable && hasSelectedRows && bulkActions.length > 0 ? (
            <div className="flex items-center gap-2 duration-150 animate-in fade-in-0 slide-in-from-left-1 motion-reduce:animate-none">
              {bulkActions.map((action, index) => {
                const IconComponent = action.icon || TrashIcon;
                return (
                  <Button
                    key={index}
                    variant={action.variant || "default"}
                    size="sm"
                    onClick={() => action.onClick(selectedRows)}
                    disabled={action.disabled || isSelectionActionPending}
                    aria-describedby={selectionPendingStatusId}
                  >
                    <IconComponent className="h-4 w-4" />
                    {typeof action.label === "function" ? (
                      action.label(selectedRows.length, selectedRows)
                    ) : (
                      <>
                        {action.label}
                        <span className="ml-0.5 rounded-full bg-primary-foreground px-1.5 text-2xs text-primary tabular-nums">
                          {selectedRows.length}
                        </span>
                      </>
                    )}
                  </Button>
                );
              })}
            </div>
          ) : null}

          {isSelectionActionPending && hasSelectionActions ? (
            <span
              id={selectionPendingStatusId}
              role="status"
              className="inline-flex items-center gap-1.5 text-xs text-muted-foreground"
            >
              <CircleNotchIcon
                aria-hidden
                className="h-3.5 w-3.5 animate-spin motion-reduce:animate-none"
              />
              {selectionActionsPendingMessage}
            </span>
          ) : null}

          {showColumnVisibility || viewSwitcher ? (
            <div className="ml-auto flex items-center gap-2">
              {viewSwitcher ? (
                <ViewSwitcher
                  size="sm"
                  value={viewSwitcher.value}
                  onValueChange={viewSwitcher.onValueChange}
                />
              ) : null}
              {showColumnVisibility ? (
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="outline" size="sm">
                      <GearSixIcon className="h-4 w-4" />
                      <span className="sr-only md:not-sr-only">Columns</span>
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end" className="w-[200px]">
                    <DropdownMenuLabel>Show columns</DropdownMenuLabel>
                    <DropdownMenuSeparator />
                    {table
                      .getAllColumns()
                      .filter((column) => column.getCanHide())
                      .map((column) => (
                        <DropdownMenuCheckboxItem
                          key={column.id}
                          checked={column.getIsVisible()}
                          onCheckedChange={(value) =>
                            column.toggleVisibility(!!value)
                          }
                        >
                          {typeof column.columnDef.header === "string" &&
                          column.columnDef.header
                            ? column.columnDef.header
                            : column.id}
                        </DropdownMenuCheckboxItem>
                      ))}
                  </DropdownMenuContent>
                </DropdownMenu>
              ) : null}
            </div>
          ) : null}
        </div>
      ) : null}

      {isGridView ? (
        <>
          {renderGrid?.(rows.map((row) => row.original))}
          {renderPaginationFooter(
            "rounded-[10px] border border-border bg-card border-t",
          )}
        </>
      ) : (
        <div
          data-slot="table-region"
          className={cn(
            "overflow-hidden rounded-[10px] border border-border bg-card",
            tableClassName,
          )}
        >
          <Table className={cn("table-fixed", tableElementClassName)}>
            <TableHeader
              className={cn("[&_tr]:border-0", tableHeaderClassName)}
            >
              {table.getHeaderGroups().map((headerGroup) => (
                <TableRow
                  key={headerGroup.id}
                  className="border-0 hover:bg-transparent"
                >
                  {headerGroup.headers.map((header) => (
                    <TableHead
                      key={header.id}
                      className={cn(
                        header.column.columnDef.meta?.className,
                        "border-b border-divider px-4",
                        denseRows ? "h-9" : "h-10",
                        tableHeaderClassName,
                      )}
                      style={{
                        width: header.column.columnDef.meta?.fluid
                          ? undefined
                          : header.getSize(),
                        position: "relative",
                      }}
                      aria-sort={
                        header.column.getIsSorted() === "asc"
                          ? "ascending"
                          : header.column.getIsSorted() === "desc"
                            ? "descending"
                            : undefined
                      }
                    >
                      {header.isPlaceholder ? null : header.column.getCanSort() ? (
                        <button
                          type="button"
                          className="group/sort -mx-1 flex w-[calc(100%+0.5rem)] items-center gap-1.5 rounded-md px-1 text-left transition-colors hover:text-foreground focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:ring-offset-background focus-visible:outline-hidden"
                          onClick={header.column.getToggleSortingHandler()}
                        >
                          <span className="truncate">
                            {flexRender(
                              header.column.columnDef.header,
                              header.getContext(),
                            )}
                          </span>
                          <SortIndicator
                            direction={header.column.getIsSorted()}
                          />
                        </button>
                      ) : (
                        flexRender(
                          header.column.columnDef.header,
                          header.getContext(),
                        )
                      )}
                      {resizable && (
                        <div
                          onMouseDown={header.getResizeHandler()}
                          onTouchStart={header.getResizeHandler()}
                          className={cn(
                            "absolute top-2 right-0 h-[calc(100%-1rem)] w-0.5 cursor-col-resize touch-none rounded-full transition-colors select-none",
                            header.column.getIsResizing()
                              ? "bg-brand"
                              : "bg-divider hover:bg-border",
                          )}
                        />
                      )}
                    </TableHead>
                  ))}
                </TableRow>
              ))}
            </TableHeader>
            <TableBody>
              {isLoading ? (
                Array.from({ length: skeletonRows }).map((_, index) => (
                  <TableRow
                    key={`skeleton-${index}`}
                    className={cn(
                      "hover:bg-transparent",
                      denseRows ? "[&_td]:h-11" : "[&_td]:h-[52px]",
                    )}
                  >
                    {table.getVisibleLeafColumns().map((column, cellIndex) => (
                      <TableCell
                        key={`${column.id}-${cellIndex}`}
                        className={cn(column.columnDef.meta?.className, "px-4")}
                      >
                        <Skeleton
                          className={cn(
                            "h-3.5 rounded-full",
                            cellIndex === 0 ? "w-40" : "w-20",
                          )}
                        />
                      </TableCell>
                    ))}
                  </TableRow>
                ))
              ) : rows.length ? (
                rows.map((row) => {
                  const unread = hasUnreadFlag(row.original)
                    ? Boolean(row.original.unread)
                    : false;

                  return (
                    <TableRow
                      key={row.id}
                      data-state={row.getIsSelected() && "selected"}
                      data-unread={unread ? "true" : undefined}
                      className={cn(
                        "group",
                        onRowClick && "cursor-pointer",
                        denseRows
                          ? "[&_td]:h-11 [&_td]:px-4 [&_td]:text-sm [&_td]:text-foreground"
                          : "[&_td]:h-[52px] [&_td]:px-4 [&_td]:text-sm [&_td]:text-foreground",
                        unread &&
                          "font-medium [&>td:first-child]:shadow-[inset_2px_0_0_hsl(var(--brand))]",
                      )}
                      onClick={() => onRowClick?.(row.original)}
                      onMouseEnter={
                        onRowIntent
                          ? () => {
                              cancelHoverIntent();
                              hoverIntentTimer.current = setTimeout(
                                () => onRowIntent(row.original),
                                ROW_HOVER_INTENT_MS,
                              );
                            }
                          : undefined
                      }
                      onMouseLeave={onRowIntent ? cancelHoverIntent : undefined}
                      onFocus={
                        onRowIntent
                          ? () => {
                              cancelHoverIntent();
                              onRowIntent(row.original);
                            }
                          : undefined
                      }
                    >
                      {row.getVisibleCells().map((cell) => (
                        <TableCell
                          key={cell.id}
                          className={cn(
                            cell.column.columnDef.meta?.className,
                            denseRows ? "py-1.5" : "py-2.5",
                          )}
                        >
                          {flexRender(
                            cell.column.columnDef.cell,
                            cell.getContext(),
                          )}
                        </TableCell>
                      ))}
                    </TableRow>
                  );
                })
              ) : (
                <TableRow className="border-0 hover:bg-transparent">
                  <TableCell
                    colSpan={table.getVisibleLeafColumns().length}
                    className="h-40 text-center"
                  >
                    {emptyState && !isFilteredEmpty ? (
                      emptyState
                    ) : (
                      <div className="flex flex-col items-center justify-center gap-3 py-6 text-sm text-muted-foreground">
                        <span className="grid size-10 place-items-center rounded-full bg-secondary">
                          <TrayIcon className="h-4 w-4" aria-hidden />
                        </span>
                        <p>{emptyTableMsg}</p>
                        {isFilteredEmpty ? (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={clearFilters}
                          >
                            Clear search and filters
                          </Button>
                        ) : null}
                      </div>
                    )}
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
          {renderPaginationFooter("")}
        </div>
      )}
    </div>
  );
}
