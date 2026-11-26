// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useMemo, useState } from "react";
import type { RowSelectionState } from "@tanstack/react-table";

const EMPTY_ROW_SELECTION: RowSelectionState = {};

interface SelectionBaseline {
  selectableRowsKey: string;
  isInventoryComplete: boolean;
}

/** The selection minus rows that can no longer be selected; the same object when none drop. */
function keepSelectableRows(
  selection: RowSelectionState,
  selectableRowIds: ReadonlySet<string>,
): RowSelectionState {
  const selectedIds = Object.keys(selection);
  if (selectedIds.every((id) => selectableRowIds.has(id))) {
    return selection;
  }
  return Object.fromEntries(
    selectedIds
      .filter((id) => selectableRowIds.has(id))
      .map((id) => [id, selection[id]]),
  );
}

/**
 * Row selection for a list that loads page by page. Once the whole inventory
 * is loaded, any change to the selectable rows clears the selection, so it
 * never carries ids the list no longer offers. Rows arriving while the
 * inventory loads, and the final page completing it, keep what the user picked.
 *
 * @param selectableRowIds Ids of the rows that can be selected, in list order.
 * @param isInventoryComplete Whether every page of the list has arrived.
 * @returns The controlled selection and its setter, as `useState` returns them.
 */
export function useInventoryRowSelection(
  selectableRowIds: readonly string[],
  isInventoryComplete: boolean,
) {
  const [rowSelection, setRowSelection] =
    useState<RowSelectionState>(EMPTY_ROW_SELECTION);
  const selectableRowsKey = useMemo(
    () => selectableRowIds.join("\n"),
    [selectableRowIds],
  );
  const [baseline, setBaseline] = useState<SelectionBaseline>({
    selectableRowsKey,
    isInventoryComplete,
  });

  // Adjusting state during render (not in an effect) keeps a stale selection
  // from ever painting. Both flags must be read from the same render: the
  // final page flips completeness and changes the rows at once.
  if (
    baseline.selectableRowsKey !== selectableRowsKey ||
    baseline.isInventoryComplete !== isInventoryComplete
  ) {
    const hasRowsChangedWhileComplete =
      baseline.isInventoryComplete && isInventoryComplete;
    setBaseline({ selectableRowsKey, isInventoryComplete });
    if (hasRowsChangedWhileComplete) {
      setRowSelection(EMPTY_ROW_SELECTION);
    } else {
      const selectableIds = new Set(selectableRowIds);
      setRowSelection((current) => keepSelectableRows(current, selectableIds));
    }
  }

  return [rowSelection, setRowSelection] as const;
}
