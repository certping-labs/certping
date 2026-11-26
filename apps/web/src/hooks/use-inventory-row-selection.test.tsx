// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { act, renderHook } from "@testing-library/react";

import { useInventoryRowSelection } from "@/hooks/use-inventory-row-selection";

interface InventoryState {
  rowIds: string[];
  isComplete: boolean;
}

function renderSelection(initial: InventoryState) {
  return renderHook(
    ({ rowIds, isComplete }: InventoryState) =>
      useInventoryRowSelection(rowIds, isComplete),
    { initialProps: initial },
  );
}

describe("useInventoryRowSelection", () => {
  it("keeps the selection while pages arrive and when the final page completes the list", () => {
    const { result, rerender } = renderSelection({
      rowIds: ["a", "b"],
      isComplete: false,
    });
    act(() => result.current[1]({ a: true }));

    rerender({ rowIds: ["a", "b", "c"], isComplete: false });
    expect(result.current[0]).toEqual({ a: true });

    // The final page changes the rows and completes the list in one render.
    rerender({ rowIds: ["a", "b", "c", "d"], isComplete: true });
    expect(result.current[0]).toEqual({ a: true });
  });

  it("clears the selection when the selectable rows change after the list is complete", () => {
    const { result, rerender } = renderSelection({
      rowIds: ["a", "b"],
      isComplete: true,
    });
    act(() => result.current[1]({ a: true, b: true }));

    rerender({ rowIds: ["a", "b"], isComplete: true });
    expect(result.current[0]).toEqual({ a: true, b: true });

    rerender({ rowIds: ["a"], isComplete: true });
    expect(result.current[0]).toEqual({});
  });

  it("drops rows that vanished during a reload instead of carrying them", () => {
    const { result, rerender } = renderSelection({
      rowIds: ["a", "b"],
      isComplete: true,
    });
    act(() => result.current[1]({ a: true, b: true }));

    rerender({ rowIds: ["a"], isComplete: false });
    expect(result.current[0]).toEqual({ a: true });

    rerender({ rowIds: ["a", "b"], isComplete: true });
    expect(result.current[0]).toEqual({ a: true });
  });

  it("keeps a cleared selection empty through a reload of the same rows", () => {
    const { result, rerender } = renderSelection({
      rowIds: ["a", "b"],
      isComplete: true,
    });
    act(() => result.current[1]({ a: true }));
    act(() => result.current[1]({}));

    rerender({ rowIds: ["a", "b"], isComplete: false });
    rerender({ rowIds: ["a", "b", "c"], isComplete: true });
    expect(result.current[0]).toEqual({});
  });
});
