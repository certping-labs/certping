// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { act, fireEvent, render, screen } from "@testing-library/react";

import { CustomTable } from "@/components/ui/custom-table";

interface Row {
  id: string;
  name: string;
}

const rows: Row[] = [
  { id: "1", name: "alpha" },
  { id: "2", name: "beta" },
  { id: "3", name: "gamma" },
];

const columns: ColumnDef<Row>[] = [
  {
    accessorKey: "name",
    header: "Name",
    cell: ({ row }) => (
      <a href={`/rows/${row.original.id}`}>{row.original.name}</a>
    ),
  },
  {
    id: "extra",
    header: "Extra",
    meta: { className: "hidden md:table-cell" },
    cell: () => "more",
  },
];

const rowOf = (name: string): HTMLElement => {
  const row = screen.getByText(name).closest("tr");
  if (!row) {
    throw new Error(`No row for ${name}`);
  }
  return row;
};

describe("CustomTable onRowIntent", () => {
  beforeEach(() => {
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it("reports nothing while the pointer only passes over rows", () => {
    const onRowIntent = jest.fn();
    render(
      <CustomTable<Row, unknown>
        columns={columns}
        data={rows}
        showPagination={false}
        onRowIntent={onRowIntent}
      />,
    );

    for (const name of ["alpha", "beta", "gamma"]) {
      fireEvent.mouseEnter(rowOf(name));
      act(() => jest.advanceTimersByTime(30));
      fireEvent.mouseLeave(rowOf(name));
    }
    act(() => jest.advanceTimersByTime(500));

    expect(onRowIntent).not.toHaveBeenCalled();
  });

  it("reports the row the pointer rests on, once", () => {
    const onRowIntent = jest.fn();
    render(
      <CustomTable<Row, unknown>
        columns={columns}
        data={rows}
        showPagination={false}
        onRowIntent={onRowIntent}
      />,
    );

    fireEvent.mouseEnter(rowOf("alpha"));
    fireEvent.mouseLeave(rowOf("alpha"));
    fireEvent.mouseEnter(rowOf("beta"));
    act(() => jest.advanceTimersByTime(99));
    expect(onRowIntent).not.toHaveBeenCalled();

    act(() => jest.advanceTimersByTime(1));
    expect(onRowIntent).toHaveBeenCalledTimes(1);
    expect(onRowIntent).toHaveBeenCalledWith(rows[1]);
  });

  it("reports a row at once when keyboard focus moves into it", () => {
    const onRowIntent = jest.fn();
    render(
      <CustomTable<Row, unknown>
        columns={columns}
        data={rows}
        showPagination={false}
        onRowIntent={onRowIntent}
      />,
    );

    act(() => screen.getByRole("link", { name: "gamma" }).focus());

    expect(onRowIntent).toHaveBeenCalledWith(rows[2]);
  });

  it("does not fire a pending hover after the table unmounts", () => {
    const onRowIntent = jest.fn();
    const { unmount } = render(
      <CustomTable<Row, unknown>
        columns={columns}
        data={rows}
        showPagination={false}
        onRowIntent={onRowIntent}
      />,
    );

    fireEvent.mouseEnter(rowOf("alpha"));
    unmount();
    act(() => jest.advanceTimersByTime(500));

    expect(onRowIntent).not.toHaveBeenCalled();
  });

  it("schedules nothing on hover when no intent handler is given", () => {
    render(
      <CustomTable<Row, unknown>
        columns={columns}
        data={rows}
        showPagination={false}
      />,
    );
    const pendingBefore = jest.getTimerCount();

    fireEvent.mouseEnter(rowOf("alpha"));

    expect(jest.getTimerCount()).toBe(pendingBefore);
  });
});

describe("CustomTable column meta className", () => {
  it("applies to the header and every cell of the column", () => {
    render(
      <CustomTable<Row, unknown>
        columns={columns}
        data={rows}
        showPagination={false}
      />,
    );

    expect(screen.getByRole("columnheader", { name: "Extra" })).toHaveClass(
      "hidden",
      "md:table-cell",
    );
    const extraCells = screen.getAllByText("more");
    expect(extraCells).toHaveLength(3);
    for (const cell of extraCells) {
      expect(cell.closest("td")).toHaveClass("hidden", "md:table-cell");
    }
  });

  it("applies to the skeleton cells too, so loading has the same columns", () => {
    const { container } = render(
      <CustomTable<Row, unknown>
        columns={columns}
        data={[]}
        isLoading
        loadingRowCount={2}
        showPagination={false}
      />,
    );

    const skeletonRows = container.querySelectorAll("tbody tr");
    expect(skeletonRows).toHaveLength(2);
    for (const row of Array.from(skeletonRows)) {
      const cells = row.querySelectorAll("td");
      expect(cells[0]).not.toHaveClass("hidden");
      expect(cells[1]).toHaveClass("hidden", "md:table-cell");
    }
  });
});
