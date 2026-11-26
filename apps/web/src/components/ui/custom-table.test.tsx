// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { ColumnDef } from "@tanstack/react-table";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { CustomTable } from "@/components/ui/custom-table";

type Row = {
  id: string;
  name: string;
  status: string;
  unread?: boolean;
};

const columns: ColumnDef<Row>[] = [
  { accessorKey: "name", header: "Name" },
  { accessorKey: "status", header: "Status" },
];

const rows: Row[] = [
  { id: "1", name: "beta", status: "FAILED", unread: true },
  { id: "2", name: "alpha", status: "ACTIVE" },
];

describe("CustomTable", () => {
  it("renders loading skeleton rows", () => {
    const { container } = render(
      <CustomTable<Row, unknown>
        columns={columns}
        data={[]}
        isLoading
        showPagination={false}
      />,
    );

    expect(container.querySelectorAll(".animate-pulse").length).toBeGreaterThan(
      0,
    );
  });

  it("renders empty state when no rows exist", async () => {
    render(
      <CustomTable<Row, unknown>
        columns={columns}
        data={[]}
        showPagination={false}
        emptyTableMsg="No rows"
      />,
    );

    expect(await screen.findByText("No rows")).toBeInTheDocument();
  });

  it("filters rows from search input and clears it from the field", async () => {
    const user = userEvent.setup();
    render(
      <CustomTable<Row, unknown>
        columns={columns}
        data={rows}
        searchBy={["name", "status"]}
        searchPlaceholder="Search rows"
        showPagination={false}
      />,
    );

    await user.type(screen.getByPlaceholderText("Search rows"), "alpha");
    await waitFor(() => {
      expect(screen.getByText("alpha")).toBeInTheDocument();
      expect(screen.queryByText("beta")).not.toBeInTheDocument();
    });

    await user.click(screen.getByRole("button", { name: "Clear search" }));
    expect(screen.getByPlaceholderText("Search rows")).toHaveValue("");
    await waitFor(() => expect(screen.getByText("beta")).toBeInTheDocument());
  });

  it("offers to clear the search when it filters every row out", async () => {
    const user = userEvent.setup();
    render(
      <CustomTable<Row, unknown>
        columns={columns}
        data={rows}
        searchBy={["name"]}
        searchPlaceholder="Search rows"
        emptyTableMsg="No rows match."
        showPagination={false}
      />,
    );

    await user.type(screen.getByPlaceholderText("Search rows"), "zzzz");
    expect(await screen.findByText("No rows match.")).toBeInTheDocument();

    await user.click(
      screen.getByRole("button", { name: "Clear search and filters" }),
    );
    await waitFor(() => expect(screen.getByText("alpha")).toBeInTheDocument());
  });

  it("shows a caller's empty state when there is no data at all", () => {
    render(
      <CustomTable<Row, unknown>
        columns={columns}
        data={[]}
        showPagination={false}
        emptyState={<p>No certificates yet</p>}
      />,
    );

    expect(screen.getByText("No certificates yet")).toBeInTheDocument();
  });

  it("debounces search change notifications for URL-backed tables", async () => {
    jest.useFakeTimers();
    try {
      const user = userEvent.setup({ advanceTimers: jest.advanceTimersByTime });
      const onSearchTermChange = jest.fn();

      render(
        <CustomTable<Row, unknown>
          columns={columns}
          data={rows}
          searchBy={["name", "status"]}
          searchPlaceholder="Search rows"
          showPagination={false}
          onSearchTermChange={onSearchTermChange}
        />,
      );

      onSearchTermChange.mockClear();
      await user.type(screen.getByPlaceholderText("Search rows"), "alpha");

      expect(onSearchTermChange).not.toHaveBeenCalled();

      act(() => {
        jest.advanceTimersByTime(249);
      });
      expect(onSearchTermChange).not.toHaveBeenCalled();

      act(() => {
        jest.advanceTimersByTime(1);
      });
      expect(onSearchTermChange).toHaveBeenCalledWith("alpha");
    } finally {
      jest.useRealTimers();
    }
  });

  it("supports sortable headers and selectable bulk actions", async () => {
    const user = userEvent.setup();
    const onBulk = jest.fn();
    const onSelect = jest.fn();

    render(
      <CustomTable<Row, unknown>
        columns={columns.map((column) => ({ ...column, enableSorting: true }))}
        data={rows}
        showPagination={false}
        selectable
        getRowId={(row) => row.id}
        onRowSelect={onSelect}
        bulkActions={[
          {
            label: "Delete",
            variant: "destructive",
            onClick: (selected) => onBulk(selected),
          },
        ]}
      />,
    );

    await user.click(screen.getByRole("button", { name: /Name/i }));
    const tableRows = screen.getAllByRole("row");
    expect(tableRows[1]).toHaveTextContent("alpha");

    await user.click(screen.getAllByRole("checkbox")[1]);
    await waitFor(() => expect(onSelect).toHaveBeenCalled());
    await user.click(screen.getByRole("button", { name: /Delete/i }));
    expect(onBulk).toHaveBeenCalledWith(
      expect.arrayContaining([
        expect.objectContaining({ id: expect.any(String) }),
      ]),
    );
  });

  it("keeps rows that cannot be selected out of select all and the bulk action", async () => {
    const user = userEvent.setup();
    const onBulk = jest.fn();
    const onSelect = jest.fn();
    const { rerender } = render(
      <CustomTable<Row, unknown>
        columns={columns}
        data={rows}
        showPagination={false}
        selectable
        canSelectRow={(row) => row.status !== "FAILED"}
        getRowId={(row) => row.id}
        onRowSelect={onSelect}
        bulkActions={[
          {
            label: (count) => `Remove ${count} rows`,
            onClick: (selected) => onBulk(selected),
          },
        ]}
      />,
    );

    const [failedRow] = screen.getAllByRole("checkbox", {
      name: "Select row",
    });
    expect(failedRow).toBeDisabled();

    await user.click(
      screen.getByRole("checkbox", { name: "Select all on this page" }),
    );
    await user.click(screen.getByRole("button", { name: "Remove 1 rows" }));
    expect(onBulk).toHaveBeenCalledWith([rows[1]]);
    expect(onSelect).toHaveBeenLastCalledWith([rows[1]]);

    rerender(
      <CustomTable<Row, unknown>
        columns={columns}
        data={rows}
        showPagination={false}
        selectable
        canSelectRow={() => false}
        getRowId={(row) => row.id}
        onRowSelect={onSelect}
        bulkActions={[
          {
            label: (count) => `Remove ${count} rows`,
            onClick: (selected) => onBulk(selected),
          },
        ]}
      />,
    );

    expect(
      screen.queryByRole("button", { name: /Remove \d+ rows/ }),
    ).not.toBeInTheDocument();
  });
});
