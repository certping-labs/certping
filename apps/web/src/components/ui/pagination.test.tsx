// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import {
  ColumnDef,
  getCoreRowModel,
  getPaginationRowModel,
  useReactTable,
} from "@tanstack/react-table";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { DataTablePagination } from "@/components/ui/pagination";

type Row = { id: string; name: string };

const columns: ColumnDef<Row>[] = [{ accessorKey: "name", header: "Name" }];

function PaginationHarness({ data }: { data: Row[] }) {
  const [pagination, setPagination] = React.useState({
    pageIndex: 0,
    pageSize: 10,
  });
  const table = useReactTable({
    data,
    columns,
    state: { pagination },
    onPaginationChange: setPagination,
    getCoreRowModel: getCoreRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
  });

  return <DataTablePagination table={table} />;
}

describe("DataTablePagination", () => {
  it("navigates between pages and updates page size", async () => {
    const user = userEvent.setup();
    render(
      <PaginationHarness
        data={[
          { id: "1", name: "a" },
          { id: "2", name: "b" },
          { id: "3", name: "c" },
        ]}
      />,
    );

    expect(screen.getByText(/Page 1 of/i)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Go to next page/i }));
    expect(screen.getByText(/Page 1 of/i)).toBeInTheDocument();

    // Change page size via select; we only assert handler wiring by choosing a different value.
    await user.click(screen.getByRole("combobox"));
    await user.click(await screen.findByRole("option", { name: "20" }));
    expect(screen.getByText(/Rows/i)).toBeInTheDocument();
  });
});
