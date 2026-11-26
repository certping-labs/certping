// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { ColumnDef } from "@tanstack/react-table";
import { render, screen, within } from "@testing-library/react";
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

describe("CustomTable (core behaviors)", () => {
  it("renders title + search header layout when column visibility is hidden", async () => {
    const user = userEvent.setup();
    render(
      <CustomTable<Row, unknown>
        columns={columns}
        data={[
          { id: "1", name: "alpha", status: "ACTIVE" },
          { id: "2", name: "beta", status: "FAILED" },
        ]}
        title="Deployments"
        searchBy={["name"]}
        showColumnVisibility={false}
        showPagination={false}
      />,
    );

    expect(screen.getByText("Deployments")).toBeInTheDocument();
    const search = screen.getByPlaceholderText("Search...");
    await user.type(search, "alp");
    expect(screen.getByText("alpha")).toBeInTheDocument();
    expect(screen.queryByText("beta")).not.toBeInTheDocument();
  });

  it("supports row click callback and unread styling", async () => {
    const user = userEvent.setup();
    const onRowClick = jest.fn();
    const { container } = render(
      <CustomTable<Row, unknown>
        columns={columns}
        data={[
          { id: "1", name: "alpha", status: "ACTIVE", unread: true },
          { id: "2", name: "beta", status: "FAILED" },
        ]}
        showPagination={false}
        onRowClick={onRowClick}
        getRowId={(row) => row.id}
      />,
    );

    const rowEls = container.querySelectorAll("tbody tr");
    expect(rowEls[0]).toHaveAttribute("data-unread", "true");
    await user.click(within(rowEls[1] as HTMLElement).getByText("beta"));
    expect(onRowClick).toHaveBeenCalledWith(
      expect.objectContaining({ id: "2" }),
    );
  });

  it("supports selection + pagination summary text", async () => {
    const user = userEvent.setup();
    render(
      <CustomTable<Row, unknown>
        columns={columns}
        data={[
          { id: "1", name: "alpha", status: "ACTIVE" },
          { id: "2", name: "beta", status: "FAILED" },
        ]}
        selectable
        getRowId={(row) => row.id}
        showPagination
        pageSize={1}
      />,
    );

    const selectionSummaries = screen.getAllByText((_, element) =>
      Boolean(element?.textContent?.includes("row(s) selected.")),
    );
    expect(
      selectionSummaries.some((node) => node.textContent?.includes("0 of")),
    ).toBe(true);

    // Select the first row using the row checkbox; selection summary should appear.
    const checkboxes = screen.getAllByRole("checkbox");
    await user.click(checkboxes[1]!);
    const selectedSummaries = screen.getAllByText((_, element) =>
      Boolean(element?.textContent?.includes("row(s) selected.")),
    );
    expect(
      selectedSummaries.some((node) => node.textContent?.includes("1 of")),
    ).toBe(true);
  });

  it("renders resizable column handles when enabled", () => {
    const { container } = render(
      <CustomTable<Row, unknown>
        columns={columns}
        data={[]}
        showPagination={false}
        resizable
      />,
    );

    expect(
      container.querySelectorAll(".cursor-col-resize").length,
    ).toBeGreaterThan(0);
  });
});
