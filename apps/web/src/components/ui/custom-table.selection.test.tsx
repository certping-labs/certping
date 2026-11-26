// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { ColumnDef } from "@tanstack/react-table";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { CustomTable } from "@/components/ui/custom-table";

jest.mock("@/components/ui/select", () =>
  jest.requireActual("@/test/select-mock"),
);

type Row = { id: string; name: string; status: string };

const columns: ColumnDef<Row>[] = [
  { accessorKey: "name", header: "Name" },
  { accessorKey: "status", header: "Status" },
];

const alpha: Row = { id: "a", name: "alpha", status: "ACTIVE" };
const beta: Row = { id: "b", name: "beta", status: "FAILED" };
const gamma: Row = { id: "c", name: "gamma", status: "FAILED" };

function ControlledTable({
  data,
  onBulk,
  onSelectionChange,
  pendingMessage,
}: {
  data: Row[];
  onBulk: (rows: Row[]) => void;
  onSelectionChange?: (selection: Record<string, boolean>) => void;
  pendingMessage?: string;
}) {
  const [rowSelection, setRowSelection] = React.useState({});
  return (
    <>
      <button type="button" onClick={() => setRowSelection({})}>
        reset
      </button>
      <CustomTable<Row, unknown>
        columns={columns}
        data={data}
        showPagination={false}
        selectable
        searchBy="name"
        filters={[
          {
            id: "status",
            type: "select",
            label: "Status",
            options: [
              { label: "All statuses", value: "all" },
              { label: "Active", value: "ACTIVE" },
              { label: "Failed", value: "FAILED" },
            ],
          },
        ]}
        canSelectRow={(row) => row.id !== "c"}
        getRowId={(row) => row.id}
        getRowSelectionLabel={(row) => `Select ${row.name}`}
        rowSelection={rowSelection}
        onRowSelectionChange={(next) => {
          setRowSelection(next);
          onSelectionChange?.(next);
        }}
        selectionShortcuts={[
          {
            label: "Select all failed",
            pickRows: (rows) => rows.filter((row) => row.status === "FAILED"),
          },
        ]}
        bulkActions={[
          {
            label: (count, rows) =>
              `Remove ${count} (${rows.map((row) => row.name).join(",")})`,
            onClick: onBulk,
          },
        ]}
        selectionActionsPendingMessage={pendingMessage}
      />
    </>
  );
}

describe("CustomTable selection", () => {
  it("keeps selecting after a selected row leaves the data", async () => {
    const user = userEvent.setup();
    const onRowSelect = jest.fn();
    const table = (data: Row[]) => (
      <CustomTable<Row, unknown>
        columns={columns}
        data={data}
        showPagination={false}
        selectable
        getRowId={(row) => row.id}
        onRowSelect={onRowSelect}
      />
    );
    const { rerender } = render(table([alpha, beta]));

    await user.click(screen.getAllByRole("checkbox")[2]);
    expect(onRowSelect).toHaveBeenLastCalledWith([beta]);

    // beta is gone (deleted, say) while its id is still in the selection.
    rerender(table([alpha]));
    onRowSelect.mockClear();
    await user.click(screen.getAllByRole("checkbox")[1]);

    expect(onRowSelect).toHaveBeenCalledTimes(1);
    expect(onRowSelect).toHaveBeenLastCalledWith([alpha]);
  });

  it("names each row checkbox and lets the owner reset a controlled selection", async () => {
    const user = userEvent.setup();
    render(<ControlledTable data={[alpha, beta]} onBulk={jest.fn()} />);

    await user.click(screen.getByRole("checkbox", { name: "Select beta" }));
    expect(
      screen.getByRole("button", { name: "Remove 1 (beta)" }),
    ).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "reset" }));
    expect(
      screen.queryByRole("button", { name: /^Remove/ }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("checkbox", { name: "Select beta" }),
    ).not.toBeChecked();
  });

  it("selects every selectable row a shortcut picks from the filtered result", async () => {
    const user = userEvent.setup();
    const onBulk = jest.fn();
    render(<ControlledTable data={[alpha, beta, gamma]} onBulk={onBulk} />);

    await user.click(screen.getByRole("button", { name: "Select all failed" }));
    // gamma is failed but not selectable, so only beta is picked.
    await user.click(screen.getByRole("button", { name: "Remove 1 (beta)" }));
    expect(onBulk).toHaveBeenCalledWith([beta]);
  });

  it("gives the shortcut a default-size button, not the compact one", () => {
    render(<ControlledTable data={[beta]} onBulk={jest.fn()} />);
    const shortcut = screen.getByRole("button", { name: "Select all failed" });
    expect(shortcut).toHaveClass("h-10");
    expect(shortcut).not.toHaveClass("h-8");
  });

  it("disables shortcuts and bulk actions with a visible reason while pending", async () => {
    const user = userEvent.setup();
    const onBulk = jest.fn();
    const { rerender } = render(
      <ControlledTable
        data={[alpha, beta]}
        onBulk={onBulk}
        pendingMessage="Loading all rows…"
      />,
    );

    const shortcut = screen.getByRole("button", { name: "Select all failed" });
    expect(shortcut).toBeDisabled();
    expect(screen.getByRole("status")).toHaveTextContent("Loading all rows…");
    expect(shortcut).toHaveAccessibleDescription("Loading all rows…");

    // Picking rows by hand still works; acting on them waits.
    await user.click(screen.getByRole("checkbox", { name: "Select beta" }));
    expect(
      screen.getByRole("button", { name: "Remove 1 (beta)" }),
    ).toBeDisabled();

    rerender(<ControlledTable data={[alpha, beta]} onBulk={onBulk} />);
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Remove 1 (beta)" }));
    expect(onBulk).toHaveBeenCalledWith([beta]);
  });

  it("hides a shortcut that would pick nothing", async () => {
    render(<ControlledTable data={[alpha]} onBulk={jest.fn()} />);
    expect(
      screen.queryByRole("button", { name: "Select all failed" }),
    ).not.toBeInTheDocument();
  });

  it("clears the selection when a filter changes", async () => {
    const user = userEvent.setup();
    const onSelectionChange = jest.fn();
    render(
      <ControlledTable
        data={[alpha, beta]}
        onBulk={jest.fn()}
        onSelectionChange={onSelectionChange}
      />,
    );

    await user.click(screen.getByRole("checkbox", { name: "Select beta" }));
    await user.click(screen.getByRole("button", { name: "Failed" }));

    await waitFor(() => expect(onSelectionChange).toHaveBeenLastCalledWith({}));
    expect(
      screen.getByRole("checkbox", { name: "Select beta" }),
    ).not.toBeChecked();
  });

  it("clears the selection when the search changes", async () => {
    const user = userEvent.setup();
    render(<ControlledTable data={[alpha, beta]} onBulk={jest.fn()} />);

    await user.click(screen.getByRole("checkbox", { name: "Select alpha" }));
    expect(
      screen.getByRole("button", { name: "Remove 1 (alpha)" }),
    ).toBeInTheDocument();
    await user.type(screen.getByRole("textbox"), "alp");

    await waitFor(() =>
      expect(
        screen.queryByRole("button", { name: /^Remove/ }),
      ).not.toBeInTheDocument(),
    );
    expect(
      screen.getByRole("checkbox", { name: "Select alpha" }),
    ).not.toBeChecked();
  });
});
