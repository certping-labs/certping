// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { ColumnDef } from "@tanstack/react-table";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

// Keep tests deterministic by mocking Radix-ish wrappers used by CustomTable.
jest.mock("@/components/ui/dropdown-menu", () => ({
  DropdownMenu: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
  DropdownMenuTrigger: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
  DropdownMenuContent: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
  DropdownMenuLabel: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
  DropdownMenuSeparator: () => <hr />,
  DropdownMenuCheckboxItem: ({
    children,
    checked,
    onCheckedChange,
  }: {
    children: React.ReactNode;
    checked?: boolean;
    onCheckedChange?: (value: boolean) => void;
  }) => (
    <button type="button" onClick={() => onCheckedChange?.(!checked)}>
      {children}
    </button>
  ),
}));

const SelectContext = React.createContext<{
  value?: string;
  onValueChange?: (value: string) => void;
} | null>(null);

jest.mock("@/components/ui/select", () => ({
  Select: ({
    value,
    onValueChange,
    children,
  }: {
    value?: string;
    onValueChange?: (value: string) => void;
    children: React.ReactNode;
  }) => (
    <SelectContext.Provider value={{ value, onValueChange }}>
      <div>{children}</div>
    </SelectContext.Provider>
  ),
  SelectTrigger: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
  SelectValue: ({ placeholder }: { placeholder?: string }) => (
    <span>{placeholder ?? ""}</span>
  ),
  SelectContent: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
  SelectItem: ({
    value,
    children,
  }: {
    value: string;
    children: React.ReactNode;
  }) => {
    const ctx = React.useContext(SelectContext);
    return (
      <button type="button" onClick={() => ctx?.onValueChange?.(value)}>
        {children}
      </button>
    );
  },
}));

jest.mock("@/components/ui/popover", () => ({
  Popover: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
  PopoverTrigger: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
  PopoverContent: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
}));

jest.mock("@/components/ui/calendar", () => ({
  Calendar: ({
    mode,
    onSelect,
  }: {
    mode?: "single" | "range";
    onSelect?: (value: unknown) => void;
  }) => (
    <button
      type="button"
      onClick={() => {
        if (mode === "single") {
          onSelect?.(new Date("2026-01-01T00:00:00Z"));
        } else {
          onSelect?.({
            from: new Date("2026-01-01T00:00:00Z"),
            to: new Date("2026-01-02T00:00:00Z"),
          });
        }
      }}
    >
      Pick date
    </button>
  ),
}));

import { CustomTable } from "@/components/ui/custom-table";

type Row = { id: string; name: string; status: string };

const columns: ColumnDef<Row>[] = [
  { accessorKey: "name", header: "Name" },
  { accessorKey: "status", header: "Status" },
];

describe("CustomTable (filters)", () => {
  it("applies select filter and calls onFilterValuesChange", async () => {
    const user = userEvent.setup();
    const onFilterValuesChange = jest.fn();

    render(
      <CustomTable<Row, unknown>
        columns={columns}
        data={[
          { id: "1", name: "alpha", status: "ACTIVE" },
          { id: "2", name: "beta", status: "FAILED" },
        ]}
        showPagination={false}
        filters={[
          {
            id: "status",
            type: "select",
            label: "Status",
            options: [
              { label: "All", value: "all" },
              { label: "ACTIVE", value: "ACTIVE" },
              { label: "FAILED", value: "FAILED" },
            ],
          },
        ]}
        onFilterValuesChange={onFilterValuesChange}
      />,
    );

    expect(screen.getByText("alpha")).toBeInTheDocument();
    expect(screen.getByText("beta")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "FAILED" }));
    await waitFor(() =>
      expect(onFilterValuesChange).toHaveBeenCalledWith({ status: "FAILED" }),
    );
    expect(screen.getAllByText("FAILED").length).toBeGreaterThan(0);
    expect(
      screen.getByRole("button", { name: "Clear filters" }),
    ).toBeInTheDocument();
  });

  it("clears filters by choosing All or Clear filters", async () => {
    const user = userEvent.setup();

    render(
      <CustomTable<Row, unknown>
        columns={columns}
        data={[
          { id: "1", name: "alpha", status: "ACTIVE" },
          { id: "2", name: "beta", status: "FAILED" },
        ]}
        showPagination={false}
        filters={[
          {
            id: "status",
            type: "select",
            label: "Status",
            options: [
              { label: "All", value: "all" },
              { label: "ACTIVE", value: "ACTIVE" },
              { label: "FAILED", value: "FAILED" },
            ],
          },
        ]}
      />,
    );

    await user.click(screen.getByRole("button", { name: "FAILED" }));
    // Column filter should narrow the visible rows.
    await waitFor(() => {
      expect(screen.getByText("beta")).toBeInTheDocument();
      expect(screen.queryByText("alpha")).not.toBeInTheDocument();
    });

    // Reset filter back to "all".
    await user.click(screen.getByRole("button", { name: "All" }));
    await waitFor(() => expect(screen.getByText("alpha")).toBeInTheDocument());
    expect(screen.getByText("beta")).toBeInTheDocument();

    expect(
      screen.queryByRole("button", { name: "Clear filters" }),
    ).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "FAILED" }));
    await waitFor(() =>
      expect(screen.queryByText("alpha")).not.toBeInTheDocument(),
    );
    await user.click(screen.getByRole("button", { name: "Clear filters" }));
    await waitFor(() => expect(screen.getByText("alpha")).toBeInTheDocument());
  });

  it("supports date and date-range filters with clear actions", async () => {
    const user = userEvent.setup();
    const datedColumns: Array<
      ColumnDef<Row & { createdAt: string; expiresAt: string }>
    > = [
      { accessorKey: "name", header: "Name" },
      { accessorKey: "createdAt", header: "Created" },
      { accessorKey: "expiresAt", header: "Expires" },
    ];

    render(
      <CustomTable<Row & { createdAt: string; expiresAt: string }, unknown>
        columns={datedColumns}
        data={[
          {
            id: "1",
            name: "alpha",
            status: "ACTIVE",
            createdAt: "2026-01-01T00:00:00Z",
            expiresAt: "2026-02-01T00:00:00Z",
          },
          {
            id: "2",
            name: "beta",
            status: "FAILED",
            createdAt: "2026-01-02T00:00:00Z",
            expiresAt: "2026-02-02T00:00:00Z",
          },
        ]}
        showPagination={false}
        filters={[
          { id: "createdAt", type: "date", label: "Created" },
          { id: "expiresAt", type: "date-range", label: "Expires" },
        ]}
      />,
    );

    // Pick date (single).
    await user.click(screen.getAllByRole("button", { name: /Pick date/i })[0]!);
    // Pick date range.
    await user.click(screen.getAllByRole("button", { name: /Pick date/i })[1]!);

    // Clear individual badge buttons should be available once filters are set.
    await waitFor(() => {
      expect(
        screen.getByRole("button", { name: /Clear Created filter/i }),
      ).toBeInTheDocument();
      expect(
        screen.getByRole("button", { name: /Clear Expires filter/i }),
      ).toBeInTheDocument();
    });

    await user.click(
      screen.getByRole("button", { name: /Clear Created filter/i }),
    );
    await user.click(
      screen.getByRole("button", { name: /Clear Expires filter/i }),
    );
  });

  it("supports column visibility toggles", async () => {
    const user = userEvent.setup();
    render(
      <CustomTable<Row, unknown>
        columns={columns}
        data={[]}
        showPagination={false}
        showColumnVisibility
        defaultHiddenColumns={["status"]}
      />,
    );

    // Columns dropdown renders checkbox items for hideable columns.
    await user.click(screen.getByRole("button", { name: "Status" }));
  });
});
