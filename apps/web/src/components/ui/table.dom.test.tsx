// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";

import {
  Table,
  TableBody,
  TableCell,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

describe("Table", () => {
  it("sits flat on its container with quiet dividers, hover and selection", () => {
    render(
      <Table>
        <TableHeader data-testid="table-header">
          <TableRow>
            <TableCell>Credential</TableCell>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow data-testid="table-row" data-state="selected">
            <TableCell>Example credential</TableCell>
          </TableRow>
        </TableBody>
      </Table>,
    );

    expect(screen.getByTestId("table-header")).toHaveClass("sticky", "bg-card");
    expect(screen.getByTestId("table-row")).toHaveClass(
      "mg-row",
      "border-divider",
      "bg-transparent",
    );
    expect(screen.getByTestId("table-row")).toHaveAttribute(
      "data-state",
      "selected",
    );
  });
});
