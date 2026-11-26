// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import "@tanstack/react-table";

declare module "@tanstack/react-table" {
  // Merged declarations must repeat the library's type parameters, used or not.
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  interface ColumnMeta<TData, TValue> {
    /** Classes for the column's header and every cell, e.g. hiding it below a breakpoint. */
    className?: string;
    /**
     * Sets no width: in the fixed layout the column takes what the sized
     * columns leave, so it grows and shrinks with the table.
     */
    fluid?: boolean;
  }
}
