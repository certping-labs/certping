// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";

/**
 * A plain-button stand-in for the Radix select: every option is a button that picks
 * itself, so tests choose a value with one click instead of driving a portal.
 * Use with `jest.mock("@/components/ui/select", () => jest.requireActual("@/test/select-mock"))`.
 */
const SelectContext = React.createContext<{
  onValueChange?: (value: string) => void;
} | null>(null);

export function Select({
  onValueChange,
  children,
}: {
  value?: string;
  onValueChange?: (value: string) => void;
  children: React.ReactNode;
}) {
  return (
    <SelectContext.Provider value={{ onValueChange }}>
      <div>{children}</div>
    </SelectContext.Provider>
  );
}

export function SelectTrigger({
  children,
  "aria-label": ariaLabel,
}: {
  children: React.ReactNode;
  "aria-label"?: string;
}) {
  return <div aria-label={ariaLabel}>{children}</div>;
}

export function SelectValue({ placeholder }: { placeholder?: string }) {
  return <span>{placeholder ?? ""}</span>;
}

export function SelectContent({ children }: { children: React.ReactNode }) {
  return <div>{children}</div>;
}

export function SelectItem({
  value,
  children,
}: {
  value: string;
  children: React.ReactNode;
}) {
  const context = React.useContext(SelectContext);
  return (
    <button type="button" onClick={() => context?.onValueChange?.(value)}>
      {children}
    </button>
  );
}
