// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import * as React from "react";
import { cn } from "@/lib/utils";

const controlClassName =
  "w-full rounded-(--radius-control) border border-[hsl(var(--control-border))] bg-[hsl(var(--control-bg))] text-sm text-foreground transition-[border-color,box-shadow,background-color] duration-150 ease-out-soft placeholder:text-muted-foreground hover:border-[hsl(var(--control-border-hover))] focus-visible:border-brand focus-visible:outline-hidden focus-visible:ring-1 focus-visible:ring-brand focus-visible:ring-offset-0 disabled:cursor-not-allowed disabled:bg-secondary disabled:opacity-60 aria-invalid:border-destructive aria-invalid:focus-visible:ring-destructive";

// Credential forms opt out of browser and password manager autofill, which
// otherwise drops the saved app login into tenant IDs and client secrets.
const NoAutofillContext = React.createContext(false);

function NoAutofill({ children }: { children: React.ReactNode }) {
  return (
    <NoAutofillContext.Provider value>{children}</NoAutofillContext.Provider>
  );
}

const Input = React.forwardRef<HTMLInputElement, React.ComponentProps<"input">>(
  ({ className, type, ...props }, ref) => {
    const noAutofill = React.useContext(NoAutofillContext);
    const autofillProps = noAutofill
      ? {
          autoComplete: type === "password" ? "new-password" : "off",
          "data-1p-ignore": "true",
          "data-lpignore": "true",
        }
      : {};
    return (
      <input
        type={type}
        {...autofillProps}
        className={cn(
          controlClassName,
          "flex h-10 px-3.5 py-2 file:border-0 file:bg-transparent file:text-sm file:font-medium file:text-foreground",
          className,
        )}
        ref={ref}
        {...props}
      />
    );
  },
);
Input.displayName = "Input";

const NoAutofillForm = React.forwardRef<
  HTMLFormElement,
  React.ComponentProps<"form">
>((props, ref) => (
  <NoAutofill>
    <form autoComplete="off" ref={ref} {...props} />
  </NoAutofill>
));
NoAutofillForm.displayName = "NoAutofillForm";

export { Input, NoAutofill, NoAutofillForm, controlClassName };
