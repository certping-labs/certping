// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React, { memo } from "react";
import type { Control } from "react-hook-form";

import {
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import type { CertificateRequestValues } from "@/lib/cert-manager/certificate-request-form";

interface CertificateDomainFieldProps {
  control: Control<CertificateRequestValues>;
  onDomainBlur: () => void;
  wildcard: boolean;
}

export const CertificateDomainField = memo(function CertificateDomainField({
  control,
  onDomainBlur,
  wildcard,
}: CertificateDomainFieldProps) {
  return (
    <FormField
      control={control}
      name="domain"
      render={({ field }) => (
        <FormItem>
          <FormLabel>Domain</FormLabel>
          <FormControl>
            <div className="relative">
              {wildcard ? (
                <span className="pointer-events-none absolute inset-y-0 left-0 z-10 inline-flex items-center rounded-l-[calc(var(--radius)+2px)] border border-r-0 border-primary/60 bg-primary/10 px-3 font-mono text-sm text-primary">
                  *.
                </span>
              ) : null}
              <Input
                autoComplete="off"
                className={`h-10 ${wildcard ? "border-primary pl-12 ring-1 ring-primary/30" : ""}`}
                placeholder="example.com"
                {...field}
                onBlur={() => {
                  field.onBlur();
                  onDomainBlur();
                }}
              />
            </div>
          </FormControl>
          <FormDescription>
            Enter the primary domain you want to secure.
          </FormDescription>
          <FormMessage />
        </FormItem>
      )}
    />
  );
});
