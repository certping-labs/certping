// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useId } from "react";
import type { Control } from "react-hook-form";

import { Badge } from "@/components/ui/badge";
import { FormControl, FormField, FormItem } from "@/components/ui/form";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import type {
  CertificateExportFormValues,
  CertificateExportFormatOption,
} from "@/lib/cert-manager/certificate-export-form";

interface ExportFormatFieldProps {
  control: Control<CertificateExportFormValues>;
  options: readonly CertificateExportFormatOption[];
  disabled: boolean;
  onFormatChange: (format: string) => void;
}

/** The format choice, one labelled row per format with what it is for. */
export function ExportFormatField({
  control,
  options,
  disabled,
  onFormatChange,
}: ExportFormatFieldProps) {
  const legendId = useId();
  return (
    <FormField
      control={control}
      name="format"
      render={({ field }) => (
        <FormItem className="space-y-2">
          <p id={legendId} className="text-sm font-medium text-foreground">
            Format
          </p>
          <FormControl>
            <RadioGroup
              aria-labelledby={legendId}
              value={field.value}
              onValueChange={(value) => {
                field.onChange(value);
                onFormatChange(value);
              }}
              disabled={disabled}
              className="gap-2"
            >
              {options.map((option) => (
                <FormatOptionRow key={option.format} option={option} />
              ))}
            </RadioGroup>
          </FormControl>
        </FormItem>
      )}
    />
  );
}

function FormatOptionRow({
  option,
}: {
  option: CertificateExportFormatOption;
}) {
  const id = useId();
  const titleId = `${id}-title`;
  const descriptionId = `${id}-description`;
  const recommendedId = `${id}-recommended`;
  return (
    <label
      htmlFor={id}
      className="flex min-h-11 cursor-pointer items-start gap-3 rounded-[10px] border border-border px-3.5 py-3 transition-colors duration-150 hover:border-[hsl(var(--control-border-hover))] has-disabled:cursor-not-allowed has-data-[state=checked]:border-primary"
    >
      <RadioGroupItem
        id={id}
        value={option.format}
        aria-labelledby={titleId}
        aria-describedby={
          option.isRecommended
            ? `${recommendedId} ${descriptionId}`
            : descriptionId
        }
        className="mt-0.5"
      />
      <span className="min-w-0 space-y-0.5">
        <span className="flex flex-wrap items-center gap-2 text-sm font-medium text-foreground">
          <span id={titleId}>{option.label}</span>
          {option.isRecommended ? (
            <Badge id={recommendedId} variant="secondary">
              Recommended
            </Badge>
          ) : null}
        </span>
        <span
          id={descriptionId}
          className="block text-xs leading-5 text-muted-foreground"
        >
          {option.description}
        </span>
      </span>
    </label>
  );
}
