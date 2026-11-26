// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import {
  useFieldArray,
  type FieldValues,
  type ArrayPath,
  type Path,
  type UseFormReturn,
} from "react-hook-form";
import { PlusIcon, TrashIcon } from "@phosphor-icons/react";

import { Button } from "@/components/ui/button";
import {
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";

export function StringListFormField<TFieldValues extends FieldValues>({
  form,
  name,
  label,
  placeholder,
  addLabel = "Add",
  description,
}: {
  form: UseFormReturn<TFieldValues>;
  name: ArrayPath<TFieldValues>;
  label: string;
  placeholder?: string;
  addLabel?: string;
  description?: string;
}) {
  const fieldArray = useFieldArray({
    control: form.control,
    name,
  });

  return (
    <FormField
      control={form.control}
      name={name as Path<TFieldValues>}
      render={() => (
        <FormItem>
          <FormLabel>{label}</FormLabel>
          <div className="space-y-2">
            {fieldArray.fields.map((field, index) => (
              <div key={field.id} className="flex items-center gap-2">
                <FormField
                  control={form.control}
                  name={`${name}.${index}` as Path<TFieldValues>}
                  render={({ field: inputField }) => (
                    <FormItem className="flex-1">
                      <FormControl>
                        <Input
                          aria-label={`${label} ${index + 1}`}
                          className="h-10"
                          placeholder={placeholder}
                          {...inputField}
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <Button
                  type="button"
                  variant="destructive"
                  size="icon"
                  className="h-10 w-10"
                  aria-label={`Remove ${label} ${index + 1}`}
                  onClick={() => fieldArray.remove(index)}
                >
                  <TrashIcon className="h-4 w-4" />
                </Button>
              </div>
            ))}
            <Button
              type="button"
              variant="default"
              size="sm"
              className="gap-2 text-gray-50"
              onClick={() => fieldArray.append("" as never)}
            >
              <PlusIcon className="h-4 w-4" />
              {addLabel}
            </Button>
          </div>
          {description ? (
            <p className="text-xs text-muted-foreground">{description}</p>
          ) : null}
          <FormMessage />
        </FormItem>
      )}
    />
  );
}
