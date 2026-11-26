// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import { PlusIcon, TrashIcon } from "@phosphor-icons/react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export function StringListEditor({
  label,
  values,
  onChange,
  placeholder,
  addLabel = "Add",
}: {
  label: string;
  values: string[];
  onChange: (values: string[]) => void;
  placeholder?: string;
  addLabel?: string;
}) {
  const remove = (index: number) => {
    onChange(values.filter((_, itemIndex) => itemIndex !== index));
  };

  const update = (index: number, nextValue: string) => {
    onChange(
      values.map((item, itemIndex) => (itemIndex === index ? nextValue : item)),
    );
  };

  const add = () => onChange([...values, ""]);

  return (
    <div className="space-y-2">
      <Label>{label}</Label>
      <div className="space-y-2">
        {values.map((value, index) => (
          <div key={`${index}`} className="flex items-center gap-2">
            <Input
              className="h-10 flex-1"
              value={value}
              placeholder={placeholder}
              onChange={(event) => update(index, event.target.value)}
            />
            <Button
              type="button"
              variant="destructive"
              size="icon"
              className="h-10 w-10"
              aria-label="Remove item"
              onClick={() => remove(index)}
            >
              <TrashIcon className="h-4 w-4" />
            </Button>
          </div>
        ))}
        <Button
          type="button"
          variant="default"
          size="sm"
          className="gap-2"
          onClick={add}
        >
          <PlusIcon className="h-4 w-4" />
          {addLabel}
        </Button>
      </div>
    </div>
  );
}
