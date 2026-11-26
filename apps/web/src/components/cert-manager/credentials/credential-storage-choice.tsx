// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";

import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import type { CredentialStorage } from "@/lib/cert-manager/credential-form-schemas/types";

const OPTIONS: Array<{
  value: CredentialStorage;
  title: string;
  description: string;
}> = [
  {
    value: "managed",
    title: "Paste the credential",
    description:
      "Enter the API token or key here. CertPing encrypts it and only your agent uses it.",
  },
  {
    value: "vault",
    title: "Agent identity or my own vault",
    description:
      "The agent signs in with its cloud identity, or reads the secret from your Key Vault, AWS or GCP secret manager.",
  },
];

/** Where a credential's secret lives: stored by CertPing, or the agent's identity or vault. */
export function CredentialStorageChoice({
  value,
  onChange,
}: {
  value: CredentialStorage;
  onChange: (value: CredentialStorage) => void;
}) {
  return (
    <fieldset className="space-y-2">
      <legend className="mb-2 text-sm font-medium">
        How does the agent get this secret?
      </legend>
      <RadioGroup
        value={value}
        onValueChange={(next) => onChange(next as CredentialStorage)}
        className="gap-3 md:max-w-xl"
      >
        {OPTIONS.map((option) => (
          <Label
            key={option.value}
            htmlFor={`credential-storage-${option.value}`}
            className="flex cursor-pointer items-start gap-3 rounded-md border border-border p-3 font-normal has-data-[state=checked]:border-primary"
          >
            <RadioGroupItem
              id={`credential-storage-${option.value}`}
              value={option.value}
              className="mt-0.5"
            />
            <span className="space-y-0.5">
              <span className="block text-sm font-medium">{option.title}</span>
              <span className="block text-xs text-muted-foreground">
                {option.description}
              </span>
            </span>
          </Label>
        ))}
      </RadioGroup>
    </fieldset>
  );
}
