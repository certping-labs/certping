// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import Image from "next/image";
import React, { useMemo } from "react";
import { PlusIcon } from "@phosphor-icons/react";
import { useRouter } from "next/navigation";

import type { CredentialRecord } from "@/types/ssl";
import { getProviderPresentation } from "@/lib/credential-providers";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectSeparator,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { MultiSelect, type Option } from "@/components/ui/multi-select";
import { BetaBadge } from "@/components/common/beta-badge";
import { isBetaProviderApiValue } from "@/lib/integration-maturity";
import { cn } from "@/lib/utils";

interface CredentialReferenceSelectProps extends Omit<
  React.ComponentPropsWithoutRef<typeof SelectTrigger>,
  "children"
> {
  credentials: CredentialRecord[];
  onValueChange: (value: string) => void;
  placeholder: string;
  value?: string;
  emptyOptionLabel?: string;
  emptyOptionValue?: string;
  addCredentialHref?: CredentialHref;
  addCredentialLabel?: string;
}

interface CredentialReferenceMultiSelectProps {
  credentials: CredentialRecord[];
  onValueChange: (values: string[]) => void;
  placeholder: string;
  value: string[];
  addCredentialHref?: CredentialHref;
  addCredentialLabel?: string;
}

const ADD_CREDENTIAL_ACTION_VALUE = "__add_credential__";

type CredentialHref = string | (() => string);

const resolveHref = (href: CredentialHref): string =>
  typeof href === "function" ? href() : href;

const getCredentialLabel = (credential: CredentialRecord): string => {
  const primary =
    credential.description || credential.credentialXref || credential.alias;
  const providerLabel =
    credential.providerDisplayName ||
    getProviderPresentation(credential.providerName, credential.provider).label;

  return providerLabel ? `${primary} (${providerLabel})` : primary;
};

/** The provider API value of a saved credential (AWS_ACM, CLOUDFLARE, ...). */
const credentialApiValue = (credential: CredentialRecord): string =>
  credential.targetType || credential.providerName || credential.provider || "";

type CredentialOption = Option & { beta: boolean };

const toOption = (credential: CredentialRecord): CredentialOption => {
  const providerPresentation = getProviderPresentation(
    credential.providerName,
    credential.provider,
  );

  return {
    label: getCredentialLabel(credential),
    icon: providerPresentation.logo,
    value: credential.credentialXref || credential.alias,
    beta: isBetaProviderApiValue(credentialApiValue(credential)),
  };
};

export const CredentialReferenceSelect = React.forwardRef<
  React.ElementRef<typeof SelectTrigger>,
  CredentialReferenceSelectProps
>(
  (
    {
      credentials,
      onValueChange,
      placeholder,
      value,
      emptyOptionLabel,
      emptyOptionValue,
      addCredentialHref,
      addCredentialLabel = "Add connection",
      className,
      ...selectTriggerProps
    },
    ref,
  ) => {
    const router = useRouter();
    const options = useMemo(() => credentials.map(toOption), [credentials]);
    const selectedOption = options.find((option) => option.value === value);

    return (
      <Select
        onValueChange={(nextValue) => {
          if (nextValue === ADD_CREDENTIAL_ACTION_VALUE && addCredentialHref) {
            router.push(resolveHref(addCredentialHref));
            return;
          }
          onValueChange(nextValue);
        }}
        value={value}
      >
        <SelectTrigger
          ref={ref}
          className={cn("h-10 min-w-0", className)}
          {...selectTriggerProps}
        >
          {selectedOption ? (
            <div className="flex min-w-0 items-center gap-2">
              {selectedOption.icon ? (
                <Image
                  src={selectedOption.icon}
                  alt=""
                  width={16}
                  height={16}
                  className="h-4 w-4 shrink-0 object-contain"
                />
              ) : null}
              <span className="truncate">{selectedOption.label}</span>
              {selectedOption.beta ? <BetaBadge /> : null}
            </div>
          ) : (
            <SelectValue placeholder={placeholder} />
          )}
        </SelectTrigger>
        <SelectContent>
          {emptyOptionLabel && emptyOptionValue ? (
            <SelectItem value={emptyOptionValue}>{emptyOptionLabel}</SelectItem>
          ) : null}
          {options.map((option) => {
            return (
              <SelectItem key={option.value} value={option.value}>
                <div className="flex max-w-104 min-w-0 items-center gap-2">
                  {option.icon ? (
                    <Image
                      src={option.icon}
                      alt=""
                      width={16}
                      height={16}
                      className="h-4 w-4 shrink-0 object-contain"
                    />
                  ) : null}
                  <span className="truncate" title={option.label}>
                    {option.label}
                  </span>
                  {option.beta ? <BetaBadge /> : null}
                </div>
              </SelectItem>
            );
          })}
          {addCredentialHref ? (
            <>
              <SelectSeparator />
              <SelectItem
                className="font-medium text-primary"
                value={ADD_CREDENTIAL_ACTION_VALUE}
              >
                <span className="flex items-center gap-2">
                  <PlusIcon className="h-4 w-4" />
                  {addCredentialLabel}
                </span>
              </SelectItem>
            </>
          ) : null}
        </SelectContent>
      </Select>
    );
  },
);
CredentialReferenceSelect.displayName = "CredentialReferenceSelect";

export function CredentialReferenceMultiSelect({
  credentials,
  onValueChange,
  placeholder,
  value,
  addCredentialHref,
  addCredentialLabel = "Add connection",
}: CredentialReferenceMultiSelectProps) {
  const router = useRouter();
  const options = useMemo(() => credentials.map(toOption), [credentials]);

  return (
    <MultiSelect
      className="min-h-10 justify-start"
      options={options}
      onChange={onValueChange}
      placeholder={placeholder}
      selected={value}
      action={
        addCredentialHref
          ? {
              label: addCredentialLabel,
              onSelect: () => router.push(resolveHref(addCredentialHref)),
            }
          : undefined
      }
    />
  );
}
