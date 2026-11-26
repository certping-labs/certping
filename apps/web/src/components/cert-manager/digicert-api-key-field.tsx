// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import type { UseFormReturn } from "react-hook-form";

import { Button } from "@/components/ui/button";
import {
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useAddCaCredential, useCaCredentials } from "@/hooks/ca-credentials";
import type { CertificateRequestValues } from "@/lib/cert-manager/certificate-request-form";
import { INTEGRATIONS_CERTIFICATE_AUTHORITIES_HREF } from "@/lib/integrations/routes";

const PROVIDER = "DIGICERT";

/**
 * Write-only DigiCert API key input. Always a password field that starts
 * empty: CertPing never sends a saved key back, so there is nothing to show.
 */
export function DigiCertApiKeyInput({
  value,
  onChange,
  id,
  label = "New DigiCert API key",
  placeholder = "Paste your CertCentral API key",
}: {
  value: string;
  onChange: (value: string) => void;
  id?: string;
  label?: string;
  placeholder?: string;
}) {
  return (
    <Input
      id={id}
      type="password"
      autoComplete="off"
      spellCheck={false}
      aria-label={label}
      placeholder={placeholder}
      value={value}
      onChange={(event) => onChange(event.target.value)}
    />
  );
}

/**
 * Picks a saved DigiCert API key for the request (the only one by default).
 * Keys are managed under Integrations; typing a key here is a fallback for
 * an organization that has not saved one yet.
 */
export function DigiCertApiKeyField({
  form,
}: {
  form: UseFormReturn<CertificateRequestValues>;
}) {
  const savedKeys = useCaCredentials(PROVIDER);
  const addKey = useAddCaCredential(PROVIDER);
  const [apiKey, setApiKey] = useState("");
  const keys = savedKeys.data ?? [];
  const onlyKey = keys.length === 1 ? keys[0].credentialXref : undefined;

  useEffect(() => {
    if (onlyKey && !form.getValues("caCredentialXref")) {
      form.setValue("caCredentialXref", onlyKey, { shouldValidate: true });
    }
  }, [form, onlyKey]);

  const saveKey = async () => {
    try {
      const saved = await addKey.mutateAsync({
        description: "DigiCert API key",
        apiKey: apiKey.trim(),
      });
      setApiKey("");
      form.setValue("caCredentialXref", saved.credentialXref, {
        shouldDirty: true,
        shouldValidate: true,
      });
    } catch {
      // The mutation's toast reports the failure.
    }
  };

  return (
    <FormField
      control={form.control}
      name="caCredentialXref"
      render={({ field }) => (
        <FormItem>
          <FormLabel>DigiCert API key</FormLabel>
          {keys.length > 0 ? (
            <Select value={field.value ?? ""} onValueChange={field.onChange}>
              <FormControl>
                <SelectTrigger className="h-10">
                  <SelectValue placeholder="Choose a saved key" />
                </SelectTrigger>
              </FormControl>
              <SelectContent>
                {keys.map((key) => (
                  <SelectItem
                    key={key.credentialXref}
                    value={key.credentialXref}
                  >
                    {key.description}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          ) : (
            <div className="flex gap-2">
              <DigiCertApiKeyInput value={apiKey} onChange={setApiKey} />
              <Button
                type="button"
                variant="outline"
                disabled={!apiKey.trim() || addKey.isPending}
                onClick={saveKey}
              >
                Save key
              </Button>
            </div>
          )}
          <FormDescription>
            DigiCert issues on your own CertCentral account. CertPing keeps the
            key in its vault and never shows it again.{" "}
            <Link
              href={INTEGRATIONS_CERTIFICATE_AUTHORITIES_HREF}
              className="font-medium text-primary underline-offset-4 hover:underline"
            >
              Manage keys in Integrations
            </Link>
          </FormDescription>
          <FormMessage />
        </FormItem>
      )}
    />
  );
}
