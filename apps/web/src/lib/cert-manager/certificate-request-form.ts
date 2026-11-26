// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { z } from "zod";

import {
  getSanGroupingKey,
  normalizeSanDomains,
} from "@/lib/cert-manager/san-domain-helpers";
import { getPrimaryDnsConfigXref } from "@/lib/certificate-management";
import type { SanDomainEntryInput } from "@/types/cert-manager";
import type { SSLCertificateDetails } from "@/types/ssl";

export const CERTIFICATE_AUTHORITY_OPTIONS = [
  {
    value: "LETS_ENCRYPT" as const,
    label: "Let's Encrypt",
    flagKey: "LETS_ENCRYPT",
  },
  {
    value: "DIGICERT" as const,
    label: "DigiCert",
    flagKey: "DIGICERT",
  },
  {
    value: "GLOBALSIGN" as const,
    label: "GlobalSign",
    flagKey: "GLOBALSIGN",
  },
];

/** Whether a request may choose the certificate's lifetime with this CA. Let's Encrypt picks the lifetime itself. */
export function caAcceptsRequestedValidity(caProvider: string): boolean {
  return caProvider !== "LETS_ENCRYPT";
}

/** Whether this CA issues on the customer's own account, so a request needs their API key. */
export function caNeedsCustomerKey(caProvider: string): boolean {
  return caProvider === "DIGICERT";
}

export const VALIDITY_DEFAULT_DAYS = 90;
export const VALIDITY_MIN_DAYS = 1;
export const VALIDITY_MAX_DAYS = 398;
export const VALIDITY_PRESETS = [
  { value: 90, label: "90 days" },
  { value: 180, label: "180 days" },
  { value: 365, label: "1 year (365 days)" },
];

export const BASE_SAN_CREDENTIAL = "__base__";

const PRIMARY_DOMAIN_REGEX =
  /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
const SAN_DOMAIN_REGEX =
  /^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

export const certificateRequestSchema = z
  .object({
    mode: z.enum(["automated", "manual"]),
    domain: z
      .string()
      .trim()
      .min(1, "Domain is required")
      .regex(
        PRIMARY_DOMAIN_REGEX,
        "Enter a valid domain name without the wildcard prefix",
      ),
    wildcard: z.boolean().default(false),
    san: z.boolean().default(false),
    sanDomains: z.array(z.string().regex(SAN_DOMAIN_REGEX)).default([]),
    sanCredentialMap: z.record(z.string()).default({}),
    caProvider: z
      .enum(["DIGICERT", "LETS_ENCRYPT", "GLOBALSIGN"])
      .default("LETS_ENCRYPT"),
    dnsCredentialXref: z.string().trim().optional(),
    caCredentialXref: z.string().trim().optional(),
    validityDays: z.coerce
      .number({ invalid_type_error: "Enter a number of days" })
      .int("Validity must be a whole number of days")
      .min(
        VALIDITY_MIN_DAYS,
        `Validity must be at least ${VALIDITY_MIN_DAYS} day`,
      )
      .max(
        VALIDITY_MAX_DAYS,
        `Validity cannot exceed ${VALIDITY_MAX_DAYS} days`,
      )
      .default(VALIDITY_DEFAULT_DAYS),
    deploymentTargets: z.array(z.string()).default([]),
  })
  .superRefine((value, context) => {
    if (value.mode === "automated" && !value.dnsCredentialXref?.trim()) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["dnsCredentialXref"],
        message: "Select a DNS connection",
      });
    }

    if (
      value.mode === "automated" &&
      caNeedsCustomerKey(value.caProvider) &&
      !value.caCredentialXref
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["caCredentialXref"],
        message: "Add or choose your DigiCert API key",
      });
    }

    if (value.san && value.sanDomains.length === 0) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["sanDomains"],
        message: "Add at least one SAN domain",
      });
    }
  });

export type CertificateRequestValues = z.infer<typeof certificateRequestSchema>;

export const dedupeDomains = (domains: string[]): string[] =>
  Array.from(new Set(domains.map((domain) => domain.trim()).filter(Boolean)));

export const parseSanInput = (value: string): string[] =>
  dedupeDomains(value.split(/[\n,]/));

export const isValidSanDomain = (domain: string): boolean =>
  SAN_DOMAIN_REGEX.test(domain);

export const buildSanEntries = (
  values: CertificateRequestValues,
): SanDomainEntryInput[] | undefined => {
  if (!values.san || values.sanDomains.length === 0) {
    return undefined;
  }

  if (values.mode === "manual") {
    const grouped = new Map<string, string[]>();
    for (const domain of values.sanDomains) {
      const groupingKey = getSanGroupingKey(domain);
      const existing = grouped.get(groupingKey) || [];
      existing.push(domain);
      grouped.set(groupingKey, existing);
    }

    return Array.from(grouped.values()).map((patterns) => ({ patterns }));
  }

  const grouped = new Map<
    string,
    { dnsCredentialXref: string; patterns: string[] }
  >();
  for (const domain of values.sanDomains) {
    const sanGroupKey = getSanGroupingKey(domain);
    const credentialXref =
      values.sanCredentialMap[sanGroupKey] ||
      values.sanCredentialMap[domain] ||
      values.dnsCredentialXref ||
      "";
    if (!credentialXref) {
      continue;
    }

    const groupingKey = `${credentialXref}::${getSanGroupingKey(domain)}`;
    const existing = grouped.get(groupingKey);
    if (existing) {
      existing.patterns.push(domain);
      continue;
    }

    grouped.set(groupingKey, {
      dnsCredentialXref: credentialXref,
      patterns: [domain],
    });
  }

  return Array.from(grouped.values());
};

export type CertificateRequestPrefill = Partial<CertificateRequestValues>;

export function certificateRequestPrefill(
  certificate: SSLCertificateDetails,
): CertificateRequestPrefill {
  const rawDomain = certificate.domain.trim().toLowerCase();
  const domain = rawDomain.startsWith("*.") ? rawDomain.slice(2) : rawDomain;
  const wildcard = Boolean(certificate.wildcard) || rawDomain !== domain;
  const sanDomains = certificate.san
    ? normalizeSanDomains(
        dedupeDomains(
          (certificate.sanDomains ?? []).map((item) => item.toLowerCase()),
        ).filter(isValidSanDomain),
        domain,
        wildcard,
      ).accepted
    : [];
  const caProvider = CERTIFICATE_AUTHORITY_OPTIONS.find(
    (option) => option.value === certificate.caProvider?.toUpperCase(),
  )?.value;
  const dnsCredentialXref = getPrimaryDnsConfigXref(
    certificate.dnsConfigXref,
    domain,
  );
  const rootDomain = getSanGroupingKey(domain);
  const sanCredentialMap: Record<string, string> = {};
  if (
    certificate.dnsConfigXref &&
    typeof certificate.dnsConfigXref === "object"
  ) {
    for (const [key, xref] of Object.entries(certificate.dnsConfigXref)) {
      const groupingKey = getSanGroupingKey(key);
      if (xref && xref !== dnsCredentialXref && groupingKey !== rootDomain) {
        sanCredentialMap[groupingKey] = xref;
      }
    }
  }

  return {
    domain,
    wildcard,
    san: sanDomains.length > 0,
    sanDomains,
    sanCredentialMap,
    deploymentTargets: certificate.deploymentCredentialXrefs ?? [],
    ...(caProvider ? { caProvider } : {}),
    ...(dnsCredentialXref
      ? { mode: "automated" as const, dnsCredentialXref }
      : {}),
  };
}
