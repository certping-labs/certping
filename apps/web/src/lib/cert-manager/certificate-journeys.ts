// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  canonicalDomain,
  readDomainParam,
} from "@/lib/cert-manager/domain-param";

const INTERNAL_PATH = /^\/(?![/\\])[^\s\\]*$/;

export function safeReturnPath(
  value: string | null | undefined,
): string | undefined {
  return value && INTERNAL_PATH.test(value) ? value : undefined;
}

function splitWildcard(value: string | null | undefined): {
  host: string | undefined;
  wildcard: boolean;
} {
  const raw = canonicalDomain(value);
  const wildcard = raw.startsWith("*.");
  return {
    host: readDomainParam(wildcard ? raw.slice(2) : raw),
    wildcard,
  };
}

export function issueCertificateHref({
  domain,
  wildcard = false,
  from,
}: {
  domain?: string | null;
  wildcard?: boolean;
  from?: string | null;
} = {}): string {
  const params = new URLSearchParams();
  const target = splitWildcard(domain);
  const source = from?.trim();
  if (source) {
    params.set("from", source);
  }
  if (target.host) {
    params.set("domain", target.host);
    if (wildcard || target.wildcard) {
      params.set("wildcard", "1");
    }
  }
  const query = params.toString();
  return query ? `/cert-manager/add?${query}` : "/cert-manager/add";
}

const CONNECT_DNS_PATH = "/integrations/connections/add?type=DNS";

export function connectDnsProviderHref(returnTo?: string): string {
  const path = safeReturnPath(returnTo);
  return path
    ? `${CONNECT_DNS_PATH}&returnTo=${encodeURIComponent(path)}`
    : CONNECT_DNS_PATH;
}
