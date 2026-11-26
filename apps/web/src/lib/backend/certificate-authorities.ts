// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { apiClient, apiRoutes } from "@/lib/api";
import { PROJECT_REPOSITORY_URL } from "@/lib/support-links";

export type CertificateAuthorityId = "LETS_ENCRYPT" | "DIGICERT" | "GLOBALSIGN";

export type CertificateAuthorityStatus =
  "CONFIGURED" | "NOT_CONFIGURED" | "UNKNOWN";

export type AcmeEnvironment = "PRODUCTION" | "STAGING" | "CUSTOM";

/** ACME account metadata the agent reports. Never includes the account key. */
export interface AcmeAccountInfo {
  directoryUrl: string;
  environment: AcmeEnvironment;
  contactEmail: string;
  accountUrl: string | null;
  keyType: string | null;
  createdAt: string | null;
}

export interface CertificateAuthorityAgent {
  agentId: string;
  agentName: string;
  lastSeenAt: string | null;
  configured: boolean;
  acme: AcmeAccountInfo | null;
}

/** A saved CA API key. Metadata only: the key itself is write-only. */
export interface CertificateAuthorityCredential {
  credentialXref: string;
  description: string;
  createdAt: string;
  updatedAt: string;
}

export interface CertificateAuthority {
  id: CertificateAuthorityId;
  name: string;
  kind: "ACME" | "API";
  status: CertificateAuthorityStatus;
  configuredWhere: "AGENT" | "ORGANIZATION";
  maturity: "TESTED" | "BETA";
  agents: CertificateAuthorityAgent[];
  credentials: CertificateAuthorityCredential[];
  docsPath: string;
}

/** Every CA the organization can issue from, with where and how each is set up. */
export const getCertificateAuthorities = async (): Promise<
  CertificateAuthority[]
> => {
  const response = await apiClient.get<{
    authorities?: CertificateAuthority[];
  }>(apiRoutes.query.certificateAuthorities);
  return response.data.authorities ?? [];
};

/** Replaces the key behind a saved CA credential. The response carries no key. */
export const replaceCaCredentialKey = async (input: {
  credentialXref: string;
  apiKey: string;
}): Promise<void> => {
  await apiClient.put(apiRoutes.mutation.credentials.ca(input.credentialXref), {
    credJson: { apiKey: input.apiKey },
  });
};

/** Deletes a saved CA credential. The server answers 409 while it is in use. */
export const deleteCaCredential = async (
  credentialXref: string,
): Promise<void> => {
  await apiClient.delete(apiRoutes.mutation.credentials.ca(credentialXref));
};

/** The setup docs for a CA, on GitHub. */
export const certificateAuthorityDocsHref = (docsPath: string): string =>
  `${PROJECT_REPOSITORY_URL}/blob/main/${docsPath.replace(/^\/+/, "")}`;
