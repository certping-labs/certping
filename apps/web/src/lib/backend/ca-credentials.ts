// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { apiClient, apiRoutes } from "@/lib/api";

export interface CaCredential {
  credentialXref: string;
  provider: string;
  description: string;
}

interface CaCredentialResponse {
  credentialXref: string;
  provider: string;
  description: string | null;
  status: string;
}

const toCaCredential = (item: CaCredentialResponse): CaCredential => ({
  credentialXref: item.credentialXref,
  provider: item.provider,
  description: item.description || item.credentialXref,
});

/** The organization's active CA credentials for {@code provider}, such as its saved DigiCert API keys. */
export const listCaCredentials = async (
  provider: string,
): Promise<CaCredential[]> => {
  const response = await apiClient.get<{ items: CaCredentialResponse[] }>(
    apiRoutes.query.credentials.list,
    { params: { type: "CA" } },
  );
  return response.data.items
    .filter((item) => item.provider === provider && item.status === "ACTIVE")
    .map(toCaCredential);
};

/** Saves a CA API key; CertPing keeps it in its vault for the agent and returns only the reference. */
export const createCaCredential = async (input: {
  provider: string;
  description: string;
  apiKey: string;
}): Promise<CaCredential> => {
  const response = await apiClient.post<CaCredentialResponse>(
    apiRoutes.mutation.credentials.createCa,
    {
      provider: input.provider,
      description: input.description,
      credJson: { apiKey: input.apiKey },
    },
  );
  return toCaCredential(response.data);
};
