// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

type CredentialSecretStoragePayload = {
  secretHandle?: string | null;
};

export function buildCredentialSecretStoragePayload(params: {
  secretHandle?: string | null;
  isKvPathRequired: boolean;
}): CredentialSecretStoragePayload {
  const secretHandle = params.secretHandle?.trim();

  if (!params.isKvPathRequired) {
    return { secretHandle: null };
  }

  return secretHandle ? { secretHandle } : { secretHandle: null };
}
