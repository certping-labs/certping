// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { CredentialStorage } from "@/lib/cert-manager/credential-form-schemas/types";
import type { AgentTransport } from "@/types/deployment-info";

/**
 * True when the secret is pasted into CertPing, which stores it for the agent, rather than kept
 * in the person's own vault or taken from the agent's identity.
 */
export function usesManagedStorage(values: {
  credentialStorage?: CredentialStorage;
}): boolean {
  return values.credentialStorage === "managed";
}

/** Whether people may choose between pasting a secret and using their own vault. */
export function canChooseCredentialStorage(
  agentTransport: AgentTransport | undefined,
): boolean {
  return agentTransport === "GATEWAY";
}

/** Handles of secrets CertPing stores for the agent (as opposed to the customer's own vault). */
export function isCertPingStoredHandle(
  handle: string | null | undefined,
): boolean {
  return Boolean(
    handle && (handle.startsWith("local:") || handle.startsWith("sealed:")),
  );
}
