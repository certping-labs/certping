// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { buildCredentialSecretStoragePayload } from "@/lib/cert-manager/credential-storage-payload";

describe("buildCredentialSecretStoragePayload", () => {
  it("trims and sends secretHandle only when the active auth mode requires it", () => {
    expect(
      buildCredentialSecretStoragePayload({
        secretHandle: "  https://vault.example/secrets/aws  ",
        isKvPathRequired: true,
      }),
    ).toEqual({ secretHandle: "https://vault.example/secrets/aws" });
  });

  it("clears stale secretHandle when the active auth mode does not use secret storage", () => {
    expect(
      buildCredentialSecretStoragePayload({
        secretHandle: "https://vault.example/secrets/old-service-principal",
        isKvPathRequired: false,
      }),
    ).toEqual({ secretHandle: null });
  });

  it("sends null secretHandle when no secret path was entered and the active auth mode does not need one", () => {
    expect(
      buildCredentialSecretStoragePayload({
        secretHandle: "",
        isKvPathRequired: false,
      }),
    ).toEqual({ secretHandle: null });
  });

  it("sends null secretHandle when a required secret path is empty", () => {
    expect(
      buildCredentialSecretStoragePayload({
        secretHandle: " ",
        isKvPathRequired: true,
      }),
    ).toEqual({ secretHandle: null });
  });
});
