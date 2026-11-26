// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { tokenStorage } from "@/stores/auth-store";

describe("auth-store tokenStorage (node runtime)", () => {
  it("gracefully no-ops when window is unavailable", () => {
    expect(tokenStorage.getAccessToken()).toBeNull();
    expect(tokenStorage.getRefreshToken()).toBeNull();
    expect(() => tokenStorage.setTokens("a", "b")).not.toThrow();
    expect(() => tokenStorage.clearTokens()).not.toThrow();
  });
});
