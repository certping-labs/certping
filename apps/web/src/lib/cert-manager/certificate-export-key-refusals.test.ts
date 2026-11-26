// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  isKeyHeldExternally,
  rememberKeyHeldExternally,
  resetKeyRefusals,
  subscribeToKeyRefusals,
} from "@/lib/cert-manager/certificate-export-key-refusals";

describe("key-held-externally refusals", () => {
  afterEach(() => resetKeyRefusals());

  it("remembers a certificate and notifies subscribers once", () => {
    const listener = jest.fn();
    const unsubscribe = subscribeToKeyRefusals(listener);

    rememberKeyHeldExternally("cert-1");
    rememberKeyHeldExternally("cert-1");

    expect(isKeyHeldExternally("cert-1")).toBe(true);
    expect(isKeyHeldExternally("cert-2")).toBe(false);
    expect(listener).toHaveBeenCalledTimes(1);

    unsubscribe();
    rememberKeyHeldExternally("cert-2");
    expect(listener).toHaveBeenCalledTimes(1);
  });

  it("keeps a bounded number, forgetting the oldest first", () => {
    for (let index = 0; index <= 500; index += 1) {
      rememberKeyHeldExternally(`cert-${index}`);
    }

    expect(isKeyHeldExternally("cert-0")).toBe(false);
    expect(isKeyHeldExternally("cert-1")).toBe(true);
    expect(isKeyHeldExternally("cert-500")).toBe(true);
  });
});
