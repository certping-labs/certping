/** @jest-environment jsdom */

// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { OBJECT_URL_REVOKE_DELAY_MS, saveBlob } from "@/lib/download";

describe("saveBlob", () => {
  const originalCreateObjectUrl = URL.createObjectURL;
  const originalRevokeObjectUrl = URL.revokeObjectURL;
  let clickSpy: jest.SpyInstance;

  beforeEach(() => {
    jest.useFakeTimers();
    URL.createObjectURL = jest.fn(() => "blob:file");
    URL.revokeObjectURL = jest.fn();
    clickSpy = jest
      .spyOn(HTMLAnchorElement.prototype, "click")
      .mockImplementation();
  });

  afterEach(() => {
    clickSpy.mockRestore();
    jest.useRealTimers();
    URL.createObjectURL = originalCreateObjectUrl;
    URL.revokeObjectURL = originalRevokeObjectUrl;
  });

  it("clicks a temporary link and revokes the object URL only after a delay", () => {
    saveBlob(new Blob(["pem"]), "example.com-cert.pem");

    expect(clickSpy).toHaveBeenCalledTimes(1);
    const anchor = clickSpy.mock.contexts[0] as HTMLAnchorElement;
    expect(anchor.download).toBe("example.com-cert.pem");
    expect(anchor.href).toBe("blob:file");
    expect(anchor.isConnected).toBe(false);
    expect(URL.revokeObjectURL).not.toHaveBeenCalled();

    jest.advanceTimersByTime(OBJECT_URL_REVOKE_DELAY_MS - 1);
    expect(URL.revokeObjectURL).not.toHaveBeenCalled();

    jest.advanceTimersByTime(1);
    expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:file");
  });

  it("still removes the link and revokes the URL when the click throws", () => {
    clickSpy.mockImplementation(() => {
      throw new Error("blocked");
    });

    expect(() => saveBlob(new Blob(["pem"]), "a.pem")).toThrow("blocked");
    expect(document.querySelector("a[download]")).toBeNull();

    jest.advanceTimersByTime(OBJECT_URL_REVOKE_DELAY_MS);
    expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:file");
  });
});
