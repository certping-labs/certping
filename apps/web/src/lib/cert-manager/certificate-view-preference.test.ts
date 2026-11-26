// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  readCertificateViewPreference,
  writeCertificateViewPreference,
} from "@/lib/cert-manager/certificate-view-preference";

describe("certificate-view-preference", () => {
  it("reads valid stored view modes and ignores invalid values", () => {
    const storage = {
      getItem: jest.fn().mockReturnValue("table"),
    };
    expect(readCertificateViewPreference(storage)).toBe("table");

    storage.getItem.mockReturnValue("card");
    expect(readCertificateViewPreference(storage)).toBe("card");

    storage.getItem.mockReturnValue("grid");
    expect(readCertificateViewPreference(storage)).toBeNull();
  });

  it("writes view preference key", () => {
    const storage = {
      setItem: jest.fn(),
    };
    writeCertificateViewPreference(storage, "card");
    expect(storage.setItem).toHaveBeenCalledWith(
      "certificates-view-preference",
      "card",
    );
  });
});
