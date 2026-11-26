// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import manifest from "@/app/manifest";

describe("manifest", () => {
  it("names the app and lists installable icons", () => {
    const value = manifest();

    expect(value.name).toBe("CertPing");
    expect(value.start_url).toBe("/");
    expect(value.icons?.map((icon) => icon.sizes)).toEqual([
      "192x192",
      "512x512",
      "any",
    ]);
  });
});
