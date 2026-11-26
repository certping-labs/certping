// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  coreSeoMetadata,
  privateRobots,
  publicDescription,
} from "@/lib/seo-metadata";

describe("seo metadata", () => {
  it("names certificate lifecycle management", () => {
    expect(coreSeoMetadata.title).toEqual({
      default: "CertPing | Certificate Lifecycle Management",
      template: "%s | CertPing",
    });
    expect(publicDescription).toContain(
      "Open source certificate lifecycle management",
    );
    expect(publicDescription).toContain("Kubernetes");
  });

  it("never presents another site as the install's canonical URL", () => {
    expect(coreSeoMetadata.metadataBase).toBeUndefined();
    expect(coreSeoMetadata.alternates).toBeUndefined();
    expect(coreSeoMetadata.openGraph).toBeUndefined();
    expect(JSON.stringify(coreSeoMetadata)).not.toContain("certping.com");
  });

  it("keeps private pages out of search indexes", () => {
    expect(privateRobots).toEqual(
      expect.objectContaining({ index: false, follow: false }),
    );
  });
});
