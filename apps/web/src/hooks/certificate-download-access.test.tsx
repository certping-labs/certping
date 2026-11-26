// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { renderHook } from "@testing-library/react";

import { useCanDownloadCertificates } from "@/hooks/certificate-download-access";

let mockFeatureOn = true;
let mockPermissions: string[] = ["certificate:read"];

jest.mock("@/hooks/use-feature-flags", () => ({
  useIsOrgFeatureEnabled: (key: string) =>
    key === "CERTIFICATE_DOWNLOAD" && mockFeatureOn,
}));

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({
    user: {
      id: "user-1",
      organizationId: "org-1",
      roles: ["USER"],
      permissions: mockPermissions,
    },
  }),
}));

describe("useCanDownloadCertificates", () => {
  afterEach(() => {
    mockFeatureOn = true;
    mockPermissions = ["certificate:read"];
  });

  it("allows downloads when the flag is on and the user can view certificates", () => {
    const { result } = renderHook(() => useCanDownloadCertificates());
    expect(result.current).toBe(true);
  });

  it("hides downloads while the flag is not confirmed on", () => {
    mockFeatureOn = false;
    const { result } = renderHook(() => useCanDownloadCertificates());
    expect(result.current).toBe(false);
  });

  it("hides downloads from users who cannot view certificates", () => {
    mockPermissions = ["credential:read"];
    const { result } = renderHook(() => useCanDownloadCertificates());
    expect(result.current).toBe(false);
  });
});
