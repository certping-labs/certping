// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { resolveActiveNavUrl } from "@/lib/sidebar-navigation";

describe("resolveActiveNavUrl", () => {
  const entries = [
    { url: "/settings/account" },
    { url: "/settings/account/notifications" },
    { url: "/cert-manager" },
    { url: "/cert-manager/deployments" },
    { url: "/integrations/apps", matchPrefix: "/integrations" },
    { url: "/dashboard", exact: true },
    {
      subMenu: [
        { url: "/machine-identity/devices" },
        { url: "/machine-identity/profiles" },
      ],
    },
  ];

  it.each([
    ["/settings/account/notifications", "/settings/account/notifications"],
    ["/settings/account", "/settings/account"],
    ["/settings/account/security", "/settings/account"],
    ["/cert-manager/deployments/12", "/cert-manager/deployments"],
    ["/cert-manager/add", "/cert-manager"],
    ["/integrations/connections/add", "/integrations/apps"],
    ["/machine-identity/devices/2", "/machine-identity/devices"],
    ["/dashboard/extra", null],
    ["/settings/accounts", null],
  ])("highlights only the most specific entry for %s", (pathname, expected) => {
    expect(resolveActiveNavUrl(pathname, entries)).toBe(expected);
  });
});
