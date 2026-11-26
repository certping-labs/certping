// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  CERTIFICATE_STATUS_QUERY_KEY,
  SSL_LIST_QUERY_KEY,
} from "@/hooks/use-certificate-list";

describe("certificate list query keys", () => {
  it("keeps list and targeted status caches isolated", () => {
    expect(SSL_LIST_QUERY_KEY).toBe("ssl-cert-list");
    expect(CERTIFICATE_STATUS_QUERY_KEY).toBe("ssl-cert-status");
  });
});
