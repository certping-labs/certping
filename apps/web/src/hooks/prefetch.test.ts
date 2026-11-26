// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { QueryClient } from "@tanstack/react-query";

import { prefetchSSLCertificates } from "./prefetch";

describe("prefetchSSLCertificates", () => {
  it("prefetches only the first progressive inventory page", () => {
    const queryClient = new QueryClient();
    const prefetchInfiniteQuery = jest
      .spyOn(queryClient, "prefetchInfiniteQuery")
      .mockResolvedValue(undefined);

    prefetchSSLCertificates(queryClient);

    expect(prefetchInfiniteQuery).toHaveBeenCalledWith(
      expect.objectContaining({
        queryKey: ["ssl-cert-list", "progressive"],
        initialPageParam: 0,
        staleTime: 10 * 60 * 1000,
      }),
    );
  });
});
