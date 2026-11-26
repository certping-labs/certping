// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  compactParams,
  resolvePageRequest,
} from "@/lib/backend/machine-identity/transport";
import { MACHINE_IDENTITY_CONFIG } from "@/lib/machine-identity/config";

const { defaultPageSize, maxPageSize } = MACHINE_IDENTITY_CONFIG.list;

describe("resolvePageRequest", () => {
  it("normalizes an empty request to the module defaults", () => {
    // Query keys embed the resolved request, so `{}` and an explicit
    // `{page: 0, size: 25}` must not become two cache entries for one page.
    expect(resolvePageRequest()).toEqual({
      page: 0,
      size: defaultPageSize,
      direction: "desc",
    });
    expect(resolvePageRequest({})).toEqual(resolvePageRequest());
    expect(
      resolvePageRequest({ page: 0, size: defaultPageSize, direction: "desc" }),
    ).toEqual(resolvePageRequest());
  });

  it("clamps a page size the backend would refuse", () => {
    expect(resolvePageRequest({ size: maxPageSize + 5_000 }).size).toBe(
      maxPageSize,
    );
    expect(resolvePageRequest({ size: 0 }).size).toBe(1);
    expect(resolvePageRequest({ size: -10 }).size).toBe(1);
  });

  it("never sends a negative page", () => {
    expect(resolvePageRequest({ page: -3 }).page).toBe(0);
  });

  it("truncates fractional paging rather than sending it on the wire", () => {
    const resolved = resolvePageRequest({ page: 2.9, size: 10.7 });
    expect(resolved).toMatchObject({ page: 2, size: 10 });
  });

  it("falls back to the defaults for values that are not finite numbers", () => {
    const resolved = resolvePageRequest({
      page: Number.NaN,
      size: Number.POSITIVE_INFINITY,
    });
    expect(resolved).toMatchObject({ page: 0, size: defaultPageSize });
  });

  it("only accepts 'asc' as an ascending direction", () => {
    expect(resolvePageRequest({ direction: "asc" }).direction).toBe("asc");
    expect(resolvePageRequest({ direction: "desc" }).direction).toBe("desc");
    expect(
      resolvePageRequest({
        direction: "ASC" as unknown as "asc",
      }).direction,
    ).toBe("desc");
  });

  it("omits sort entirely when none was asked for", () => {
    expect("sort" in resolvePageRequest({})).toBe(false);
    expect(resolvePageRequest({ sort: "validTo" }).sort).toBe("validTo");
  });
});

describe("compactParams", () => {
  it("drops absent and blank filters so they never reach the query string", () => {
    expect(
      compactParams({
        source: "src_1",
        status: undefined,
        os: null as unknown as string,
        q: "   ",
      }),
    ).toEqual({ source: "src_1" });
  });

  it("keeps falsy values that are still real filters", () => {
    // `0` and `false` are meaningful; only absence and whitespace are not.
    expect(
      compactParams({ expiringWithinDays: 0, includeArchived: false }),
    ).toEqual({ expiringWithinDays: 0, includeArchived: false });
  });

  it("preserves a search term that merely has surrounding whitespace", () => {
    expect(compactParams({ q: " laptop " })).toEqual({ q: " laptop " });
  });
});
