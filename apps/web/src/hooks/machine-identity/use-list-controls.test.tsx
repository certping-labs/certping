// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { act, renderHook } from "@testing-library/react";

import { useListControls } from "@/hooks/machine-identity/use-list-controls";
import { MACHINE_IDENTITY_CONFIG } from "@/lib/machine-identity/config";

const replaceMock = jest.fn();
let mockSearchParams = "";

jest.mock("next/navigation", () => ({
  useRouter: () => ({ replace: replaceMock }),
  usePathname: () => "/machine-identity/devices",
  useSearchParams: () => new URLSearchParams(mockSearchParams),
}));

interface Filters extends Record<string, string | undefined> {
  status: string | undefined;
  source: string | undefined;
}

const DEFAULTS: Filters = { status: undefined, source: undefined };

function setup(search = "") {
  mockSearchParams = search;
  return renderHook(() => useListControls<Filters>(DEFAULTS));
}

/** The query string of the most recent address-bar write. */
function lastUrl(): string {
  return replaceMock.mock.calls.at(-1)?.[0] ?? "";
}

beforeEach(() => {
  jest.useFakeTimers();
  replaceMock.mockReset();
});

afterEach(() => {
  jest.useRealTimers();
});

describe("useListControls", () => {
  it("starts from the module's default page size", () => {
    const { result } = setup();
    expect(result.current.page).toBe(0);
    expect(result.current.pageSize).toBe(
      MACHINE_IDENTITY_CONFIG.list.defaultPageSize,
    );
    expect(result.current.search).toBeUndefined();
  });

  it("restores filters and search from a shared link", () => {
    const { result } = setup("status=ORPHANED&search=laptop");
    expect(result.current.filters.status).toBe("ORPHANED");
    expect(result.current.searchInput).toBe("laptop");
  });

  it("does not rewrite the address bar just because someone arrived", () => {
    // A deep link that immediately rewrote its own URL would break the back
    // button on first navigation.
    setup("status=ORPHANED");
    act(() => {
      jest.advanceTimersByTime(1_000);
    });
    expect(replaceMock).not.toHaveBeenCalled();
  });

  it("rejects a URL value that is not shaped like a filter", () => {
    // Filter values are enum constants, xrefs, or vendor names; anything else
    // is dropped rather than rendered into a chip or sent to the API.
    const { result } = setup(
      `status=${encodeURIComponent("<script>alert(1)</script>")}`,
    );
    expect(result.current.filters.status).toBeUndefined();
  });

  it("accepts a vendor name containing spaces", () => {
    const { result } = setup("source=Windows 10");
    expect(result.current.filters.source).toBe("Windows 10");
  });

  it("ignores URL keys the caller never declared", () => {
    const { result } = setup("somethingElse=1");
    expect(result.current.filters).toEqual(DEFAULTS);
  });

  it("debounces search rather than firing a request per keystroke", () => {
    const { result } = setup();

    act(() => {
      result.current.setSearchInput("la");
    });
    act(() => {
      result.current.setSearchInput("laptop");
    });
    expect(result.current.search).toBeUndefined();

    act(() => {
      jest.advanceTimersByTime(400);
    });
    expect(result.current.search).toBe("laptop");
  });

  it("trims the debounced term and treats whitespace as no search", () => {
    const { result } = setup();

    act(() => {
      result.current.setSearchInput("  laptop  ");
    });
    act(() => {
      jest.advanceTimersByTime(400);
    });
    expect(result.current.search).toBe("laptop");

    act(() => {
      result.current.setSearchInput("   ");
    });
    act(() => {
      jest.advanceTimersByTime(400);
    });
    expect(result.current.search).toBeUndefined();
  });

  it("returns to the first page whenever the result set narrows", () => {
    // Narrowing while sitting on page 7 lands on an empty page, which reads as
    // "no matches".
    const { result } = setup();

    act(() => {
      result.current.setPage(7);
    });
    expect(result.current.page).toBe(7);

    act(() => {
      result.current.setFilter("status", "ORPHANED");
    });
    expect(result.current.page).toBe(0);

    act(() => {
      result.current.setPage(7);
    });
    act(() => {
      result.current.setSearchInput("laptop");
    });
    act(() => {
      jest.advanceTimersByTime(400);
    });
    expect(result.current.page).toBe(0);
  });

  it("returns to the first page when the page size changes", () => {
    const { result } = setup();
    act(() => {
      result.current.setPage(4);
    });
    act(() => {
      result.current.setPageSize(100);
    });
    expect(result.current.pageSize).toBe(100);
    expect(result.current.page).toBe(0);
  });

  it("writes only the filters that differ from the page defaults", () => {
    const { result } = setup();

    act(() => {
      result.current.setFilter("status", "ORPHANED");
    });
    act(() => {
      jest.advanceTimersByTime(400);
    });

    expect(lastUrl()).toContain("status=ORPHANED");
    expect(lastUrl()).not.toContain("source=");
  });

  it("removes a filter from the URL when it is cleared", () => {
    const { result } = setup();

    act(() => {
      result.current.setFilter("status", "ORPHANED");
    });
    act(() => {
      jest.advanceTimersByTime(400);
    });
    act(() => {
      result.current.setFilter("status", undefined);
    });
    act(() => {
      jest.advanceTimersByTime(400);
    });

    expect(lastUrl()).toBe("/machine-identity/devices");
  });

  it("keeps a stable identity while nothing changes", () => {
    // The controls object is a dependency of the table's memoized columns and
    // of every query key on the page.
    const { result, rerender } = setup();
    const first = result.current;
    rerender();
    expect(result.current).toBe(first);
  });
});
