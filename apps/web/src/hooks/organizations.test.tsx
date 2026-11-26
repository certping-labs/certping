// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";

import {
  ORGANIZATIONS_QUERY_KEY,
  useCreateOrganization,
  useDeleteOrganization,
  useOrganizationById,
  useOrganizationBySlug,
  useOrganizations,
  useUpdateOrganization,
} from "@/hooks/organizations";
import * as organizationBackend from "@/lib/backend/organizations";

jest.mock("@/lib/backend/organizations");

const organizations = organizationBackend as jest.Mocked<
  typeof organizationBackend
>;
/**
 * A mutation hook under test, erased to the one shape these cases exercise.
 *
 * <p>Each hook has its own variables and result types, so a heterogeneous
 * `it.each` cannot infer a single signature for `renderHook`. Naming the shape
 * once keeps the table readable without casting at every call site.
 */
type AnyMutation = { mutateAsync: (variables: never) => Promise<unknown> };
/** Only the affordances these cases use, so any mocked adapter fits. */
type MutationSpy = { mockResolvedValue: (value: never) => unknown };
type MutationCase = [string, () => AnyMutation, () => MutationSpy];

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const wrapper = ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );
  return { queryClient, wrapper };
}

beforeEach(() => {
  jest.clearAllMocks();
});

describe("organization lookups", () => {
  it("lists organizations", async () => {
    organizations.listOrganizations.mockResolvedValue([] as never);
    const { wrapper } = createWrapper();

    renderHook(() => useOrganizations({ enabled: true }), { wrapper });

    await waitFor(() =>
      expect(organizations.listOrganizations).toHaveBeenCalled(),
    );
  });

  it("trims a padded id before it reaches the URL", async () => {
    // Ids arrive from route params and admin inputs; a stray space produces a
    // 404 against a path that looks correct in the address bar.
    organizations.getOrganizationById.mockResolvedValue({ id: 1 } as never);
    const { wrapper } = createWrapper();

    renderHook(() => useOrganizationById("  42  "), { wrapper });

    await waitFor(() =>
      expect(organizations.getOrganizationById).toHaveBeenCalledWith("42"),
    );
  });

  it("does not fetch an organization without an id", () => {
    const { wrapper } = createWrapper();
    const { result } = renderHook(() => useOrganizationById(undefined), {
      wrapper,
    });

    expect(organizations.getOrganizationById).not.toHaveBeenCalled();
    expect(result.current.fetchStatus).toBe("idle");
  });

  it("treats a whitespace-only id as no id at all", () => {
    const { wrapper } = createWrapper();
    renderHook(() => useOrganizationById("   "), { wrapper });
    expect(organizations.getOrganizationById).not.toHaveBeenCalled();
  });

  it("caches by-id and by-slug lookups separately", async () => {
    organizations.getOrganizationById.mockResolvedValue({ id: 1 } as never);
    organizations.getOrganizationBySlug.mockResolvedValue({ id: 1 } as never);
    const { wrapper } = createWrapper();

    renderHook(() => useOrganizationById("acme"), { wrapper });
    renderHook(() => useOrganizationBySlug("acme"), { wrapper });

    // Same string, two different endpoints - one cache entry would serve the
    // wrong response to whichever ran second.
    await waitFor(() =>
      expect(organizations.getOrganizationById).toHaveBeenCalled(),
    );
    expect(organizations.getOrganizationBySlug).toHaveBeenCalledWith("acme");
  });
});

describe("organization mutations", () => {
  it("refreshes the list on create", async () => {
    organizations.createOrganization.mockResolvedValue({ id: 1 } as never);
    const { queryClient, wrapper } = createWrapper();
    const invalidateSpy = jest.spyOn(queryClient, "invalidateQueries");

    const { result } = renderHook(() => useCreateOrganization(), { wrapper });
    await act(async () => {
      await result.current.mutateAsync({ name: "Acme" } as never);
    });

    expect(invalidateSpy).toHaveBeenCalledWith({
      queryKey: ORGANIZATIONS_QUERY_KEY,
    });
  });

  const organizationMutations: MutationCase[] = [
    [
      "update",
      () => useUpdateOrganization(),
      () => organizations.updateOrganization,
    ],
    [
      "delete",
      () => useDeleteOrganization(),
      () => organizations.deleteOrganization,
    ],
  ];

  it.each(organizationMutations)(
    "refreshes the organization list after %s",
    async (_label, useHook, getMock) => {
      // Every one of these changes what the organization list should show;
      // leaving a stale list behind is how an admin sees a deleted org.
      getMock().mockResolvedValue({} as never);
      const { queryClient, wrapper } = createWrapper();
      const invalidateSpy = jest.spyOn(queryClient, "invalidateQueries");

      const { result } = renderHook(useHook, { wrapper });
      await act(async () => {
        await result.current
          .mutateAsync({ organizationId: "1" } as never)
          .catch(() => undefined);
      });

      expect(invalidateSpy).toHaveBeenCalledWith({
        queryKey: ORGANIZATIONS_QUERY_KEY,
      });
    },
  );
});
