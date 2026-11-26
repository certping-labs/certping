// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { renderHook } from "@testing-library/react";

import { useUnsavedChangesWarning } from "@/hooks/use-unsaved-changes-warning";

describe("useUnsavedChangesWarning", () => {
  it("blocks history.pushState navigation when the user cancels", () => {
    const confirmSpy = jest
      .spyOn(window, "confirm")
      .mockImplementation(() => false);

    const { unmount } = renderHook(() =>
      useUnsavedChangesWarning(true, "Leave?"),
    );

    const before = window.location.pathname;
    window.history.pushState({}, "", "/somewhere-else");
    expect(confirmSpy).toHaveBeenCalled();
    expect(window.location.pathname).toBe(before);

    unmount();
    confirmSpy.mockRestore();
  });

  it("allows navigation when shouldWarn is false", () => {
    const confirmSpy = jest.spyOn(window, "confirm");

    renderHook(() => useUnsavedChangesWarning(false, "Leave?"));

    const before = window.location.pathname;
    window.history.pushState({}, "", "/ok");
    expect(confirmSpy).not.toHaveBeenCalled();
    expect(window.location.pathname).not.toBe(before);

    confirmSpy.mockRestore();
  });
});
