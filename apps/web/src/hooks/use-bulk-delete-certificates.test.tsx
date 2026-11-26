// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";
import { AxiosError, AxiosHeaders } from "axios";
import { type ExternalToast, toast } from "sonner";

import { useBulkDeleteCertificates } from "@/hooks/use-bulk-delete-certificates";
import { deleteCertificate } from "@/lib/backend/certs";
import { BULK_DELETE_TIMEOUT_MS } from "@/lib/cert-manager/bulk-certificate-delete";

jest.mock("@/lib/backend/certs", () => ({
  deleteCertificate: jest.fn(),
}));

jest.mock("sonner", () => ({
  toast: { success: jest.fn(), error: jest.fn(), info: jest.fn() },
}));

const deleteCertificateMock = jest.mocked(deleteCertificate);
const toastError = jest.mocked(toast.error);
const toastInfo = jest.mocked(toast.info);
const toastSuccess = jest.mocked(toast.success);

function httpError(status: number) {
  return new AxiosError("request failed", "ERR", undefined, undefined, {
    status,
    statusText: "",
    headers: {},
    config: { headers: new AxiosHeaders() },
    data: {},
  });
}

function renderBulkDelete() {
  const queryClient = new QueryClient();
  const wrapper = ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );
  return renderHook(() => useBulkDeleteCertificates(), { wrapper });
}

type ToastAction = {
  onClick: (event: React.MouseEvent<HTMLButtonElement>) => void;
};

function clickAction(options: ExternalToast | undefined) {
  const preventDefault = jest.fn();
  const action = options?.action as ToastAction;
  action.onClick({
    preventDefault,
  } as unknown as React.MouseEvent<HTMLButtonElement>);
  return preventDefault;
}

describe("useBulkDeleteCertificates", () => {
  afterEach(() => {
    jest.useRealTimers();
  });

  it("says why the deletes failed in the summary toast", async () => {
    deleteCertificateMock.mockResolvedValueOnce(undefined);
    deleteCertificateMock.mockRejectedValue(httpError(403));
    const { result } = renderBulkDelete();

    await act(() => result.current.deleteDomains(["a", "b", "c"]));

    expect(toastError).toHaveBeenCalledWith(
      "Deleted 1. 2 couldn't be deleted.",
      expect.objectContaining({
        id: "bulk-certificate-delete",
        description: "You don't have permission to delete these.",
        action: expect.objectContaining({ label: "Retry" }),
      }),
    );
  });

  it("reports a timed-out delete as possibly done", async () => {
    jest.useFakeTimers();
    deleteCertificateMock.mockReturnValue(new Promise(() => {}));
    const { result } = renderBulkDelete();

    await act(async () => {
      const run = result.current.deleteDomains(["a"]);
      await jest.advanceTimersByTimeAsync(BULK_DELETE_TIMEOUT_MS);
      await run;
    });

    expect(toastError).toHaveBeenCalledWith(
      "Deleted 0. 1 couldn't be deleted.",
      expect.objectContaining({
        description:
          "The request timed out; it may still have completed. Retry to check.",
      }),
    );
  });

  it("answers Retry during another run in the same toast, then retries once idle", async () => {
    deleteCertificateMock.mockRejectedValueOnce(httpError(500));
    const { result } = renderBulkDelete();
    await act(() => result.current.deleteDomains(["failed"]));
    const [, summaryOptions] = toastError.mock.calls[0]!;

    let finishSecondRun: () => void = () => {};
    deleteCertificateMock.mockReturnValueOnce(
      new Promise<void>((resolve) => {
        finishSecondRun = resolve;
      }),
    );
    let secondRun: Promise<unknown> = Promise.resolve();
    act(() => {
      secondRun = result.current.deleteDomains(["other"]);
    });
    await waitFor(() => expect(deleteCertificateMock).toHaveBeenCalledTimes(2));
    expect(result.current.isRunning).toBe(true);

    const preventDefault = clickAction(summaryOptions);

    expect(preventDefault).toHaveBeenCalled();
    expect(deleteCertificateMock).toHaveBeenCalledTimes(2);
    expect(toastInfo).toHaveBeenCalledWith(
      "Retry when the current run finishes.",
      expect.objectContaining({
        id: summaryOptions?.id,
        description: "Deleted 0. 1 couldn't be deleted.",
        action: expect.objectContaining({ label: "Retry" }),
      }),
    );

    await act(async () => {
      finishSecondRun();
      await secondRun;
    });
    expect(toastSuccess).toHaveBeenCalledWith("Deleted 1.", {
      id: summaryOptions?.id,
    });

    deleteCertificateMock.mockResolvedValueOnce(undefined);
    const [, noticeOptions] = toastInfo.mock.calls[0]!;
    await act(async () => {
      expect(clickAction(noticeOptions)).not.toHaveBeenCalled();
    });
    expect(deleteCertificateMock).toHaveBeenLastCalledWith("failed");
  });
});
