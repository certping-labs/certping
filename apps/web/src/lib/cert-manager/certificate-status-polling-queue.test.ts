// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  getCertificatePollingInterval,
  getPendingPollingCandidates,
  INITIAL_CERTIFICATE_POLLING_STATE,
  pollNextCertificateBatch,
} from "@/lib/cert-manager/certificate-status-polling-queue";
import { createCertificateStatusUpdate } from "@/lib/cert-manager/certificate-status-polling";
import type { SSLCertificateListItem } from "@/types/ssl";

const certificate = (
  index: number,
  status = "PENDING",
): SSLCertificateListItem => ({
  certificateXref: `cert-${index}`,
  userDomainCertId: String(index),
  domain: `${index}.example.com`,
  status,
});

describe("certificate status polling queue", () => {
  it("removes terminal updates from the pending queue", () => {
    const original = certificate(1);
    const active = certificate(1, "ACTIVE");

    expect(
      getPendingPollingCandidates(
        [original, certificate(2)],
        [createCertificateStatusUpdate(original, active)],
      ),
    ).toEqual([certificate(2)]);
  });

  it("polls at most four certificates per tick and rotates fairly", async () => {
    const certificates = Array.from({ length: 10 }, (_, index) =>
      certificate(index),
    );
    const fetchStatus = jest.fn(async (item: SSLCertificateListItem) =>
      createCertificateStatusUpdate(item, item),
    );

    const firstState = await pollNextCertificateBatch(
      certificates,
      INITIAL_CERTIFICATE_POLLING_STATE,
      fetchStatus,
    );
    const secondState = await pollNextCertificateBatch(
      certificates,
      firstState,
      fetchStatus,
    );

    expect(fetchStatus).toHaveBeenCalledTimes(8);
    expect(
      fetchStatus.mock.calls.map(([item]) => item.certificateXref),
    ).toEqual([
      "cert-0",
      "cert-1",
      "cert-2",
      "cert-3",
      "cert-4",
      "cert-5",
      "cert-6",
      "cert-7",
    ]);
    expect(secondState.nextCandidateIndex).toBe(8);
  });

  it("keeps successful updates when another request in the batch fails", async () => {
    const first = certificate(1);
    const second = certificate(2);
    const fetchStatus = jest
      .fn()
      .mockRejectedValueOnce(new Error("Temporary failure"))
      .mockResolvedValueOnce(
        createCertificateStatusUpdate(second, certificate(2, "ACTIVE")),
      );

    const state = await pollNextCertificateBatch(
      [first, second],
      INITIAL_CERTIFICATE_POLLING_STATE,
      fetchStatus,
    );

    expect(state.updates).toHaveLength(1);
    expect(state.updates[0]?.certificate.status).toBe("ACTIVE");
    expect(state.consecutiveEmptyPolls).toBe(0);
  });

  it("backs off boundedly when a polling batch returns no update", async () => {
    const fetchStatus = jest.fn().mockRejectedValue(new Error("Unavailable"));
    const firstState = await pollNextCertificateBatch(
      [certificate(1)],
      INITIAL_CERTIFICATE_POLLING_STATE,
      fetchStatus,
    );
    const repeatedFailureState = {
      ...firstState,
      consecutiveEmptyPolls: 20,
    };

    expect(firstState.consecutiveEmptyPolls).toBe(1);
    expect(getCertificatePollingInterval(firstState)).toBe(10_000);
    expect(getCertificatePollingInterval(repeatedFailureState)).toBe(30_000);
  });

  it("returns the existing state when every certificate is terminal", async () => {
    const fetchStatus = jest.fn();

    const state = await pollNextCertificateBatch(
      [certificate(1, "ACTIVE")],
      INITIAL_CERTIFICATE_POLLING_STATE,
      fetchStatus,
    );

    expect(state).toBe(INITIAL_CERTIFICATE_POLLING_STATE);
    expect(fetchStatus).not.toHaveBeenCalled();
    expect(getCertificatePollingInterval(undefined)).toBe(5000);
  });
});
