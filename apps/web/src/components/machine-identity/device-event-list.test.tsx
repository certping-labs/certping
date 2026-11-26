// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { DeviceEventList } from "@/components/machine-identity/device-event-list";
import type { DeviceEventDto } from "@/types/machine-identity-backend";

const EVENT_WITH_LEGACY_NULLS: DeviceEventDto = {
  eventXref: "evt_1",
  eventType: null,
  eventStatus: null,
  eventMessage: null,
  actorSource: null,
  actorUserId: null,
  correlationId: null,
  detail: null,
  occurredAt: "2026-08-27T22:17:02Z",
};

describe("DeviceEventList", () => {
  it("renders legacy events with nullable labels without crashing", () => {
    render(
      <DeviceEventList
        events={[EVENT_WITH_LEGACY_NULLS]}
        isLoading={false}
        emptyMessage="No events"
      />,
    );

    expect(screen.getByText("Unknown event")).toBeInTheDocument();
    expect(screen.getByText("Recorded")).toBeInTheDocument();
    expect(screen.getByText("System")).toBeInTheDocument();
  });

  it("preserves explicit failure labels", () => {
    render(
      <DeviceEventList
        events={[
          {
            ...EVENT_WITH_LEGACY_NULLS,
            eventType: "CERTIFICATE_ENROLLMENT_FAILED",
            eventStatus: "FAILED",
            actorSource: "AGENT",
          },
        ]}
        isLoading={false}
        emptyMessage="No events"
      />,
    );

    expect(
      screen.getByText("Certificate enrollment failed"),
    ).toBeInTheDocument();
    expect(screen.getByText("Failed")).toBeInTheDocument();
    expect(screen.getByText("Agent")).toBeInTheDocument();
  });

  it("folds a run of identical events into one entry", async () => {
    // A source reporting health every five minutes produces hundreds of
    // identical rows; the one failure among them has to stay findable.
    const heartbeat = (index: number): DeviceEventDto => ({
      ...EVENT_WITH_LEGACY_NULLS,
      eventXref: `evt_health_${index}`,
      eventType: "HEALTH_REPORTED",
      eventStatus: "HEALTHY",
      occurredAt: `2026-08-27T2${index}:00:00Z`,
    });

    render(
      <DeviceEventList
        events={[heartbeat(1), heartbeat(2), heartbeat(3)]}
        isLoading={false}
        emptyMessage="No events"
      />,
    );

    expect(screen.getAllByText("Health reported")).toHaveLength(1);
    expect(screen.getByText("×3")).toBeInTheDocument();

    await userEvent.click(
      screen.getByRole("button", { name: /show 3 occurrences/i }),
    );
    expect(
      screen.getByRole("button", { name: /hide occurrences/i }),
    ).toBeInTheDocument();
  });

  it("never folds across a different event, so a failure keeps its own row", () => {
    const base = {
      ...EVENT_WITH_LEGACY_NULLS,
      eventType: "HEALTH_REPORTED",
      eventStatus: "HEALTHY",
    };

    render(
      <DeviceEventList
        events={[
          { ...base, eventXref: "a" },
          {
            ...base,
            eventXref: "b",
            eventType: "SYNC_FAILED",
            eventStatus: "FAILED",
          },
          { ...base, eventXref: "c" },
        ]}
        isLoading={false}
        emptyMessage="No events"
      />,
    );

    expect(screen.getByText("Sync failed")).toBeInTheDocument();
    // Two separate runs of the heartbeat, not one collapsed pair.
    expect(screen.getAllByText("Health reported")).toHaveLength(2);
    expect(screen.queryByText("×2")).not.toBeInTheDocument();
  });

  it("keeps events that carry a detail payload individually inspectable", async () => {
    const withDetail: DeviceEventDto = {
      ...EVENT_WITH_LEGACY_NULLS,
      eventType: "CERTIFICATE_ISSUED",
      eventStatus: "ISSUED",
      detail: { caProvider: "EJBCA" },
    };

    render(
      <DeviceEventList
        events={[
          { ...withDetail, eventXref: "one" },
          { ...withDetail, eventXref: "two" },
        ]}
        isLoading={false}
        emptyMessage="No events"
      />,
    );

    expect(screen.getAllByText("Certificate issued")).toHaveLength(2);

    await userEvent.click(
      screen.getAllByRole("button", { name: /show details/i })[0],
    );
    expect(screen.getByText("CA provider")).toBeInTheDocument();
    expect(screen.getByText("EJBCA")).toBeInTheDocument();
  });
});
