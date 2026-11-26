// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import {
  StatusBanner,
  STATUS_PAGE_URL,
  statusMessage,
} from "@/components/common/status-banner";
import {
  debounceFailedSources,
  RECHECK_AFTER_MS,
  type SourceMemory,
  STATUS_POLL_MS,
} from "@/hooks/use-public-status";
import { useNetworkStatusStore } from "@/lib/network-status";
import {
  type ComponentState,
  type ComponentStatus,
  fetchStatus,
  type StatusReport,
} from "@/lib/public-status";
import { STATUS_SOURCES, type StatusSource } from "@/lib/status-sources";

jest.mock("@/lib/public-status", () => ({
  ...jest.requireActual("@/lib/public-status"),
  fetchStatus: jest.fn(),
}));

const fetchMock = jest.mocked(fetchStatus);

const NAMES: Record<string, string> = {
  api: "API and sign-in",
  certificates: "Certificate issuance and renewal",
  notifications: "Email notifications",
  search: "Search",
};

function components(states: Record<string, ComponentState>): ComponentStatus[] {
  return Object.entries(states).map(([id, state]) => ({
    id,
    name: NAMES[id] ?? id,
    state,
  }));
}

function report(states: Record<string, ComponentState>): StatusReport {
  return {
    checkedAt: new Date(),
    components: components(states),
    reachedEverySource: !Object.values(states).includes("not_responding"),
  };
}

const operational = {
  api: "operational",
  notifications: "operational",
  certificates: "operational",
} as const;

let visibility: DocumentVisibilityState = "visible";
let online = true;

beforeEach(() => {
  visibility = "visible";
  online = true;
  jest
    .spyOn(document, "visibilityState", "get")
    .mockImplementation(() => visibility);
  jest.spyOn(navigator, "onLine", "get").mockImplementation(() => online);
  window.sessionStorage.clear();
  useNetworkStatusStore.setState({ issue: null });
});

function setVisibility(next: DocumentVisibilityState) {
  visibility = next;
  document.dispatchEvent(new Event("visibilitychange"));
}

describe("statusMessage", () => {
  it.each<[Record<string, ComponentState>, string | null]>([
    [operational, null],
    [
      { ...operational, notifications: "major_outage" },
      "Email notifications are delayed. Work is queued and resumes when the service recovers.",
    ],
    [
      { ...operational, certificates: "major_outage" },
      "Certificate issuance and renewal is delayed. Work is queued and resumes when the service recovers.",
    ],
    [
      { ...operational, certificates: "partial_outage" },
      "Certificate issuance and renewal is delayed. Work is queued and resumes when the service recovers.",
    ],
    [
      { ...operational, notifications: "degraded_performance" },
      "Email notifications are delayed.",
    ],
    [
      { ...operational, certificates: "degraded_performance" },
      "Certificate issuance and renewal is delayed.",
    ],
    [
      { ...operational, certificates: "under_maintenance" },
      "Certificate issuance and renewal is delayed.",
    ],
    [
      {
        ...operational,
        notifications: "major_outage",
        certificates: "major_outage",
      },
      "Email notifications are delayed. Certificate issuance and renewal is delayed. Work is queued and resumes when the service recovers.",
    ],
    [
      { ...operational, api: "degraded_performance" },
      "Sign-in and the API are slower than usual.",
    ],
    [{ ...operational, api: "major_outage" }, "Sign-in and the API are down."],
    [
      { ...operational, api: "partial_outage" },
      "Sign-in and the API are down.",
    ],
    [
      { ...operational, api: "under_maintenance" },
      "Sign-in and the API are under maintenance.",
    ],
    [
      { ...operational, api: "unknown" },
      "Sign-in and the API may not be working normally.",
    ],
    [{ ...operational, search: "major_outage" }, "Search is down."],
    [
      { ...operational, search: "unknown" },
      "Search may not be working normally.",
    ],
    [
      {
        ...operational,
        api: "not_responding",
        notifications: "not_responding",
        certificates: "not_responding",
      },
      "We could not reach some CertPing services.",
    ],
    [
      { ...operational, api: "major_outage", certificates: "not_responding" },
      "Sign-in and the API are down. We could not reach some CertPing services.",
    ],
    [
      { ...operational, api: "not_responding", notifications: "major_outage" },
      "Email notifications are delayed. Work is queued and resumes when the service recovers. We could not reach some CertPing services.",
    ],
  ])("%j says %j", (states, want) => {
    expect(statusMessage(components(states))).toBe(want);
  });

  it("names a component it does not know by the name the document gives", () => {
    expect(
      statusMessage([
        { id: "search", name: "Certificate lookups", state: "major_outage" },
      ]),
    ).toBe("Certificate lookups is down.");
  });
});

describe("StatusBanner", () => {
  it("shows nothing while every service is operational", async () => {
    fetchMock.mockResolvedValue(report(operational));

    const { container } = render(<StatusBanner />);

    await act(async () => undefined);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(container).toBeEmptyDOMElement();
  });

  it("names the affected service and links to the status page", async () => {
    fetchMock.mockResolvedValue(
      report({ ...operational, certificates: "major_outage" }),
    );

    render(<StatusBanner />);

    expect(
      await screen.findByText(
        /Certificate issuance and renewal is delayed\. Work is queued and resumes when the service recovers\./,
      ),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "View status" })).toHaveAttribute(
      "href",
      "/health/",
    );
    expect(STATUS_PAGE_URL).toBe("/health/");
  });

  it("polls every minute only while the tab is visible, and checks at once when it shows again", async () => {
    jest.useFakeTimers();
    try {
      fetchMock.mockResolvedValue(report(operational));
      render(<StatusBanner />);
      await act(async () => undefined);
      expect(fetchMock).toHaveBeenCalledTimes(1);

      await act(async () => {
        jest.advanceTimersByTime(STATUS_POLL_MS);
      });
      expect(fetchMock).toHaveBeenCalledTimes(2);

      act(() => setVisibility("hidden"));
      await act(async () => {
        jest.advanceTimersByTime(STATUS_POLL_MS * 5);
      });
      expect(fetchMock).toHaveBeenCalledTimes(2);

      await act(async () => setVisibility("visible"));
      expect(fetchMock).toHaveBeenCalledTimes(3);
      await act(async () => {
        jest.advanceTimersByTime(STATUS_POLL_MS);
      });
      expect(fetchMock).toHaveBeenCalledTimes(4);
    } finally {
      jest.useRealTimers();
    }
  });

  it("leaves offline to the offline notice: no check, no banner", async () => {
    online = false;
    fetchMock.mockResolvedValue(
      report({ ...operational, api: "major_outage" }),
    );

    const { container } = render(<StatusBanner />);

    await act(async () => undefined);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(container).toBeEmptyDOMElement();

    online = true;
    await act(async () => {
      window.dispatchEvent(new Event("online"));
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(await screen.findByRole("status")).toBeInTheDocument();
  });

  it("hides while the browser is reported offline, whatever the last answer said", async () => {
    fetchMock.mockResolvedValue(
      report({ ...operational, api: "major_outage" }),
    );
    render(<StatusBanner />);
    expect(await screen.findByRole("status")).toBeInTheDocument();

    act(() =>
      useNetworkStatusStore
        .getState()
        .reportNetworkIssue("Your browser appears to be offline.", "browser"),
    );

    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("drops an answer that arrives after the browser went offline", async () => {
    let resolve: (value: StatusReport) => void = () => {};
    fetchMock.mockReturnValue(
      new Promise((done) => {
        resolve = done;
      }),
    );
    const { container } = render(<StatusBanner />);

    online = false;
    await act(async () =>
      resolve(report({ ...operational, api: "not_responding" })),
    );

    expect(container).toBeEmptyDOMElement();
  });

  it("stays dismissed while the incident is the same, and returns when a service or its state changes", async () => {
    jest.useFakeTimers();
    try {
      const user = userEvent.setup({ advanceTimers: jest.advanceTimersByTime });
      fetchMock.mockResolvedValue(
        report({ ...operational, notifications: "degraded_performance" }),
      );
      render(<StatusBanner />);
      await act(async () => undefined);
      expect(screen.getByRole("status")).toHaveTextContent(
        "Email notifications are delayed.",
      );

      await user.click(
        screen.getByRole("button", { name: "Dismiss the status notice" }),
      );
      expect(screen.queryByRole("status")).not.toBeInTheDocument();

      await act(async () => {
        jest.advanceTimersByTime(STATUS_POLL_MS);
      });
      expect(screen.queryByRole("status")).not.toBeInTheDocument();

      fetchMock.mockResolvedValue(
        report({ ...operational, notifications: "major_outage" }),
      );
      await act(async () => {
        jest.advanceTimersByTime(STATUS_POLL_MS);
      });
      expect(screen.getByRole("status")).toHaveTextContent(
        "Email notifications are delayed. Work is queued and resumes when the service recovers.",
      );

      await user.click(
        screen.getByRole("button", { name: "Dismiss the status notice" }),
      );
      fetchMock.mockResolvedValue(
        report({
          ...operational,
          notifications: "major_outage",
          certificates: "major_outage",
        }),
      );
      await act(async () => {
        jest.advanceTimersByTime(STATUS_POLL_MS);
      });
      expect(screen.getByRole("status")).toHaveTextContent(
        "Email notifications are delayed. Certificate issuance and renewal is delayed. Work is queued and resumes when the service recovers.",
      );
    } finally {
      jest.useRealTimers();
    }
  });

  it("shows a source as not responding only after two failed reads in a row, and a reported outage at once", async () => {
    jest.useFakeTimers();
    try {
      fetchMock.mockResolvedValue(
        report({
          api: "not_responding",
          notifications: "not_responding",
          certificates: "not_responding",
        }),
      );
      const { container } = render(<StatusBanner />);
      await act(async () => undefined);
      expect(container).toBeEmptyDOMElement();

      await act(async () => {
        jest.advanceTimersByTime(STATUS_POLL_MS);
      });
      expect(screen.getByRole("status")).toHaveTextContent(
        "We could not reach some CertPing services.",
      );

      fetchMock.mockResolvedValue(
        report({ ...operational, api: "major_outage" }),
      );
      await act(async () => {
        jest.advanceTimersByTime(STATUS_POLL_MS);
      });
      expect(screen.getByRole("status")).toHaveTextContent(
        "Sign-in and the API are down.",
      );
      expect(screen.getByRole("status")).not.toHaveTextContent(
        /could not reach/,
      );
    } finally {
      jest.useRealTimers();
    }
  });

  it("skips the check on showing the tab again within 30 s of the last one", async () => {
    jest.useFakeTimers();
    try {
      fetchMock.mockResolvedValue(report(operational));
      render(<StatusBanner />);
      await act(async () => undefined);
      expect(fetchMock).toHaveBeenCalledTimes(1);

      act(() => setVisibility("hidden"));
      await act(async () => {
        jest.advanceTimersByTime(RECHECK_AFTER_MS - 1);
      });
      await act(async () => setVisibility("visible"));
      expect(fetchMock).toHaveBeenCalledTimes(1);

      act(() => setVisibility("hidden"));
      await act(async () => {
        jest.advanceTimersByTime(1);
      });
      await act(async () => setVisibility("visible"));
      expect(fetchMock).toHaveBeenCalledTimes(2);
    } finally {
      jest.useRealTimers();
    }
  });

  it("keeps a dismissal across a reload of the shell in the same session", async () => {
    window.sessionStorage.setItem(
      "certping.status-banner.dismissed",
      "notifications:major_outage",
    );
    fetchMock.mockResolvedValue(
      report({ ...operational, notifications: "major_outage" }),
    );

    const { container } = render(<StatusBanner />);

    await act(async () => undefined);
    expect(container).toBeEmptyDOMElement();
  });
});

describe("debounceFailedSources", () => {
  const failing = report({
    api: "not_responding",
    notifications: "not_responding",
    certificates: "not_responding",
  });
  const states = (r: StatusReport) =>
    Object.fromEntries(r.components.map((c) => [c.id, c.state]));

  /** A second source only these tests know, so the per-source rule stays covered. */
  const search: StatusSource = {
    id: "search",
    path: "/api/v1/public/search-status",
    components: [{ id: "search", name: "Search" }],
  };
  const BOTH: readonly StatusSource[] = [...STATUS_SOURCES, search];

  it("says nothing for a source whose first read fails", () => {
    expect(states(debounceFailedSources(failing, new Map()))).toEqual({});
  });

  it("keeps another source's answer while the first read of a source fails", () => {
    const partial = report({
      api: "not_responding",
      notifications: "not_responding",
      certificates: "not_responding",
      search: "operational",
    });
    expect(states(debounceFailedSources(partial, new Map(), BOTH))).toEqual({
      search: "operational",
    });
  });

  it("keeps a source's last answer through one failed read, then reports it", () => {
    const memory = new Map<string, SourceMemory>();
    debounceFailedSources(
      report({ ...operational, api: "degraded_performance" }),
      memory,
    );

    expect(states(debounceFailedSources(failing, memory)).api).toBe(
      "degraded_performance",
    );
    expect(states(debounceFailedSources(failing, memory)).api).toBe(
      "not_responding",
    );
  });

  it("starts the count again after a successful read", () => {
    const memory = new Map<string, SourceMemory>();
    debounceFailedSources(failing, memory);
    debounceFailedSources(report(operational), memory);

    expect(states(debounceFailedSources(failing, memory)).api).toBe(
      "operational",
    );
  });

  it("passes through components no source expects", () => {
    const extra: StatusReport = {
      ...failing,
      components: [
        ...failing.components,
        { id: "search", name: "Search", state: "major_outage" },
      ],
    };
    expect(states(debounceFailedSources(extra, new Map())).search).toBe(
      "major_outage",
    );
  });
});
