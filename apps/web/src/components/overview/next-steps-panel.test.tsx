// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import {
  NextStepsPanel,
  readSnoozes,
  SNOOZE_STORAGE_KEY,
} from "@/components/overview/next-steps-panel";
import type { NextStep } from "@/lib/overview-next-steps";

const STEPS: NextStep[] = [
  {
    id: "alerts",
    tone: "critical",
    title: "2 priority alerts unread",
    detail: "Review them.",
    action: { kind: "link", label: "Review alerts", href: "/incidents" },
  },
  {
    id: "certificate:first",
    tone: "opportunity",
    title: "Issue your first certificate",
    detail: "Request a TLS certificate.",
    action: {
      kind: "link",
      label: "Issue certificate",
      href: "/cert-manager/add",
    },
  },
];

describe("NextStepsPanel", () => {
  beforeEach(() => window.localStorage.clear());

  it("gives only the first step the primary action", () => {
    render(<NextStepsPanel steps={STEPS} isLoading={false} />);

    const [first, second] = screen.getAllByRole("listitem");
    expect(first).toHaveAttribute("data-tone", "critical");
    expect(
      within(first!).getByRole("link", { name: "Review alerts" }),
    ).toHaveAttribute("data-variant", "default");
    expect(
      within(second!).getByRole("link", { name: "Issue certificate" }),
    ).toHaveAttribute("data-variant", "outline");
  });

  it("celebrates when nothing is left to do", () => {
    render(<NextStepsPanel steps={[]} isLoading={false} />);

    expect(screen.getByText("All set")).toBeInTheDocument();
  });

  it("never says all set when a source could not be checked", async () => {
    const user = userEvent.setup();
    const onRetry = jest.fn();
    render(
      <NextStepsPanel
        steps={[]}
        isLoading={false}
        failedSources={["certificates", "alerts"]}
        onRetry={onRetry}
      />,
    );

    expect(screen.queryByText("All set")).not.toBeInTheDocument();
    expect(
      screen.getByText(
        "We couldn't check certificates and alerts just now, so this list may be incomplete. Try again in a moment.",
      ),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Try again" }));
    expect(onRetry).toHaveBeenCalled();
  });

  it("leaves the primary action to the page when asked", () => {
    render(
      <NextStepsPanel steps={STEPS} isLoading={false} primaryFirst={false} />,
    );

    expect(screen.getByRole("link", { name: "Review alerts" })).toHaveAttribute(
      "data-variant",
      "outline",
    );
  });

  it("snoozes an offer for 30 days, but never a risk", async () => {
    const user = userEvent.setup();
    const now = Date.now();
    const { unmount } = render(
      <NextStepsPanel steps={STEPS} isLoading={false} />,
    );

    expect(
      screen.queryByRole("button", {
        name: "Hide for 30 days: 2 priority alerts unread",
      }),
    ).not.toBeInTheDocument();
    await user.click(
      screen.getByRole("button", {
        name: "Hide for 30 days: Issue your first certificate",
      }),
    );
    expect(
      screen.queryByText("Issue your first certificate"),
    ).not.toBeInTheDocument();
    const until = readSnoozes()["certificate:first"];
    expect(until).toBeGreaterThanOrEqual(now + 30 * 86_400_000 - 1000);
    unmount();

    render(<NextStepsPanel steps={STEPS} isLoading={false} />);
    expect(
      screen.queryByText("Issue your first certificate"),
    ).not.toBeInTheDocument();
    expect(screen.getByText("2 priority alerts unread")).toBeInTheDocument();
  });

  it("brings an offer back once its snooze ends and survives bad storage", () => {
    window.localStorage.setItem(
      SNOOZE_STORAGE_KEY,
      JSON.stringify({ "certificate:first": Date.now() - 1, other: "x" }),
    );
    expect(readSnoozes()).toEqual({});
    window.localStorage.setItem(SNOOZE_STORAGE_KEY, "{not json");
    expect(readSnoozes()).toEqual({});

    const getItem = jest
      .spyOn(Storage.prototype, "getItem")
      .mockImplementation(() => {
        throw new Error("blocked");
      });
    expect(readSnoozes()).toEqual({});
    getItem.mockRestore();
  });

  it("holds the layout while signals load", () => {
    render(<NextStepsPanel steps={[]} isLoading />);

    expect(screen.queryByText("All set")).not.toBeInTheDocument();
    expect(screen.getAllByRole("listitem")).toHaveLength(3);
  });
});
