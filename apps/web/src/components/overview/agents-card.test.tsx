// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";

import { AgentsCard } from "@/components/overview/agents-card";

const mockAuth = jest.fn();

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => mockAuth(),
}));

jest.mock("@/hooks/agent", () => ({
  useAgentHealth: () => ({
    data: {
      organizationId: 7,
      overallStatus: "UNHEALTHY",
      listening: false,
      checkedAt: null,
      stale: true,
      failureReason: null,
    },
  }),
  useAgentHealthCadence: () => ({ data: { heartbeatCadenceMinutes: 5 } }),
  useUpdateAgentHealthCadence: () => ({
    isPending: false,
    mutateAsync: jest.fn(),
  }),
}));

const signIn = (roles: string[]) =>
  mockAuth.mockReturnValue({
    user: { id: "u1", organizationId: "7", roles, permissions: [] },
    isSuperAdmin: false,
  });

describe("AgentsCard", () => {
  it("is called Agents, links to the Agents page and keeps Adjust cadence", () => {
    signIn(["ORGANIZATION_ADMIN"]);

    render(<AgentsCard />);

    expect(screen.getByRole("heading", { name: "Agents" })).toBeInTheDocument();
    expect(
      screen.getByText(
        "Whether your agents are connected and how often they check in",
      ),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "View agents" })).toHaveAttribute(
      "href",
      "/agents",
    );
    expect(
      screen.getByRole("button", { name: "Adjust cadence" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        "The agent is not responding or reported an unhealthy state.",
      ),
    ).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/Sentinel|edge agent/i);
  });

  it("leaves out the link for members who cannot open the Agents page", () => {
    signIn(["VIEWER"]);

    render(<AgentsCard />);

    expect(
      screen.queryByRole("link", { name: "View agents" }),
    ).not.toBeInTheDocument();
  });
});
