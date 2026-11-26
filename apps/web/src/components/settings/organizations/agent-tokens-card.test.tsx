// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";

import { AgentTokensCard } from "@/components/settings/organizations/agent-tokens-card";
import {
  useAgentTokens,
  useCreateAgentToken,
  useRevokeAgentToken,
} from "@/hooks/agent-tokens";

jest.mock("@/hooks/agent-tokens", () => ({
  useAgentTokens: jest.fn(),
  useCreateAgentToken: jest.fn(),
  useRevokeAgentToken: jest.fn(),
}));

jest.mock("sonner", () => ({
  toast: { success: jest.fn(), error: jest.fn() },
}));

const mockedTokens = useAgentTokens as jest.Mock;
const mockedCreate = useCreateAgentToken as jest.Mock;
const mockedRevoke = useRevokeAgentToken as jest.Mock;

const created = {
  token: {
    id: 9,
    organizationId: "7",
    name: "edge",
    tokenPrefix: "cpa_abcdef",
  },
  value: "cpa_abcdefSECRET",
  gatewayPath: "/api/v1/agent-gateway",
  dockerCommand: "docker run ... -e CERTPING_AGENT_TOKEN=cpa_abcdefSECRET",
};

describe("AgentTokensCard", () => {
  let createAsync: jest.Mock;
  let revokeAsync: jest.Mock;

  beforeEach(() => {
    createAsync = jest.fn().mockResolvedValue(created);
    revokeAsync = jest.fn().mockResolvedValue(undefined);
    mockedCreate.mockReturnValue({
      mutateAsync: createAsync,
      isPending: false,
    });
    mockedRevoke.mockReturnValue({
      mutateAsync: revokeAsync,
      isPending: false,
    });
    mockedTokens.mockReturnValue({
      isLoading: false,
      error: null,
      data: [
        {
          id: 1,
          organizationId: "7",
          name: "datacenter-east",
          tokenPrefix: "cpa_111111",
          createdAt: "2026-10-01T00:00:00Z",
          lastUsedAt: "2026-10-20T00:00:00Z",
          revokedAt: null,
        },
        {
          id: 2,
          organizationId: "7",
          name: "old",
          tokenPrefix: "cpa_222222",
          createdAt: "2026-09-01T00:00:00Z",
          lastUsedAt: null,
          revokedAt: "2026-09-02T00:00:00Z",
        },
      ],
    });
    Object.assign(navigator, {
      clipboard: { writeText: jest.fn().mockResolvedValue(undefined) },
    });
  });

  it("links to the Agents page", () => {
    render(<AgentTokensCard organizationId="7" canManage />);

    expect(screen.getByRole("link", { name: "Manage agents" })).toHaveAttribute(
      "href",
      "/agents",
    );
  });

  it("sends the chosen expiry and omits it for Never", async () => {
    render(<AgentTokensCard organizationId="7" canManage />);

    const expiry = screen.getByRole("combobox", { name: "Expires after" });
    expect(
      Array.from((expiry as HTMLSelectElement).options).map((o) => o.text),
    ).toEqual(["Never", "30 days", "90 days", "365 days"]);
    fireEvent.change(expiry, { target: { value: "90" } });
    fireEvent.click(screen.getByRole("button", { name: "Add agent" }));

    await waitFor(() =>
      expect(createAsync).toHaveBeenCalledWith({
        name: "agent",
        serverUrl: window.location.origin,
        expiresInDays: 90,
      }),
    );
  });

  it("shows the expiry and marks expired tokens", () => {
    mockedTokens.mockReturnValue({
      isLoading: false,
      error: null,
      data: [
        {
          id: 3,
          organizationId: "7",
          name: "lapsed",
          tokenPrefix: "cpa_333333",
          createdAt: "2020-01-01T00:00:00Z",
          lastUsedAt: null,
          revokedAt: null,
          expiresAt: "2020-02-01T00:00:00Z",
        },
        {
          id: 4,
          organizationId: "7",
          name: "fresh",
          tokenPrefix: "cpa_444444",
          createdAt: "2026-10-01T00:00:00Z",
          lastUsedAt: null,
          revokedAt: null,
          expiresAt: "2999-01-01T00:00:00Z",
        },
        {
          id: 5,
          organizationId: "7",
          name: "forever",
          tokenPrefix: "cpa_555555",
          createdAt: "2026-10-01T00:00:00Z",
          lastUsedAt: null,
          revokedAt: null,
        },
      ],
    });
    render(<AgentTokensCard organizationId="7" canManage />);

    expect(screen.getAllByText("Expired")).toHaveLength(1);
    expect(screen.getByText(/· expired /)).toBeInTheDocument();
    expect(screen.getByText(/· expires /)).toBeInTheDocument();
    expect(screen.getByText(/never expires/)).toBeInTheDocument();
  });

  it("creates a token and shows it once with the start command", async () => {
    render(<AgentTokensCard organizationId="7" canManage />);

    fireEvent.change(screen.getByLabelText("Agent name"), {
      target: { value: "edge" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add agent" }));

    await waitFor(() =>
      expect(createAsync).toHaveBeenCalledWith({
        name: "edge",
        serverUrl: window.location.origin,
      }),
    );
    expect(await screen.findByText("cpa_abcdefSECRET")).toBeInTheDocument();
    expect(screen.getByText(/It is shown only once/)).toBeInTheDocument();

    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Copy Agent token" }));
    });
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(
      "cpa_abcdefSECRET",
    );

    fireEvent.click(screen.getByRole("button", { name: "Done" }));
    expect(screen.queryByText("cpa_abcdefSECRET")).not.toBeInTheDocument();
  });

  it("lists tokens and revokes an active one after confirming", async () => {
    render(<AgentTokensCard organizationId="7" canManage />);

    expect(screen.getByText("datacenter-east")).toBeInTheDocument();
    expect(screen.getByText("Revoked")).toBeInTheDocument();
    const revokeButtons = screen.getAllByRole("button", { name: "Revoke" });
    expect(revokeButtons).toHaveLength(1);

    fireEvent.click(revokeButtons[0]);
    fireEvent.click(
      within(await screen.findByRole("alertdialog")).getByRole("button", {
        name: "Revoke",
      }),
    );
    await waitFor(() => expect(revokeAsync).toHaveBeenCalledWith(1));
  });

  it("does nothing when the revoke is cancelled", async () => {
    render(<AgentTokensCard organizationId="7" canManage />);
    fireEvent.click(screen.getByRole("button", { name: "Revoke" }));
    fireEvent.click(await screen.findByRole("button", { name: "Cancel" }));
    expect(revokeAsync).not.toHaveBeenCalled();
  });

  it("reports create and revoke failures", async () => {
    const { toast } = jest.requireMock("sonner");
    createAsync.mockRejectedValueOnce(new Error("nope"));
    revokeAsync.mockRejectedValueOnce(new Error("nope"));
    render(<AgentTokensCard organizationId="7" canManage />);

    fireEvent.click(screen.getByRole("button", { name: "Add agent" }));
    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith(
        "Could not create the agent token",
      ),
    );
    fireEvent.click(screen.getByRole("button", { name: "Revoke" }));
    fireEvent.click(
      within(await screen.findByRole("alertdialog")).getByRole("button", {
        name: "Revoke",
      }),
    );
    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith(
        "Could not revoke the agent token",
      ),
    );
  });

  it("shows loading, error and empty states, and hides controls without permission", () => {
    mockedTokens.mockReturnValueOnce({
      isLoading: true,
      error: null,
      data: undefined,
    });
    const { rerender } = render(
      <AgentTokensCard organizationId="7" canManage={false} />,
    );
    expect(screen.getByText("Loading agents...")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Add agent" }),
    ).not.toBeInTheDocument();

    mockedTokens.mockReturnValueOnce({
      isLoading: false,
      error: new Error("x"),
      data: undefined,
    });
    rerender(<AgentTokensCard organizationId="7" canManage={false} />);
    expect(
      screen.getByText("Could not load agent tokens."),
    ).toBeInTheDocument();

    mockedTokens.mockReturnValueOnce({
      isLoading: false,
      error: null,
      data: [],
    });
    rerender(<AgentTokensCard organizationId="7" canManage={false} />);
    expect(screen.getByText(/No agents yet/)).toBeInTheDocument();
  });
});
