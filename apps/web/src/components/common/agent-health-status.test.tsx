// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";

import { AgentHealthSummaryCard } from "@/components/common/agent-health-status";

const noop = () => undefined;

function renderCard(
  agentHealth: React.ComponentProps<
    typeof AgentHealthSummaryCard
  >["agentHealth"],
) {
  return render(
    <AgentHealthSummaryCard
      agentHealth={agentHealth}
      cadenceMinutes={undefined}
      editingCadence={false}
      cadenceInput=""
      isSavingCadence={false}
      onCadenceInputChange={noop}
      onEditCadence={noop}
      onCancelCadence={noop}
      onSaveCadence={noop}
    />,
  );
}

describe("AgentHealthSummaryCard", () => {
  it("states the heartbeat status once while it is still checking", () => {
    renderCard(undefined);

    expect(screen.getAllByText("Checking")).toHaveLength(1);
    expect(screen.getByText("Heartbeat cadence")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Adjust cadence" }),
    ).toBeInTheDocument();
  });
});
