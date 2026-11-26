// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useForm } from "react-hook-form";

import { AzureAppGatewayFields } from "@/components/cert-manager/credentials/providers/azure-app-gateway-fields";
import { AzureFrontDoorFields } from "@/components/cert-manager/credentials/providers/azure-front-door-fields";
import { AzureKvFields } from "@/components/cert-manager/credentials/providers/azure-kv-fields";
import { AZURE_WORKLOAD_IDENTITY_CLIENT_ID_HELP } from "@/components/cert-manager/credentials/providers/azure-service-principal-client-id-field";
import { Form } from "@/components/ui/form";

// These field components do not import React, and Jest compiles JSX with the classic runtime.
(globalThis as { React?: typeof React }).React = React;

function Harness({ children }: { children: (form: never) => React.ReactNode }) {
  const form = useForm({
    defaultValues: { azureAfdCustomDomains: [], azureAppGwListeners: [] },
  });
  return (
    <Form {...form}>
      <form>{children(form as never)}</form>
    </Form>
  );
}

describe("Azure provider fields", () => {
  it.each([
    [
      "Key Vault",
      (form: never) => (
        <AzureKvFields authMode="WORKLOAD_IDENTITY" form={form} />
      ),
    ],
    [
      "App Gateway",
      (form: never) => (
        <AzureAppGatewayFields authMode="WORKLOAD_IDENTITY" form={form} />
      ),
    ],
    [
      "Front Door",
      (form: never) => (
        <AzureFrontDoorFields authMode="WORKLOAD_IDENTITY" form={form} />
      ),
    ],
  ])(
    "describes the %s workload identity client ID as required",
    (_, renderFields) => {
      render(<Harness>{renderFields}</Harness>);

      expect(screen.getByLabelText("Client ID")).toBeInTheDocument();
      expect(
        screen.getByText(AZURE_WORKLOAD_IDENTITY_CLIENT_ID_HELP),
      ).toBeInTheDocument();
      expect(screen.queryByText(/Only needed when/)).not.toBeInTheDocument();
    },
  );

  it("asks for Front Door custom domain hostnames with labelled rows", async () => {
    const user = userEvent.setup();
    render(
      <Harness>
        {(form) => (
          <AzureFrontDoorFields authMode="SERVICE_PRINCIPAL" form={form} />
        )}
      </Harness>,
    );

    await user.click(screen.getByRole("button", { name: "Add custom domain" }));

    const row = screen.getByRole("textbox", { name: "Custom domains 1" });
    expect(row).toHaveAttribute("placeholder", "api.example.com");
    expect(screen.getByText(/Hostnames of the Front Door/)).toBeInTheDocument();
  });

  it("labels App Gateway listener rows", async () => {
    const user = userEvent.setup();
    render(
      <Harness>
        {(form) => (
          <AzureAppGatewayFields authMode="SERVICE_PRINCIPAL" form={form} />
        )}
      </Harness>,
    );

    await user.click(screen.getByRole("button", { name: "Add listener" }));

    expect(
      screen.getByRole("textbox", { name: "Listeners 1" }),
    ).toBeInTheDocument();
    expect(screen.queryByText("undefined")).not.toBeInTheDocument();
  });
});
