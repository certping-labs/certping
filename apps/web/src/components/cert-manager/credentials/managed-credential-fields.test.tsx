// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";
import { useForm } from "react-hook-form";

import { ManagedCredentialFields } from "@/components/cert-manager/credentials/managed-credential-fields";
import { Form } from "@/components/ui/form";
import { Input, NoAutofillForm } from "@/components/ui/input";
import type { CredentialFormValidationValues } from "@/lib/cert-manager/credential-form-schemas/types";
import type { KubernetesAuthMethod } from "@/lib/credential-config-schemas/kubernetes-secrets";

function KubernetesCredentialFieldsHarness({
  authMethod,
}: {
  authMethod: KubernetesAuthMethod;
}) {
  const form = useForm<CredentialFormValidationValues>({
    defaultValues: {},
  });

  return (
    <Form {...form}>
      <form>
        <ManagedCredentialFields
          form={form}
          mode="create"
          type="DEPLOYMENT"
          providerApiValue="KUBERNETES_SECRETS"
          kubernetesAuthMethod={authMethod}
        />
      </form>
    </Form>
  );
}

describe("ManagedCredentialFields Kubernetes credentials", () => {
  it("shows every required Azure credential field", () => {
    render(<KubernetesCredentialFieldsHarness authMethod="AZURE" />);

    expect(screen.getByLabelText("Tenant ID")).toBeInTheDocument();
    expect(screen.getByLabelText("Subscription ID")).toBeInTheDocument();
    expect(screen.getByLabelText("Resource group")).toBeInTheDocument();
    expect(screen.getByLabelText("Client ID")).toBeInTheDocument();
    expect(screen.getByLabelText("Client secret")).toBeInTheDocument();
    expect(screen.getByText("Private cluster access")).toBeInTheDocument();
  });

  it("shows every required GCP credential field", () => {
    render(<KubernetesCredentialFieldsHarness authMethod="GCP" />);

    expect(screen.getByLabelText("Project ID")).toBeInTheDocument();
    expect(screen.getByLabelText("Location")).toBeInTheDocument();
    expect(
      screen.getByLabelText("Service account key JSON (optional)"),
    ).toBeInTheDocument();
  });

  it("asks for the API server, token and CA of a service account token credential", () => {
    render(<KubernetesCredentialFieldsHarness authMethod="SA_TOKEN" />);

    expect(screen.getByLabelText("API server URL")).toBeInTheDocument();
    expect(screen.getByLabelText("Service account token")).toHaveAttribute(
      "type",
      "password",
    );
    expect(screen.getByLabelText("Cluster CA certificate")).toBeInTheDocument();
    expect(screen.getByText(/k3s, kubeadm/)).toBeInTheDocument();
    expect(
      screen.queryByText("No stored secret needed"),
    ).not.toBeInTheDocument();
  });

  it("needs no secret for an in-cluster credential", () => {
    render(<KubernetesCredentialFieldsHarness authMethod="SA_INCLUSTER" />);

    expect(screen.getByText("No stored secret needed")).toBeInTheDocument();
    expect(screen.queryByLabelText("API server URL")).not.toBeInTheDocument();
  });

  it("does not expose internal app-mode terminology", () => {
    render(<KubernetesCredentialFieldsHarness authMethod="SA_INCLUSTER" />);

    expect(
      screen.queryByText(/self-serve|enterprise/i),
    ).not.toBeInTheDocument();
  });
});

function AzureKvServicePrincipalHarness() {
  const form = useForm<CredentialFormValidationValues>({
    defaultValues: {},
  });

  return (
    <Form {...form}>
      <NoAutofillForm>
        <Input aria-label="Name" />
        <ManagedCredentialFields
          form={form}
          mode="create"
          type="DEPLOYMENT"
          providerApiValue="AZURE_KV"
          azureKvAuthMode="SERVICE_PRINCIPAL"
        />
      </NoAutofillForm>
    </Form>
  );
}

describe("ManagedCredentialFields browser autofill", () => {
  it("keeps saved logins out of credential inputs", () => {
    render(<AzureKvServicePrincipalHarness />);

    expect(screen.getByLabelText("Name")).toHaveAttribute(
      "autocomplete",
      "off",
    );
    expect(screen.getByLabelText("Client ID")).toHaveAttribute(
      "autocomplete",
      "off",
    );
    const secret = screen.getByLabelText("Client secret");
    expect(secret).toHaveAttribute("autocomplete", "new-password");
    expect(secret).toHaveAttribute("data-1p-ignore", "true");
    expect(secret).toHaveAttribute("data-lpignore", "true");
    expect(secret.closest("form")).toHaveAttribute("autocomplete", "off");
  });
});
