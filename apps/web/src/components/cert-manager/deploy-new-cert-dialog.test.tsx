// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { DeployNewCertDialog } from "@/components/cert-manager/deploy-new-cert-dialog";

const mockUseListCertificates = jest.fn();
const mockUseCertificateHistories = jest.fn();
const mockUseCredentials = jest.fn();
const mockUseDeployCertificate = jest.fn();
const mockUseDeploymentCredentialConfig = jest.fn();
const mockDeployMutateAsync = jest.fn();
const mockOnOpenChange = jest.fn();
const mockPush = jest.fn();

jest.mock("next/navigation", () => ({
  useRouter: () => ({ push: mockPush }),
}));

jest.mock("@/hooks/ssl", () => ({
  useCertificateHistories: (...args: unknown[]) =>
    mockUseCertificateHistories(...args),
}));

jest.mock("@/hooks/use-progressive-certificate-list", () => ({
  useProgressiveCertificateList: (...args: unknown[]) =>
    mockUseListCertificates(...args),
}));

const mockUseCanAddCredential = jest.fn<boolean, [string]>(() => true);
jest.mock("@/hooks/credentials", () => ({
  useCanAddCredential: (type: string) => mockUseCanAddCredential(type),
  useCredentials: (...args: unknown[]) => mockUseCredentials(...args),
}));

jest.mock("@/hooks/deployments", () => ({
  useDeployCertificate: () => mockUseDeployCertificate(),
  useDeploymentCredentialConfig: (
    certificateXref?: string,
    deploymentCredentialXref?: string,
  ) =>
    mockUseDeploymentCredentialConfig(
      certificateXref,
      deploymentCredentialXref,
    ),
}));

jest.mock("next/image", () => ({
  __esModule: true,
  default: (props: React.ImgHTMLAttributes<HTMLImageElement>) => (
    // eslint-disable-next-line @next/next/no-img-element
    <img alt={props.alt ?? ""} {...props} />
  ),
}));

const lifecycleCertificates = [
  {
    certificateXref: "cert-629541900320827",
    domain: "app.example.org",
    status: "PENDING",
    userDomainCertId: "101",
  },
  {
    certificateXref: "cert-629275318339601",
    domain: "app.example.org",
    status: "RENEW_SUCCESS",
    userDomainCertId: "101",
  },
  {
    certificateXref: "cert-629478390362668",
    domain: "app.example.org",
    status: "RENEWING",
    userDomainCertId: "101",
  },
];

describe("DeployNewCertDialog lifecycle certificate selection", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockUseCanAddCredential.mockReturnValue(true);
    mockUseListCertificates.mockReturnValue({
      data: lifecycleCertificates,
      isFetched: true,
    });
    mockUseCertificateHistories.mockReturnValue([]);
    mockUseCredentials.mockReturnValue({
      data: [
        {
          credentialXref: "deploy-azure-kv",
          description: "Prod vault",
          providerName: "AZURE_KV",
          targetType: "AZURE_KV",
        },
      ],
      isLoading: false,
    });
    mockUseDeployCertificate.mockReturnValue({
      isPending: false,
      mutateAsync: mockDeployMutateAsync,
    });
    mockUseDeploymentCredentialConfig.mockReturnValue({
      data: null,
      isFetched: true,
      isLoading: false,
    });
    mockDeployMutateAsync.mockResolvedValue({});
  });

  it("points to adding a deployment target when none exist and one may be added", () => {
    mockUseCredentials.mockReturnValue({ data: [], isLoading: false });

    render(<DeployNewCertDialog open onOpenChange={mockOnOpenChange} />);

    expect(mockUseCanAddCredential).toHaveBeenCalledWith("DEPLOYMENT");
    expect(
      screen.getByText(/Use “Add deployment target” below/),
    ).toBeInTheDocument();
  });

  it("does not mention adding a credential when credentials cannot be added", () => {
    mockUseCanAddCredential.mockReturnValue(false);
    mockUseCredentials.mockReturnValue({ data: [], isLoading: false });

    render(<DeployNewCertDialog open onOpenChange={mockOnOpenChange} />);

    expect(
      screen.getByText(
        "A deployment target is required before you start a deployment.",
      ),
    ).toBeInTheDocument();
    expect(screen.queryByText(/Add deployment target/)).not.toBeInTheDocument();
  });

  it("labels the deployment credential trigger for stable interaction", () => {
    render(
      <DeployNewCertDialog
        initialCertificateId="cert-629541900320827"
        open
        onOpenChange={mockOnOpenChange}
      />,
    );

    expect(
      screen.getByRole("combobox", { name: "Deployment target" }),
    ).toBeInTheDocument();
  });

  it("keeps deployment choices stable while the dialog is open", () => {
    render(
      <DeployNewCertDialog
        initialCertificateId="cert-629541900320827"
        open
        onOpenChange={mockOnOpenChange}
      />,
    );

    expect(mockUseListCertificates).toHaveBeenCalledWith({
      enabled: true,
      pollWhilePending: false,
    });
    expect(mockUseCredentials).toHaveBeenCalledWith({
      category: "deployment_target",
      enabled: true,
      pollWhilePending: false,
    });
    expect(mockUseCertificateHistories).toHaveBeenCalledWith(["101"], {
      enabled: true,
      pollWhilePending: false,
    });
  });

  it("does not request lifecycle history for active certificates", () => {
    mockUseListCertificates.mockReturnValue({
      data: [
        {
          certificateXref: "cert-active",
          domain: "active.example.com",
          status: "ACTIVE",
          userDomainCertId: "active-udc",
        },
      ],
      isFetched: true,
    });

    render(<DeployNewCertDialog open onOpenChange={mockOnOpenChange} />);

    expect(mockUseCertificateHistories).toHaveBeenCalledWith([], {
      enabled: false,
      pollWhilePending: false,
    });
  });

  it("keeps the form usable while lifecycle versions are resolving", () => {
    mockUseCertificateHistories.mockReturnValue([
      { isPending: true, isFetching: true },
      { isError: true },
    ]);

    render(<DeployNewCertDialog open onOpenChange={mockOnOpenChange} />);

    expect(screen.getByRole("status")).toHaveTextContent(
      "Checking renewing certificate versions…",
    );
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Some renewing certificates could not be checked",
    );
    expect(screen.getAllByRole("combobox")[0]).toBeEnabled();
  });

  it("submits the current renewing xref when opened from a pending renewal xref", async () => {
    const user = userEvent.setup();

    render(
      <DeployNewCertDialog
        initialCertificateId="cert-629541900320827"
        open
        onOpenChange={mockOnOpenChange}
      />,
    );

    await waitFor(() => {
      const [certificateCombobox] = screen.getAllByRole("combobox");
      expect(certificateCombobox).toHaveTextContent("app.example.org");
    });

    const comboboxes = screen.getAllByRole("combobox");
    await user.click(comboboxes[0]!);
    const certificateOptions = await screen.findAllByRole("option", {
      name: "app.example.org",
    });
    expect(certificateOptions).toHaveLength(1);
    await user.click(certificateOptions[0]!);

    await user.click(comboboxes[1]!);
    const credentialOption = await screen.findByRole("option", {
      name: /Prod vault/i,
    });
    await user.click(credentialOption);

    const certificateNameInput = within(
      screen.getByText("Certificate name").parentElement as HTMLElement,
    ).getByRole("textbox");
    await user.clear(certificateNameInput);
    await user.type(certificateNameInput, "app-example-org");
    await user.click(
      screen.getByRole("button", { name: "Request deployment" }),
    );

    await waitFor(() =>
      expect(mockDeployMutateAsync).toHaveBeenCalledWith({
        certificateXref: "cert-629478390362668",
        deploymentCredentialXref: "deploy-azure-kv",
        targetType: "AZURE_KV",
        targets: { certificateName: "app-example-org" },
      }),
    );
  });

  it("loads lifecycle history so a renewal domain appears when the certificate list only has a pending row", async () => {
    const user = userEvent.setup();
    mockUseListCertificates.mockReturnValue({
      data: [
        {
          certificateXref: "cert-629541900320827",
          domain: "app.example.org",
          status: "PENDING",
          userDomainCertId: "101",
        },
      ],
      isFetched: true,
    });
    mockUseCertificateHistories.mockReturnValue([
      {
        data: {
          items: [
            {
              certificateXref: "cert-629478390362668",
              domain: "app.example.org",
              status: "RENEWING",
              userDomainCertId: "101",
            },
            {
              certificateXref: "cert-629275318339601",
              domain: "app.example.org",
              status: "RENEW_SUCCESS",
              userDomainCertId: "101",
            },
          ],
        },
      },
    ]);

    render(
      <DeployNewCertDialog
        initialCertificateId={undefined}
        open
        onOpenChange={mockOnOpenChange}
      />,
    );

    expect(mockUseCertificateHistories).toHaveBeenCalledWith(["101"], {
      enabled: true,
      pollWhilePending: false,
    });

    const comboboxes = screen.getAllByRole("combobox");
    await user.click(comboboxes[0]!);
    const certificateOption = await screen.findByRole("option", {
      name: "app.example.org",
    });
    await user.click(certificateOption);

    await user.click(comboboxes[1]!);
    await user.click(
      await screen.findByRole("option", { name: /Prod vault/i }),
    );

    const certificateNameInput = within(
      screen.getByText("Certificate name").parentElement as HTMLElement,
    ).getByRole("textbox");
    await user.clear(certificateNameInput);
    await user.type(certificateNameInput, "app-example-org");
    await user.click(
      screen.getByRole("button", { name: "Request deployment" }),
    );

    await waitFor(() =>
      expect(mockDeployMutateAsync).toHaveBeenCalledWith({
        certificateXref: "cert-629478390362668",
        deploymentCredentialXref: "deploy-azure-kv",
        targetType: "AZURE_KV",
        targets: { certificateName: "app-example-org" },
      }),
    );
  });

  it("submits the active lifecycle xref when opened from a renewal-success history row", async () => {
    const user = userEvent.setup();
    mockUseListCertificates.mockReturnValue({
      data: [
        {
          certificateXref: "cert-123207217728585",
          domain: "app.example.org",
          status: "RENEW_SUCCESS",
          userDomainCertId: "101",
        },
      ],
      isFetched: true,
    });
    mockUseCertificateHistories.mockReturnValue([
      {
        data: {
          items: [
            {
              certificateXref: "cert-123207217728585",
              domain: "app.example.org",
              status: "RENEW_SUCCESS",
              userDomainCertId: "101",
            },
            {
              certificateXref: "cert-123490622080213",
              domain: "app.example.org",
              status: "ACTIVE",
              userDomainCertId: "101",
            },
          ],
        },
      },
    ]);

    render(
      <DeployNewCertDialog
        initialCertificateId="cert-123207217728585"
        open
        onOpenChange={mockOnOpenChange}
      />,
    );

    expect(mockUseCertificateHistories).toHaveBeenCalledWith(["101"], {
      enabled: true,
      pollWhilePending: false,
    });

    const comboboxes = screen.getAllByRole("combobox");
    await user.click(comboboxes[1]!);
    await user.click(
      await screen.findByRole("option", { name: /Prod vault/i }),
    );

    const certificateNameInput = within(
      screen.getByText("Certificate name").parentElement as HTMLElement,
    ).getByRole("textbox");
    await user.clear(certificateNameInput);
    await user.type(certificateNameInput, "app-example-org");
    await user.click(
      screen.getByRole("button", { name: "Request deployment" }),
    );

    await waitFor(() =>
      expect(mockDeployMutateAsync).toHaveBeenCalledWith({
        certificateXref: "cert-123490622080213",
        deploymentCredentialXref: "deploy-azure-kv",
        targetType: "AZURE_KV",
        targets: { certificateName: "app-example-org" },
      }),
    );
  });

  it("does not loop when lifecycle history query results change reference between renders", async () => {
    mockUseListCertificates.mockReturnValue({
      data: [
        {
          certificateXref: "cert-629541900320827",
          domain: "app.example.org",
          status: "PENDING",
          userDomainCertId: "101",
        },
      ],
      isFetched: true,
    });
    mockUseCertificateHistories.mockImplementation(() => [
      {
        data: {
          items: [
            {
              certificateXref: "cert-629478390362668",
              domain: "app.example.org",
              status: "RENEWING",
              userDomainCertId: "101",
            },
          ],
        },
      },
    ]);

    render(
      <DeployNewCertDialog
        initialCertificateId="cert-629541900320827"
        open
        onOpenChange={mockOnOpenChange}
      />,
    );

    await waitFor(() => {
      const [certificateCombobox] = screen.getAllByRole("combobox");
      expect(certificateCombobox).toHaveTextContent("app.example.org");
    });
  });

  const selectDeploymentTarget = async (
    user: ReturnType<typeof userEvent.setup>,
    name: RegExp,
  ) => {
    await waitFor(() => {
      const [certificateCombobox] = screen.getAllByRole("combobox");
      expect(certificateCombobox).toHaveTextContent("app.example.org");
    });
    await user.click(screen.getAllByRole("combobox")[1]!);
    await user.click(await screen.findByRole("option", { name }));
  };

  it("prefills the Key Vault certificate name and flags it when cleared", async () => {
    const user = userEvent.setup();
    render(
      <DeployNewCertDialog
        initialCertificateId="cert-629478390362668"
        open
        onOpenChange={mockOnOpenChange}
      />,
    );
    await selectDeploymentTarget(user, /Prod vault/i);

    const certificateName = screen.getByLabelText("Certificate name");
    expect(certificateName).toHaveValue("app-example-org");

    await user.clear(certificateName);
    await user.click(
      screen.getByRole("button", { name: "Request deployment" }),
    );

    expect(
      await screen.findByText("Certificate name is required."),
    ).toBeInTheDocument();
    expect(certificateName).toHaveAttribute("aria-invalid", "true");
    expect(mockDeployMutateAsync).not.toHaveBeenCalled();
  });

  it("defaults Front Door and App Gateway names and flags them when cleared", async () => {
    const user = userEvent.setup();
    mockUseCredentials.mockReturnValue({
      data: [
        {
          credentialXref: "deploy-azure-afd",
          description: "Edge front door",
          providerName: "AZURE_AFD",
          targetType: "AZURE_AFD",
        },
        {
          credentialXref: "deploy-azure-agw",
          description: "Prod gateway",
          providerName: "AZURE_APP_GW",
          targetType: "AZURE_APP_GW",
        },
      ],
      isLoading: false,
    });
    render(
      <DeployNewCertDialog
        initialCertificateId="cert-629478390362668"
        open
        onOpenChange={mockOnOpenChange}
      />,
    );
    await selectDeploymentTarget(user, /Edge front door/i);

    expect(screen.getByLabelText("Certificate name")).toHaveValue(
      "app-example-org-afd",
    );
    const secretName = screen.getByLabelText("Secret name");
    expect(secretName).toHaveValue("app-example-org-afd-secret");

    await user.clear(secretName);
    await user.click(
      screen.getByRole("button", { name: "Request deployment" }),
    );
    expect(
      await screen.findByText("Secret name is required."),
    ).toBeInTheDocument();

    await user.click(screen.getAllByRole("combobox")[1]!);
    await user.click(
      await screen.findByRole("option", { name: /Prod gateway/i }),
    );
    const sslCertName = screen.getByLabelText("SSL cert name");
    expect(sslCertName).toHaveValue("certping-app-example-org");
    expect(screen.queryByText(/is required\./)).not.toBeInTheDocument();

    await user.clear(sslCertName);
    await user.click(
      screen.getByRole("button", { name: "Request deployment" }),
    );
    expect(
      await screen.findByText("SSL cert name is required."),
    ).toBeInTheDocument();
    expect(mockDeployMutateAsync).not.toHaveBeenCalled();
  });

  it("auto-selects the current certificate when opened from the manage page", async () => {
    render(
      <DeployNewCertDialog
        initialCertificateId="cert-629478390362668"
        open
        onOpenChange={mockOnOpenChange}
      />,
    );

    await waitFor(() => {
      const [certificateCombobox] = screen.getAllByRole("combobox");
      expect(certificateCombobox).toHaveTextContent("app.example.org");
    });
  });

  it("keeps a manual certificate selection when the initial xref is not deployable", async () => {
    const user = userEvent.setup();
    mockUseListCertificates.mockReturnValue({
      data: [
        {
          certificateXref: "cert-revoked",
          domain: "example.org",
          status: "REVOKED",
          userDomainCertId: "102",
        },
        {
          certificateXref: "cert-active",
          domain: "example.com",
          status: "ACTIVE",
          userDomainCertId: "103",
        },
      ],
      isFetched: true,
    });
    mockUseCertificateHistories.mockReturnValue([]);

    render(
      <DeployNewCertDialog
        initialCertificateId="cert-revoked"
        open
        onOpenChange={mockOnOpenChange}
      />,
    );

    const comboboxes = screen.getAllByRole("combobox");
    await user.click(comboboxes[0]!);
    await user.click(
      await screen.findByRole("option", { name: "example.com" }),
    );

    await user.click(comboboxes[1]!);
    await user.click(
      await screen.findByRole("option", { name: /Prod vault/i }),
    );

    const certificateNameInput = within(
      screen.getByText("Certificate name").parentElement as HTMLElement,
    ).getByRole("textbox");
    await user.clear(certificateNameInput);
    await user.type(certificateNameInput, "certping-ai");
    await user.click(
      screen.getByRole("button", { name: "Request deployment" }),
    );

    await waitFor(() =>
      expect(mockDeployMutateAsync).toHaveBeenCalledWith({
        certificateXref: "cert-active",
        deploymentCredentialXref: "deploy-azure-kv",
        targetType: "AZURE_KV",
        targets: { certificateName: "certping-ai" },
      }),
    );
  });
});
