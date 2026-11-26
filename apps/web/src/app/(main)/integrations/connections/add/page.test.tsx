// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import AddCredentialPage from "@/app/(main)/integrations/connections/add/page";

let mockAgentTransport: "GATEWAY" | undefined;
jest.mock("@/hooks/use-deployment-mode", () => ({
  useAgentTransport: () => mockAgentTransport,
}));

const pushMock = jest.fn();
const useUnsavedChangesWarningMock = jest.fn((shouldWarn: boolean) => ({
  confirmLeave: () => true,
  shouldWarn,
}));
const originalAppMode = process.env.NEXT_PUBLIC_APP_MODE;
let certificateDeploymentEnabled = true;
let dnsCredentialsEnabled = true;
let searchParams = "";

jest.mock("next/navigation", () => ({
  useRouter: () => ({
    push: pushMock,
  }),
  useSearchParams: () => new URLSearchParams(searchParams),
}));

jest.mock("next/image", () => ({
  __esModule: true,
  default: (props: React.ImgHTMLAttributes<HTMLImageElement>) => (
    // eslint-disable-next-line @next/next/no-img-element
    <img alt={props.alt ?? ""} {...props} />
  ),
}));

jest.mock("@/hooks/credentials", () => ({
  useAddCredential: () => ({
    isPending: false,
    mutateAsync: jest.fn(),
  }),
}));

jest.mock("@/hooks/use-feature-flags", () => ({
  useIsFeatureEnabled: (key: string) => {
    if (key === "CERTIFICATE_DEPLOYMENT") {
      return certificateDeploymentEnabled;
    }
    if (key === "DNS_CREDENTIALS") {
      return dnsCredentialsEnabled;
    }
    return true;
  },
  useIsOrgFeatureEnabled: (key: string) => {
    if (key === "CERTIFICATE_DEPLOYMENT") {
      return certificateDeploymentEnabled;
    }
    if (key === "DNS_CREDENTIALS") {
      return dnsCredentialsEnabled;
    }
    return true;
  },
}));

jest.mock("@/hooks/use-unsaved-changes-warning", () => ({
  useUnsavedChangesWarning: (shouldWarn: boolean) =>
    useUnsavedChangesWarningMock(shouldWarn),
}));

jest.mock("@/components/ui/page-header", () => ({
  PageHeader: ({ title }: { title: string }) => <div>{title}</div>,
}));

jest.mock("@/components/common/feature-disabled", () => ({
  FeatureDisabledPage: ({ featureKey }: { featureKey: string }) => (
    <div>{featureKey} disabled</div>
  ),
}));

jest.mock(
  "@/components/cert-manager/credentials/credential-selected-provider-banner",
  () => ({
    CredentialSelectedProviderBanner: ({ label }: { label: string }) => (
      <div>{label}</div>
    ),
  }),
);

jest.mock(
  "@/components/cert-manager/credentials/credential-page-actions",
  () => ({
    CredentialPageActions: () => null,
  }),
);

jest.mock(
  "@/components/cert-manager/credentials/credential-provider-info-dialog",
  () => ({
    CredentialProviderInfoDialog: () => null,
  }),
);

jest.mock(
  "@/components/cert-manager/credentials/credential-secret-payload-card",
  () => ({
    CredentialSecretPayloadCard: () => null,
  }),
);

jest.mock(
  "@/components/cert-manager/credentials/providers/provider-fields",
  () => ({
    CredentialProviderFields: () => null,
  }),
);

describe("AddCredentialPage provider grouping", () => {
  beforeEach(() => {
    pushMock.mockReset();
    useUnsavedChangesWarningMock.mockClear();
    certificateDeploymentEnabled = true;
    dnsCredentialsEnabled = true;
    searchParams = "";
  });

  afterEach(() => {
    mockAgentTransport = undefined;
    process.env.NEXT_PUBLIC_APP_MODE = originalAppMode;
  });

  it("shows grouped cards for API Gateway and Load Balancers", async () => {
    const user = userEvent.setup();
    render(<AddCredentialPage />);

    expect(
      screen.getByRole("button", { name: "AWS API Gateway" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "AWS Load Balancer" }),
    ).toBeInTheDocument();

    expect(
      screen.queryByRole("button", { name: "AWS API Gateway REST" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "AWS API Gateway HTTP/WebSocket" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "AWS Application Load Balancer" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "AWS Network Load Balancer" }),
    ).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "AWS API Gateway" }));

    expect(
      screen.getByRole("button", { name: "AWS API Gateway REST" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "AWS API Gateway HTTP/WebSocket" }),
    ).toBeInTheDocument();

    await user.click(
      screen.getByRole("button", { name: "AWS API Gateway REST" }),
    );
    expect(screen.getByText("AWS API Gateway REST")).toBeInTheDocument();
  });

  it("shows managed credential inputs instead of kv path in managed credential mode", async () => {
    mockAgentTransport = "GATEWAY";
    const user = userEvent.setup();

    render(<AddCredentialPage />);

    await user.click(screen.getByRole("button", { name: "Cloudflare Edge" }));

    expect(screen.getByLabelText("Cloudflare API token")).toBeInTheDocument();
    expect(screen.queryByLabelText("Secret handle")).not.toBeInTheDocument();
  });

  it("lets self-hosted installs paste the secret or use their own vault", async () => {
    mockAgentTransport = "GATEWAY";
    try {
      const user = userEvent.setup();

      render(<AddCredentialPage />);

      await user.click(screen.getByRole("button", { name: "Cloudflare Edge" }));

      expect(
        screen.getByText("How does the agent get this secret?"),
      ).toBeInTheDocument();
      expect(screen.getByLabelText("Cloudflare API token")).toBeInTheDocument();
      expect(screen.queryByLabelText("Secret handle")).not.toBeInTheDocument();

      await user.click(screen.getByLabelText(/Agent identity or my own vault/));

      expect(screen.getByLabelText("Secret handle")).toBeInTheDocument();
      expect(
        screen.queryByLabelText("Cloudflare API token"),
      ).not.toBeInTheDocument();
    } finally {
      mockAgentTransport = undefined;
    }
  });

  it("does not warn on provider selection but warns after editing provider form fields", async () => {
    const user = userEvent.setup();

    render(<AddCredentialPage />);

    expect(useUnsavedChangesWarningMock).toHaveBeenLastCalledWith(false);

    await user.click(screen.getByRole("button", { name: "Cloudflare Edge" }));

    expect(useUnsavedChangesWarningMock).toHaveBeenLastCalledWith(false);

    await user.type(screen.getByLabelText("Name"), "cf-prod");

    expect(useUnsavedChangesWarningMock).toHaveBeenLastCalledWith(true);
  });

  it("keeps in-cluster Kubernetes auth available when the credential is pasted", async () => {
    mockAgentTransport = "GATEWAY";
    const user = userEvent.setup();

    render(<AddCredentialPage />);

    await user.click(
      screen.getByRole("button", { name: "Kubernetes Secrets" }),
    );

    // The default in-cluster method is offered as is instead of being swapped for AKS.
    expect(screen.getByText("No stored secret needed")).toBeInTheDocument();
    expect(screen.queryByLabelText("Tenant ID")).not.toBeInTheDocument();
  });

  it("blocks direct deployment credential creation when deployment is disabled", () => {
    certificateDeploymentEnabled = false;
    searchParams = "type=DEPLOYMENT";

    render(<AddCredentialPage />);

    expect(
      screen.getByText("CERTIFICATE_DEPLOYMENT disabled"),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "AWS API Gateway" }),
    ).not.toBeInTheDocument();
  });

  it("keeps DNS credential creation available when deployment is disabled", () => {
    certificateDeploymentEnabled = false;

    render(<AddCredentialPage />);

    expect(screen.getByRole("tab", { name: "DNS" })).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Cloudflare DNS" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Deployment" }),
    ).not.toBeInTheDocument();
  });

  it("blocks direct DNS provider creation while DNS credentials are off", () => {
    dnsCredentialsEnabled = false;
    searchParams = "type=DNS";

    render(<AddCredentialPage />);

    expect(screen.getByText("DNS_CREDENTIALS disabled")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Cloudflare DNS" }),
    ).not.toBeInTheDocument();
  });

  it("offers deployment targets only while DNS credentials are off", () => {
    dnsCredentialsEnabled = false;

    render(<AddCredentialPage />);

    expect(screen.getByRole("tab", { name: "Deployment" })).toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: "DNS" })).not.toBeInTheDocument();
  });

  it("shows the non-incremental DNS warning when Namecheap is selected", async () => {
    mockAgentTransport = "GATEWAY";
    const user = userEvent.setup();

    render(<AddCredentialPage />);

    await user.click(screen.getByRole("tab", { name: "DNS" }));
    await user.click(screen.getByRole("button", { name: "Namecheap DNS" }));

    expect(
      screen.getByText("Non-incremental DNS record updates"),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/strongly recommend exporting a backup/i),
    ).toBeInTheDocument();
  });

  it("shows the IP whitelisting note when NEXT_PUBLIC_NAMECHEAP_OUTBOUND_IP is set", async () => {
    mockAgentTransport = "GATEWAY";
    process.env.NEXT_PUBLIC_NAMECHEAP_OUTBOUND_IP = "203.0.113.40";
    const user = userEvent.setup();

    render(<AddCredentialPage />);

    await user.click(screen.getByRole("tab", { name: "DNS" }));
    await user.click(screen.getByRole("button", { name: "Namecheap DNS" }));

    expect(screen.getByText("IP whitelisting required")).toBeInTheDocument();
    expect(screen.getByText("203.0.113.40")).toBeInTheDocument();

    delete process.env.NEXT_PUBLIC_NAMECHEAP_OUTBOUND_IP;
  });

  it("shows the IP whitelisting note with generic agent text in enterprise mode when NEXT_PUBLIC_NAMECHEAP_OUTBOUND_IP is set", async () => {
    process.env.NEXT_PUBLIC_APP_MODE = "enterprise";
    process.env.NEXT_PUBLIC_NAMECHEAP_OUTBOUND_IP = "203.0.113.40";
    const user = userEvent.setup();

    render(<AddCredentialPage />);

    await user.click(screen.getByRole("tab", { name: "DNS" }));
    await user.click(screen.getByRole("button", { name: "Namecheap DNS" }));

    expect(screen.getByText("IP whitelisting required")).toBeInTheDocument();
    expect(
      screen.getByText("the public IP for where the CertPing agent is running"),
    ).toBeInTheDocument();
    expect(screen.queryByText("203.0.113.40")).not.toBeInTheDocument();

    delete process.env.NEXT_PUBLIC_NAMECHEAP_OUTBOUND_IP;
  });

  it("points to the agent's NAMECHEAP_CLIENT_IP when no outbound IP is known", async () => {
    mockAgentTransport = "GATEWAY";
    delete process.env.NEXT_PUBLIC_NAMECHEAP_OUTBOUND_IP;
    const user = userEvent.setup();

    render(<AddCredentialPage />);

    await user.click(screen.getByRole("tab", { name: "DNS" }));
    await user.click(screen.getByRole("button", { name: "Namecheap DNS" }));

    expect(
      screen.getByText("Non-incremental DNS record updates"),
    ).toBeInTheDocument();
    // Namecheap rejects calls from IPs that are not allow-listed, so the note always shows.
    expect(screen.getByText("IP whitelisting required")).toBeInTheDocument();
    expect(screen.getByText(/NAMECHEAP_CLIENT_IP setting/)).toBeInTheDocument();
    expect(screen.getByLabelText("Namecheap API user")).toBeInTheDocument();
    expect(screen.getByLabelText("Namecheap username")).toBeInTheDocument();
    expect(screen.getByLabelText("Namecheap API key")).toBeInTheDocument();
  });
});
