// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import AddCredentialPage from "@/app/(main)/integrations/connections/add/page";

let mockAgentTransport: "GATEWAY" | undefined;
jest.mock("@/hooks/use-deployment-mode", () => ({
  useAgentTransport: () => mockAgentTransport,
}));

const pushMock = jest.fn();
const refreshMock = jest.fn();
const originalAppMode = process.env.NEXT_PUBLIC_APP_MODE;

jest.mock("next/navigation", () => ({
  useRouter: () => ({
    push: pushMock,
    refresh: refreshMock,
    replace: jest.fn(),
  }),
  useSearchParams: () => new URLSearchParams("type=DEPLOYMENT"),
}));

jest.mock("next/image", () => ({
  __esModule: true,
  default: (props: React.ImgHTMLAttributes<HTMLImageElement>) => (
    // eslint-disable-next-line @next/next/no-img-element
    <img alt={props.alt ?? ""} {...props} />
  ),
}));

const mutateAsyncMock = jest.fn<Promise<unknown>, [unknown]>();
jest.mock("@/hooks/credentials", () => ({
  useAddCredential: () => ({
    isPending: false,
    mutateAsync: mutateAsyncMock,
  }),
}));

jest.mock("@/hooks/use-feature-flags", () => ({
  useIsFeatureEnabled: () => true,
  useIsOrgFeatureEnabled: () => true,
}));

jest.mock("@/components/ui/page-header", () => ({
  PageHeader: ({ title }: { title: string }) => <div>{title}</div>,
}));

jest.mock(
  "@/components/cert-manager/credentials/credential-provider-selector",
  () => ({
    CredentialProviderSelector: ({
      options,
      onSelectProvider,
    }: {
      options: Array<{ label: string; apiValue: string }>;
      onSelectProvider: (apiValue: string) => void;
    }) => (
      <div>
        {options.map((option) => (
          <button
            key={option.apiValue}
            type="button"
            onClick={() => onSelectProvider(option.apiValue)}
          >
            {option.label}
          </button>
        ))}
      </div>
    ),
  }),
);

// Keep the tests deterministic by bypassing the full provider field components.
jest.mock(
  "@/components/cert-manager/credentials/providers/provider-fields",
  () => ({
    CredentialProviderFields: ({
      form,
      providerApiValue,
      usesManagedCredentials,
    }: {
      form: { register: (name: string) => Record<string, unknown> };
      providerApiValue: string;
      usesManagedCredentials?: boolean;
    }) => {
      switch (providerApiValue) {
        case "AWS_ACM":
          return (
            <div>
              <label htmlFor="awsAcmAuthMode">AWS ACM auth mode</label>
              <select id="awsAcmAuthMode" {...form.register("awsAcmAuthMode")}>
                <option value="STATIC_KEYS">Static keys</option>
                <option value="ASSUME_ROLE">Assume role</option>
                <option value="INSTANCE_PROFILE">Instance profile</option>
              </select>
              <label htmlFor="awsAcmRegion">Region</label>
              <input id="awsAcmRegion" {...form.register("awsAcmRegion")} />
              <label htmlFor="awsAcmRoleArn">Role ARN</label>
              <input id="awsAcmRoleArn" {...form.register("awsAcmRoleArn")} />
              <label htmlFor="awsAcmExternalId">External ID</label>
              <input
                id="awsAcmExternalId"
                {...form.register("awsAcmExternalId")}
              />
            </div>
          );
        case "AWS_ALB":
        case "AWS_NLB":
          return (
            <div>
              <label htmlFor="awsElbRegion">Region</label>
              <input id="awsElbRegion" {...form.register("awsElbRegion")} />
              <label htmlFor="awsElbListeners.0">Listeners</label>
              <input
                id="awsElbListeners.0"
                {...form.register("awsElbListeners.0")}
              />
            </div>
          );
        case "AWS_API_GW_REST":
        case "AWS_API_GW_HTTP":
          return (
            <div>
              <label htmlFor="awsApiGwRegion">Region</label>
              <input id="awsApiGwRegion" {...form.register("awsApiGwRegion")} />
              <label htmlFor="awsApiGwCustomDomains.0">Custom domains</label>
              <input
                id="awsApiGwCustomDomains.0"
                {...form.register("awsApiGwCustomDomains.0")}
              />
            </div>
          );
        case "AWS_CLOUDFRONT":
          return (
            <div>
              <label htmlFor="awsCloudFrontDistributionId">
                Distribution ID
              </label>
              <input
                id="awsCloudFrontDistributionId"
                {...form.register("awsCloudFrontDistributionId")}
              />
            </div>
          );
        case "AZURE_KV":
          return (
            <div>
              <label htmlFor="azureKvAuthMode">Azure Key Vault auth mode</label>
              <select
                id="azureKvAuthMode"
                {...form.register("azureKvAuthMode")}
              >
                <option value="SERVICE_PRINCIPAL">Service principal</option>
                <option value="WORKLOAD_IDENTITY">Workload identity</option>
              </select>
              <label htmlFor="azureKvTenantId">Tenant ID</label>
              <input
                id="azureKvTenantId"
                {...form.register("azureKvTenantId")}
              />
              <label htmlFor="azureKvVaultUri">Vault URI</label>
              <input
                id="azureKvVaultUri"
                {...form.register("azureKvVaultUri")}
              />
              <label htmlFor="azureKvClientId">Client ID</label>
              <input
                id="azureKvClientId"
                {...form.register("azureKvClientId")}
              />
            </div>
          );
        case "AZURE_APP_GW":
          return (
            <div>
              <label htmlFor="azureAppGwTenantId">Tenant ID</label>
              <input
                id="azureAppGwTenantId"
                {...form.register("azureAppGwTenantId")}
              />
              <label htmlFor="azureAppGwSubscriptionId">Subscription ID</label>
              <input
                id="azureAppGwSubscriptionId"
                {...form.register("azureAppGwSubscriptionId")}
              />
              <label htmlFor="azureAppGwResourceGroup">Resource group</label>
              <input
                id="azureAppGwResourceGroup"
                {...form.register("azureAppGwResourceGroup")}
              />
              <label htmlFor="azureAppGwAppGateway">
                Application Gateway name
              </label>
              <input
                id="azureAppGwAppGateway"
                {...form.register("azureAppGwAppGateway")}
              />
              {usesManagedCredentials ? (
                <>
                  <label htmlFor="azureAppGwClientId">Client ID</label>
                  <input
                    id="azureAppGwClientId"
                    {...form.register("azureAppGwClientId")}
                  />
                </>
              ) : null}
              <label htmlFor="azureAppGwKeyVaultUri">Key Vault URI</label>
              <input
                id="azureAppGwKeyVaultUri"
                {...form.register("azureAppGwKeyVaultUri")}
              />
              <label htmlFor="azureAppGwListeners.0">Listeners</label>
              <input
                id="azureAppGwListeners.0"
                {...form.register("azureAppGwListeners.0")}
              />
            </div>
          );
        case "AZURE_APP_GW_CONTAINERS":
          return (
            <div>
              <label htmlFor="azureAgcTenantId">Tenant ID</label>
              <input
                id="azureAgcTenantId"
                {...form.register("azureAgcTenantId")}
              />
              <label htmlFor="azureAgcSubscriptionId">Subscription ID</label>
              <input
                id="azureAgcSubscriptionId"
                {...form.register("azureAgcSubscriptionId")}
              />
              <label htmlFor="azureAgcResourceGroup">Resource group</label>
              <input
                id="azureAgcResourceGroup"
                {...form.register("azureAgcResourceGroup")}
              />
              <label htmlFor="azureAgcClusterName">Cluster name</label>
              <input
                id="azureAgcClusterName"
                {...form.register("azureAgcClusterName")}
              />
              <label htmlFor="azureAgcNamespace">AGC namespace</label>
              <input
                id="azureAgcNamespace"
                {...form.register("azureAgcNamespace")}
              />
              <label htmlFor="azureAgcSecretNamespaces.0">
                Allowed secret namespaces
              </label>
              <input
                id="azureAgcSecretNamespaces.0"
                {...form.register("azureAgcSecretNamespaces.0")}
              />
            </div>
          );
        case "AZURE_AFD":
          return (
            <div>
              <label htmlFor="azureAfdTenantId">Tenant ID</label>
              <input
                id="azureAfdTenantId"
                {...form.register("azureAfdTenantId")}
              />
              <label htmlFor="azureAfdSubscriptionId">Subscription ID</label>
              <input
                id="azureAfdSubscriptionId"
                {...form.register("azureAfdSubscriptionId")}
              />
              <label htmlFor="azureAfdResourceGroup">Resource group</label>
              <input
                id="azureAfdResourceGroup"
                {...form.register("azureAfdResourceGroup")}
              />
              <label htmlFor="azureAfdProfileName">AFD profile name</label>
              <input
                id="azureAfdProfileName"
                {...form.register("azureAfdProfileName")}
              />
              {usesManagedCredentials ? (
                <>
                  <label htmlFor="azureAfdClientId">Client ID</label>
                  <input
                    id="azureAfdClientId"
                    {...form.register("azureAfdClientId")}
                  />
                </>
              ) : null}
              <label htmlFor="azureAfdKeyVaultUri">Key Vault URI</label>
              <input
                id="azureAfdKeyVaultUri"
                {...form.register("azureAfdKeyVaultUri")}
              />
              <label htmlFor="azureAfdCustomDomains.0">Custom domains</label>
              <input
                id="azureAfdCustomDomains.0"
                {...form.register("azureAfdCustomDomains.0")}
              />
            </div>
          );
        case "CLOUDFLARE_EDGE":
          return (
            <div>
              <label htmlFor="cloudflareZoneId">Zone ID</label>
              <input
                id="cloudflareZoneId"
                {...form.register("cloudflareZoneId")}
              />
            </div>
          );
        case "AKAMAI_CPS":
          return (
            <div>
              <label htmlFor="akamaiHost">Host</label>
              <input id="akamaiHost" {...form.register("akamaiHost")} />
              <label htmlFor="akamaiEnrollmentId">Enrollment ID</label>
              <input
                id="akamaiEnrollmentId"
                {...form.register("akamaiEnrollmentId")}
              />
            </div>
          );
        case "KUBERNETES_SECRETS":
          return (
            <div>
              <label htmlFor="k8sAuthMethod">Auth method</label>
              <select id="k8sAuthMethod" {...form.register("k8sAuthMethod")}>
                <option value="SA_INCLUSTER">In-cluster service account</option>
                <option value="SA_TOKEN">
                  Kubernetes (service account token)
                </option>
                <option value="AWS">AWS (EKS)</option>
                <option value="AZURE">Azure (AKS)</option>
                <option value="GCP">GCP (GKE)</option>
              </select>
              <label htmlFor="k8sClusterName">Cluster name</label>
              <input id="k8sClusterName" {...form.register("k8sClusterName")} />
              <label htmlFor="k8sNamespaces.0">Namespaces</label>
              <input
                id="k8sNamespaces.0"
                {...form.register("k8sNamespaces.0")}
              />
            </div>
          );
        case "GCP_CERT_MANAGER":
          return (
            <div>
              <label htmlFor="gcpAuthMode">GCP auth mode</label>
              <select id="gcpAuthMode" {...form.register("gcpAuthMode")}>
                <option value="SERVICE_ACCOUNT_KEY">Service account key</option>
                <option value="WORKLOAD_IDENTITY">Workload identity</option>
                <option value="IMPERSONATE_SERVICE_ACCOUNT">
                  Impersonate service account
                </option>
              </select>
              <label htmlFor="gcpProjectId">Project ID</label>
              <input id="gcpProjectId" {...form.register("gcpProjectId")} />
              <label htmlFor="gcpLocation">Location</label>
              <input id="gcpLocation" {...form.register("gcpLocation")} />
              <label htmlFor="gcpImpersonateServiceAccount">
                Impersonate service account
              </label>
              <input
                id="gcpImpersonateServiceAccount"
                {...form.register("gcpImpersonateServiceAccount")}
              />
              <label htmlFor="gcpCertManagerCertificateMap">
                Certificate map
              </label>
              <input
                id="gcpCertManagerCertificateMap"
                {...form.register("gcpCertManagerCertificateMap")}
              />
            </div>
          );
        case "F5_BIGIP":
          return (
            <div>
              <label htmlFor="f5BigipHost">BIG-IP host</label>
              <input id="f5BigipHost" {...form.register("f5BigipHost")} />
              <label htmlFor="f5BigipPartition">Partition</label>
              <input
                id="f5BigipPartition"
                {...form.register("f5BigipPartition")}
              />
            </div>
          );
        default:
          return null;
      }
    },
  }),
);

async function selectProvider(providerLabel: string): Promise<void> {
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: providerLabel }));
}

async function saveCredential(): Promise<void> {
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Save credential" }));
}

describe("AddCredentialPage deployment payloads", () => {
  beforeEach(() => {
    pushMock.mockReset();
    refreshMock.mockReset();
    mutateAsyncMock.mockReset();
    mutateAsyncMock.mockResolvedValue({});
  });

  afterEach(() => {
    mockAgentTransport = undefined;
    process.env.NEXT_PUBLIC_APP_MODE = originalAppMode;
  });

  it("submits Azure App Gateway scope configJson", async () => {
    const user = userEvent.setup();
    render(<AddCredentialPage />);

    await selectProvider("Azure Application Gateway");
    await user.type(screen.getByLabelText("Name"), "agw-prod");
    await user.type(
      screen.getByLabelText("Secret handle"),
      "https://vault.vault.azure.net/secrets/azure/123",
    );
    await user.type(screen.getByLabelText("Tenant ID"), "tenant-1");
    await user.type(screen.getByLabelText("Subscription ID"), "sub-1");
    await user.type(screen.getByLabelText("Resource group"), "rg-1");
    await user.type(screen.getByLabelText("Application Gateway name"), "agw-1");
    await user.type(
      screen.getByLabelText("Key Vault URI"),
      "https://kv.vault.azure.net/",
    );
    await user.type(screen.getByLabelText("Listeners"), "https-443");

    await saveCredential();
    await waitFor(() => expect(mutateAsyncMock).toHaveBeenCalledTimes(1));

    const payload = mutateAsyncMock.mock.calls[0]?.[0] as {
      provider: string;
      configJson: unknown;
    };
    expect(payload.provider).toBe("AZURE_APP_GW");
    expect(payload.configJson).toEqual({
      authMode: "SERVICE_PRINCIPAL",
      tenantId: "tenant-1",
      subscriptionId: "sub-1",
      resourceGroup: "rg-1",
      appGateway: "agw-1",
      listeners: ["https-443"],
      keyVaultUri: "https://kv.vault.azure.net/",
    });
    expect(pushMock).toHaveBeenCalledWith("/integrations/deployment-targets");
    expect(refreshMock).toHaveBeenCalled();
  });

  it("submits Azure App Gateway with a secret stored in CertPing and Key Vault URI", async () => {
    mockAgentTransport = "GATEWAY";
    const user = userEvent.setup();
    render(<AddCredentialPage />);

    await selectProvider("Azure Application Gateway");
    await user.type(screen.getByLabelText("Name"), "agw-prod");
    await user.type(screen.getByLabelText("Tenant ID"), "tenant-1");
    await user.type(screen.getByLabelText("Subscription ID"), "sub-1");
    await user.type(screen.getByLabelText("Resource group"), "rg-1");
    await user.type(screen.getByLabelText("Application Gateway name"), "agw-1");
    await user.type(screen.getByLabelText("Client ID"), "client-1");
    await user.type(
      screen.getByLabelText("Key Vault URI"),
      "https://kv.vault.azure.net/",
    );
    await user.type(screen.getByLabelText("Listeners"), "https-443");
    await user.type(screen.getByLabelText("Client secret"), "secret-1");

    await saveCredential();
    await waitFor(() => expect(mutateAsyncMock).toHaveBeenCalledTimes(1));

    const payload = mutateAsyncMock.mock.calls[0]?.[0] as {
      provider: string;
      secretHandle: string | null;
      credJson: unknown;
      configJson: Record<string, unknown>;
    };
    expect(payload.provider).toBe("AZURE_APP_GW");
    expect(payload.secretHandle).toBeNull();
    expect(payload.credJson).toEqual({
      clientId: "client-1",
      clientSecret: "secret-1",
    });
    expect(payload.configJson).toEqual({
      authMode: "SERVICE_PRINCIPAL",
      tenantId: "tenant-1",
      subscriptionId: "sub-1",
      clientId: "client-1",
      resourceGroup: "rg-1",
      appGateway: "agw-1",
      listeners: ["https-443"],
      keyVaultUri: "https://kv.vault.azure.net/",
    });
  });

  it("submits Azure Front Door scope configJson", async () => {
    const user = userEvent.setup();
    render(<AddCredentialPage />);

    await selectProvider("Azure Front Door");
    await user.type(screen.getByLabelText("Name"), "afd-prod");
    await user.type(
      screen.getByLabelText("Secret handle"),
      "https://vault.vault.azure.net/secrets/azure/123",
    );
    await user.type(screen.getByLabelText("Tenant ID"), "tenant-1");
    await user.type(screen.getByLabelText("Subscription ID"), "sub-1");
    await user.type(screen.getByLabelText("Resource group"), "rg-1");
    await user.type(screen.getByLabelText("AFD profile name"), "afd-1");
    await user.type(
      screen.getByLabelText("Key Vault URI"),
      "https://kv.vault.azure.net/",
    );
    await user.type(screen.getByLabelText("Custom domains"), "api-example-com");

    await saveCredential();
    await waitFor(() => expect(mutateAsyncMock).toHaveBeenCalledTimes(1));

    const payload = mutateAsyncMock.mock.calls[0]?.[0] as {
      provider: string;
      configJson: unknown;
    };
    expect(payload.provider).toBe("AZURE_AFD");
    expect(payload.configJson).toEqual({
      authMode: "SERVICE_PRINCIPAL",
      tenantId: "tenant-1",
      subscriptionId: "sub-1",
      resourceGroup: "rg-1",
      profileName: "afd-1",
      keyVaultUri: "https://kv.vault.azure.net/",
      customDomains: ["api-example-com"],
    });
    expect(pushMock).toHaveBeenCalledWith("/integrations/deployment-targets");
    expect(refreshMock).toHaveBeenCalled();
  });

  it("submits GCP Certificate Manager scope configJson", async () => {
    const user = userEvent.setup();
    render(<AddCredentialPage />);

    await selectProvider("GCP Certificate Manager");
    await user.type(screen.getByLabelText("Name"), "gcp-cm");
    await user.type(
      screen.getByLabelText("Secret handle"),
      "https://vault.vault.azure.net/secrets/gcp/123",
    );
    await user.type(screen.getByLabelText("Project ID"), "proj-1");
    await user.clear(screen.getByLabelText("Location"));
    await user.type(screen.getByLabelText("Location"), "global");
    await user.type(screen.getByLabelText("Certificate map"), "map-1");

    await saveCredential();
    await waitFor(() => expect(mutateAsyncMock).toHaveBeenCalledTimes(1));

    const payload = mutateAsyncMock.mock.calls[0]?.[0] as {
      provider: string;
      configJson: unknown;
    };
    expect(payload.provider).toBe("GCP_CERT_MANAGER");
    expect(payload.configJson).toEqual({
      authMode: "SERVICE_ACCOUNT_KEY",
      projectId: "proj-1",
      location: "global",
      certificateMap: "map-1",
    });
  });

  it("clears stale GCP secretHandle and impersonation after switching to workload identity", async () => {
    const user = userEvent.setup();
    render(<AddCredentialPage />);

    await selectProvider("GCP Certificate Manager");
    await user.type(screen.getByLabelText("Name"), "gcp-cm");
    await user.type(
      screen.getByLabelText("Secret handle"),
      "https://vault.vault.azure.net/secrets/gcp/service-account-key",
    );
    await user.selectOptions(
      screen.getByLabelText("GCP auth mode"),
      "IMPERSONATE_SERVICE_ACCOUNT",
    );
    await user.type(screen.getByLabelText("Project ID"), "proj-1");
    await user.clear(screen.getByLabelText("Location"));
    await user.type(screen.getByLabelText("Location"), "global");
    await user.type(
      screen.getByLabelText("Impersonate service account"),
      "deployer@proj-1.iam.gserviceaccount.com",
    );
    await user.type(screen.getByLabelText("Certificate map"), "map-1");
    await user.selectOptions(
      screen.getByLabelText("GCP auth mode"),
      "WORKLOAD_IDENTITY",
    );

    await saveCredential();
    await waitFor(() => expect(mutateAsyncMock).toHaveBeenCalledTimes(1));

    const payload = mutateAsyncMock.mock.calls[0]?.[0] as {
      provider: string;
      secretHandle: string | null;
      configJson: Record<string, unknown>;
    };
    expect(payload.provider).toBe("GCP_CERT_MANAGER");
    expect(payload.secretHandle).toBeNull();
    expect(payload.configJson).toEqual({
      authMode: "WORKLOAD_IDENTITY",
      projectId: "proj-1",
      location: "global",
      certificateMap: "map-1",
    });
  });

  it("submits F5 BIG-IP scope configJson with server-defaulted fields omitted", async () => {
    const user = userEvent.setup();
    render(<AddCredentialPage />);

    await selectProvider("F5 BIG-IP");
    await user.type(screen.getByLabelText("Name"), "f5-prod");
    await user.type(
      screen.getByLabelText("Secret handle"),
      "https://vault.vault.azure.net/secrets/f5/123",
    );
    await user.type(screen.getByLabelText("BIG-IP host"), "bigip.example.com");
    await user.clear(screen.getByLabelText("Partition"));
    await user.type(screen.getByLabelText("Partition"), "Common");

    await saveCredential();
    await waitFor(() => expect(mutateAsyncMock).toHaveBeenCalledTimes(1));

    const payload = mutateAsyncMock.mock.calls[0]?.[0] as {
      provider: string;
      configJson: unknown;
    };
    expect(payload.provider).toBe("F5_BIGIP");
    expect(payload.configJson).toEqual({
      bigipHost: "bigip.example.com",
      partition: "Common",
      clientSslProfiles: ["clientssl-api"],
    });
  });

  it("submits AWS ACM scope configJson", async () => {
    const user = userEvent.setup();
    render(<AddCredentialPage />);

    await selectProvider("AWS Certificate Manager");
    await user.type(screen.getByLabelText("Name"), "acm-prod");
    await user.type(
      screen.getByLabelText("Secret handle"),
      "https://vault.vault.azure.net/secrets/aws/123",
    );
    await user.type(screen.getByLabelText("Region"), "us-east-1");

    await saveCredential();
    await waitFor(() => expect(mutateAsyncMock).toHaveBeenCalledTimes(1));

    const payload = mutateAsyncMock.mock.calls[0]?.[0] as {
      provider: string;
      configJson: unknown;
    };
    expect(payload.provider).toBe("AWS_ACM");
    expect(payload.configJson).toEqual({
      authMode: "STATIC_KEYS",
      region: "us-east-1",
    });
  });

  it("clears stale AWS ACM secretHandle and role fields after switching to instance profile auth", async () => {
    const user = userEvent.setup();
    render(<AddCredentialPage />);

    await selectProvider("AWS Certificate Manager");
    await user.type(screen.getByLabelText("Name"), "acm-prod");
    await user.type(
      screen.getByLabelText("Secret handle"),
      "https://vault.vault.azure.net/secrets/aws/static",
    );
    await user.type(screen.getByLabelText("Region"), "us-east-1");
    await user.selectOptions(
      screen.getByLabelText("AWS ACM auth mode"),
      "ASSUME_ROLE",
    );
    await user.type(
      screen.getByLabelText("Role ARN"),
      "arn:aws:iam::123456789012:role/deployer",
    );
    await user.type(screen.getByLabelText("External ID"), "external-1");
    await user.selectOptions(
      screen.getByLabelText("AWS ACM auth mode"),
      "INSTANCE_PROFILE",
    );

    await saveCredential();
    await waitFor(() => expect(mutateAsyncMock).toHaveBeenCalledTimes(1));

    const payload = mutateAsyncMock.mock.calls[0]?.[0] as {
      provider: string;
      secretHandle: string | null;
      configJson: Record<string, unknown>;
    };
    expect(payload.provider).toBe("AWS_ACM");
    expect(payload.secretHandle).toBeNull();
    expect(payload.configJson).toEqual({
      authMode: "INSTANCE_PROFILE",
      region: "us-east-1",
    });
  });

  it("submits AWS ALB scope configJson", async () => {
    const user = userEvent.setup();
    render(<AddCredentialPage />);

    await selectProvider("AWS Application Load Balancer");
    await user.type(screen.getByLabelText("Name"), "alb-prod");
    await user.type(
      screen.getByLabelText("Secret handle"),
      "https://vault.vault.azure.net/secrets/aws/123",
    );
    await user.type(screen.getByLabelText("Region"), "us-east-1");
    await user.type(screen.getByLabelText("Listeners"), "listener-1");

    await saveCredential();
    await waitFor(() => expect(mutateAsyncMock).toHaveBeenCalledTimes(1));

    const payload = mutateAsyncMock.mock.calls[0]?.[0] as {
      provider: string;
      configJson: unknown;
    };
    expect(payload.provider).toBe("AWS_ALB");
    expect(payload.configJson).toEqual({
      authMode: "STATIC_KEYS",
      region: "us-east-1",
      listeners: ["listener-1"],
    });
  });

  it("submits AWS API Gateway REST scope configJson", async () => {
    const user = userEvent.setup();
    render(<AddCredentialPage />);

    await selectProvider("AWS API Gateway REST");
    await user.type(screen.getByLabelText("Name"), "apigw-prod");
    await user.type(
      screen.getByLabelText("Secret handle"),
      "https://vault.vault.azure.net/secrets/aws/123",
    );
    await user.type(screen.getByLabelText("Region"), "us-east-1");
    await user.type(screen.getByLabelText("Custom domains"), "api.example.com");

    await saveCredential();
    await waitFor(() => expect(mutateAsyncMock).toHaveBeenCalledTimes(1));

    const payload = mutateAsyncMock.mock.calls[0]?.[0] as {
      provider: string;
      configJson: unknown;
    };
    expect(payload.provider).toBe("AWS_API_GW_REST");
    expect(payload.configJson).toEqual({
      authMode: "STATIC_KEYS",
      region: "us-east-1",
      customDomains: ["api.example.com"],
    });
  });

  it("submits AWS CloudFront scope configJson", async () => {
    const user = userEvent.setup();
    render(<AddCredentialPage />);

    await selectProvider("AWS CloudFront");
    await user.type(screen.getByLabelText("Name"), "cloudfront-prod");
    await user.type(
      screen.getByLabelText("Secret handle"),
      "https://vault.vault.azure.net/secrets/aws/123",
    );
    await user.type(screen.getByLabelText("Distribution ID"), "dist-1");

    await saveCredential();
    await waitFor(() => expect(mutateAsyncMock).toHaveBeenCalledTimes(1));

    const payload = mutateAsyncMock.mock.calls[0]?.[0] as {
      provider: string;
      configJson: unknown;
    };
    expect(payload.provider).toBe("AWS_CLOUDFRONT");
    expect(payload.configJson).toEqual({
      authMode: "STATIC_KEYS",
      distributionId: "dist-1",
    });
  });

  it("submits Azure Key Vault scope configJson", async () => {
    const user = userEvent.setup();
    render(<AddCredentialPage />);

    await selectProvider("Azure Key Vault");
    await user.type(screen.getByLabelText("Name"), "kv-prod");
    await user.type(
      screen.getByLabelText("Secret handle"),
      "https://vault.vault.azure.net/secrets/azure/123",
    );
    await user.type(screen.getByLabelText("Tenant ID"), "tenant-1");
    await user.type(
      screen.getByLabelText("Vault URI"),
      "https://my-vault.vault.azure.net/",
    );

    await saveCredential();
    await waitFor(() => expect(mutateAsyncMock).toHaveBeenCalledTimes(1));

    const payload = mutateAsyncMock.mock.calls[0]?.[0] as {
      provider: string;
      configJson: unknown;
    };
    expect(payload.provider).toBe("AZURE_KV");
    expect(payload.configJson).toEqual({
      authMode: "SERVICE_PRINCIPAL",
      tenantId: "tenant-1",
      vaultUri: "https://my-vault.vault.azure.net/",
    });
  });

  it("clears stale Azure Key Vault secretHandle after switching to workload identity", async () => {
    const user = userEvent.setup();
    render(<AddCredentialPage />);

    await selectProvider("Azure Key Vault");
    await user.type(screen.getByLabelText("Name"), "kv-prod");
    await user.type(
      screen.getByLabelText("Secret handle"),
      "https://vault.vault.azure.net/secrets/azure/service-principal",
    );
    await user.type(screen.getByLabelText("Tenant ID"), "tenant-1");
    await user.type(
      screen.getByLabelText("Vault URI"),
      "https://my-vault.vault.azure.net/",
    );
    await user.selectOptions(
      screen.getByLabelText("Azure Key Vault auth mode"),
      "WORKLOAD_IDENTITY",
    );
    await user.type(screen.getByLabelText("Client ID"), "workload-client-1");

    await saveCredential();
    await waitFor(() => expect(mutateAsyncMock).toHaveBeenCalledTimes(1));

    const payload = mutateAsyncMock.mock.calls[0]?.[0] as {
      provider: string;
      secretHandle: string | null;
      configJson: Record<string, unknown>;
    };
    expect(payload.provider).toBe("AZURE_KV");
    expect(payload.secretHandle).toBeNull();
    expect(payload.configJson).toEqual({
      authMode: "WORKLOAD_IDENTITY",
      tenantId: "tenant-1",
      vaultUri: "https://my-vault.vault.azure.net/",
      clientId: "workload-client-1",
    });
  });

  it("submits Cloudflare Edge scope configJson", async () => {
    const user = userEvent.setup();
    render(<AddCredentialPage />);

    await selectProvider("Cloudflare Edge");
    await user.type(screen.getByLabelText("Name"), "cf-prod");
    await user.type(
      screen.getByLabelText("Secret handle"),
      "https://vault.vault.azure.net/secrets/cloudflare/123",
    );
    await user.type(screen.getByLabelText("Zone ID"), "zone-1");

    await saveCredential();
    await waitFor(() => expect(mutateAsyncMock).toHaveBeenCalledTimes(1));

    const payload = mutateAsyncMock.mock.calls[0]?.[0] as {
      provider: string;
      configJson: unknown;
    };
    expect(payload.provider).toBe("CLOUDFLARE_EDGE");
    expect(payload.configJson).toEqual({ zoneId: "zone-1" });
  });

  it("submits Akamai CPS scope configJson", async () => {
    const user = userEvent.setup();
    render(<AddCredentialPage />);

    await selectProvider("Akamai CPS");
    await user.type(screen.getByLabelText("Name"), "akamai-prod");
    await user.type(
      screen.getByLabelText("Secret handle"),
      "https://vault.vault.azure.net/secrets/akamai/123",
    );
    await user.type(screen.getByLabelText("Host"), "cps.akamaiapis.net");
    await user.type(screen.getByLabelText("Enrollment ID"), "12345");

    await saveCredential();
    await waitFor(() => expect(mutateAsyncMock).toHaveBeenCalledTimes(1));

    const payload = mutateAsyncMock.mock.calls[0]?.[0] as {
      provider: string;
      configJson: unknown;
    };
    expect(payload.provider).toBe("AKAMAI_CPS");
    expect(payload.configJson).toEqual({
      host: "cps.akamaiapis.net",
      enrollmentId: "12345",
    });
  });

  it("submits Kubernetes Secrets scope configJson with null secretHandle for in-cluster auth", async () => {
    const user = userEvent.setup();
    render(<AddCredentialPage />);

    await selectProvider("Kubernetes Secrets");
    await user.type(screen.getByLabelText("Name"), "k8s-prod");
    await user.type(screen.getByLabelText("Cluster name"), "aks-prod");
    await user.type(screen.getByLabelText("Namespaces"), "app-prod");

    await saveCredential();
    await waitFor(() => expect(mutateAsyncMock).toHaveBeenCalledTimes(1));

    const payload = mutateAsyncMock.mock.calls[0]?.[0] as {
      provider: string;
      secretHandle?: string | null;
      configJson: unknown;
    };
    expect(payload.provider).toBe("KUBERNETES_SECRETS");
    expect(payload.secretHandle).toBeNull();
    expect(payload.configJson).toEqual({
      authMethod: "SA_INCLUSTER",
      clusterName: "aks-prod",
      namespaces: ["app-prod"],
    });
  });

  it("normalizes managed Kubernetes credentials to Azure service principal payloads", async () => {
    mockAgentTransport = "GATEWAY";
    const user = userEvent.setup();
    render(<AddCredentialPage />);

    await selectProvider("Kubernetes Secrets");
    await user.selectOptions(screen.getByLabelText("Auth method"), "AZURE");
    await user.type(screen.getByLabelText("Name"), "aks-prod");
    await user.type(screen.getByLabelText("Cluster name"), "aks-prod");
    await user.type(screen.getByLabelText("Namespaces"), "app-prod");
    await user.type(screen.getByLabelText("Tenant ID"), "tenant-1");
    await user.type(screen.getByLabelText("Subscription ID"), "sub-1");
    await user.type(screen.getByLabelText("Resource group"), "rg-aks");
    await user.type(screen.getByLabelText("Client ID"), "client-1");
    await user.type(screen.getByLabelText("Client secret"), "secret-1");

    await saveCredential();
    await waitFor(() => expect(mutateAsyncMock).toHaveBeenCalledTimes(1));

    const payload = mutateAsyncMock.mock.calls[0]?.[0] as {
      provider: string;
      secretHandle?: string;
      credJson?: unknown;
      configJson: unknown;
    };
    expect(payload.provider).toBe("KUBERNETES_SECRETS");
    expect(payload.secretHandle).toBeNull();
    expect(payload.configJson).toEqual({
      authMethod: "AZURE",
      clusterName: "aks-prod",
      namespaces: ["app-prod"],
    });
    expect(payload.credJson).toEqual({
      azureTenantId: "tenant-1",
      azureSubscriptionId: "sub-1",
      azureResourceGroup: "rg-aks",
      azureClientId: "client-1",
      azureClientSecret: "secret-1",
    });
  });

  it("submits a pasted Kubernetes service account token as the API expects", async () => {
    mockAgentTransport = "GATEWAY";
    const user = userEvent.setup();
    render(<AddCredentialPage />);

    await selectProvider("Kubernetes Secrets");
    await user.selectOptions(screen.getByLabelText("Auth method"), "SA_TOKEN");
    await user.type(screen.getByLabelText("Name"), "k3s-lab");
    await user.type(screen.getByLabelText("Cluster name"), "lab");
    await user.type(screen.getByLabelText("Namespaces"), "certping");
    await user.type(
      screen.getByLabelText("API server URL"),
      "https://k3s:6443",
    );
    await user.type(screen.getByLabelText("Service account token"), "sa-token");
    await user.type(
      screen.getByLabelText("Cluster CA certificate"),
      "-----BEGIN CERTIFICATE-----MIIB-----END CERTIFICATE-----",
    );

    await saveCredential();
    await waitFor(() => expect(mutateAsyncMock).toHaveBeenCalledTimes(1));

    // The same shape deploy/e2e-lab/e2e.py sends.
    const payload = mutateAsyncMock.mock.calls[0]?.[0] as {
      provider: string;
      secretHandle?: string;
      credJson?: unknown;
      configJson: unknown;
    };
    expect(payload.provider).toBe("KUBERNETES_SECRETS");
    expect(payload.secretHandle).toBeNull();
    expect(payload.configJson).toEqual({
      authMethod: "SA_TOKEN",
      clusterName: "lab",
      namespaces: ["certping"],
    });
    expect(payload.credJson).toEqual({
      apiServer: "https://k3s:6443",
      bearerToken: "sa-token",
      caCertPem: "-----BEGIN CERTIFICATE-----MIIB-----END CERTIFICATE-----",
    });
  });

  it("submits credJson instead of secretHandle in managed credential mode", async () => {
    mockAgentTransport = "GATEWAY";
    const user = userEvent.setup();
    render(<AddCredentialPage />);

    await selectProvider("Cloudflare Edge");
    await user.type(screen.getByLabelText("Name"), "cf-managed");
    await user.type(screen.getByLabelText("Zone ID"), "zone-1");
    await user.type(
      screen.getByLabelText("Cloudflare API token"),
      "cf-rotated",
    );

    await saveCredential();
    await waitFor(() => expect(mutateAsyncMock).toHaveBeenCalledTimes(1));

    const payload = mutateAsyncMock.mock.calls[0]?.[0] as {
      provider: string;
      secretHandle?: string;
      credJson?: unknown;
      configJson: unknown;
    };
    expect(payload.provider).toBe("CLOUDFLARE_EDGE");
    expect(payload.secretHandle).toBeNull();
    expect(payload.credJson).toEqual({
      apiToken: "cf-rotated",
    });
    expect(payload.configJson).toEqual({ zoneId: "zone-1" });
  });
});
