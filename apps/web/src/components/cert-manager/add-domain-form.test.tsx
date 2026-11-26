// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { CertificateRequestForm } from "@/components/cert-manager/add-domain-form";

const pushMock = jest.fn();

let manualIssuanceEnabled = true;
let certificateDeploymentEnabled = true;

const automatedMutateAsync = jest.fn();
const manualMutateAsync = jest.fn();
let deploymentCredentialSelectorRenderCount = 0;

const CLOUDFLARE_DNS = {
  credentialXref: "dns-1",
  alias: "dns-1",
  providerName: "CLOUDFLARE",
  description: "Cloudflare DNS",
};
const DNS_CREDENTIALS = [CLOUDFLARE_DNS];

const DEPLOYMENT_CREDENTIALS: Array<Record<string, unknown>> = [];

jest.mock("next/navigation", () => ({
  useRouter: () => ({
    push: pushMock,
  }),
}));

jest.mock("@/hooks/use-feature-flags", () => ({
  useFeatureFlags: () => ({
    isEnabled: (key: string) => {
      if (key === "CERTIFICATE_MANUAL_ISSUANCE") {
        return manualIssuanceEnabled;
      }
      if (key === "CERTIFICATE_DEPLOYMENT") {
        return certificateDeploymentEnabled;
      }
      return true;
    },
  }),
}));

const mockUseCanAddCredential = jest.fn<boolean, [string]>(() => true);
const DIGICERT_KEY = {
  credentialXref: "ca-1",
  provider: "DIGICERT",
  description: "DigiCert API key",
};
const mockDigiCertKeys: Array<typeof DIGICERT_KEY> = [DIGICERT_KEY];
const mockAddCaCredential = jest.fn();
jest.mock("@/hooks/ca-credentials", () => ({
  useCaCredentials: () => ({ data: mockDigiCertKeys, isLoading: false }),
  useAddCaCredential: () => ({
    isPending: false,
    mutateAsync: mockAddCaCredential,
  }),
}));
jest.mock("@/hooks/credentials", () => ({
  useCanAddCredential: (type: string) => mockUseCanAddCredential(type),
  useCredentials: ({ category }: { category?: string }) => {
    if (category === "dns_credential") {
      return {
        data: DNS_CREDENTIALS,
        isLoading: false,
      };
    }
    if (category === "deployment_target") {
      return { data: DEPLOYMENT_CREDENTIALS, isLoading: false };
    }
    return { data: [], isLoading: false };
  },
}));

jest.mock("@/hooks/ssl", () => ({
  useIssueCertificateRequest: () => ({
    isPending: false,
    mutateAsync: automatedMutateAsync,
  }),
  useIssueManualCertificateRequest: () => ({
    isPending: false,
    mutateAsync: manualMutateAsync,
  }),
}));

// Make the select-like primitives deterministic in jsdom.
const SelectContext = React.createContext<{
  value?: string;
  onValueChange?: (value: string) => void;
} | null>(null);

const TabsContext = React.createContext<{
  value?: string;
  onValueChange?: (value: string) => void;
} | null>(null);

jest.mock("@/components/ui/select", () => ({
  Select: ({
    value,
    onValueChange,
    children,
  }: {
    value?: string;
    onValueChange?: (value: string) => void;
    children: React.ReactNode;
  }) => (
    <SelectContext.Provider value={{ value, onValueChange }}>
      <div>{children}</div>
    </SelectContext.Provider>
  ),
  SelectTrigger: ({ children }: { children: React.ReactNode }) => (
    <button type="button">{children}</button>
  ),
  SelectValue: ({ placeholder }: { placeholder?: string }) => (
    <span>{placeholder ?? ""}</span>
  ),
  SelectContent: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
  SelectItem: ({
    value,
    children,
  }: {
    value: string;
    children: React.ReactNode;
  }) => {
    const ctx = React.useContext(SelectContext);
    return (
      <button type="button" onClick={() => ctx?.onValueChange?.(value)}>
        {children}
      </button>
    );
  },
}));

jest.mock("@/components/ui/tabs", () => ({
  Tabs: ({
    value,
    onValueChange,
    children,
  }: {
    value: string;
    onValueChange: (value: string) => void;
    children: React.ReactNode;
  }) => (
    <TabsContext.Provider value={{ value, onValueChange }}>
      {children}
    </TabsContext.Provider>
  ),
  TabsList: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
  TabsTrigger: ({
    value,
    children,
  }: {
    value: string;
    children: React.ReactNode;
  }) => {
    const ctx = React.useContext(TabsContext);
    return (
      <button type="button" onClick={() => ctx?.onValueChange?.(value)}>
        {children}
      </button>
    );
  },
}));

jest.mock("@/components/cert-manager/credential-reference-select", () => ({
  CredentialReferenceSelect: ({
    credentials,
    value,
    onValueChange,
    placeholder,
    addCredentialHref,
  }: {
    addCredentialHref?: unknown;
    credentials: Array<{
      credentialXref?: string;
      alias?: string;
      description?: string;
    }>;
    value?: string;
    onValueChange: (value: string) => void;
    placeholder?: string;
  }) => (
    <label>
      <span>{placeholder ?? "Select credential"}</span>
      <select
        aria-label={placeholder ?? "Select credential"}
        value={value || ""}
        onChange={(e) => onValueChange(e.target.value)}
      >
        <option value="">(none)</option>
        {credentials.map((cred) => {
          const id = cred.credentialXref || cred.alias || "";
          return (
            <option key={id} value={id}>
              {cred.description || id}
            </option>
          );
        })}
      </select>
      {addCredentialHref ? <span>add-dns-credential-option</span> : null}
    </label>
  ),
  CredentialReferenceMultiSelect: ({
    credentials,
    value,
    onValueChange,
    placeholder,
    addCredentialHref,
  }: {
    addCredentialHref?: unknown;
    credentials: Array<{
      credentialXref?: string;
      alias?: string;
      description?: string;
    }>;
    value: string[];
    onValueChange: (value: string[]) => void;
    placeholder?: string;
  }) => {
    deploymentCredentialSelectorRenderCount += 1;
    return (
      <fieldset>
        <legend>{placeholder ?? "Select credentials"}</legend>
        {addCredentialHref ? (
          <span>add-deployment-credential-option</span>
        ) : null}
        {credentials.map((cred) => {
          const id = cred.credentialXref || cred.alias || "";
          const checked = value.includes(id);
          return (
            <label key={id}>
              <input
                type="checkbox"
                checked={checked}
                onChange={() => {
                  const next = checked
                    ? value.filter((item) => item !== id)
                    : [...value, id];
                  onValueChange(next);
                }}
              />
              {cred.description || id}
            </label>
          );
        })}
      </fieldset>
    );
  },
}));

jest.mock("@/components/cert-manager/kubernetes-ns-map-editor", () => ({
  KubernetesNsMapEditor: () => <div>KubernetesNsMapEditor</div>,
}));

jest.mock("@/components/ui/multi-select", () => ({
  MultiSelect: ({
    selected,
    placeholder,
  }: {
    selected: string[];
    placeholder?: string;
  }) => (
    <div>
      <div>{placeholder ?? "Select options..."}</div>
      {selected.map((value) => (
        <div key={value}>{value}</div>
      ))}
    </div>
  ),
}));

describe("CertificateRequestForm", () => {
  beforeEach(() => {
    mockUseCanAddCredential.mockReturnValue(true);
    manualIssuanceEnabled = true;
    certificateDeploymentEnabled = true;
    DEPLOYMENT_CREDENTIALS.splice(0, DEPLOYMENT_CREDENTIALS.length);
    DNS_CREDENTIALS.splice(0, DNS_CREDENTIALS.length, CLOUDFLARE_DNS);
    mockDigiCertKeys.splice(0, mockDigiCertKeys.length, DIGICERT_KEY);
    mockAddCaCredential.mockReset();
    pushMock.mockReset();
    automatedMutateAsync.mockReset();
    manualMutateAsync.mockReset();
    deploymentCredentialSelectorRenderCount = 0;
    automatedMutateAsync.mockResolvedValue({ certificateXref: "cert-1" });
    manualMutateAsync.mockResolvedValue({ certificateXref: "cert-2" });
  });

  it("does not rerender deployment controls for every domain keystroke", async () => {
    const user = userEvent.setup();
    render(<CertificateRequestForm />);

    await screen.findByPlaceholderText("example.com");
    const renderCountBeforeTyping = deploymentCredentialSelectorRenderCount;

    await user.type(
      screen.getByPlaceholderText("example.com"),
      "customer.example.com",
    );

    expect(
      deploymentCredentialSelectorRenderCount - renderCountBeforeTyping,
    ).toBeLessThanOrEqual(1);
  });

  it("requires a DNS credential in automated mode", async () => {
    const user = userEvent.setup();
    render(<CertificateRequestForm />);

    await user.type(screen.getByPlaceholderText("example.com"), "example.com");
    await user.click(
      screen.getByRole("button", { name: /Request certificate/i }),
    );

    const messages = await screen.findAllByText("Select a DNS connection");
    expect(messages.length).toBeGreaterThan(0);
    expect(automatedMutateAsync).not.toHaveBeenCalled();
  });

  it("rejects wildcard prefixes in the primary domain field", async () => {
    const user = userEvent.setup();
    render(<CertificateRequestForm />);

    await user.type(
      screen.getByPlaceholderText("example.com"),
      "*.example.com",
    );
    await user.click(screen.getByText("Cloudflare DNS"));
    await user.click(
      screen.getByRole("button", { name: /Request certificate/i }),
    );

    expect(
      await screen.findByText(
        "Enter a valid domain name without the wildcard prefix",
      ),
    ).toBeInTheDocument();
    expect(automatedMutateAsync).not.toHaveBeenCalled();
  });

  it("submits manual mode without DNS credential when manual issuance is enabled", async () => {
    const user = userEvent.setup();
    render(<CertificateRequestForm />);

    await user.click(
      screen.getByRole("button", { name: "I'll add a DNS record" }),
    );
    expect(
      screen.getByText(
        "After you request it, we show the TXT records to add, one for each name on the certificate. Once they're published, select Validate DNS to finish. Manual certificates don't renew automatically.",
      ),
    ).toBeInTheDocument();

    await user.type(screen.getByPlaceholderText("example.com"), "example.com");
    await user.click(
      screen.getByRole("button", { name: /Create manual order/i }),
    );

    await waitFor(() => {
      expect(manualMutateAsync).toHaveBeenCalledWith(
        expect.objectContaining({
          domain: "example.com",
          wildcard: false,
          san: false,
        }),
      );
    });
    expect(pushMock).toHaveBeenCalledWith("/cert-manager/manage/cert-2");
  });

  it("starts without a DNS provider on the DNS record path", async () => {
    DNS_CREDENTIALS.splice(0, DNS_CREDENTIALS.length);
    const user = userEvent.setup();
    render(<CertificateRequestForm initialDomain="shop.example.com" />);

    expect(
      await screen.findByRole("button", { name: /Create manual order/i }),
    ).toBeInTheDocument();
    await user.click(
      screen.getByRole("button", { name: /Create manual order/i }),
    );

    await waitFor(() =>
      expect(manualMutateAsync).toHaveBeenCalledWith(
        expect.objectContaining({ domain: "shop.example.com" }),
      ),
    );
  });

  it("offers to connect a DNS provider and come back to this request", async () => {
    DNS_CREDENTIALS.splice(0, DNS_CREDENTIALS.length);
    manualIssuanceEnabled = false;
    const user = userEvent.setup();
    render(<CertificateRequestForm />);

    await user.type(
      screen.getByPlaceholderText("example.com"),
      "a.example.com",
    );
    expect(
      screen.getByText("Connect your DNS provider first"),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /add a DNS record instead/i }),
    ).not.toBeInTheDocument();
    await user.click(
      screen.getByRole("button", { name: "Connect DNS provider" }),
    );

    expect(pushMock).toHaveBeenCalledWith(
      `/integrations/connections/add?type=DNS&returnTo=${encodeURIComponent(
        "/cert-manager/add?domain=a.example.com",
      )}`,
    );
  });

  it("hides every add-credential entry point when credentials cannot be added", async () => {
    mockUseCanAddCredential.mockReturnValue(false);
    DNS_CREDENTIALS.splice(0, DNS_CREDENTIALS.length);
    manualIssuanceEnabled = false;
    const user = userEvent.setup();
    render(<CertificateRequestForm />);

    await user.type(
      screen.getByPlaceholderText("example.com"),
      "a.example.com",
    );

    expect(mockUseCanAddCredential).toHaveBeenCalledWith("DNS");
    expect(mockUseCanAddCredential).toHaveBeenCalledWith("DEPLOYMENT");
    expect(
      screen.getByText("No DNS provider is connected"),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Connect DNS provider" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText("add-dns-credential-option"),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText("add-deployment-credential-option"),
    ).not.toBeInTheDocument();
  });

  it("offers add-credential options in the pickers when allowed", async () => {
    const user = userEvent.setup();
    render(<CertificateRequestForm />);

    await user.type(screen.getByPlaceholderText("example.com"), "example.com");

    expect(screen.getByText("add-dns-credential-option")).toBeInTheDocument();
  });

  it("switches to the DNS record path from the connect prompt", async () => {
    DNS_CREDENTIALS.splice(0, DNS_CREDENTIALS.length);
    const user = userEvent.setup();
    render(
      <CertificateRequestForm
        initialValues={{ mode: "automated", domain: "a.example.com" }}
      />,
    );

    await user.click(
      screen.getByRole("button", { name: /add a DNS record instead/i }),
    );

    expect(
      screen.getByRole("button", { name: /Create manual order/i }),
    ).toBeInTheDocument();
  });

  it("reissues with every field the previous certificate carried", async () => {
    const user = userEvent.setup();
    render(
      <CertificateRequestForm
        sourceCertificateXref="cert-old"
        initialValues={{
          mode: "automated",
          domain: "shop.example.com",
          wildcard: true,
          caProvider: "DIGICERT",
          dnsCredentialXref: "dns-1",
          deploymentTargets: ["missing-target"],
        }}
      />,
    );

    expect(screen.getByDisplayValue("shop.example.com")).toBeInTheDocument();
    await user.click(
      screen.getByRole("button", { name: /Request certificate/i }),
    );

    await waitFor(() =>
      expect(automatedMutateAsync).toHaveBeenCalledWith(
        expect.objectContaining({
          domain: "shop.example.com",
          wildcard: true,
          caProvider: "DIGICERT",
          caCredentialXref: "ca-1",
          dnsCredentialXref: "dns-1",
          deploymentTargets: [],
        }),
      ),
    );
  });

  it("offers saved DigiCert keys by name and links to manage them", async () => {
    render(
      <CertificateRequestForm
        initialValues={{
          mode: "automated",
          domain: "shop.example.com",
          caProvider: "DIGICERT",
          dnsCredentialXref: CLOUDFLARE_DNS.credentialXref,
        }}
      />,
    );

    expect(
      await screen.findByRole("button", { name: "DigiCert API key" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Manage keys in Integrations" }),
    ).toHaveAttribute("href", "/integrations/certificate-authorities");
    expect(
      screen.queryByLabelText("New DigiCert API key"),
    ).not.toBeInTheDocument();
  });

  it("asks for a DigiCert API key before requesting a DigiCert certificate", async () => {
    mockDigiCertKeys.splice(0, mockDigiCertKeys.length);
    const user = userEvent.setup();
    render(
      <CertificateRequestForm
        initialValues={{
          mode: "automated",
          domain: "shop.example.com",
          caProvider: "DIGICERT",
          dnsCredentialXref: CLOUDFLARE_DNS.credentialXref,
        }}
      />,
    );

    await user.click(
      screen.getByRole("button", { name: /Request certificate/i }),
    );

    expect(
      await screen.findByText("Add or choose your DigiCert API key"),
    ).toBeInTheDocument();
    expect(automatedMutateAsync).not.toHaveBeenCalled();
  });

  it("saves a new DigiCert API key and requests with it", async () => {
    mockDigiCertKeys.splice(0, mockDigiCertKeys.length);
    mockAddCaCredential.mockResolvedValue({
      ...DIGICERT_KEY,
      credentialXref: "ca-new",
    });
    const user = userEvent.setup();
    render(
      <CertificateRequestForm
        initialValues={{
          mode: "automated",
          domain: "shop.example.com",
          caProvider: "DIGICERT",
          dnsCredentialXref: CLOUDFLARE_DNS.credentialXref,
        }}
      />,
    );

    await user.type(
      screen.getByLabelText("New DigiCert API key"),
      " dc-secret ",
    );
    await user.click(screen.getByRole("button", { name: "Save key" }));
    await user.click(
      screen.getByRole("button", { name: /Request certificate/i }),
    );

    expect(mockAddCaCredential).toHaveBeenCalledWith({
      description: "DigiCert API key",
      apiKey: "dc-secret",
    });
    await waitFor(() =>
      expect(automatedMutateAsync).toHaveBeenCalledWith(
        expect.objectContaining({
          caProvider: "DIGICERT",
          caCredentialXref: "ca-new",
        }),
      ),
    );
  });

  it("validates SAN inputs and allows add/remove", async () => {
    const user = userEvent.setup();
    render(<CertificateRequestForm />);

    // Enable SAN.
    await user.click(screen.getByRole("button", { name: /SAN/i }));
    // Enable wildcard on primary domain to ensure apex SAN is still allowed.
    await user.click(screen.getByRole("button", { name: /Wildcard/i }));

    const sanInput = screen.getByPlaceholderText(
      "www.example.com, api.example.com",
    );

    await user.type(sanInput, "not-a-domain");
    await user.click(screen.getByRole("button", { name: "Add" }));
    expect(await screen.findByText(/Invalid SAN domain/i)).toBeInTheDocument();

    await user.clear(sanInput);
    await user.type(sanInput, "example.com,www.example.com{enter}");

    const apexMatches = await screen.findAllByText("example.com");
    expect(apexMatches.length).toBeGreaterThan(0);
    const matches = await screen.findAllByText("www.example.com");
    expect(matches.length).toBeGreaterThan(0);

    await user.click(
      screen.getByRole("button", { name: /Remove www\.example\.com/i }),
    );
    await waitFor(() => {
      expect(screen.queryAllByText("www.example.com").length).toBe(0);
    });
  });

  it("allows wildcard SANs for the primary domain when primary wildcard is disabled", async () => {
    const user = userEvent.setup();
    render(<CertificateRequestForm />);

    await user.type(
      screen.getByPlaceholderText("example.com"),
      "app.example.com",
    );
    await user.click(screen.getByRole("button", { name: /SAN/i }));

    const sanInput = screen.getByPlaceholderText(
      "www.example.com, api.example.com",
    );
    await user.type(sanInput, "*.app.example.com{enter}");

    const wildcardSanMatches = await screen.findAllByText("*.app.example.com");
    expect(wildcardSanMatches.length).toBeGreaterThan(0);
    expect(
      screen.queryByText(/already covered by the primary domain/i),
    ).not.toBeInTheDocument();
  });

  it("keeps the lifetime choice for a CA that accepts one", async () => {
    const user = userEvent.setup();
    render(<CertificateRequestForm />);

    await user.click(screen.getByRole("button", { name: "DigiCert" }));

    expect(screen.getByText("Certificate validity")).toBeInTheDocument();
  });

  it("includes SAN entries in automated submission payload", async () => {
    const user = userEvent.setup();
    render(<CertificateRequestForm />);

    await user.type(screen.getByPlaceholderText("example.com"), "example.com");

    // Select a base DNS credential.
    await user.selectOptions(
      screen.getByLabelText("Select a DNS connection"),
      "dns-1",
    );

    // Enable SAN and add two domains.
    await user.click(screen.getByRole("button", { name: /SAN/i }));
    const sanInput = screen.getByPlaceholderText(
      "www.example.com, api.example.com",
    );
    await user.type(sanInput, "www.example.com,api.example.com{enter}");

    await user.click(
      screen.getByRole("button", { name: /Request certificate/i }),
    );

    await waitFor(() => {
      expect(automatedMutateAsync).toHaveBeenCalledWith(
        expect.objectContaining({
          domain: "example.com",
          dnsCredentialXref: "dns-1",
          san: true,
          sanDomainEntries: expect.arrayContaining([
            expect.objectContaining({
              dnsCredentialXref: "dns-1",
              patterns: expect.arrayContaining([
                "www.example.com",
                "api.example.com",
              ]),
            }),
          ]),
        }),
      );
    });
    expect(pushMock).toHaveBeenCalledWith("/cert-manager/manage/cert-1");
  });

  it("hides deployment targets and submits none when deployment is disabled", async () => {
    const user = userEvent.setup();
    certificateDeploymentEnabled = false;
    DEPLOYMENT_CREDENTIALS.splice(0, DEPLOYMENT_CREDENTIALS.length, {
      credentialXref: "deploy-1",
      alias: "deploy-1",
      description: "Deployment target",
      targetType: "AZURE_KV",
      providerName: "AZURE_KV",
    });

    render(<CertificateRequestForm />);

    await user.type(screen.getByPlaceholderText("example.com"), "example.com");
    await user.selectOptions(
      screen.getByLabelText("Select a DNS connection"),
      "dns-1",
    );

    expect(screen.queryByText("Deployment targets")).not.toBeInTheDocument();
    expect(screen.queryByText("Deployment target")).not.toBeInTheDocument();

    await user.click(
      screen.getByRole("button", { name: /Request certificate/i }),
    );

    await waitFor(() => {
      expect(automatedMutateAsync).toHaveBeenCalledWith(
        expect.objectContaining({
          deploymentTargets: [],
          deploymentTargetConfigs: undefined,
        }),
      );
    });
  });

  it("normalizes primary and SAN domains before automated submission", async () => {
    const user = userEvent.setup();
    render(<CertificateRequestForm />);

    await user.type(
      screen.getByPlaceholderText("example.com"),
      "APP.EXAMPLE.COM",
    );
    await user.selectOptions(
      screen.getByLabelText("Select a DNS connection"),
      "dns-1",
    );
    await user.click(screen.getByRole("button", { name: /SAN/i }));

    const sanInput = screen.getByPlaceholderText(
      "www.example.com, api.example.com",
    );
    await user.type(sanInput, "*.APP.EXAMPLE.COM{enter}");

    await user.click(
      screen.getByRole("button", { name: /Request certificate/i }),
    );

    await waitFor(() => {
      expect(automatedMutateAsync).toHaveBeenCalledWith(
        expect.objectContaining({
          domain: "app.example.com",
          sanDomainEntries: expect.arrayContaining([
            expect.objectContaining({
              patterns: ["*.app.example.com"],
            }),
          ]),
        }),
      );
    });
  });

  it("submits selected Kubernetes deployment target using saved default config", async () => {
    const user = userEvent.setup();

    DEPLOYMENT_CREDENTIALS.splice(0, DEPLOYMENT_CREDENTIALS.length, {
      credentialXref: "k8s-1",
      alias: "k8s-1",
      description: "Kubernetes Secrets (prod)",
      targetType: "KUBERNETES_SECRETS",
      providerName: "KUBERNETES_SECRETS",
      configJson: {
        authMethod: "SA_INCLUSTER",
        clusterName: "aks-prod",
        namespaces: ["app-prod"],
      },
    });

    render(<CertificateRequestForm />);

    await user.type(screen.getByPlaceholderText("example.com"), "example.com");

    await user.selectOptions(
      screen.getByLabelText("Select a DNS connection"),
      "dns-1",
    );

    await user.click(
      screen.getByRole("checkbox", { name: "Kubernetes Secrets (prod)" }),
    );

    // Switch Kubernetes config to "saved default config".
    await user.click(await screen.findByText("Use saved default config"));

    await user.click(
      screen.getByRole("button", { name: /Request certificate/i }),
    );

    await waitFor(() => {
      expect(automatedMutateAsync).toHaveBeenCalledWith(
        expect.objectContaining({
          deploymentTargetConfigs: expect.arrayContaining([
            expect.objectContaining({
              deploymentCredentialXref: "k8s-1",
              config: { useDefault: true },
            }),
          ]),
        }),
      );
    });
  });

  it("prefills configured deployment target domains from credential allow-list", async () => {
    const user = userEvent.setup();

    DEPLOYMENT_CREDENTIALS.splice(0, DEPLOYMENT_CREDENTIALS.length, {
      credentialXref: "apigw-1",
      alias: "apigw-1",
      description: "AWS API Gateway (prod)",
      targetType: "AWS_API_GW_HTTP",
      providerName: "AWS_API_GW_HTTP",
      configJson: {
        config: {
          authMode: "INSTANCE_PROFILE",
          region: "us-east-1",
          customDomains: ["api.allowed.example.com", "api.other.example.com"],
        },
      },
    });

    render(<CertificateRequestForm />);

    // Primary domain is not on the allow-list.
    await user.type(screen.getByPlaceholderText("example.com"), "example.com");
    await user.selectOptions(
      screen.getByLabelText("Select a DNS connection"),
      "dns-1",
    );

    await user.click(
      screen.getByRole("checkbox", { name: "AWS API Gateway (prod)" }),
    );

    expect(
      await screen.findByText("api.allowed.example.com"),
    ).toBeInTheDocument();
  });

  it("prefills Azure App Gateway listeners from credential allow-list", async () => {
    const user = userEvent.setup();

    DEPLOYMENT_CREDENTIALS.splice(0, DEPLOYMENT_CREDENTIALS.length, {
      credentialXref: "appgw-1",
      alias: "appgw-1",
      description: "Azure App Gateway (prod)",
      targetType: "AZURE_APP_GW",
      providerName: "AZURE_APP_GW",
      configJson: {
        config: {
          authMode: "WORKLOAD_IDENTITY",
          tenantId: "tenant-1",
          subscriptionId: "sub-1",
          resourceGroup: "rg-1",
          appGateway: "agw-1",
          listeners: ["https-443", "https-8443"],
          keyVaultUri: "https://kv.vault.azure.net/",
        },
      },
    });

    render(<CertificateRequestForm />);

    await user.type(screen.getByPlaceholderText("example.com"), "example.com");
    await user.selectOptions(
      screen.getByLabelText("Select a DNS connection"),
      "dns-1",
    );
    await user.click(
      screen.getByRole("checkbox", { name: "Azure App Gateway (prod)" }),
    );

    expect(await screen.findByText("https-443")).toBeInTheDocument();
  });

  it("defaults Key Vault and Front Door certificate names apart and blocks a shared name in one vault", async () => {
    const user = userEvent.setup();

    DEPLOYMENT_CREDENTIALS.splice(
      0,
      DEPLOYMENT_CREDENTIALS.length,
      {
        credentialXref: "kv-1",
        alias: "kv-1",
        description: "Azure Key Vault (prod)",
        targetType: "AZURE_KV",
        providerName: "AZURE_KV",
        configJson: {
          config: {
            authMode: "WORKLOAD_IDENTITY",
            tenantId: "tenant-1",
            vaultUri: "https://kv.vault.azure.net/",
          },
        },
      },
      {
        credentialXref: "afd-1",
        alias: "afd-1",
        description: "Azure Front Door (prod)",
        targetType: "AZURE_AFD",
        providerName: "AZURE_AFD",
        configJson: {
          config: {
            authMode: "WORKLOAD_IDENTITY",
            tenantId: "tenant-1",
            subscriptionId: "sub-1",
            resourceGroup: "rg-1",
            profileName: "afd-prod",
            keyVaultUri: "https://kv.vault.azure.net",
            customDomains: ["example.com"],
          },
        },
      },
    );

    render(<CertificateRequestForm />);

    await user.type(screen.getByPlaceholderText("example.com"), "example.com");
    await user.selectOptions(
      screen.getByLabelText("Select a DNS connection"),
      "dns-1",
    );
    await user.click(
      screen.getByRole("checkbox", { name: "Azure Key Vault (prod)" }),
    );
    await user.click(
      screen.getByRole("checkbox", { name: "Azure Front Door (prod)" }),
    );

    expect(await screen.findByDisplayValue("example-com")).toBeInTheDocument();
    const afdCertificateName =
      await screen.findByDisplayValue("example-com-afd");

    await user.clear(afdCertificateName);
    await user.type(afdCertificateName, "example-com");
    await user.click(
      screen.getByRole("button", { name: /Request certificate/i }),
    );

    expect(
      await screen.findByText(
        /Key Vault target kv-1 and Front Door target afd-1 both use certificate name "example-com"/,
      ),
    ).toBeInTheDocument();
    expect(automatedMutateAsync).not.toHaveBeenCalled();
  });

  it("shows Azure AGC namespaces from credential allow-list", async () => {
    const user = userEvent.setup();

    DEPLOYMENT_CREDENTIALS.splice(0, DEPLOYMENT_CREDENTIALS.length, {
      credentialXref: "agc-1",
      alias: "agc-1",
      description: "Azure AGC (prod)",
      targetType: "AZURE_APP_GW_CONTAINERS",
      providerName: "AZURE_APP_GW_CONTAINERS",
      configJson: {
        config: {
          azureAuthMode: "WORKLOAD_IDENTITY",
          tenantId: "tenant-1",
          subscriptionId: "sub-1",
          resourceGroup: "rg-1",
          clusterAuthMode: "AZURE",
          clusterName: "aks-prod",
          agcNamespace: "alb-system",
          apiStyle: "GATEWAY_API",
          secretNamespaces: ["app-prod"],
        },
      },
    });

    render(<CertificateRequestForm />);

    await user.type(screen.getByPlaceholderText("example.com"), "example.com");
    await user.selectOptions(
      screen.getByLabelText("Select a DNS connection"),
      "dns-1",
    );
    await user.click(
      screen.getByRole("checkbox", { name: "Azure AGC (prod)" }),
    );

    expect(await screen.findByDisplayValue("app-prod")).toBeInTheDocument();
  });
});
