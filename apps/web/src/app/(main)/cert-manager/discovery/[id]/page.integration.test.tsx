// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";

import DiscoveredCertDetailPage from "@/app/(main)/cert-manager/discovery/[id]/page";
import { useAuthStore } from "@/stores/auth-store";
import { server } from "@/test/msw/server";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL as string;
const DISCOVERY_URL = `${API_BASE_URL}/api/v1/discovery/certs`;

const baseUser = {
  id: "user-1",
  email: "user@example.com",
  organizationId: "org-1",
  organizationName: "Org",
  roles: ["USER"],
  permissions: ["certificate:read"],
  authMethod: "LOCAL" as const,
};

const mockAuthState = {
  user: baseUser,
  isSuperAdmin: false,
  isLoading: false,
};

jest.mock("next/navigation", () => ({
  useParams: () => ({ id: "7" }),
  useRouter: () => ({ replace: jest.fn(), push: jest.fn() }),
}));

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => mockAuthState,
}));

jest.mock("next/image", () => ({
  __esModule: true,
  default: (props: React.ImgHTMLAttributes<HTMLImageElement>) => (
    // eslint-disable-next-line @next/next/no-img-element
    <img {...props} alt={props.alt ?? ""} />
  ),
}));

jest.mock("@/components/ui/page-header", () => ({
  PageHeader: ({ title, subtitle }: { title: string; subtitle?: string }) => (
    <div>
      <h1>{title}</h1>
      {subtitle ? <p>{subtitle}</p> : null}
    </div>
  ),
}));

function renderPage() {
  useAuthStore.setState({
    user: baseUser,
    isLoading: false,
    isSuperAdmin: false,
    expiresAt: Date.now() + 60_000,
  });

  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <DiscoveredCertDetailPage />
    </QueryClientProvider>,
  );
}

describe("DiscoveredCertDetailPage integration (UI + MSW)", () => {
  it("renders Kubernetes source, impact, services, and workloads", async () => {
    const user = userEvent.setup();
    server.use(
      http.get(`${DISCOVERY_URL}/:id`, ({ params }) =>
        HttpResponse.json({
          id: Number(params.id),
          organizationId: 2,
          targetType: "KUBERNETES_SECRETS",
          resourceId: "k8s://prod-aks/frontend/secrets/api-tls",
          domain: "k8s.example.net",
          certStatus: "ISSUED",
          notBefore: "2026-03-01T00:00:00Z",
          notAfter: "2026-09-01T00:00:00Z",
          issuer: "Example CA",
          inUseBy: ["frontend/IngressRoute/api-route"],
          sanDomains: ["k8s.example.net"],
          subjectDn: "CN=k8s.example.net",
          keyUsage: "digitalSignature,keyEncipherment",
          extendedKeyUsage: "1.3.6.1.5.5.7.3.1",
          inventoryStatus: "PRESENT",
          managed: false,
          discoveredAt: "2026-06-24T10:10:09Z",
          providerData: {
            clusterName: "prod-aks",
            usageComplete: true,
            impactComplete: true,
            unreadableResourceTypes: [],
            source: {
              apiVersion: "v1",
              kind: "Secret",
              namespace: "frontend",
              name: "api-tls",
              uid: "secret-uid",
              resourceVersion: "12345",
              type: "kubernetes.io/tls",
              fingerprintSha256: "AA:BB:CC",
            },
            usages: [
              {
                apiVersion: "traefik.io/v1alpha1",
                kind: "IngressRoute",
                namespace: "frontend",
                name: "api-route",
                uid: "route-uid",
                fieldPath: "spec.tls.secretName",
                usageType: "TLS_TERMINATION",
                hostnames: ["k8s.example.net"],
                backendServices: [
                  {
                    namespace: "frontend",
                    name: "api-service",
                    portName: null,
                    portNumber: 443,
                  },
                ],
                affectedWorkloads: [
                  {
                    apiVersion: "apps/v1",
                    kind: "ReplicaSet",
                    namespace: "frontend",
                    name: "api-rs",
                    containers: ["api"],
                    referencePath: "service selector",
                  },
                ],
                confidence: "HIGH",
              },
            ],
            impact: {
              externallyServed: true,
              directlyMountedByWorkloads: false,
              affectedHostnames: ["k8s.example.net"],
              affectedServices: ["frontend/api-service"],
              affectedWorkloads: ["frontend/ReplicaSet/api-rs"],
              summary: "Critical TLS endpoint",
            },
            warnings: [],
          },
        }),
      ),
    );

    renderPage();

    expect(
      await screen.findByRole("heading", { name: "k8s.example.net" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Risk and impact")).toBeInTheDocument();
    expect(screen.getByText("Kubernetes source")).toBeInTheDocument();
    expect(screen.getByText("Kubernetes usage paths (1)")).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText("prod-aks")).toBeInTheDocument();
    });
    expect(screen.getByText("Critical TLS endpoint")).toBeInTheDocument();
    expect(screen.getAllByText("frontend/api-service")).not.toHaveLength(0);
    expect(screen.getAllByText("frontend/ReplicaSet/api-rs")).not.toHaveLength(
      0,
    );

    await user.click(screen.getByRole("button", { name: /IngressRoute/i }));
    expect(await screen.findByText("Containers:")).toBeInTheDocument();
    expect(screen.getByText("api")).toBeInTheDocument();
    expect(screen.getByText("spec.tls.secretName")).toBeInTheDocument();
    expect(screen.getAllByText("AA:BB:CC")).not.toHaveLength(0);
  });
  describe("reissue hand-off", () => {
    const unmanagedCert = {
      id: 7,
      organizationId: 2,
      targetType: "AWS_ACM",
      resourceId: "arn:aws:acm:us-east-1:123:certificate/7",
      domain: "*.shop.example.net",
      certStatus: "ISSUED",
      notBefore: "2026-03-01T00:00:00Z",
      notAfter: "2026-12-01T00:00:00Z",
      issuer: "Amazon",
      inUseBy: [],
      sanDomains: [],
      subjectDn: "CN=*.shop.example.net",
      keyUsage: null,
      extendedKeyUsage: null,
      inventoryStatus: "PRESENT",
      managed: false,
      discoveredAt: "2026-06-24T10:10:09Z",
      providerData: null,
    };

    afterEach(() => {
      mockAuthState.user = baseUser;
    });

    it("offers to reissue an unmanaged certificate with CertPing", async () => {
      mockAuthState.user = {
        ...baseUser,
        permissions: ["certificate:read", "certificate:issue"],
      };
      server.use(
        http.get(`${DISCOVERY_URL}/:id`, () =>
          HttpResponse.json(unmanagedCert),
        ),
      );

      renderPage();

      expect(
        await screen.findByRole("link", { name: "Reissue with CertPing" }),
      ).toHaveAttribute(
        "href",
        "/cert-manager/add?domain=shop.example.net&wildcard=1",
      );
    });

    it.each([
      ["the user cannot issue", ["certificate:read"], false],
      [
        "CertPing already manages it",
        ["certificate:read", "certificate:issue"],
        true,
      ],
      [
        "it is not yet known whether CertPing manages it",
        ["certificate:read", "certificate:issue"],
        null,
      ],
    ])(
      "does not offer a reissue when %s",
      async (_label, permissions, managed) => {
        mockAuthState.user = { ...baseUser, permissions };
        server.use(
          http.get(`${DISCOVERY_URL}/:id`, () =>
            HttpResponse.json({ ...unmanagedCert, managed }),
          ),
        );

        renderPage();

        expect(
          await screen.findByRole("heading", { name: "*.shop.example.net" }),
        ).toBeInTheDocument();
        expect(
          screen.queryByRole("link", { name: "Reissue with CertPing" }),
        ).not.toBeInTheDocument();
      },
    );
  });
});
