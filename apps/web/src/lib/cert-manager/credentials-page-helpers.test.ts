// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  K8S_AUTH_METHOD_OPTIONS,
  copyTextToClipboard,
  editCredentialSchema,
  getCredentialTabCount,
} from "@/lib/cert-manager/credentials-page-helpers";
import { createCredentialFormSchema } from "@/lib/cert-manager/credential-form-schemas";
import type { CredentialRecord } from "@/types/ssl";

const originalAppMode = process.env.NEXT_PUBLIC_APP_MODE;

function makeCredential(
  overrides: Partial<CredentialRecord>,
): CredentialRecord {
  return overrides as CredentialRecord;
}

describe("credentials-page-helpers", () => {
  afterEach(() => {
    process.env.NEXT_PUBLIC_APP_MODE = originalAppMode;
  });

  describe("createCredentialFormSchema", () => {
    it("requires provider and description on create", () => {
      const result = createCredentialFormSchema.safeParse({
        type: "DEPLOYMENT",
        provider: "",
        description: "",
        secretHandle: "",
        k8sAuthMethod: "SA_INCLUSTER",
        k8sClusterName: "",
        k8sNamespaceMode: "explicit",
        k8sNamespaces: [],
      });

      expect(result.success).toBe(false);
      if (!result.success) {
        const paths = result.error.issues.map((issue) => String(issue.path[0]));
        expect(paths).toContain("provider");
        expect(paths).toContain("description");
      }
    });

    it("requires ALB/NLB config fields when provider is AWS_ALB", () => {
      const result = createCredentialFormSchema.safeParse({
        type: "DEPLOYMENT",
        provider: "AWS_ALB",
        description: "alb credential",
        secretHandle: "https://example-vault.vault.azure.net/secrets/CRED/ver",
        awsElbAuthMode: "STATIC_KEYS",
        awsElbRegion: "us-east-1",
        awsElbListeners: [],
        k8sAuthMethod: "SA_INCLUSTER",
        k8sClusterName: "",
        k8sNamespaceMode: "explicit",
        k8sNamespaces: [],
      });

      expect(result.success).toBe(false);
      if (!result.success) {
        const paths = result.error.issues.map((issue) => String(issue.path[0]));
        expect(paths).toContain("awsElbListeners");
      }
    });

    it("requires API Gateway custom domains when provider is AWS_API_GW_REST", () => {
      const result = createCredentialFormSchema.safeParse({
        type: "DEPLOYMENT",
        provider: "AWS_API_GW_REST",
        description: "api gw credential",
        secretHandle: "https://example-vault.vault.azure.net/secrets/CRED/ver",
        awsApiGwAuthMode: "STATIC_KEYS",
        awsApiGwRegion: "us-east-1",
        awsApiGwCustomDomains: [],
        k8sAuthMethod: "SA_INCLUSTER",
        k8sClusterName: "",
        k8sNamespaceMode: "explicit",
        k8sNamespaces: [],
      });

      expect(result.success).toBe(false);
      if (!result.success) {
        const paths = result.error.issues.map((issue) => String(issue.path[0]));
        expect(paths).toContain("awsApiGwCustomDomains");
      }
    });

    it("keeps enterprise deployment auth modes unrestricted", () => {
      process.env.NEXT_PUBLIC_APP_MODE = "enterprise";

      const result = createCredentialFormSchema.safeParse({
        type: "DEPLOYMENT",
        provider: "AWS_API_GW_REST",
        description: "api gw credential",
        secretHandle: "https://example-vault.vault.azure.net/secrets/CRED/ver",
        awsApiGwAuthMode: "ASSUME_ROLE",
        awsApiGwRegion: "us-east-1",
        awsApiGwRoleArn: "arn:aws:iam::123456789012:role/certping",
        awsApiGwCustomDomains: ["api.example.com"],
        k8sAuthMethod: "SA_INCLUSTER",
        k8sClusterName: "",
        k8sNamespaceMode: "explicit",
        k8sNamespaces: [],
      });

      expect(result.success).toBe(true);
    });

    it("blocks auth modes a credential stored in CertPing cannot use", () => {
      const result = createCredentialFormSchema.safeParse({
        credentialStorage: "managed",
        type: "DEPLOYMENT",
        provider: "GCP_CERT_MANAGER",
        description: "gcp credential",
        gcpAuthMode: "WORKLOAD_IDENTITY",
        gcpProjectId: "certping-prod",
        gcpLocation: "global",
        k8sAuthMethod: "SA_INCLUSTER",
        k8sClusterName: "",
        k8sNamespaceMode: "explicit",
        k8sNamespaces: [],
      });

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues).toEqual(
          expect.arrayContaining([
            expect.objectContaining({
              path: ["gcpAuthMode"],
              message:
                "Credentials stored in CertPing only support GCP service account key auth.",
            }),
          ]),
        );
      }
    });

    it("keeps enterprise Azure service principal client ID optional in provider config", () => {
      process.env.NEXT_PUBLIC_APP_MODE = "enterprise";

      const result = createCredentialFormSchema.safeParse({
        type: "DEPLOYMENT",
        provider: "AZURE_APP_GW",
        description: "app gateway credential",
        secretHandle: "https://example-vault.vault.azure.net/secrets/CRED/ver",
        azureAppGwAuthMode: "SERVICE_PRINCIPAL",
        azureAppGwTenantId: "tenant-1",
        azureAppGwSubscriptionId: "subscription-1",
        azureAppGwResourceGroup: "rg-prod",
        azureAppGwAppGateway: "agw-prod",
        azureAppGwListeners: ["listener-1"],
        azureAppGwKeyVaultUri: "https://target.vault.azure.net",
        k8sAuthMethod: "SA_INCLUSTER",
        k8sClusterName: "",
        k8sNamespaceMode: "explicit",
        k8sNamespaces: [],
      });

      expect(result.success).toBe(true);
    });

    it("keeps enterprise Azure deployment Key Vault URI required", () => {
      process.env.NEXT_PUBLIC_APP_MODE = "enterprise";

      const result = createCredentialFormSchema.safeParse({
        type: "DEPLOYMENT",
        provider: "AZURE_APP_GW",
        description: "app gateway credential",
        secretHandle: "https://example-vault.vault.azure.net/secrets/CRED/ver",
        azureAppGwAuthMode: "SERVICE_PRINCIPAL",
        azureAppGwTenantId: "tenant-1",
        azureAppGwSubscriptionId: "subscription-1",
        azureAppGwResourceGroup: "rg-prod",
        azureAppGwAppGateway: "agw-prod",
        azureAppGwListeners: ["listener-1"],
        k8sAuthMethod: "SA_INCLUSTER",
        k8sClusterName: "",
        k8sNamespaceMode: "explicit",
        k8sNamespaces: [],
      });

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues).toEqual(
          expect.arrayContaining([
            expect.objectContaining({
              path: ["azureAppGwKeyVaultUri"],
            }),
          ]),
        );
      }
    });

    it("requires Azure deployment client ID for a stored service principal", () => {
      const result = createCredentialFormSchema.safeParse({
        credentialStorage: "managed",
        type: "DEPLOYMENT",
        provider: "AZURE_APP_GW",
        description: "app gateway credential",
        azureAppGwAuthMode: "SERVICE_PRINCIPAL",
        azureAppGwTenantId: "tenant-1",
        azureAppGwSubscriptionId: "subscription-1",
        azureAppGwResourceGroup: "rg-prod",
        azureAppGwAppGateway: "agw-prod",
        azureAppGwListeners: ["listener-1"],
        azureAppGwKeyVaultUri: "https://target.vault.azure.net",
        k8sAuthMethod: "SA_INCLUSTER",
        k8sClusterName: "",
        k8sNamespaceMode: "explicit",
        k8sNamespaces: [],
      });

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues).toEqual(
          expect.arrayContaining([
            expect.objectContaining({
              path: ["azureAppGwClientId"],
              message:
                "Client ID is required for Azure service principal auth.",
            }),
          ]),
        );
      }
    });

    it("allows a stored Azure deployment service principal with Key Vault URI", () => {
      const result = createCredentialFormSchema.safeParse({
        credentialStorage: "managed",
        type: "DEPLOYMENT",
        provider: "AZURE_APP_GW",
        description: "app gateway credential",
        azureAppGwAuthMode: "SERVICE_PRINCIPAL",
        azureAppGwTenantId: "tenant-1",
        azureAppGwSubscriptionId: "subscription-1",
        azureAppGwClientId: "client-1",
        azureAppGwResourceGroup: "rg-prod",
        azureAppGwAppGateway: "agw-prod",
        azureAppGwListeners: ["listener-1"],
        azureAppGwKeyVaultUri: "https://target.vault.azure.net",
        k8sAuthMethod: "SA_INCLUSTER",
        k8sClusterName: "",
        k8sNamespaceMode: "explicit",
        k8sNamespaces: [],
      });

      expect(result.success).toBe(true);
    });
  });

  describe("editCredentialSchema", () => {
    it("requires secretHandle for non-kubernetes providers", () => {
      const result = editCredentialSchema.safeParse({
        provider: "AKAMAI_CPS",
        secretHandle: "",
      });
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues.map((issue) => issue.message)).toContain(
          "Secret handle is required",
        );
      }
    });

    it("validates secretHandle as url for non-kubernetes providers", () => {
      const result = editCredentialSchema.safeParse({
        provider: "AKAMAI_CPS",
        secretHandle: "not-a-url",
      });
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues.map((issue) => issue.message)).toContain(
          "Enter a valid secret handle",
        );
      }
    });

    it("accepts a GCP Secret Manager resource path as a secret handle", () => {
      const result = editCredentialSchema.safeParse({
        provider: "AKAMAI_CPS",
        secretHandle: "projects/123456789012/secrets/cf/versions/1",
      });
      const messages = result.success
        ? []
        : result.error.issues.map((issue) => issue.message);
      expect(messages).not.toContain("Enter a valid secret handle");
    });

    it("accepts an AWS Secrets Manager ARN as a secret handle", () => {
      const result = editCredentialSchema.safeParse({
        provider: "AKAMAI_CPS",
        secretHandle:
          "arn:aws:secretsmanager:us-east-1:123456789012:secret:certping/cf-AbCdEf",
      });
      const messages = result.success
        ? []
        : result.error.issues.map((issue) => issue.message);
      expect(messages).not.toContain("Enter a valid secret handle");
    });

    it.each([
      ["AZURE_KV", "azureKvAuthMode", "azureKvClientId"],
      ["AZURE_APP_GW", "azureAppGwAuthMode", "azureAppGwClientId"],
      ["AZURE_AFD", "azureAfdAuthMode", "azureAfdClientId"],
    ])(
      "requires a client ID for %s workload identity",
      (provider, authModeField, clientIdField) => {
        const base = {
          provider,
          secretHandle: "",
          [authModeField]: "WORKLOAD_IDENTITY",
        };
        const clientIdIssues = (values: Record<string, unknown>) => {
          const result = editCredentialSchema.safeParse(values);
          return result.success
            ? []
            : result.error.issues.filter(
                (issue) => issue.path[0] === clientIdField,
              );
        };

        expect(clientIdIssues(base).map((issue) => issue.message)).toEqual([
          "Client ID is required for workload identity",
        ]);
        expect(
          clientIdIssues({
            ...base,
            [clientIdField]: "00000000-0000-0000-0000-000000000001",
          }),
        ).toEqual([]);
      },
    );

    it("allows empty secretHandle for kubernetes in-cluster auth", () => {
      const result = editCredentialSchema.safeParse({
        provider: "KUBERNETES_SECRETS",
        secretHandle: "",
        k8sAuthMethod: "SA_INCLUSTER",
        k8sClusterName: "prod",
        k8sNamespaceMode: "all_namespaces",
        k8sNamespaces: [],
      });
      expect(result.success).toBe(true);
    });

    it("maps kubernetes config schema issues into k8s field paths", () => {
      const result = editCredentialSchema.safeParse({
        provider: "KUBERNETES_SECRETS",
        secretHandle: "https://vault/k8s",
        k8sAuthMethod: "SA_TOKEN",
        k8sClusterName: "",
        k8sNamespaceMode: "explicit",
        k8sNamespaces: ["INVALID_NAMESPACE"],
      });

      expect(result.success).toBe(false);
      if (!result.success) {
        const paths = result.error.issues.map((issue) => String(issue.path[0]));
        expect(paths).toContain("k8sClusterName");
        expect(paths).toContain("k8sNamespaces");
      }
    });
  });

  describe("K8S_AUTH_METHOD_OPTIONS", () => {
    it("exposes every supported auth method option", () => {
      expect(K8S_AUTH_METHOD_OPTIONS.map((opt) => opt.value)).toEqual([
        "SA_INCLUSTER",
        "SA_TOKEN",
        "AWS",
        "AZURE",
        "GCP",
      ]);
    });
  });

  describe("copyTextToClipboard", () => {
    it("does not throw if clipboard write fails", async () => {
      const clipboard = {
        writeText: jest.fn().mockRejectedValue(new Error("x")),
      };
      Object.defineProperty(navigator, "clipboard", {
        value: clipboard,
        configurable: true,
      });

      await expect(copyTextToClipboard("hello")).resolves.toBeUndefined();
      expect(clipboard.writeText).toHaveBeenCalledWith("hello");
    });
  });

  describe("getCredentialTabCount", () => {
    it("counts credential records by type", () => {
      expect(
        getCredentialTabCount(
          [
            makeCredential({ type: "DNS" }),
            makeCredential({ type: "DEPLOYMENT" }),
            makeCredential({ type: "DEPLOYMENT" }),
          ],
          "DEPLOYMENT",
        ),
      ).toBe(2);
    });
  });
});
