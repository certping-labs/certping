// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { CredentialReferenceType } from "@/types/cert-manager";
import type { AwsAcmAuthMode } from "@/lib/credential-config-schemas/aws-acm";
import type { AwsApiGwAuthMode } from "@/lib/credential-config-schemas/aws-api-gateway";
import type { AwsCloudFrontAuthMode } from "@/lib/credential-config-schemas/aws-cloudfront";
import type { AwsLoadBalancerAuthMode } from "@/lib/credential-config-schemas/aws-load-balancer";
import type {
  AzureAgcAuthMode,
  AzureAgcClusterAuthMode,
} from "@/lib/credential-config-schemas/azure-agc";
import type { AzureAfdAuthMode } from "@/lib/credential-config-schemas/azure-afd";
import type { AzureAppGwAuthMode } from "@/lib/credential-config-schemas/azure-app-gw";
import type { AzureKvAuthMode } from "@/lib/credential-config-schemas/azure-kv";
import type { GcpAuthMode } from "@/lib/credential-config-schemas/gcp-shared";
import type { KubernetesAuthMethod } from "@/lib/credential-config-schemas/kubernetes-secrets";
import type { CredentialFormValidationValues } from "@/lib/cert-manager/credential-form-schemas/types";
import { usesManagedStorage } from "@/lib/cert-manager/credential-storage";
import { z } from "zod";

const jsonRecordSchema = z.record(z.string(), z.unknown());
type JsonRecord = z.infer<typeof jsonRecordSchema>;
type ManagedCredentialFormContext = {
  type: CredentialReferenceType;
  providerApiValue?: string | null;
  kubernetesAuthMethod?: KubernetesAuthMethod | null;
  awsAcmAuthMode?: AwsAcmAuthMode | null;
  awsElbAuthMode?: AwsLoadBalancerAuthMode | null;
  awsApiGwAuthMode?: AwsApiGwAuthMode | null;
  awsCloudFrontAuthMode?: AwsCloudFrontAuthMode | null;
  azureKvAuthMode?: AzureKvAuthMode | null;
  azureAppGwAuthMode?: AzureAppGwAuthMode | null;
  azureAgcAzureAuthMode?: AzureAgcAuthMode | null;
  azureAgcClusterAuthMode?: AzureAgcClusterAuthMode | null;
  azureAfdAuthMode?: AzureAfdAuthMode | null;
  gcpAuthMode?: GcpAuthMode | null;
  fallbackTemplate?: string | null;
};

function readString(record: JsonRecord, key: string): string {
  const value = record[key];
  return typeof value === "string" ? value.trim() : "";
}

function hasNonBlankString(record: JsonRecord, key: string): boolean {
  return readString(record, key).length > 0;
}

function formatJson(value: JsonRecord): string {
  return JSON.stringify(value, null, 2);
}

function parseFallbackTemplate(fallbackTemplate?: string | null): JsonRecord {
  if (!fallbackTemplate) {
    return {};
  }

  try {
    const parsed = jsonRecordSchema.safeParse(JSON.parse(fallbackTemplate));
    return parsed.success ? parsed.data : {};
  } catch {
    return {};
  }
}

function getDnsTemplate(
  provider: string,
  fallbackTemplate?: string | null,
): JsonRecord {
  switch (provider) {
    case "AWS_ROUTE53":
      return {
        accessKeyId: "AKIA...",
        secretAccessKey: "secret-access-key",
      };
    case "CLOUDFLARE":
      return {
        apiToken: "cf-xxx",
      };
    case "CERTPING":
      return {
        apiKey: "cpk_live_…",
      };
    case "GODADDY":
      return {
        apiKey: "godaddy-api-key",
        apiSecret: "godaddy-api-secret",
      };
    case "NAMEDOTCOM":
      return {
        username: "namecom-username",
        apiToken: "namecom-api-token",
      };
    case "HOSTINGER":
      return {
        apiToken: "hostinger-api-token",
      };
    case "NAMECHEAP":
      return {
        apiUser: "namecheap-api-user",
        username: "namecheap-username",
        apiKey: "namecheap-api-key",
      };
    default:
      return parseFallbackTemplate(fallbackTemplate);
  }
}

function getDeploymentTemplate(
  context: ManagedCredentialFormContext,
): JsonRecord {
  const provider = (context.providerApiValue || "").trim().toUpperCase();

  switch (provider) {
    case "AWS_ACM":
    case "AWS_ALB":
    case "AWS_NLB":
    case "AWS_API_GW_REST":
    case "AWS_API_GW_HTTP":
    case "AWS_CLOUDFRONT":
      return {};
    case "AZURE_KV":
      return {
        tenantId: "11111111-1111-1111-1111-111111111111",
        vaultUri: "https://target.vault.azure.net",
      };
    case "AZURE_APP_GW":
    case "AZURE_APP_GW_CONTAINERS":
    case "AZURE_AFD":
      return (context.azureAppGwAuthMode ||
        context.azureAgcAzureAuthMode ||
        context.azureAfdAuthMode) === "SERVICE_PRINCIPAL"
        ? {
            clientId: "azure-client-id",
            clientSecret: "azure-client-secret",
          }
        : {};
    case "GCP_CERT_MANAGER":
    case "GCP_ALB":
    case "GCP_PROXY_NLB":
    case "GCP_API_GW":
    case "GCP_CLOUD_CDN":
      return context.gcpAuthMode === "SERVICE_ACCOUNT_KEY"
        ? {
            serviceAccountKeyJson: {
              type: "service_account",
              project_id: "my-project",
              private_key:
                "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
            },
          }
        : {};
    case "CLOUDFLARE_EDGE":
      return {
        apiToken: "cf-xxx",
      };
    case "KUBERNETES_SECRETS":
      switch (context.kubernetesAuthMethod || "SA_INCLUSTER") {
        case "SA_TOKEN":
          return {
            apiServer: "https://k8s-api.example.com",
            bearerToken: "eyJ...",
            caCertBase64: "LS0t...",
          };
        case "AWS":
          return {
            awsRegion: "us-east-1",
          };
        case "AZURE":
          return {
            azureTenantId: "11111111-1111-1111-1111-111111111111",
            azureSubscriptionId: "22222222-2222-2222-2222-222222222222",
            azureResourceGroup: "rg-prod",
          };
        case "GCP":
          return {
            gcpProjectId: "my-project",
            gcpLocation: "us-central1",
          };
        case "SA_INCLUSTER":
        default:
          return {};
      }
    case "AKAMAI_CPS":
      return {
        host: "akab-xxx.luna.akamaiapis.net",
        clientToken: "akab-ct-xxx",
        accessToken: "akab-at-xxx",
        clientSecret: "akamai-client-secret",
        enrollments: [
          {
            enrollmentId: "12345",
            contractId: "C-XXX",
            commonName: "example.com",
            domains: ["example.com", "www.example.com"],
            network: "production",
            certType: "third-party",
          },
        ],
      };
    case "F5_BIGIP":
      return {
        username: "admin",
        password: "f5-password",
      };
    default:
      return parseFallbackTemplate(context.fallbackTemplate);
  }
}

function getMissingDnsFields(provider: string, record: JsonRecord): string[] {
  switch (provider) {
    case "AWS_ROUTE53":
      return ["accessKeyId", "secretAccessKey"].filter(
        (field) => !hasNonBlankString(record, field),
      );
    case "CLOUDFLARE":
      return hasNonBlankString(record, "apiToken") ? [] : ["apiToken"];
    case "CERTPING":
      // apiUrl is optional: the agent defaults it to the CertPing token API.
      return hasNonBlankString(record, "apiKey") ? [] : ["apiKey"];
    case "GODADDY":
      return ["apiKey", "apiSecret"].filter(
        (field) => !hasNonBlankString(record, field),
      );
    case "NAMEDOTCOM":
      return ["username", "apiToken"].filter(
        (field) => !hasNonBlankString(record, field),
      );
    case "HOSTINGER":
      return hasNonBlankString(record, "apiToken") ? [] : ["apiToken"];
    case "NAMECHEAP":
      return ["apiUser", "username", "apiKey"].filter(
        (field) => !hasNonBlankString(record, field),
      );
    default:
      return [];
  }
}

function getMissingDeploymentFields(
  context: ManagedCredentialFormContext,
  record: JsonRecord,
): string[] {
  const provider = (context.providerApiValue || "").trim().toUpperCase();

  switch (provider) {
    case "AZURE_KV": {
      const missing: string[] = [];
      if (!hasNonBlankString(record, "tenantId")) {
        missing.push("tenantId");
      }
      const allowedVaults = Array.isArray(record.allowedVaults)
        ? record.allowedVaults
        : [];
      const hasAllowedVault = allowedVaults.some(
        (item) => typeof item === "string" && item.trim().length > 0,
      );
      if (!hasNonBlankString(record, "vaultUri") && !hasAllowedVault) {
        missing.push("vaultUri or allowedVaults[0]");
      }
      return missing;
    }
    case "CLOUDFLARE_EDGE":
      return hasNonBlankString(record, "apiToken") ? [] : ["apiToken"];
    case "KUBERNETES_SECRETS": {
      switch (context.kubernetesAuthMethod || "SA_INCLUSTER") {
        case "SA_TOKEN": {
          const missing: string[] = [];
          if (!hasNonBlankString(record, "apiServer")) {
            missing.push("apiServer");
          }
          if (
            !hasNonBlankString(record, "bearerToken") &&
            !hasNonBlankString(record, "serviceAccountToken")
          ) {
            missing.push("bearerToken or serviceAccountToken");
          }
          if (
            !hasNonBlankString(record, "caCertPem") &&
            !hasNonBlankString(record, "caCertBase64")
          ) {
            missing.push("caCertPem or caCertBase64");
          }
          return missing;
        }
        case "AWS":
          return hasNonBlankString(record, "awsRegion") ? [] : ["awsRegion"];
        case "AZURE":
          return [
            "azureTenantId",
            "azureSubscriptionId",
            "azureResourceGroup",
          ].filter((field) => !hasNonBlankString(record, field));
        case "GCP":
          return ["gcpProjectId", "gcpLocation"].filter(
            (field) => !hasNonBlankString(record, field),
          );
        case "SA_INCLUSTER":
        default:
          return [];
      }
    }
    case "AKAMAI_CPS": {
      const missing = [
        "host",
        "clientToken",
        "accessToken",
        "clientSecret",
      ].filter((field) => !hasNonBlankString(record, field));
      const enrollments = Array.isArray(record.enrollments)
        ? record.enrollments
        : [];

      if (enrollments.length === 0) {
        missing.push("enrollments");
        return missing;
      }

      const firstEnrollment = enrollments[0];
      const parsedEnrollment = jsonRecordSchema.safeParse(firstEnrollment);
      if (!parsedEnrollment.success) {
        missing.push("enrollments[0]");
        return missing;
      }
      const enrollment = parsedEnrollment.data;

      const enrollmentFields = [
        "enrollmentId",
        "contractId",
        "commonName",
        "network",
        "certType",
      ].filter((field) => !hasNonBlankString(enrollment, field));
      const domains = Array.isArray(enrollment.domains)
        ? enrollment.domains
        : [];
      if (
        !domains.some(
          (item) => typeof item === "string" && item.trim().length > 0,
        )
      ) {
        enrollmentFields.push("domains");
      }

      return missing.concat(
        enrollmentFields.map((field) => `enrollments[0].${field}`),
      );
    }
    case "F5_BIGIP":
      return ["username", "password"].filter(
        (field) => !hasNonBlankString(record, field),
      );
    default:
      return [];
  }
}

function requiresCredentialJsonOnCreate(
  context: ManagedCredentialFormContext,
): boolean {
  const provider = (context.providerApiValue || "").trim().toUpperCase();
  if (context.type === "DNS") {
    return getMissingDnsFields(provider, {}).length > 0;
  }
  return getMissingDeploymentFields(context, {}).length > 0;
}

export function getManagedCredentialJsonTemplate(
  context: ManagedCredentialFormContext,
): string {
  const provider = (context.providerApiValue || "").trim().toUpperCase();
  const template =
    context.type === "DNS"
      ? getDnsTemplate(provider, context.fallbackTemplate)
      : getDeploymentTemplate(context);

  return formatJson(template);
}

export function parseManagedCredentialJson(params: {
  input?: string | null;
  context: ManagedCredentialFormContext;
  mode: "create" | "edit";
}): JsonRecord | undefined {
  const trimmed = (params.input || "").trim();
  const provider = (params.context.providerApiValue || "").trim().toUpperCase();

  if (!trimmed) {
    if (params.mode === "edit") {
      return undefined;
    }
    if (requiresCredentialJsonOnCreate(params.context)) {
      throw new Error("Credential details are required.");
    }
    return {};
  }

  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(trimmed);
  } catch {
    throw new Error("Credential JSON must be valid JSON.");
  }

  const parsed = jsonRecordSchema.safeParse(parsedJson);
  if (!parsed.success) {
    throw new Error("Credential JSON must be a JSON object.");
  }

  const missing =
    params.context.type === "DNS"
      ? getMissingDnsFields(provider, parsed.data)
      : getMissingDeploymentFields(params.context, parsed.data);

  if (missing.length > 0) {
    throw new Error(`Credential JSON is missing: ${missing.join(", ")}.`);
  }

  return parsed.data;
}

export const MANAGED_CREDENTIAL_FIELD_DEFAULTS = {
  secretDnsAwsAccessKeyId: "",
  secretDnsAwsSecretAccessKey: "",
  secretDnsCloudflareApiToken: "",
  secretDnsCloudflareZoneId: "",
  secretDnsCertPingApiKey: "",
  secretDnsGodaddyApiKey: "",
  secretDnsGodaddyApiSecret: "",
  secretDnsNamecomUsername: "",
  secretDnsNamecomApiToken: "",
  secretDnsHostingerApiToken: "",
  secretDnsNamecheapApiToken: "",
  secretDnsNamecheapApiUser: "",
  secretDnsNamecheapUserName: "",
  secretAwsAccessKeyId: "",
  secretAwsSecretAccessKey: "",
  secretAzureClientId: "",
  secretAzureClientSecret: "",
  secretGcpServiceAccountKeyJson: "",
  secretCloudflareApiToken: "",
  secretK8sApiServer: "",
  secretK8sBearerToken: "",
  secretK8sServiceAccountToken: "",
  secretK8sCaCertPem: "",
  secretK8sCaCertBase64: "",
  secretK8sAwsRegion: "",
  secretK8sAzureTenantId: "",
  secretK8sAzureSubscriptionId: "",
  secretK8sAzureResourceGroup: "",
  secretK8sAzureClientId: "",
  secretK8sAzureClientSecret: "",
  secretK8sGcpProjectId: "",
  secretK8sGcpLocation: "",
  secretK8sGcpServiceAccountKeyJson: "",
  secretAkamaiClientToken: "",
  secretAkamaiAccessToken: "",
  secretAkamaiClientSecret: "",
  secretAkamaiContractId: "",
  secretAkamaiCommonName: "",
  secretAkamaiDomains: [] as string[],
  secretAkamaiNetwork: "",
  secretAkamaiCertType: "",
  secretF5Username: "",
  secretF5Password: "",
} satisfies Partial<CredentialFormValidationValues>;

export class CredentialFieldError extends Error {
  readonly field: keyof CredentialFormValidationValues;

  constructor(field: keyof CredentialFormValidationValues, message: string) {
    super(message);
    this.name = "CredentialFieldError";
    this.field = field;
  }
}

function trimValue(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function trimStringList(value: unknown): string[] {
  return Array.isArray(value)
    ? value
        .map((item) => (typeof item === "string" ? item.trim() : ""))
        .filter((item) => item.length > 0)
    : [];
}

function throwFieldError(
  field: keyof CredentialFormValidationValues,
  message: string,
): never {
  throw new CredentialFieldError(field, message);
}

function requireTrimmedString(
  values: CredentialFormValidationValues,
  field: keyof CredentialFormValidationValues,
  label: string,
): string {
  const value = trimValue(values[field]);
  if (!value) {
    throwFieldError(field, `${label} is required.`);
  }
  return value;
}

function parseServiceAccountKeyJson(
  field: keyof CredentialFormValidationValues,
  value: string,
): JsonRecord {
  let parsedJson: unknown;

  try {
    parsedJson = JSON.parse(value);
  } catch {
    throwFieldError(field, "Service account key JSON must be valid JSON.");
  }

  const parsed = jsonRecordSchema.safeParse(parsedJson);
  if (!parsed.success) {
    throwFieldError(field, "Service account key JSON must be a JSON object.");
  }

  return parsed.data;
}

function requireKubernetesApiServer(
  values: CredentialFormValidationValues,
): string {
  const apiServer = requireTrimmedString(
    values,
    "secretK8sApiServer",
    "API server URL",
  );
  let url: URL;
  try {
    url = new URL(apiServer);
  } catch {
    throwFieldError(
      "secretK8sApiServer",
      "API server URL must be a full URL, for example https://10.0.0.1:6443.",
    );
  }
  if (url.protocol !== "https:") {
    throwFieldError(
      "secretK8sApiServer",
      "API server URL must start with https://.",
    );
  }
  return apiServer;
}

const PEM_CERTIFICATE_MARKER = "-----BEGIN CERTIFICATE-----";

/**
 * The agent always verifies the API server against this CA (there is no skip TLS option), so it
 * is required. Accepts a PEM, or the base64 certificate-authority-data value from a kubeconfig.
 */
function readKubernetesCaCertificate(
  values: CredentialFormValidationValues,
): { caCertPem: string } | { caCertBase64: string } {
  const value = trimValue(values.secretK8sCaCertPem);
  if (!value) {
    throwFieldError(
      "secretK8sCaCertPem",
      "Cluster CA certificate is required. CertPing always verifies the API server certificate.",
    );
  }
  if (value.includes(PEM_CERTIFICATE_MARKER)) {
    return { caCertPem: value };
  }
  const compact = value.replace(/\s+/g, "");
  let decoded = "";
  try {
    decoded = atob(compact);
  } catch {
    decoded = "";
  }
  if (!decoded.includes(PEM_CERTIFICATE_MARKER)) {
    throwFieldError(
      "secretK8sCaCertPem",
      "Cluster CA certificate must be a PEM certificate or the base64 certificate-authority-data from your kubeconfig.",
    );
  }
  return { caCertBase64: compact };
}

function hasAnyManagedCredentialValue(
  values: CredentialFormValidationValues,
  fields: Array<keyof CredentialFormValidationValues>,
): boolean {
  return fields.some((field) => {
    const value = values[field];
    return Array.isArray(value)
      ? trimStringList(value).length > 0
      : trimValue(value).length > 0;
  });
}

function buildDnsCredentialJson(
  values: CredentialFormValidationValues,
  provider: string,
  mode?: "create" | "edit",
): JsonRecord | undefined {
  switch (provider) {
    case "AWS_ROUTE53":
      return {
        accessKeyId: requireTrimmedString(
          values,
          "secretDnsAwsAccessKeyId",
          "AWS access key ID",
        ),
        secretAccessKey: requireTrimmedString(
          values,
          "secretDnsAwsSecretAccessKey",
          "AWS secret access key",
        ),
      };
    case "CLOUDFLARE":
      return {
        apiToken: requireTrimmedString(
          values,
          "secretDnsCloudflareApiToken",
          "Cloudflare API token",
        ),
        ...(trimValue(values.secretDnsCloudflareZoneId)
          ? { zoneId: trimValue(values.secretDnsCloudflareZoneId) }
          : {}),
      };
    case "CERTPING":
      return {
        apiKey: requireTrimmedString(
          values,
          "secretDnsCertPingApiKey",
          "CertPing DNS API token",
        ),
      };
    case "GODADDY":
      return {
        apiKey: requireTrimmedString(
          values,
          "secretDnsGodaddyApiKey",
          "API key",
        ),
        apiSecret: requireTrimmedString(
          values,
          "secretDnsGodaddyApiSecret",
          "API secret",
        ),
      };
    case "NAMEDOTCOM":
      return {
        username: requireTrimmedString(
          values,
          "secretDnsNamecomUsername",
          "Username",
        ),
        apiToken: requireTrimmedString(
          values,
          "secretDnsNamecomApiToken",
          "API token",
        ),
      };
    case "HOSTINGER":
      return {
        apiToken: requireTrimmedString(
          values,
          "secretDnsHostingerApiToken",
          "Hostinger API token",
        ),
      };
    case "NAMECHEAP": {
      const hasNamecheapValues = hasAnyManagedCredentialValue(values, [
        "secretDnsNamecheapApiUser",
        "secretDnsNamecheapUserName",
        "secretDnsNamecheapApiToken",
      ]);
      if (mode === "edit" && !hasNamecheapValues) {
        return undefined;
      }
      if (usesManagedStorage(values)) {
        return {
          apiUser: requireTrimmedString(
            values,
            "secretDnsNamecheapApiUser",
            "Namecheap API user",
          ),
          username: requireTrimmedString(
            values,
            "secretDnsNamecheapUserName",
            "Namecheap username",
          ),
          apiKey: requireTrimmedString(
            values,
            "secretDnsNamecheapApiToken",
            "Namecheap API key",
          ),
        };
      } else {
        return {
          apiUser: requireTrimmedString(
            values,
            "secretDnsNamecheapApiUser",
            "Namecheap API user",
          ),
          username: requireTrimmedString(
            values,
            "secretDnsNamecheapUserName",
            "Namecheap username",
          ),
        };
      }
    }
    default:
      return {};
  }
}

function buildDeploymentCredentialJson(params: {
  values: CredentialFormValidationValues;
  context: ManagedCredentialFormContext;
  mode: "create" | "edit";
}): JsonRecord | undefined {
  const { values, context, mode } = params;
  const provider = (context.providerApiValue || "").trim().toUpperCase();

  switch (provider) {
    case "AWS_ACM":
    case "AWS_ALB":
    case "AWS_NLB":
    case "AWS_API_GW_REST":
    case "AWS_API_GW_HTTP":
    case "AWS_CLOUDFRONT": {
      const hasStaticKeys = hasAnyManagedCredentialValue(values, [
        "secretAwsAccessKeyId",
        "secretAwsSecretAccessKey",
      ]);
      if (!hasStaticKeys && mode === "edit") {
        return undefined;
      }
      if (!hasStaticKeys && mode === "create") {
        throwFieldError(
          "secretAwsAccessKeyId",
          "AWS access key ID is required for this authentication method.",
        );
      }
      if (!hasStaticKeys) {
        return {};
      }
      return {
        accessKeyId: requireTrimmedString(
          values,
          "secretAwsAccessKeyId",
          "AWS access key ID",
        ),
        secretAccessKey: requireTrimmedString(
          values,
          "secretAwsSecretAccessKey",
          "AWS secret access key",
        ),
      };
    }
    case "AZURE_KV": {
      const hasSpCreds = hasAnyManagedCredentialValue(values, [
        "secretAzureClientId",
        "secretAzureClientSecret",
      ]);
      if (
        context.azureKvAuthMode === "SERVICE_PRINCIPAL" &&
        !hasSpCreds &&
        mode === "create"
      ) {
        throwFieldError(
          "secretAzureClientId",
          "Client ID is required for Azure service principal authentication.",
        );
      }
      if (mode === "edit" && !hasSpCreds) {
        return undefined;
      }
      return {
        tenantId: requireTrimmedString(values, "azureKvTenantId", "Tenant ID"),
        vaultUri: requireTrimmedString(values, "azureKvVaultUri", "Vault URI"),
        ...(hasSpCreds
          ? {
              clientId: requireTrimmedString(
                values,
                "secretAzureClientId",
                "Client ID",
              ),
              clientSecret: requireTrimmedString(
                values,
                "secretAzureClientSecret",
                "Client secret",
              ),
            }
          : {}),
      };
    }
    case "AZURE_APP_GW": {
      const hasSecret = hasAnyManagedCredentialValue(values, [
        "secretAzureClientSecret",
      ]);
      if (
        context.azureAppGwAuthMode === "SERVICE_PRINCIPAL" &&
        !hasSecret &&
        mode === "create"
      ) {
        throwFieldError(
          "secretAzureClientSecret",
          "Client secret is required for Azure service principal authentication.",
        );
      }
      if (mode === "edit" && !hasSecret) {
        return undefined;
      }
      return hasSecret
        ? {
            clientId: requireTrimmedString(
              values,
              "azureAppGwClientId",
              "Client ID",
            ),
            clientSecret: requireTrimmedString(
              values,
              "secretAzureClientSecret",
              "Client secret",
            ),
          }
        : {};
    }
    case "AZURE_APP_GW_CONTAINERS": {
      const hasSecret = hasAnyManagedCredentialValue(values, [
        "secretAzureClientSecret",
      ]);
      if (
        context.azureAgcAzureAuthMode === "SERVICE_PRINCIPAL" &&
        !hasSecret &&
        mode === "create"
      ) {
        throwFieldError(
          "secretAzureClientSecret",
          "Client secret is required for Azure service principal authentication.",
        );
      }
      if (mode === "edit" && !hasSecret) {
        return undefined;
      }
      return hasSecret
        ? {
            clientId: requireTrimmedString(
              values,
              "azureAgcClientId",
              "Client ID",
            ),
            clientSecret: requireTrimmedString(
              values,
              "secretAzureClientSecret",
              "Client secret",
            ),
          }
        : {};
    }
    case "AZURE_AFD": {
      const hasSecret = hasAnyManagedCredentialValue(values, [
        "secretAzureClientSecret",
      ]);
      if (
        context.azureAfdAuthMode === "SERVICE_PRINCIPAL" &&
        !hasSecret &&
        mode === "create"
      ) {
        throwFieldError(
          "secretAzureClientSecret",
          "Client secret is required for Azure service principal authentication.",
        );
      }
      if (mode === "edit" && !hasSecret) {
        return undefined;
      }
      return hasSecret
        ? {
            clientId: requireTrimmedString(
              values,
              "azureAfdClientId",
              "Client ID",
            ),
            clientSecret: requireTrimmedString(
              values,
              "secretAzureClientSecret",
              "Client secret",
            ),
          }
        : {};
    }
    case "GCP_CERT_MANAGER":
    case "GCP_ALB":
    case "GCP_PROXY_NLB":
    case "GCP_API_GW":
    case "GCP_CLOUD_CDN": {
      const keyJson = trimValue(values.secretGcpServiceAccountKeyJson);
      if (
        context.gcpAuthMode === "SERVICE_ACCOUNT_KEY" &&
        !keyJson &&
        mode === "create"
      ) {
        throwFieldError(
          "secretGcpServiceAccountKeyJson",
          "Service account key JSON is required for this authentication method.",
        );
      }
      if (!keyJson) {
        return mode === "edit" ? undefined : {};
      }
      return {
        serviceAccountKeyJson: parseServiceAccountKeyJson(
          "secretGcpServiceAccountKeyJson",
          keyJson,
        ),
      };
    }
    case "CLOUDFLARE_EDGE":
      return {
        apiToken: requireTrimmedString(
          values,
          "secretCloudflareApiToken",
          "Cloudflare API token",
        ),
      };
    case "KUBERNETES_SECRETS":
      switch (context.kubernetesAuthMethod || "SA_INCLUSTER") {
        case "SA_TOKEN": {
          const hasRotationValues = hasAnyManagedCredentialValue(values, [
            "secretK8sApiServer",
            "secretK8sBearerToken",
            "secretK8sCaCertPem",
          ]);
          if (mode === "edit" && !hasRotationValues) {
            return undefined;
          }
          const apiServer = requireKubernetesApiServer(values);
          const bearerToken = trimValue(values.secretK8sBearerToken);
          if (!bearerToken) {
            throwFieldError(
              "secretK8sBearerToken",
              "Service account token is required.",
            );
          }
          return {
            apiServer,
            bearerToken,
            ...readKubernetesCaCertificate(values),
          };
        }
        case "AWS": {
          const hasRotationValues = hasAnyManagedCredentialValue(values, [
            "secretK8sAwsRegion",
          ]);
          if (mode === "edit" && !hasRotationValues) {
            return undefined;
          }
          return {
            awsRegion: requireTrimmedString(
              values,
              "secretK8sAwsRegion",
              "AWS region",
            ),
          };
        }
        case "AZURE": {
          const hasRotationValues = hasAnyManagedCredentialValue(values, [
            "secretK8sAzureTenantId",
            "secretK8sAzureSubscriptionId",
            "secretK8sAzureResourceGroup",
            "secretK8sAzureClientId",
            "secretK8sAzureClientSecret",
          ]);
          if (mode === "edit" && !hasRotationValues) {
            return undefined;
          }
          return {
            azureTenantId: requireTrimmedString(
              values,
              "secretK8sAzureTenantId",
              "Tenant ID",
            ),
            azureSubscriptionId: requireTrimmedString(
              values,
              "secretK8sAzureSubscriptionId",
              "Subscription ID",
            ),
            azureResourceGroup: requireTrimmedString(
              values,
              "secretK8sAzureResourceGroup",
              "Resource group",
            ),
            azureClientId: requireTrimmedString(
              values,
              "secretK8sAzureClientId",
              "Client ID",
            ),
            azureClientSecret: requireTrimmedString(
              values,
              "secretK8sAzureClientSecret",
              "Client secret",
            ),
          };
        }
        case "GCP": {
          const hasRotationValues = hasAnyManagedCredentialValue(values, [
            "secretK8sGcpProjectId",
            "secretK8sGcpLocation",
            "secretK8sGcpServiceAccountKeyJson",
          ]);
          if (mode === "edit" && !hasRotationValues) {
            return undefined;
          }
          return {
            gcpProjectId: requireTrimmedString(
              values,
              "secretK8sGcpProjectId",
              "Project ID",
            ),
            gcpLocation: requireTrimmedString(
              values,
              "secretK8sGcpLocation",
              "Location",
            ),
            ...(trimValue(values.secretK8sGcpServiceAccountKeyJson)
              ? {
                  gcpServiceAccountJson: parseServiceAccountKeyJson(
                    "secretK8sGcpServiceAccountKeyJson",
                    trimValue(values.secretK8sGcpServiceAccountKeyJson),
                  ),
                }
              : {}),
          };
        }
        case "SA_INCLUSTER":
        default:
          return mode === "edit" ? undefined : {};
      }
    case "AKAMAI_CPS": {
      const hasRotationValues = hasAnyManagedCredentialValue(values, [
        "secretAkamaiClientToken",
        "secretAkamaiAccessToken",
        "secretAkamaiClientSecret",
        "secretAkamaiContractId",
        "secretAkamaiCommonName",
        "secretAkamaiDomains",
        "secretAkamaiNetwork",
        "secretAkamaiCertType",
      ]);
      if (mode === "edit" && !hasRotationValues) {
        return undefined;
      }
      return {
        host: requireTrimmedString(values, "akamaiHost", "Host"),
        clientToken: requireTrimmedString(
          values,
          "secretAkamaiClientToken",
          "Client token",
        ),
        accessToken: requireTrimmedString(
          values,
          "secretAkamaiAccessToken",
          "Access token",
        ),
        clientSecret: requireTrimmedString(
          values,
          "secretAkamaiClientSecret",
          "Client secret",
        ),
        enrollments: [
          {
            enrollmentId: requireTrimmedString(
              values,
              "akamaiEnrollmentId",
              "Enrollment ID",
            ),
            contractId: requireTrimmedString(
              values,
              "secretAkamaiContractId",
              "Contract ID",
            ),
            commonName: requireTrimmedString(
              values,
              "secretAkamaiCommonName",
              "Common name",
            ),
            domains: (() => {
              const domains = trimStringList(values.secretAkamaiDomains);
              if (domains.length === 0) {
                throwFieldError(
                  "secretAkamaiDomains",
                  "At least one Akamai domain is required.",
                );
              }
              return domains;
            })(),
            network: requireTrimmedString(
              values,
              "secretAkamaiNetwork",
              "Network",
            ),
            certType: requireTrimmedString(
              values,
              "secretAkamaiCertType",
              "Certificate type",
            ),
          },
        ],
      };
    }
    case "F5_BIGIP": {
      const hasRotationValues = hasAnyManagedCredentialValue(values, [
        "secretF5Username",
        "secretF5Password",
      ]);
      if (mode === "edit" && !hasRotationValues) {
        return undefined;
      }
      return {
        username: requireTrimmedString(values, "secretF5Username", "Username"),
        password: requireTrimmedString(values, "secretF5Password", "Password"),
      };
    }
    default:
      return {};
  }
}

export function buildManagedCredentialJsonFromValues(params: {
  values: CredentialFormValidationValues;
  context: ManagedCredentialFormContext;
  mode: "create" | "edit";
}): JsonRecord | undefined {
  const provider = (params.context.providerApiValue || "").trim().toUpperCase();

  if (params.context.type === "DNS") {
    return buildDnsCredentialJson(params.values, provider, params.mode);
  }

  return buildDeploymentCredentialJson(params);
}
