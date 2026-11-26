// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  buildManagedCredentialJsonFromValues,
  CredentialFieldError,
  getManagedCredentialJsonTemplate,
  MANAGED_CREDENTIAL_FIELD_DEFAULTS,
  parseManagedCredentialJson,
} from "@/lib/cert-manager/managed-credential-json";
import type { CredentialFormValidationValues } from "@/lib/cert-manager/credential-form-schemas/types";

/**
 * These functions produce the credential JSON that is handed to the agent and
 * then to a cloud provider. A wrong or missing key here does not fail loudly
 * in the UI - it fails later, during a deployment, as an opaque provider
 * error. So the field names are asserted literally rather than snapshotted.
 */
function values(
  overrides: Partial<CredentialFormValidationValues> = {},
): CredentialFormValidationValues {
  return {
    ...MANAGED_CREDENTIAL_FIELD_DEFAULTS,
    ...overrides,
  } as CredentialFormValidationValues;
}

const dnsContext = (providerApiValue: string) =>
  ({ type: "DNS", providerApiValue }) as const;

describe("getManagedCredentialJsonTemplate", () => {
  it.each([
    ["AWS_ROUTE53", ["accessKeyId", "secretAccessKey"]],
    ["CLOUDFLARE", ["apiToken"]],
    ["CERTPING", ["apiKey"]],
    ["GODADDY", ["apiKey", "apiSecret"]],
    ["NAMEDOTCOM", ["username", "apiToken"]],
    ["HOSTINGER", ["apiToken"]],
    ["NAMECHEAP", ["apiUser", "username"]],
  ])("offers %s the keys its API expects", (provider, keys) => {
    const template = JSON.parse(
      getManagedCredentialJsonTemplate(dnsContext(provider)),
    );
    for (const key of keys) {
      expect(template).toHaveProperty(key);
    }
  });

  it("is pretty-printed, because a human edits it", () => {
    expect(
      getManagedCredentialJsonTemplate(dnsContext("CLOUDFLARE")),
    ).toContain("\n  ");
  });

  it("matches the provider case-insensitively and ignores stray whitespace", () => {
    const template = JSON.parse(
      getManagedCredentialJsonTemplate({
        type: "DNS",
        providerApiValue: "  cloudflare  ",
      }),
    );
    expect(template).toHaveProperty("apiToken");
  });

  it("falls back to the server-supplied template for an unknown provider", () => {
    const template = JSON.parse(
      getManagedCredentialJsonTemplate({
        type: "DNS",
        providerApiValue: "SOME_NEW_DNS",
        fallbackTemplate: '{"customToken":"..."}',
      }),
    );
    expect(template).toEqual({ customToken: "..." });
  });

  it("degrades to an empty object when the fallback template is unusable", () => {
    // A malformed template from the backend must not blank the form with a
    // parse exception.
    for (const fallbackTemplate of ["not json", "[1,2,3]", null]) {
      expect(
        JSON.parse(
          getManagedCredentialJsonTemplate({
            type: "DNS",
            providerApiValue: "SOME_NEW_DNS",
            fallbackTemplate,
          }),
        ),
      ).toEqual({});
    }
  });
});

describe("parseManagedCredentialJson", () => {
  it("treats an empty box on edit as 'leave the stored secret alone'", () => {
    // Returning `{}` here would wipe a working credential.
    expect(
      parseManagedCredentialJson({
        input: "   ",
        context: dnsContext("CLOUDFLARE"),
        mode: "edit",
      }),
    ).toBeUndefined();
  });

  it("refuses an empty box on create for a provider that needs secrets", () => {
    expect(() =>
      parseManagedCredentialJson({
        input: "",
        context: dnsContext("CLOUDFLARE"),
        mode: "create",
      }),
    ).toThrow("Credential details are required.");
  });

  it("accepts an empty box on create when the provider needs nothing", () => {
    expect(
      parseManagedCredentialJson({
        input: "",
        context: dnsContext("SOME_NEW_DNS"),
        mode: "create",
      }),
    ).toEqual({});
  });

  it("names the problem when the text is not JSON", () => {
    expect(() =>
      parseManagedCredentialJson({
        input: "{apiToken: nope}",
        context: dnsContext("CLOUDFLARE"),
        mode: "create",
      }),
    ).toThrow("Credential JSON must be valid JSON.");
  });

  it("rejects valid JSON that is not an object", () => {
    for (const input of ["[1,2,3]", '"a string"', "42"]) {
      expect(() =>
        parseManagedCredentialJson({
          input,
          context: dnsContext("CLOUDFLARE"),
          mode: "create",
        }),
      ).toThrow("Credential JSON must be a JSON object.");
    }
  });

  it("lists every missing field at once rather than one per attempt", () => {
    expect(() =>
      parseManagedCredentialJson({
        input: "{}",
        context: dnsContext("NAMECHEAP"),
        mode: "create",
      }),
    ).toThrow("Credential JSON is missing: apiUser, username, apiKey.");
  });

  it("counts a blank string as missing, not as provided", () => {
    expect(() =>
      parseManagedCredentialJson({
        input: '{"apiToken":"   "}',
        context: dnsContext("CLOUDFLARE"),
        mode: "create",
      }),
    ).toThrow("Credential JSON is missing: apiToken.");
  });

  it("returns the parsed object once every required field is present", () => {
    expect(
      parseManagedCredentialJson({
        input: '{"accessKeyId":"AKIA1","secretAccessKey":"s3cret"}',
        context: dnsContext("AWS_ROUTE53"),
        mode: "create",
      }),
    ).toEqual({ accessKeyId: "AKIA1", secretAccessKey: "s3cret" });
  });

  it("leaves PowerDNS apiUrl optional - the agent defaults it", () => {
    expect(
      parseManagedCredentialJson({
        input: '{"apiKey":"cpk_live_1"}',
        context: dnsContext("CERTPING"),
        mode: "create",
      }),
    ).toEqual({ apiKey: "cpk_live_1" });
  });
});

describe("buildManagedCredentialJsonFromValues - DNS providers", () => {
  it.each([
    [
      "AWS_ROUTE53",
      { secretDnsAwsAccessKeyId: "AKIA1", secretDnsAwsSecretAccessKey: "s1" },
      { accessKeyId: "AKIA1", secretAccessKey: "s1" },
    ],
    [
      "CLOUDFLARE",
      { secretDnsCloudflareApiToken: "cf-1" },
      { apiToken: "cf-1" },
    ],
    ["CERTPING", { secretDnsCertPingApiKey: "cpk-1" }, { apiKey: "cpk-1" }],
    [
      "GODADDY",
      { secretDnsGodaddyApiKey: "k", secretDnsGodaddyApiSecret: "s" },
      { apiKey: "k", apiSecret: "s" },
    ],
    [
      "NAMEDOTCOM",
      { secretDnsNamecomUsername: "u", secretDnsNamecomApiToken: "t" },
      { username: "u", apiToken: "t" },
    ],
    ["HOSTINGER", { secretDnsHostingerApiToken: "h-1" }, { apiToken: "h-1" }],
  ])(
    "maps %s form fields onto the provider's own key names",
    (provider, formValues, expected) => {
      expect(
        buildManagedCredentialJsonFromValues({
          values: values(formValues as Partial<CredentialFormValidationValues>),
          context: dnsContext(provider),
          mode: "create",
        }),
      ).toEqual(expected);
    },
  );

  it("trims what the operator pasted", () => {
    expect(
      buildManagedCredentialJsonFromValues({
        values: values({ secretDnsCloudflareApiToken: "  cf-1  " }),
        context: dnsContext("CLOUDFLARE"),
        mode: "create",
      }),
    ).toEqual({ apiToken: "cf-1" });
  });

  it("raises a field-targeted error so the form can highlight the input", () => {
    try {
      buildManagedCredentialJsonFromValues({
        values: values(),
        context: dnsContext("CLOUDFLARE"),
        mode: "create",
      });
      throw new Error("expected a CredentialFieldError");
    } catch (error) {
      expect(error).toBeInstanceOf(CredentialFieldError);
      expect((error as CredentialFieldError).field).toBe(
        "secretDnsCloudflareApiToken",
      );
    }
  });

  it("sends no Namecheap API key when the key stays in the person's vault", () => {
    // A vault-backed credential keeps the key in the secret store; only a
    // credential stored in CertPing collects it in the form.
    expect(
      buildManagedCredentialJsonFromValues({
        values: values({
          secretDnsNamecheapApiUser: "u",
          secretDnsNamecheapUserName: "n",
          secretDnsNamecheapApiToken: "t",
        }),
        context: dnsContext("NAMECHEAP"),
        mode: "create",
      }),
    ).toEqual({ apiUser: "u", username: "n" });
  });

  it("sends the Namecheap API key for a credential stored in CertPing", () => {
    expect(
      buildManagedCredentialJsonFromValues({
        values: values({
          credentialStorage: "managed",
          secretDnsNamecheapApiUser: "u",
          secretDnsNamecheapUserName: "n",
          secretDnsNamecheapApiToken: "t",
        }),
        context: dnsContext("NAMECHEAP"),
        mode: "create",
      }),
    ).toEqual({ apiUser: "u", username: "n", apiKey: "t" });
  });

  it("leaves an untouched Namecheap credential alone on edit", () => {
    expect(
      buildManagedCredentialJsonFromValues({
        values: values(),
        context: dnsContext("NAMECHEAP"),
        mode: "edit",
      }),
    ).toBeUndefined();
  });

  it("produces nothing for a provider it does not model", () => {
    expect(
      buildManagedCredentialJsonFromValues({
        values: values(),
        context: dnsContext("SOME_NEW_DNS"),
        mode: "create",
      }),
    ).toEqual({});
  });
});

describe("buildManagedCredentialJsonFromValues - deployment targets", () => {
  const awsContext = {
    type: "DEPLOYMENT",
    providerApiValue: "AWS_ACM",
  } as const;

  it("emits static AWS keys when the operator supplied them", () => {
    expect(
      buildManagedCredentialJsonFromValues({
        values: values({
          secretAwsAccessKeyId: "AKIA1",
          secretAwsSecretAccessKey: "s1",
        }),
        context: awsContext,
        mode: "create",
      }),
    ).toEqual({ accessKeyId: "AKIA1", secretAccessKey: "s1" });
  });

  it("keeps a role-based AWS credential untouched on edit", () => {
    // No keys typed means "keep whatever is stored", not "clear it".
    expect(
      buildManagedCredentialJsonFromValues({
        values: values(),
        context: awsContext,
        mode: "edit",
      }),
    ).toBeUndefined();
  });

  it("refuses to create an AWS credential with no key at all", () => {
    expect(() =>
      buildManagedCredentialJsonFromValues({
        values: values(),
        context: awsContext,
        mode: "create",
      }),
    ).toThrow(/AWS access key ID is required/);
  });

  it("always sends Azure Key Vault's non-secret coordinates", () => {
    expect(
      buildManagedCredentialJsonFromValues({
        values: values({
          azureKvTenantId: "tenant-1",
          azureKvVaultUri: "https://kv.vault.azure.net/",
          secretAzureClientId: "client-1",
          secretAzureClientSecret: "secret-1",
        } as Partial<CredentialFormValidationValues>),
        context: {
          type: "DEPLOYMENT",
          providerApiValue: "AZURE_KV",
          azureKvAuthMode: "SERVICE_PRINCIPAL",
        },
        mode: "create",
      }),
    ).toEqual({
      tenantId: "tenant-1",
      vaultUri: "https://kv.vault.azure.net/",
      clientId: "client-1",
      clientSecret: "secret-1",
    });
  });

  it("requires a client id when Azure is set to service-principal auth", () => {
    expect(() =>
      buildManagedCredentialJsonFromValues({
        values: values({
          azureKvTenantId: "tenant-1",
          azureKvVaultUri: "https://kv.vault.azure.net/",
        } as Partial<CredentialFormValidationValues>),
        context: {
          type: "DEPLOYMENT",
          providerApiValue: "AZURE_KV",
          azureKvAuthMode: "SERVICE_PRINCIPAL",
        },
        mode: "create",
      }),
    ).toThrow(/Client ID is required/);
  });

  it("parses a GCP service account key rather than forwarding a string", () => {
    const keyJson = JSON.stringify({
      type: "service_account",
      project_id: "p",
    });
    const built = buildManagedCredentialJsonFromValues({
      values: values({ secretGcpServiceAccountKeyJson: keyJson }),
      context: {
        type: "DEPLOYMENT",
        providerApiValue: "GCP_CERT_MANAGER",
        gcpAuthMode: "SERVICE_ACCOUNT_KEY",
      },
      mode: "create",
    });
    expect(built?.serviceAccountKeyJson).toEqual({
      type: "service_account",
      project_id: "p",
    });
  });

  it("requires the GCP key when that is the chosen auth mode", () => {
    expect(() =>
      buildManagedCredentialJsonFromValues({
        values: values(),
        context: {
          type: "DEPLOYMENT",
          providerApiValue: "GCP_ALB",
          gcpAuthMode: "SERVICE_ACCOUNT_KEY",
        },
        mode: "create",
      }),
    ).toThrow(/Service account key JSON is required/);
  });

  it("sends nothing for GCP workload identity, which carries no secret", () => {
    expect(
      buildManagedCredentialJsonFromValues({
        values: values(),
        context: {
          type: "DEPLOYMENT",
          providerApiValue: "GCP_ALB",
          gcpAuthMode: "WORKLOAD_IDENTITY",
        },
        mode: "create",
      }),
    ).toEqual({});
  });

  it("accepts either Kubernetes token form, but insists on one", () => {
    const context = {
      type: "DEPLOYMENT",
      providerApiValue: "KUBERNETES_SECRETS",
      kubernetesAuthMethod: "SA_TOKEN",
    } as const;

    expect(
      buildManagedCredentialJsonFromValues({
        values: values({
          secretK8sApiServer: "https://k8s.local",
          secretK8sBearerToken: "bearer-1",
          secretK8sCaCertPem: "-----BEGIN CERTIFICATE-----",
        }),
        context,
        mode: "create",
      }),
    ).toMatchObject({
      apiServer: "https://k8s.local",
      bearerToken: "bearer-1",
    });

    expect(() =>
      buildManagedCredentialJsonFromValues({
        values: values({
          secretK8sApiServer: "https://k8s.local",
          secretK8sCaCertPem: "-----BEGIN CERTIFICATE-----",
        }),
        context,
        mode: "create",
      }),
    ).toThrow(/Service account token is required/);
  });

  it("insists on a Kubernetes CA certificate in one encoding or the other", () => {
    expect(() =>
      buildManagedCredentialJsonFromValues({
        values: values({
          secretK8sApiServer: "https://k8s.local",
          secretK8sBearerToken: "bearer-1",
        }),
        context: {
          type: "DEPLOYMENT",
          providerApiValue: "KUBERNETES_SECRETS",
          kubernetesAuthMethod: "SA_TOKEN",
        },
        mode: "create",
      }),
    ).toThrow(/Cluster CA certificate is required/);
  });

  it("sends the kubeconfig base64 CA as caCertBase64 and needs an https API server", () => {
    const context = {
      type: "DEPLOYMENT",
      providerApiValue: "KUBERNETES_SECRETS",
      kubernetesAuthMethod: "SA_TOKEN",
    } as const;
    const caBase64 = btoa(
      "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
    );

    expect(
      buildManagedCredentialJsonFromValues({
        values: values({
          secretK8sApiServer: "https://k3s:6443",
          secretK8sBearerToken: "sa-token",
          secretK8sCaCertPem: caBase64,
        }),
        context,
        mode: "create",
      }),
    ).toEqual({
      apiServer: "https://k3s:6443",
      bearerToken: "sa-token",
      caCertBase64: caBase64,
    });

    expect(() =>
      buildManagedCredentialJsonFromValues({
        values: values({
          secretK8sApiServer: "http://k3s:6443",
          secretK8sBearerToken: "sa-token",
          secretK8sCaCertPem: caBase64,
        }),
        context,
        mode: "create",
      }),
    ).toThrow(/must start with https/);
  });

  it("leaves an in-cluster Kubernetes credential empty - there is no secret", () => {
    expect(
      buildManagedCredentialJsonFromValues({
        values: values(),
        context: {
          type: "DEPLOYMENT",
          providerApiValue: "KUBERNETES_SECRETS",
          kubernetesAuthMethod: "SA_INCLUSTER",
        },
        mode: "create",
      }),
    ).toEqual({});
  });

  it("maps Cloudflare edge onto its own token key", () => {
    expect(
      buildManagedCredentialJsonFromValues({
        values: values({ secretCloudflareApiToken: "cf-edge" }),
        context: {
          type: "DEPLOYMENT",
          providerApiValue: "CLOUDFLARE_EDGE",
        },
        mode: "create",
      }),
    ).toEqual({ apiToken: "cf-edge" });
  });
});
