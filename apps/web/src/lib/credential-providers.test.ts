// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  CREDENTIAL_PROVIDER_CONFIG,
  formatProviderLabel,
  getCredentialProviderFromType,
  getCredentialReferenceProviderOptions,
  getCredentialTypeLabel,
  getProviderLogoByApiValue,
  getProviderPresentation,
  resolveCredentialProvider,
  resolveCredentialProviderFromApiValue,
  toIntegrationOptions,
  toIntegrationTypeOptions,
  tryGetCredentialProviderFromType,
} from "@/lib/credential-providers";
import type { CredentialTypeDefinition } from "@/types/ssl";

describe("credential-providers", () => {
  it("formats provider labels across known, option-mapped and fallback values", () => {
    expect(formatProviderLabel("aws_route53")).toBe("AWS Route 53");
    expect(formatProviderLabel("AZURE_KV")).toBe("Azure Key Vault");
    expect(formatProviderLabel("custom_provider_dns")).toBe(
      "Custom Provider DNS",
    );
    expect(formatProviderLabel(undefined)).toBe("Unknown");
  });

  it("returns provider options filtered by reference type", () => {
    const dnsOptions = getCredentialReferenceProviderOptions("DNS");
    const deploymentOptions =
      getCredentialReferenceProviderOptions("DEPLOYMENT");

    expect(dnsOptions.every((option) => option.type === "DNS")).toBe(true);
    expect(dnsOptions.map((option) => option.apiValue)).not.toContain(
      "AZURE_DNS",
    );
    expect(dnsOptions.map((option) => option.apiValue)).toContain("HOSTINGER");
    expect(dnsOptions.map((option) => option.apiValue)).toContain("NAMEDOTCOM");
    expect(
      deploymentOptions.every((option) => option.type === "DEPLOYMENT"),
    ).toBe(true);
    expect(
      deploymentOptions.some(
        (option) => option.apiValue === "AZURE_APP_GW_CONTAINERS",
      ),
    ).toBe(false);
  });

  it("documents the Cloudflare DNS secret payload with its optional zone ID", () => {
    const dnsOptions = getCredentialReferenceProviderOptions("DNS");
    const cloudflareDnsOption = dnsOptions.find(
      (option) => option.apiValue === "CLOUDFLARE",
    );

    expect(cloudflareDnsOption?.secretPayloadTemplate).toBe(
      '{"apiToken":"<cloudflare-api-token>","zoneId":"<optional-zone-id>"}',
    );
  });

  it("documents the Namecheap vault secret with the fields the agent reads", () => {
    const namecheap = getCredentialReferenceProviderOptions("DNS").find(
      (option) => option.apiValue === "NAMECHEAP",
    );

    // The agent's NamecheapDnsProvider needs apiUser, username and apiKey; the
    // client IP comes from the agent's NAMECHEAP_CLIENT_IP setting, not the secret.
    expect(
      Object.keys(JSON.parse(namecheap?.secretPayloadTemplate ?? "{}")).sort(),
    ).toEqual(["apiKey", "apiUser", "username"]);
  });

  it("resolves human-friendly credential type labels", () => {
    expect(getCredentialTypeLabel("aws_acm")).toBe("AWS Certificate Manager");
    expect(getCredentialTypeLabel("custom_type_name")).toBe("Custom Type Name");
    expect(getCredentialTypeLabel(undefined)).toBe("Unknown");
  });

  it("maps credential types to providers using aliases and prefixes", () => {
    expect(tryGetCredentialProviderFromType("azure_dns")).toBe("azure");
    expect(tryGetCredentialProviderFromType("cloudflare_api_token")).toBe(
      "cloudflare",
    );
    expect(tryGetCredentialProviderFromType("namecom_dns_credentials")).toBe(
      "namecom",
    );
    expect(tryGetCredentialProviderFromType("hostinger_dns")).toBe("hostinger");
    expect(tryGetCredentialProviderFromType("AKAMAI_CPS")).toBe("akamai");
    expect(tryGetCredentialProviderFromType("f5_bigip")).toBe("f5");
    expect(tryGetCredentialProviderFromType("aws_unknown")).toBe("aws");
    expect(
      tryGetCredentialProviderFromType("unknown_provider"),
    ).toBeUndefined();
  });

  it("falls back to aws when provider type cannot be inferred", () => {
    expect(getCredentialProviderFromType("invalid")).toBe("aws");
    expect(getCredentialProviderFromType(undefined)).toBe("aws");
  });

  it("resolves provider from records using provider fields and type fallback", () => {
    expect(
      resolveCredentialProvider({
        provider: "aws",
        providerName: undefined,
        credentialType: "aws_acm",
        typeName: "aws_acm",
      }),
    ).toBe("aws");

    expect(
      resolveCredentialProvider({
        provider: "azure",
        providerName: "azure",
        credentialType: "azure_dns",
        typeName: "azure_dns",
      }),
    ).toBe("azure");

    expect(
      resolveCredentialProvider({
        provider: undefined,
        providerName: undefined,
        credentialType: "cloudflare_api",
        typeName: undefined,
      }),
    ).toBe("cloudflare");
  });

  it("resolves provider by API value and returns logos/presentations", () => {
    expect(resolveCredentialProviderFromApiValue("AWS_ACM")).toBe("aws");
    expect(resolveCredentialProviderFromApiValue("HOSTINGER")).toBe(
      "hostinger",
    );
    expect(resolveCredentialProviderFromApiValue("NAMEDOTCOM")).toBe("namecom");
    expect(resolveCredentialProviderFromApiValue("AKAMAI_CPS")).toBe("akamai");
    expect(resolveCredentialProviderFromApiValue("F5_BIGIP")).toBe("f5");
    expect(resolveCredentialProviderFromApiValue("missing")).toBeUndefined();

    expect(getProviderLogoByApiValue("AZURE_KV")).toBe(
      CREDENTIAL_PROVIDER_CONFIG.azure.logo,
    );
    expect(getProviderLogoByApiValue("HOSTINGER")).toBe(
      CREDENTIAL_PROVIDER_CONFIG.hostinger.logo,
    );
    expect(getProviderLogoByApiValue("UNKNOWN")).toBeUndefined();
    expect(getProviderLogoByApiValue("AKAMAI_CPS")).toBe(
      CREDENTIAL_PROVIDER_CONFIG.akamai.logo,
    );
    expect(getProviderLogoByApiValue("F5_BIGIP")).toBe(
      CREDENTIAL_PROVIDER_CONFIG.f5.logo,
    );

    expect(getProviderPresentation("AWS_ACM")).toEqual({
      label: "AWS Certificate Manager",
      logo: CREDENTIAL_PROVIDER_CONFIG.aws.logo,
      providerKey: "aws",
    });
    expect(getProviderPresentation("cloudflare", "cloudflare")).toEqual({
      label: "Cloudflare",
      logo: CREDENTIAL_PROVIDER_CONFIG.cloudflare.logo,
      providerKey: "cloudflare",
    });
  });

  it("exposes credential reference options for newly supported deployment providers", () => {
    const deploymentOptions =
      getCredentialReferenceProviderOptions("DEPLOYMENT");
    const apiValues = deploymentOptions.map((option) => option.apiValue);

    expect(apiValues).toContain("AKAMAI_CPS");
    expect(apiValues).toContain("F5_BIGIP");
  });

  it("uses target-specific docs links for deployment credential options", () => {
    const deploymentOptions =
      getCredentialReferenceProviderOptions("DEPLOYMENT");
    const docsByApiValue = new Map(
      deploymentOptions.map((option) => [option.apiValue, option.docs]),
    );

    expect(docsByApiValue.get("AWS_ACM")).toContain("/acm/");
    expect(docsByApiValue.get("AWS_ALB")).toContain("/elasticloadbalancing/");
    expect(docsByApiValue.get("AWS_API_GW_REST")).toContain("/apigateway/");
    expect(docsByApiValue.get("AWS_CLOUDFRONT")).toContain(
      "/AmazonCloudFront/",
    );
    expect(docsByApiValue.get("AZURE_APP_GW")).toContain(
      "/azure/application-gateway/",
    );
    expect(docsByApiValue.get("AZURE_AFD")).toContain("/azure/frontdoor/");
    expect(docsByApiValue.get("KUBERNETES_SECRETS")).toContain(
      "kubernetes.io/docs/reference/access-authn-authz/rbac",
    );
    expect(docsByApiValue.get("CLOUDFLARE_EDGE")).toContain(
      "/ssl/edge-certificates/custom-certificates/",
    );
    expect(docsByApiValue.get("GCP_CERT_MANAGER")).toContain(
      "/certificate-manager/docs/maps",
    );
    expect(docsByApiValue.get("GCP_ALB")).toContain(
      "/load-balancing/docs/ssl-certificates/",
    );
  });

  it("builds integration provider options and keeps best-priority type per provider", () => {
    const credentialTypes: CredentialTypeDefinition[] = [
      {
        providerName: "aws_route53",
        providerDisplayName: "AWS",
        typeName: "aws_route53",
        category: "DNS",
        description: "Route53",
      },
      {
        providerName: "aws_acm",
        providerDisplayName: "AWS",
        typeName: "aws_acm",
        category: "DEPLOYMENT",
        description: "ACM",
      },
      {
        providerName: "azure_dns",
        providerDisplayName: "Azure",
        typeName: "azure_dns",
        category: "DNS",
        description: "Azure DNS",
      },
      {
        providerName: "unsupported",
        providerDisplayName: "Unsupported",
        typeName: "unknown",
        category: "DNS",
        description: "Ignored",
      },
    ];

    const options = toIntegrationOptions(credentialTypes);

    expect(options).toHaveLength(2);
    const aws = options.find((option) => option.value === "aws");
    expect(aws?.credentialType).toBe("aws_acm");
    expect(aws?.label).toBe("AWS Certificate Manager");
    const azure = options.find((option) => option.value === "azure");
    expect(azure?.credentialType).toBe("azure_dns");
  });

  it("builds sorted unique integration type options", () => {
    const credentialTypes: CredentialTypeDefinition[] = [
      {
        providerName: "azure_dns",
        providerDisplayName: "Azure",
        typeName: "azure_dns",
        category: "DNS",
        description: "Azure DNS",
      },
      {
        providerName: "azure_dns",
        providerDisplayName: "Azure",
        typeName: "AZURE_DNS",
        category: "DNS",
        description: "Duplicate should be ignored",
      },
      {
        providerName: "aws_route53",
        providerDisplayName: "AWS",
        typeName: "aws_route53",
        category: "DNS",
        description: "Route53",
      },
    ];

    const options = toIntegrationTypeOptions(credentialTypes);

    expect(options).toEqual([
      expect.objectContaining({
        credentialType: "aws_route53",
        provider: "aws",
      }),
      expect.objectContaining({
        credentialType: "azure_dns",
        provider: "azure",
      }),
    ]);
  });

  it("builds integration options for akamai and f5 providers", () => {
    const credentialTypes: CredentialTypeDefinition[] = [
      {
        providerName: "akamai_cps",
        providerDisplayName: "Akamai",
        typeName: "akamai_cps",
        category: "DEPLOYMENT",
        description: "Akamai CPS",
      },
      {
        providerName: "f5_bigip",
        providerDisplayName: "F5",
        typeName: "f5_bigip",
        category: "DEPLOYMENT",
        description: "F5 BIG-IP",
      },
    ];

    const options = toIntegrationOptions(credentialTypes);

    expect(options).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          value: "akamai",
          credentialType: "akamai_cps",
          logo: CREDENTIAL_PROVIDER_CONFIG.akamai.logo,
        }),
        expect.objectContaining({
          value: "f5",
          credentialType: "f5_bigip",
          logo: CREDENTIAL_PROVIDER_CONFIG.f5.logo,
        }),
      ]),
    );
  });
});
