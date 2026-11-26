// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  defaultAzureAfdCertificateName,
  defaultAzureAfdSecretName,
  defaultAzureAppGatewaySslCertName,
  defaultAzureKvCertificateName,
  findKeyVaultCertificateNameCollision,
  getDeploymentTargetApiValue,
  getDeploymentTargetConfigKind,
} from "@/lib/cert-manager/deployment-target-config";

describe("deployment-target-config", () => {
  it("normalizes deployment target api value from targetType/providerName", () => {
    expect(
      getDeploymentTargetApiValue({
        targetType: " azure_kv ",
        providerName: "",
      }),
    ).toBe("AZURE_KV");
    expect(
      getDeploymentTargetApiValue({
        targetType: "",
        providerName: " aws_alb ",
      }),
    ).toBe("AWS_ALB");
    expect(
      getDeploymentTargetApiValue({ targetType: undefined, providerName: " " }),
    ).toBe("");
  });

  it("derives config kind for known target types", () => {
    expect(
      getDeploymentTargetConfigKind({
        targetType: "KUBERNETES_SECRETS",
        providerName: "",
      }),
    ).toBe("KUBERNETES_SECRETS");
    expect(
      getDeploymentTargetConfigKind({
        targetType: "azure_kv",
        providerName: "",
      }),
    ).toBe("AZURE_KV");
    expect(
      getDeploymentTargetConfigKind({
        targetType: "AZURE_AFD",
        providerName: "",
      }),
    ).toBe("AZURE_AFD");
    expect(
      getDeploymentTargetConfigKind({
        targetType: "AZURE_APP_GW",
        providerName: "",
      }),
    ).toBe("AZURE_APP_GW");
    expect(
      getDeploymentTargetConfigKind({
        targetType: "AZURE_APP_GW_CONTAINERS",
        providerName: "",
      }),
    ).toBe("AZURE_APP_GW_CONTAINERS");
    expect(
      getDeploymentTargetConfigKind({
        targetType: "AWS_ALB",
        providerName: "",
      }),
    ).toBe("AWS_LOAD_BALANCER");
    expect(
      getDeploymentTargetConfigKind({
        targetType: "AWS_NLB",
        providerName: "",
      }),
    ).toBe("AWS_LOAD_BALANCER");
    expect(
      getDeploymentTargetConfigKind({
        targetType: "AWS_API_GW_REST",
        providerName: "",
      }),
    ).toBe("AWS_API_GATEWAY");
    expect(
      getDeploymentTargetConfigKind({
        targetType: "AWS_API_GW_HTTP",
        providerName: "",
      }),
    ).toBe("AWS_API_GATEWAY");
    expect(
      getDeploymentTargetConfigKind({
        targetType: "unknown",
        providerName: "",
      }),
    ).toBe("NONE");
  });

  it("generates default Azure KV certificate name from domain", () => {
    expect(defaultAzureKvCertificateName("example.com")).toBe("example-com");
    expect(defaultAzureKvCertificateName("*.Example.COM")).toBe("example-com");
    expect(defaultAzureKvCertificateName("...example.com...")).toBe(
      "example-com",
    );
    expect(defaultAzureKvCertificateName("$$$")).toBe("certificate");
  });

  it("generates default Azure AFD secret name from domain", () => {
    expect(defaultAzureAfdSecretName("example.com")).toBe(
      "example-com-afd-secret",
    );
    expect(defaultAzureAfdSecretName("*.example.com")).toBe(
      "example-com-afd-secret",
    );
    expect(defaultAzureAfdSecretName("$$$")).toBe("afd-secret");
  });

  it("gives Front Door a certificate name distinct from the Key Vault default", () => {
    expect(defaultAzureAfdCertificateName("afdtest.example.com")).toBe(
      "afdtest-example-com-afd",
    );
    expect(defaultAzureAfdCertificateName("$$$")).toBe("afd-certificate");
    expect(defaultAzureAfdCertificateName("example.com")).not.toBe(
      defaultAzureKvCertificateName("example.com"),
    );
  });

  it("flags Key Vault and Front Door targets that share a certificate name in one vault", () => {
    const kv = {
      credentialXref: "kv-1",
      kind: "AZURE_KV" as const,
      vaultUri: "https://my-kv.vault.azure.net/",
      certificateName: "example-com",
    };
    const afd = {
      credentialXref: "afd-1",
      kind: "AZURE_AFD" as const,
      vaultUri: "https://MY-KV.vault.azure.net",
      certificateName: "Example-com",
    };

    expect(findKeyVaultCertificateNameCollision([kv, afd])).toMatch(
      /kv-1 and Front Door target afd-1/,
    );
    expect(
      findKeyVaultCertificateNameCollision([
        kv,
        { ...afd, vaultUri: "https://other-kv.vault.azure.net/" },
      ]),
    ).toBeNull();
    expect(
      findKeyVaultCertificateNameCollision([kv, { ...afd, vaultUri: "" }]),
    ).not.toBeNull();
    expect(
      findKeyVaultCertificateNameCollision([
        kv,
        { ...afd, certificateName: "example-com-afd" },
      ]),
    ).toBeNull();
  });

  it("generates default Azure App Gateway ssl cert name from domain", () => {
    expect(defaultAzureAppGatewaySslCertName("example.com")).toBe(
      "certping-example-com",
    );
    expect(defaultAzureAppGatewaySslCertName("*.Example.COM")).toBe(
      "certping-example-com",
    );
    expect(defaultAzureAppGatewaySslCertName("$$$")).toBe(
      "certping-certificate",
    );
  });
});
