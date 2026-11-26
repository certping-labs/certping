// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  awsApiGatewayCredentialConfigSchema,
  isAwsApiGatewayKvPathRequired,
  isAwsApiGatewayProvider,
  isAwsApiGatewayHttpProvider,
  isAwsApiGatewayRestProvider,
  parseAwsApiGatewayCredentialConfig,
} from "@/lib/credential-config-schemas/aws-api-gateway";

describe("aws-api-gateway-credential-config", () => {
  it("accepts static-keys config with custom domains", () => {
    const result = awsApiGatewayCredentialConfigSchema.safeParse({
      authMode: "STATIC_KEYS",
      region: "us-east-1",
      customDomains: ["api.example.com", "edge.example.com"],
    });

    expect(result.success).toBe(true);
  });

  it("requires roleArn when authMode is ASSUME_ROLE", () => {
    const result = awsApiGatewayCredentialConfigSchema.safeParse({
      authMode: "ASSUME_ROLE",
      region: "us-east-1",
      customDomains: ["api.example.com"],
    });

    expect(result.success).toBe(false);
  });

  it("parses string configJson payloads", () => {
    const parsed = parseAwsApiGatewayCredentialConfig(
      JSON.stringify({
        authMode: "INSTANCE_PROFILE",
        region: "us-east-1",
        customDomains: ["api.example.com"],
      }),
    );

    expect(parsed?.customDomains).toEqual(["api.example.com"]);
  });

  it("maps providers and kv-path behavior", () => {
    expect(isAwsApiGatewayRestProvider("AWS_API_GW_REST")).toBe(true);
    expect(isAwsApiGatewayHttpProvider("AWS_API_GW_HTTP")).toBe(true);
    expect(isAwsApiGatewayProvider("AWS_API_GW_REST")).toBe(true);
    expect(isAwsApiGatewayProvider("AWS_API_GW_HTTP")).toBe(true);
    expect(isAwsApiGatewayKvPathRequired("INSTANCE_PROFILE")).toBe(false);
    expect(isAwsApiGatewayKvPathRequired("ASSUME_ROLE")).toBe(false);
    expect(isAwsApiGatewayKvPathRequired("STATIC_KEYS")).toBe(true);
  });
});
