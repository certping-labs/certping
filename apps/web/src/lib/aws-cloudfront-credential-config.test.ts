// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  getAwsCloudFrontAuthModeHelp,
  getAwsCloudFrontAuthModeLabel,
  isAwsCloudFrontKvPathRequired,
  isAwsCloudFrontProvider,
  parseAwsCloudFrontCredentialConfig,
} from "@/lib/credential-config-schemas/aws-cloudfront";

describe("aws cloudfront credential config", () => {
  it("parses string and object config payloads", () => {
    const payload = {
      authMode: "ASSUME_ROLE",
      distributionId: "E123EXAMPLE",
      roleArn: "arn:aws:iam::123456789012:role/example",
      externalId: "external",
    } as const;

    expect(parseAwsCloudFrontCredentialConfig(JSON.stringify(payload))).toEqual(
      payload,
    );
    expect(parseAwsCloudFrontCredentialConfig(payload)).toEqual(payload);
  });

  it("parses nested config object payloads and rejects invalid payloads", () => {
    expect(
      parseAwsCloudFrontCredentialConfig({
        config: {
          authMode: "STATIC_KEYS",
          distributionId: "E123EXAMPLE",
        },
      }),
    ).toEqual({
      authMode: "STATIC_KEYS",
      distributionId: "E123EXAMPLE",
    });

    expect(parseAwsCloudFrontCredentialConfig({ bad: true })).toBeNull();
    expect(parseAwsCloudFrontCredentialConfig("{bad-json")).toBeNull();
  });

  it("returns labels/help and provider utilities", () => {
    expect(getAwsCloudFrontAuthModeLabel("STATIC_KEYS")).toBe(
      "Static access keys",
    );
    expect(getAwsCloudFrontAuthModeHelp("ASSUME_ROLE")).toContain("Assume");
    expect(isAwsCloudFrontProvider("AWS_CLOUDFRONT")).toBe(true);
    expect(isAwsCloudFrontProvider("AWS_ACM")).toBe(false);
    expect(isAwsCloudFrontKvPathRequired("INSTANCE_PROFILE")).toBe(false);
    expect(isAwsCloudFrontKvPathRequired("ASSUME_ROLE")).toBe(false);
    expect(isAwsCloudFrontKvPathRequired("STATIC_KEYS")).toBe(true);
  });
});
