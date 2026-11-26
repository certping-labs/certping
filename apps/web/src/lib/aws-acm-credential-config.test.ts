// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  parseAwsAcmCredentialConfig,
  getAwsAcmAuthModeLabel,
  getAwsAcmAuthModeHelp,
  isAwsAcmProvider,
  isAwsAcmKvPathRequired,
} from "@/lib/credential-config-schemas/aws-acm";

describe("aws acm credential config", () => {
  it("parses string and object config payloads", () => {
    const payload = {
      authMode: "ASSUME_ROLE",
      region: "us-east-1",
      roleArn: "arn:aws:iam::123456789012:role/example",
      externalId: "external",
    } as const;

    expect(parseAwsAcmCredentialConfig(JSON.stringify(payload))).toEqual(
      payload,
    );
    expect(parseAwsAcmCredentialConfig(payload)).toEqual(payload);
  });

  it("parses nested config object payloads and rejects invalid payloads", () => {
    expect(
      parseAwsAcmCredentialConfig({
        config: {
          authMode: "STATIC_KEYS",
          region: "us-east-1",
        },
      }),
    ).toEqual({
      authMode: "STATIC_KEYS",
      region: "us-east-1",
    });

    expect(parseAwsAcmCredentialConfig({ bad: true })).toBeNull();
    expect(parseAwsAcmCredentialConfig("{bad-json")).toBeNull();
  });

  it("returns labels/help and provider utilities", () => {
    expect(getAwsAcmAuthModeLabel("STATIC_KEYS")).toBe("Static access keys");
    expect(getAwsAcmAuthModeHelp("ASSUME_ROLE")).toContain("assume");
    expect(isAwsAcmProvider("AWS_ACM")).toBe(true);
    expect(isAwsAcmProvider("AZURE_KV")).toBe(false);
    expect(isAwsAcmKvPathRequired("INSTANCE_PROFILE")).toBe(false);
    expect(isAwsAcmKvPathRequired("ASSUME_ROLE")).toBe(false);
    expect(isAwsAcmKvPathRequired("STATIC_KEYS")).toBe(true);
  });
});
