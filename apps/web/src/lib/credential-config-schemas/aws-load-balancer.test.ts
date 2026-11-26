// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  awsLoadBalancerCredentialConfigSchema,
  isAwsAlbProvider,
  isAwsLoadBalancerKvPathRequired,
  isAwsLoadBalancerProvider,
  isAwsNlbProvider,
  parseAwsLoadBalancerCredentialConfig,
} from "@/lib/credential-config-schemas/aws-load-balancer";

describe("aws-load-balancer-credential-config", () => {
  it("accepts assume-role configuration with listeners", () => {
    const result = awsLoadBalancerCredentialConfigSchema.safeParse({
      authMode: "ASSUME_ROLE",
      region: "us-east-1",
      roleArn: "arn:aws:iam::123456789012:role/certping-role",
      externalId: "certping-prod",
      loadBalancerArn:
        "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/prod-alb/abcd1234",
      listeners: [
        "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/prod-alb/abcd1234/aaaa5678",
      ],
    });

    expect(result.success).toBe(true);
  });

  it("requires roleArn when authMode is ASSUME_ROLE", () => {
    const result = awsLoadBalancerCredentialConfigSchema.safeParse({
      authMode: "ASSUME_ROLE",
      region: "us-east-1",
      loadBalancerArn:
        "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/prod-nlb/abcd1234",
      listeners: [
        "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/net/prod-nlb/abcd1234/aaaa5678",
      ],
    });

    expect(result.success).toBe(false);
  });

  it("parses string configJson payloads", () => {
    const parsed = parseAwsLoadBalancerCredentialConfig(
      JSON.stringify({
        authMode: "STATIC_KEYS",
        region: "us-east-1",
        loadBalancerArn:
          "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/prod-alb/abcd1234",
        listeners: [
          "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/prod-alb/abcd1234/aaaa5678",
        ],
      }),
    );

    expect(parsed?.region).toBe("us-east-1");
  });

  it("identifies provider kinds and kv-path behavior", () => {
    expect(isAwsAlbProvider("AWS_ALB")).toBe(true);
    expect(isAwsNlbProvider("AWS_NLB")).toBe(true);
    expect(isAwsLoadBalancerProvider("AWS_ALB")).toBe(true);
    expect(isAwsLoadBalancerProvider("AWS_NLB")).toBe(true);
    expect(isAwsLoadBalancerKvPathRequired("INSTANCE_PROFILE")).toBe(false);
    expect(isAwsLoadBalancerKvPathRequired("ASSUME_ROLE")).toBe(false);
    expect(isAwsLoadBalancerKvPathRequired("STATIC_KEYS")).toBe(true);
  });
});
