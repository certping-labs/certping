// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.cloud.aws;

/**
 * AWS credential scope — fields parsed from {@code credentialScopeJson} on the wire.
 * All fields except {@code region} are optional depending on {@link AwsAuthMode}.
 *
 * @param region     AWS region (always required for adapters that target regional resources)
 * @param roleArn    target role ARN (required for ASSUME_ROLE; nullable for STATIC_KEYS/INSTANCE_PROFILE)
 * @param externalId optional external-id for cross-account assume-role
 */
public record AwsAuthScope(String region, String roleArn, String externalId) {}
