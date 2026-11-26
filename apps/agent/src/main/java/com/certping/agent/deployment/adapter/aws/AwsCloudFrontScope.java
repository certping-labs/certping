// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.aws;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Parsed shape of {@code credentialScopeJson} for {@code AWS_CLOUDFRONT}.
 *
 * <p>One credential = one distribution. CloudFront is a global service and only accepts
 * ACM certs from {@code us-east-1} — the adapter forces that region; operators don't set it.
 *
 * @param authMode        STATIC_KEYS | ASSUME_ROLE | INSTANCE_PROFILE
 * @param roleArn         required when authMode=ASSUME_ROLE
 * @param externalId      optional even on ASSUME_ROLE
 * @param distributionId  required — the CloudFront distribution to update
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AwsCloudFrontScope(
        String authMode,
        String roleArn,
        String externalId,
        String distributionId) {}
