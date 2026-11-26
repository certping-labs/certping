// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.aws;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Parsed shape of {@code credentialScopeJson} for {@code AWS_ACM}.
 *
 * @param authMode   STATIC_KEYS | ASSUME_ROLE | INSTANCE_PROFILE
 * @param region     required — where the ACM cert will live
 * @param roleArn    required for ASSUME_ROLE
 * @param externalId optional STS external-id
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AwsAcmScope(
        String authMode,
        String region,
        String roleArn,
        String externalId) {}
