// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.cloud.aws;

/**
 * AWS bootstrap secret pulled from KV. Both fields are nullable: empty for INSTANCE_PROFILE,
 * and optionally empty for ASSUME_ROLE when the agent already has ambient AWS identity
 * (IRSA / instance profile) to bootstrap STS from.
 */
public record AwsAuthSecret(String accessKeyId, String secretAccessKey) {

    public static AwsAuthSecret empty() {
        return new AwsAuthSecret(null, null);
    }

    public boolean hasKeys() {
        return accessKeyId != null && !accessKeyId.isBlank()
                && secretAccessKey != null && !secretAccessKey.isBlank();
    }
}
