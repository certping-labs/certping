// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.cloud.aws;

/** AWS auth mode declared in {@code credential_references.config.authMode}. */
public enum AwsAuthMode {
    /** Static AWS access key + secret stored in KV. */
    STATIC_KEYS,
    /** Optional bootstrap keys (or ambient identity), then STS AssumeRole into a target role. */
    ASSUME_ROLE,
    /** Use ambient AWS identity (EC2 instance profile / EKS IRSA / pod identity). No KV secret. */
    INSTANCE_PROFILE
}
