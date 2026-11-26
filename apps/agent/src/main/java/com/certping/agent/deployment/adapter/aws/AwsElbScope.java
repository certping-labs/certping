// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.aws;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Parsed shape of {@code credentialScopeJson} for {@code AWS_ALB} / {@code AWS_NLB}.
 *
 * <p>One credential = one load balancer. The available listeners on that LB live in
 * scope; per-cert targets pick a subset.
 *
 * @param authMode   STATIC_KEYS | ASSUME_ROLE | INSTANCE_PROFILE
 * @param region     required — AWS region (e.g. us-east-1)
 * @param roleArn    required when authMode=ASSUME_ROLE
 * @param externalId optional even on ASSUME_ROLE (defense-in-depth)
 * @param listeners  required — all available listener ARNs on this LB
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AwsElbScope(
        String authMode,
        String region,
        String roleArn,
        String externalId,
        List<String> listeners) {}
