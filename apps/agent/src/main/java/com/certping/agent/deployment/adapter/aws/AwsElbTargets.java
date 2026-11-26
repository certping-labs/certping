// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.aws;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * {@code targetsJson} for {@code AWS_ALB} / {@code AWS_NLB}.
 *
 * <p>Selects which listeners (from the credential scope's {@code listeners[]})
 * this particular certificate should be attached to.
 *
 * @param listenerArns selected listener ARNs — must be a subset of scope.listeners
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AwsElbTargets(List<String> listenerArns) {}
