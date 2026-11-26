// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.aws;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * {@code targetsJson} for {@code AWS_CLOUDFRONT}: empty — the single distribution
 * lives in scope ({@link AwsCloudFrontScope#distributionId()}).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AwsCloudFrontTargets() {}
