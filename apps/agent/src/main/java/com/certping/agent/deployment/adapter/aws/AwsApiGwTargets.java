// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.aws;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * {@code targetsJson} for API Gateway (REST + HTTP): selects which custom domains
 * (from {@code scope.customDomains}) this cert should be deployed to.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AwsApiGwTargets(List<String> domainNames) {}
