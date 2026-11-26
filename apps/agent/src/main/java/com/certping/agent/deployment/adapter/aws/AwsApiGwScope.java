// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.aws;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Parsed shape of {@code credentialScopeJson} for AWS API Gateway (REST + HTTP).
 *
 * <p>One credential = one set of custom domains. The available domain names live here
 * as the guardrail list. Per-cert targets select a subset via {@code domainNames}.
 *
 * <p>{@code endpointType} is NOT stored — the adapter auto-discovers it per domain
 * by calling {@code getDomainName()} at deploy time.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AwsApiGwScope(
        String authMode,
        String region,
        String roleArn,
        String externalId,
        /** All available custom domain names for this credential. */
        List<String> customDomains) {}
