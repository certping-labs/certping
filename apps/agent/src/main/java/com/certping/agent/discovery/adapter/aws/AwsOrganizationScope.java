// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.aws;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Parsed {@code credentialScopeJson} for {@code AWS_ORGANIZATION} discovery.
 *
 * @param authMode       how the agent gets hub credentials: STATIC_KEYS | ASSUME_ROLE | INSTANCE_PROFILE
 * @param region         home region for STS calls (for example us-east-1)
 * @param roleArn        hub role to assume first (ASSUME_ROLE only)
 * @param externalId     optional external ID used when assuming the member role
 * @param memberRoleName read-only role that exists in every member account
 * @param accountIds     optional: scan only these accounts instead of listing the organization
 * @param regions        optional: scan only these regions instead of every enabled region
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AwsOrganizationScope(
        String authMode,
        String region,
        String roleArn,
        String externalId,
        String memberRoleName,
        List<String> accountIds,
        List<String> regions) {

    public static final String DEFAULT_MEMBER_ROLE = "CertPingDiscoveryReadOnly";

    public String memberRoleOrDefault() {
        return memberRoleName == null || memberRoleName.isBlank() ? DEFAULT_MEMBER_ROLE : memberRoleName.trim();
    }
}
