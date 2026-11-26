// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.aws;

import org.springframework.stereotype.Component;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.account.AccountClient;
import software.amazon.awssdk.services.account.model.ListRegionsRequest;
import software.amazon.awssdk.services.account.model.RegionOptStatus;
import software.amazon.awssdk.services.acm.AcmClient;
import software.amazon.awssdk.services.organizations.OrganizationsClient;
import software.amazon.awssdk.services.organizations.model.Account;
import software.amazon.awssdk.services.organizations.model.AccountStatus;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.auth.StsAssumeRoleCredentialsProvider;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;

import java.util.List;

/** Real AWS SDK implementation of {@link AwsOrganizationClients}. */
@Component
public class SdkAwsOrganizationClients implements AwsOrganizationClients {

    private static final String SESSION_NAME = "certping-discovery";

    @Override
    public List<String> listActiveAccountIds(AwsCredentialsProvider hub) {
        try (OrganizationsClient org = OrganizationsClient.builder()
                .region(Region.US_EAST_1).credentialsProvider(hub).build()) {
            return org.listAccountsPaginator(r -> { }).stream().flatMap(page -> page.accounts().stream())
                    .filter(a -> a.status() == AccountStatus.ACTIVE)
                    .map(Account::id)
                    .sorted()
                    .toList();
        }
    }

    @Override
    public String callerAccountId(AwsCredentialsProvider hub, String region) {
        try (StsClient sts = StsClient.builder().region(Region.of(region)).credentialsProvider(hub).build()) {
            return sts.getCallerIdentity().account();
        }
    }

    @Override
    public MemberCredentials assumeMemberRole(AwsCredentialsProvider hub, String roleArn,
            String externalId, String region) {
        StsClient sts = StsClient.builder().region(Region.of(region)).credentialsProvider(hub).build();
        AssumeRoleRequest.Builder request = AssumeRoleRequest.builder()
                .roleArn(roleArn)
                .roleSessionName(SESSION_NAME)
                .durationSeconds(3600);
        if (externalId != null && !externalId.isBlank()) {
            request.externalId(externalId);
        }
        StsAssumeRoleCredentialsProvider provider = StsAssumeRoleCredentialsProvider.builder()
                .stsClient(sts)
                .refreshRequest(request.build())
                .build();
        // Fail now (bad trust policy, missing role) rather than on the first ACM call.
        provider.resolveCredentials();
        return new MemberCredentials() {
            @Override
            public AwsCredentialsProvider provider() {
                return provider;
            }

            @Override
            public void close() {
                provider.close();
                sts.close();
            }
        };
    }

    @Override
    public List<String> enabledRegions(AwsCredentialsProvider credentials) {
        try (AccountClient account = AccountClient.builder()
                .region(Region.US_EAST_1).credentialsProvider(credentials).build()) {
            return account.listRegionsPaginator(ListRegionsRequest.builder()
                            .regionOptStatusContains(RegionOptStatus.ENABLED, RegionOptStatus.ENABLED_BY_DEFAULT)
                            .build())
                    .regions().stream()
                    .map(r -> r.regionName())
                    .sorted()
                    .toList();
        }
    }

    @Override
    public AcmClient acmClient(String region, AwsCredentialsProvider credentials) {
        return AcmClient.builder().region(Region.of(region)).credentialsProvider(credentials).build();
    }
}
