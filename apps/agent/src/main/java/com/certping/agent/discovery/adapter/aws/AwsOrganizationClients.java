// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.aws;

import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.services.acm.AcmClient;

import java.util.List;

/**
 * The AWS calls org-wide discovery needs, behind one seam so the adapter can be tested
 * without AWS.
 */
public interface AwsOrganizationClients {

    /** IDs of every ACTIVE account in the organization. Needs organizations:ListAccounts. */
    List<String> listActiveAccountIds(AwsCredentialsProvider hub);

    /** The account the hub credentials belong to. */
    String callerAccountId(AwsCredentialsProvider hub, String region);

    /** Credentials for the member role in another account. The caller closes the result. */
    MemberCredentials assumeMemberRole(AwsCredentialsProvider hub, String roleArn, String externalId, String region);

    /** Regions enabled for the account. Needs account:ListRegions. */
    List<String> enabledRegions(AwsCredentialsProvider credentials);

    AcmClient acmClient(String region, AwsCredentialsProvider credentials);

    /** Assumed-role credentials plus whatever must be closed when the account is done. */
    interface MemberCredentials extends AutoCloseable {
        AwsCredentialsProvider provider();

        @Override
        void close();
    }
}
