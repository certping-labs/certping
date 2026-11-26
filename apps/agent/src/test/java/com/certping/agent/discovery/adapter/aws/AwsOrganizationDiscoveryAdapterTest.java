// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.aws;

import com.certping.agent.deployment.cloud.aws.AwsAuthMode;
import com.certping.agent.deployment.cloud.aws.AwsAuthScope;
import com.certping.agent.deployment.cloud.aws.AwsAuthSecret;
import com.certping.agent.deployment.cloud.aws.AwsCloudCredentialResolver;
import com.certping.agent.discovery.DiscoveryResult;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.message.DiscoveryFailedScope;
import com.certping.agent.model.enums.TargetType;
import com.certping.agent.model.message.CertDiscoveryMessage;
import com.certping.agent.model.message.DiscoveredCertEntry;
import com.certping.agent.secrets.SecretStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.services.acm.AcmClient;
import tools.jackson.databind.json.JsonMapper;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AwsOrganizationDiscoveryAdapterTest {

    private static final String HUB = "111111111111";
    private static final String MEMBER = "222222222222";

    @Mock private SecretStore secretStore;
    @Mock private AwsCloudCredentialResolver resolver;
    @Mock private AwsAcmDiscoveryAdapter acm;
    @Mock private AwsOrganizationClients clients;
    @Mock private AwsCredentialsProvider hubCreds;
    @Mock private AwsCredentialsProvider memberCreds;
    @Mock private AcmClient acmClient;

    private AwsOrganizationDiscoveryAdapter adapter;
    private AwsOrganizationClients.MemberCredentials member;

    @BeforeEach
    void setUp() {
        adapter = new AwsOrganizationDiscoveryAdapter(secretStore, JsonMapper.builder().build(),
                resolver, acm, clients);
        member = mock(AwsOrganizationClients.MemberCredentials.class);
        when(member.provider()).thenReturn(memberCreds);
        when(resolver.resolve(eq(AwsAuthMode.INSTANCE_PROFILE), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString())).thenReturn(hubCreds);
        when(clients.callerAccountId(hubCreds, "us-east-1")).thenReturn(HUB);
        when(clients.acmClient(anyString(), any())).thenReturn(acmClient);
    }

    @Test
    void scansEveryAccountAndEnabledRegion() {
        when(clients.listActiveAccountIds(hubCreds)).thenReturn(List.of(HUB, MEMBER));
        when(clients.assumeMemberRole(eq(hubCreds), anyString(), any(), anyString())).thenReturn(member);
        when(clients.enabledRegions(any())).thenReturn(List.of("us-east-1", "eu-west-1"));
        when(acm.discoverCertificates(eq(acmClient), eq("org-1"), any())).thenReturn(List.of(entry("a")));

        List<DiscoveredCertEntry> result = adapter.discover(message("{\"authMode\":\"INSTANCE_PROFILE\",\"region\":\"us-east-1\",\"externalId\":\"x-1\"}"));

        assertThat(result).hasSize(4);
        verify(clients).assumeMemberRole(hubCreds,
                "arn:aws:iam::" + MEMBER + ":role/CertPingDiscoveryReadOnly", "x-1", "us-east-1");
        verify(clients, never()).assumeMemberRole(any(), eq("arn:aws:iam::" + HUB + ":role/CertPingDiscoveryReadOnly"),
                any(), anyString());
    }

    @Test
    void oneBrokenAccountDoesNotStopTheScan() {
        when(clients.listActiveAccountIds(hubCreds)).thenReturn(List.of(HUB, MEMBER));
        when(clients.assumeMemberRole(any(), anyString(), any(), anyString()))
                .thenThrow(new RuntimeException("AccessDenied"));
        when(clients.enabledRegions(any())).thenReturn(List.of("us-east-1"));
        when(acm.discoverCertificates(eq(acmClient), eq("org-1"), any())).thenReturn(List.of(entry("a")));

        assertThat(adapter.discover(message("{\"authMode\":\"INSTANCE_PROFILE\",\"region\":\"us-east-1\"}")))
                .hasSize(1);
    }

    @Test
    void accessDeniedInOneAccountIsReportedAsFailedScopeAndOtherAccountsStillReturnResults() {
        String third = "333333333333";
        when(clients.listActiveAccountIds(hubCreds)).thenReturn(List.of(HUB, MEMBER, third));
        when(clients.assumeMemberRole(any(), eq("arn:aws:iam::" + MEMBER + ":role/CertPingDiscoveryReadOnly"),
                any(), anyString())).thenThrow(software.amazon.awssdk.services.sts.model.StsException.builder()
                        .message("User is not authorized to perform: sts:AssumeRole")
                        .awsErrorDetails(software.amazon.awssdk.awscore.exception.AwsErrorDetails.builder()
                                .errorCode("AccessDenied").build())
                        .build());
        when(clients.assumeMemberRole(any(), eq("arn:aws:iam::" + third + ":role/CertPingDiscoveryReadOnly"),
                any(), anyString())).thenReturn(member);
        when(clients.enabledRegions(any())).thenReturn(List.of("us-east-1"));
        when(acm.discoverCertificates(eq(acmClient), eq("org-1"), any())).thenReturn(List.of(entry("a")));

        DiscoveryResult result = adapter.discoverWithFailedScopes(
                message("{\"authMode\":\"INSTANCE_PROFILE\",\"region\":\"us-east-1\"}"));

        assertThat(result.certificates()).hasSize(2);
        assertThat(result.failedScopes()).singleElement().satisfies(f -> {
            assertThat(f.getScopeType()).isEqualTo(DiscoveryFailedScope.ScopeType.AWS_ACCOUNT);
            assertThat(f.getScopeId()).isEqualTo(MEMBER);
            assertThat(f.getErrorCode()).isEqualTo("DISCOVERY_AWS_ACCOUNT_ACCESS_DENIED");
            assertThat(f.getMessage()).contains("not authorized");
        });
    }

    @Test
    void regionErrorIsReportedWithAccountAndRegion() {
        AcmClient brokenRegion = mock(AcmClient.class);
        when(clients.listActiveAccountIds(hubCreds)).thenReturn(List.of(HUB));
        when(clients.enabledRegions(hubCreds)).thenReturn(List.of("us-east-1", "eu-west-1"));
        when(clients.acmClient(eq("eu-west-1"), any())).thenReturn(brokenRegion);
        when(acm.discoverCertificates(eq(acmClient), eq("org-1"), any())).thenReturn(List.of(entry("a")));
        when(acm.discoverCertificates(eq(brokenRegion), eq("org-1"), any()))
                .thenThrow(new RuntimeException("Region eu-west-1 endpoint timeout"));

        DiscoveryResult result = adapter.discoverWithFailedScopes(
                message("{\"authMode\":\"INSTANCE_PROFILE\",\"region\":\"us-east-1\"}"));

        assertThat(result.certificates()).hasSize(1);
        assertThat(result.failedScopes()).singleElement().satisfies(f -> {
            assertThat(f.getScopeType()).isEqualTo(DiscoveryFailedScope.ScopeType.AWS_REGION);
            assertThat(f.getScopeId()).isEqualTo(HUB + "/eu-west-1");
            assertThat(f.getErrorCode()).isEqualTo("DISCOVERY_ACM_ERROR");
        });
    }

    @Test
    void completeScanHasNoFailedScopes() {
        when(clients.listActiveAccountIds(hubCreds)).thenReturn(List.of(HUB));
        when(clients.enabledRegions(hubCreds)).thenReturn(List.of("us-east-1"));
        when(acm.discoverCertificates(eq(acmClient), eq("org-1"), any())).thenReturn(List.of(entry("a")));

        DiscoveryResult result = adapter.discoverWithFailedScopes(
                message("{\"authMode\":\"INSTANCE_PROFILE\",\"region\":\"us-east-1\"}"));

        assertThat(result.partial()).isFalse();
        assertThat(result.certificates()).hasSize(1);
    }

    @Test
    void failsClearlyWhenNoAccountCanBeRead() {
        when(clients.listActiveAccountIds(hubCreds)).thenReturn(List.of(MEMBER));
        when(clients.assumeMemberRole(any(), anyString(), any(), anyString()))
                .thenThrow(new RuntimeException("AccessDenied"));

        assertThatThrownBy(() -> adapter.discover(message("{\"authMode\":\"INSTANCE_PROFILE\",\"region\":\"us-east-1\"}")))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("could not read any account");
    }

    @Test
    void usesConfiguredAccountsAndRegionsWithoutListing() {
        when(clients.assumeMemberRole(any(), anyString(), any(), anyString())).thenReturn(member);
        when(acm.discoverCertificates(eq(acmClient), eq("org-1"), any())).thenReturn(List.of(entry("a")));

        List<DiscoveredCertEntry> result = adapter.discover(message(
                "{\"authMode\":\"INSTANCE_PROFILE\",\"region\":\"us-east-1\",\"memberRoleName\":\"ReadCerts\","
                        + "\"accountIds\":[\"" + MEMBER + "\"],\"regions\":[\"ap-south-1\"]}"));

        assertThat(result).hasSize(1);
        verify(clients, never()).listActiveAccountIds(any());
        verify(clients, never()).enabledRegions(any());
        verify(clients).acmClient("ap-south-1", memberCreds);
        verify(clients).assumeMemberRole(hubCreds, "arn:aws:iam::" + MEMBER + ":role/ReadCerts", null, "us-east-1");
    }

    @Test
    void singleAccountWhenOrganizationCannotBeListed() {
        when(clients.listActiveAccountIds(hubCreds)).thenThrow(new RuntimeException("AWSOrganizationsNotInUse"));
        when(clients.enabledRegions(hubCreds)).thenReturn(List.of("us-east-1", "eu-west-1"));
        when(acm.discoverCertificates(eq(acmClient), eq("org-1"), any())).thenReturn(List.of(entry("a")));

        assertThat(adapter.discover(message("{\"authMode\":\"INSTANCE_PROFILE\",\"region\":\"us-east-1\"}")))
                .hasSize(2);
        verify(clients, never()).assumeMemberRole(any(), anyString(), any(), anyString());
        verify(clients).acmClient("eu-west-1", hubCreds);
    }

    @Test
    void noAwsIdentityIsPermanent() {
        when(clients.callerAccountId(hubCreds, "us-east-1")).thenThrow(new RuntimeException("Unable to load credentials"));

        assertThatThrownBy(() -> adapter.discover(message("{\"authMode\":\"INSTANCE_PROFILE\",\"region\":\"us-east-1\"}")))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("could not sign in to AWS");
    }

    @Test
    void partitionFollowsRegion() {
        assertThat(AwsOrganizationDiscoveryAdapter.partition("us-gov-west-1")).isEqualTo("aws-us-gov");
        assertThat(AwsOrganizationDiscoveryAdapter.partition("cn-north-1")).isEqualTo("aws-cn");
        assertThat(AwsOrganizationDiscoveryAdapter.partition("eu-west-1")).isEqualTo("aws");
    }

    private static DiscoveredCertEntry entry(String id) {
        return DiscoveredCertEntry.builder().resourceId(id).domain("example.com").build();
    }

    private static CertDiscoveryMessage message(String scopeJson) {
        CertDiscoveryMessage msg = new CertDiscoveryMessage();
        msg.setRequestId("req-1");
        msg.setCorrelationId("corr-1");
        msg.setOrganizationId("org-1");
        msg.setTargetType(TargetType.AWS_ORGANIZATION);
        msg.setCredentialScopeJson(scopeJson);
        msg.setRequestedAt("2026-10-26T00:00:00Z");
        return msg;
    }
}
