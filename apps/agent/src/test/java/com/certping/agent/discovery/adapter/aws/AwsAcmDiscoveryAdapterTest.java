// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.aws;

import com.certping.agent.deployment.cloud.aws.AwsAuthMode;
import com.certping.agent.deployment.cloud.aws.AwsAuthScope;
import com.certping.agent.deployment.cloud.aws.AwsAuthSecret;
import com.certping.agent.deployment.cloud.aws.AwsCloudCredentialResolver;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.model.enums.TargetType;
import com.certping.agent.model.message.CertDiscoveryMessage;
import com.certping.agent.model.message.DiscoveredCertEntry;
import com.certping.agent.secrets.SecretStore;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.services.acm.AcmClient;
import software.amazon.awssdk.services.acm.model.AcmException;
import software.amazon.awssdk.services.acm.model.CertificateDetail;
import software.amazon.awssdk.services.acm.model.CertificateStatus;
import software.amazon.awssdk.services.acm.model.CertificateSummary;
import software.amazon.awssdk.services.acm.model.CertificateType;
import software.amazon.awssdk.services.acm.model.DescribeCertificateRequest;
import software.amazon.awssdk.services.acm.model.DescribeCertificateResponse;
import software.amazon.awssdk.services.acm.model.ExtendedKeyUsage;
import software.amazon.awssdk.services.acm.model.ExtendedKeyUsageName;
import software.amazon.awssdk.services.acm.model.GetCertificateRequest;
import software.amazon.awssdk.services.acm.model.GetCertificateResponse;
import software.amazon.awssdk.services.acm.model.KeyAlgorithm;
import software.amazon.awssdk.services.acm.model.KeyUsage;
import software.amazon.awssdk.services.acm.model.KeyUsageName;
import software.amazon.awssdk.services.acm.model.ListCertificatesRequest;
import software.amazon.awssdk.services.acm.model.ListCertificatesResponse;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AwsAcmDiscoveryAdapterTest {

    @Mock private SecretStore secretStore;
    @Mock private AwsCloudCredentialResolver awsCredentialResolver;
    @Mock private AwsCredentialsProvider credentialsProvider;
    @Mock private AcmClient acmClient;

    private AwsAcmDiscoveryAdapter adapter;

    private static final String KV_SECRET_JSON =
            "{\"accessKeyId\":\"AKIATEST\",\"secretAccessKey\":\"secret\"}";
    private static final String STATIC_SCOPE_JSON =
            "{\"authMode\":\"STATIC_KEYS\",\"region\":\"us-east-1\"}";
    private static final String ASSUME_ROLE_SCOPE_JSON =
            "{\"authMode\":\"ASSUME_ROLE\",\"region\":\"us-east-1\","
                    + "\"roleArn\":\"arn:aws:iam::123456789012:role/certping-discovery\"}";

    /** Self-signed leaf, CN=imported.example.com, RSA 2048, returned by GetCertificate in tests. */
    private static final String TEST_LEAF_PEM =
            """
            -----BEGIN CERTIFICATE-----
            MIICtTCCAZ0CBBI0VngwDQYJKoZIhvcNAQELBQAwHzEdMBsGA1UEAwwUaW1wb3J0
            ZWQuZXhhbXBsZS5jb20wHhcNMjYwNjIzMTkwNTI0WhcNMjYwNjI1MTkwNTI0WjAf
            MR0wGwYDVQQDDBRpbXBvcnRlZC5leGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEB
            BQADggEPADCCAQoCggEBANztAhuTmm10OmATqebW5d7ZJImSw7O6asEQhUAN6IhJ
            R5Nrr2UP1UvcEzFqcpzM2nnh0JtyDCKjgvxvlAsV3jo0u8KBotfQX/GAtrUMpeQC
            MTx0wh5zleDelLULJF7ylLJIkBbT237y6pCUGmEo9Xc8YSOePxsdKUcHqSlKOmp0
            MiO/XqdC6Fm9scob4ec+eiAnrNLdrbTfne/t9xAqExR8jHAEaUM5phCLW1Crgwwr
            O1Rd4+OEIKomWAFzU7p3ej96ICYGcASCyIsK43F76zQVsAo/+hpemtru9J0XDL7y
            yT9czvhiOLRfMIHVOHpuqAebjdbY+Xv2SVg0Uo+P9LUCAwEAATANBgkqhkiG9w0B
            AQsFAAOCAQEAjKTYNToaS6rMgRVfcU5RVuiRNRG1CoV6QnqwagHTCRCjf0kp/faj
            duBAr/cT3EPAx5qWrYdqBLgqKLrkO1ECzu3zr6dMSRYxhfJocVDS7GJBv7hsd3QV
            T5Ck51rBoZwj7NxSszP8hYtg/6XN+AmLIF17vpB5hJbcoS4LHBQuan6ZQu2GYelP
            IxbxNfz8u4ZHRxQvB+5ysdobU3YLD/PmVLgbf+a7Kw9kQvMXiRDz9EHs8mkRZtKq
            5YUe9Qmg+2MNh5OV23MCq5sJF1C8xZm62WgLqRUCKYTiTt+0PgXcHcnK0cwpyvI5
            jpB0qmG8hX7/yBhnlfnsID7ik2EDbBjIBA==
            -----END CERTIFICATE-----
            """;

    @BeforeEach
    void setUp() {
        adapter = new AwsAcmDiscoveryAdapter(secretStore, JsonMapper.builderWithJackson2Defaults().build(), awsCredentialResolver);
    }

    @Test
    void discover_staticKeys_readsCredentialFromKvPathAndUsesResolver() {
        when(secretStore.read("https://kv-test.vault.azure.net/secrets/aws-acm-cred"))
                .thenReturn(KV_SECRET_JSON);
        when(awsCredentialResolver.resolve(eq(AwsAuthMode.STATIC_KEYS), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), eq("AWS ACM Discovery"))).thenReturn(credentialsProvider);

        AwsAcmDiscoveryAdapter spy = org.mockito.Mockito.spy(adapter);
        doReturn(acmClient).when(spy).buildClient(eq("us-east-1"), eq(credentialsProvider));
        doReturn(List.of()).when(spy).discoverCertificates(eq(acmClient), eq("org-123"), org.mockito.ArgumentMatchers.any());

        assertThat(spy.discover(buildMessage(STATIC_SCOPE_JSON))).isEmpty();

        verify(secretStore).read("https://kv-test.vault.azure.net/secrets/aws-acm-cred");
        verify(awsCredentialResolver).resolve(eq(AwsAuthMode.STATIC_KEYS), isA(AwsAuthScope.class),
                isA(AwsAuthSecret.class), eq("AWS ACM Discovery"));
        verify(spy).buildClient("us-east-1", credentialsProvider);
    }

    @Test
    void discover_assumeRoleScope_usesAssumeRoleAuthMode() {
        when(secretStore.read("https://kv-test.vault.azure.net/secrets/aws-acm-cred"))
                .thenReturn(KV_SECRET_JSON);
        when(awsCredentialResolver.resolve(eq(AwsAuthMode.ASSUME_ROLE), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), eq("AWS ACM Discovery"))).thenReturn(credentialsProvider);

        AwsAcmDiscoveryAdapter spy = org.mockito.Mockito.spy(adapter);
        doReturn(acmClient).when(spy).buildClient(eq("us-east-1"), eq(credentialsProvider));
        doReturn(List.of()).when(spy).discoverCertificates(eq(acmClient), eq("org-123"), org.mockito.ArgumentMatchers.any());

        assertThat(spy.discover(buildMessage(ASSUME_ROLE_SCOPE_JSON))).isEmpty();

        verify(awsCredentialResolver).resolve(eq(AwsAuthMode.ASSUME_ROLE), isA(AwsAuthScope.class),
                isA(AwsAuthSecret.class), eq("AWS ACM Discovery"));
    }

    @Test
    void discover_instanceProfileScope_allowsMissingKvPath() {
        CertDiscoveryMessage message = buildMessage(
                "{\"authMode\":\"INSTANCE_PROFILE\",\"region\":\"us-east-1\"}");
        message.setDeploymentCredHandle(null);
        when(awsCredentialResolver.resolve(eq(AwsAuthMode.INSTANCE_PROFILE), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), eq("AWS ACM Discovery"))).thenReturn(credentialsProvider);

        AwsAcmDiscoveryAdapter spy = org.mockito.Mockito.spy(adapter);
        doReturn(acmClient).when(spy).buildClient(eq("us-east-1"), eq(credentialsProvider));
        doReturn(List.of()).when(spy).discoverCertificates(eq(acmClient), eq("org-123"), org.mockito.ArgumentMatchers.any());

        assertThat(spy.discover(message)).isEmpty();
    }

    @Test
    void discover_invalidKvSecretJson_throwsPermanentCredentialInvalid() {
        when(secretStore.read("https://kv-test.vault.azure.net/secrets/aws-acm-cred"))
                .thenReturn("not-valid-json");

        assertThatThrownBy(() -> adapter.discover(buildMessage(STATIC_SCOPE_JSON)))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void discover_missingScopeJson_throwsPermanentCredentialInvalid() {
        assertThatThrownBy(() -> adapter.discover(buildMessage(null)))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void discover_missingRegion_throwsPermanentCredentialInvalid() {
        assertThatThrownBy(() -> adapter.discover(buildMessage("{\"authMode\":\"STATIC_KEYS\"}")))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void discover_allAwsTargetTypes_areHandledBySameAdapter() {
        List<TargetType> awsTargets = List.of(
                TargetType.AWS_ACM,
                TargetType.AWS_ALB,
                TargetType.AWS_NLB,
                TargetType.AWS_CLOUDFRONT,
                TargetType.AWS_API_GW_REST,
                TargetType.AWS_API_GW_HTTP);

        for (TargetType targetType : awsTargets) {
            assertThat(adapter.getClass().getAnnotation(
                    com.certping.agent.discovery.DiscoveryAdapterFor.class).value())
                    .contains(targetType);
        }
    }

    @Test
    void discoverCertificates_blankKeyAlgorithm_derivesFromLeafViaGetCertificate() {
        String arn = "arn:aws:acm:us-east-1:123:certificate/imported";
        stubList(arn);
        // ACM left keyAlgorithm empty (typical for imported certs), but status is ISSUED.
        stubDescribe(CertificateDetail.builder()
                .certificateArn(arn)
                .domainName("imported.example.com")
                .status(CertificateStatus.ISSUED)
                .build());
        when(acmClient.getCertificate(any(GetCertificateRequest.class)))
                .thenReturn(GetCertificateResponse.builder().certificate(TEST_LEAF_PEM).build());

        List<com.certping.agent.model.message.DiscoveredCertEntry> result =
                adapter.discoverCertificates(acmClient, "org-1");

        assertThat(result).hasSize(1);
        // RSA 2048 leaf → ACM-style "ALGO_size" form, matching ACM's native enum value.
        assertThat(result.get(0).getKeyAlgorithm()).isEqualTo("RSA_2048");
    }

    @Test
    void discoverCertificates_keyAlgorithmPresent_doesNotCallGetCertificate() {
        String arn = "arn:aws:acm:us-east-1:123:certificate/managed";
        stubList(arn);
        stubDescribe(CertificateDetail.builder()
                .certificateArn(arn)
                .domainName("managed.example.com")
                .status(CertificateStatus.ISSUED)
                .keyAlgorithm(KeyAlgorithm.RSA_2048)
                .build());

        List<com.certping.agent.model.message.DiscoveredCertEntry> result =
                adapter.discoverCertificates(acmClient, "org-1");

        assertThat(result).hasSize(1);
        assertThat(result.get(0).getKeyAlgorithm()).isEqualTo(KeyAlgorithm.RSA_2048.toString());
        verify(acmClient, never()).getCertificate(any(GetCertificateRequest.class));
    }

    @Test
    void discoverCertificates_getCertificateFails_leavesKeyAlgorithmNull() {
        String arn = "arn:aws:acm:us-east-1:123:certificate/no-perm";
        stubList(arn);
        stubDescribe(CertificateDetail.builder()
                .certificateArn(arn)
                .domainName("no-perm.example.com")
                .status(CertificateStatus.ISSUED)
                .build());
        // e.g. the org's role lacks acm:GetCertificate — scan must still succeed.
        when(acmClient.getCertificate(any(GetCertificateRequest.class)))
                .thenThrow(new RuntimeException("AccessDenied"));

        List<com.certping.agent.model.message.DiscoveredCertEntry> result =
                adapter.discoverCertificates(acmClient, "org-1");

        assertThat(result).hasSize(1);
        assertThat(result.get(0).getKeyAlgorithm()).isNull();
    }

    @Test
    void discoverWithFailedScopes_describeDenied_reportsRegionAsFailedScope() {
        String arn = "arn:aws:acm:us-east-1:123456789012:certificate/denied";
        when(awsCredentialResolver.resolve(any(), any(), any(), eq("AWS ACM Discovery")))
                .thenReturn(credentialsProvider);
        stubList(arn);
        when(acmClient.describeCertificate(any(software.amazon.awssdk.services.acm.model.DescribeCertificateRequest.class)))
                .thenThrow(AcmException.builder().message("AccessDenied").build());
        AwsAcmDiscoveryAdapter spy = org.mockito.Mockito.spy(adapter);
        doReturn(acmClient).when(spy).buildClient(eq("us-east-1"), eq(credentialsProvider));

        com.certping.agent.discovery.DiscoveryResult result = spy.discoverWithFailedScopes(buildMessage(
                "{\"authMode\":\"INSTANCE_PROFILE\",\"region\":\"us-east-1\"}"));

        assertThat(result.certificates()).isEmpty();
        assertThat(result.failedScopes()).singleElement().satisfies(f -> {
            assertThat(f.getScopeType()).isEqualTo(
                    com.certping.agent.model.message.DiscoveryFailedScope.ScopeType.AWS_REGION);
            assertThat(f.getScopeId()).isEqualTo("123456789012/us-east-1");
            assertThat(f.getErrorCode()).isEqualTo("DISCOVERY_ACM_DESCRIBE_FAILED");
        });
    }

    // -------- discover() outer catch blocks ---------------------------------

    @Test
    void discover_acmException_accessDenied_throwsPermanent() {
        AcmException denied = (AcmException) AcmException.builder()
                .message("nope")
                .awsErrorDetails(AwsErrorDetails.builder().errorCode("AccessDeniedException").build())
                .build();
        when(awsCredentialResolver.resolve(any(), any(), any(), eq("AWS ACM Discovery")))
                .thenReturn(credentialsProvider);
        when(acmClient.listCertificates(any(ListCertificatesRequest.class))).thenThrow(denied);

        AwsAcmDiscoveryAdapter spy = org.mockito.Mockito.spy(adapter);
        doReturn(acmClient).when(spy).buildClient(eq("us-east-1"), eq(credentialsProvider));

        assertThatThrownBy(() -> spy.discover(buildMessage(
                "{\"authMode\":\"INSTANCE_PROFILE\",\"region\":\"us-east-1\"}")))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DISCOVERY_ACM_ACCESS_DENIED"));
    }

    @Test
    void discover_acmException_authorizationError_throwsPermanent() {
        AcmException denied = (AcmException) AcmException.builder()
                .message("nope")
                .awsErrorDetails(AwsErrorDetails.builder().errorCode("AuthorizationError").build())
                .build();
        when(awsCredentialResolver.resolve(any(), any(), any(), eq("AWS ACM Discovery")))
                .thenReturn(credentialsProvider);
        when(acmClient.listCertificates(any(ListCertificatesRequest.class))).thenThrow(denied);

        AwsAcmDiscoveryAdapter spy = org.mockito.Mockito.spy(adapter);
        doReturn(acmClient).when(spy).buildClient(eq("us-east-1"), eq(credentialsProvider));

        assertThatThrownBy(() -> spy.discover(buildMessage(
                "{\"authMode\":\"INSTANCE_PROFILE\",\"region\":\"us-east-1\"}")))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DISCOVERY_ACM_ACCESS_DENIED"));
    }

    @Test
    void discover_acmException_otherCode_throwsTransient() {
        AcmException other = (AcmException) AcmException.builder()
                .message("boom")
                .awsErrorDetails(AwsErrorDetails.builder().errorCode("ServiceUnavailable").build())
                .build();
        when(awsCredentialResolver.resolve(any(), any(), any(), eq("AWS ACM Discovery")))
                .thenReturn(credentialsProvider);
        when(acmClient.listCertificates(any(ListCertificatesRequest.class))).thenThrow(other);

        AwsAcmDiscoveryAdapter spy = org.mockito.Mockito.spy(adapter);
        doReturn(acmClient).when(spy).buildClient(eq("us-east-1"), eq(credentialsProvider));

        assertThatThrownBy(() -> spy.discover(buildMessage(
                "{\"authMode\":\"INSTANCE_PROFILE\",\"region\":\"us-east-1\"}")))
                .isInstanceOf(TransientAgentException.class)
                .satisfies(e -> assertThat(((TransientAgentException) e).getErrorCode())
                        .isEqualTo("DISCOVERY_ACM_ERROR"));
    }

    @Test
    void discover_acmException_nullAwsErrorDetails_throwsTransient() {
        AcmException noDetails = (AcmException) AcmException.builder().message("oops").build();
        when(awsCredentialResolver.resolve(any(), any(), any(), eq("AWS ACM Discovery")))
                .thenReturn(credentialsProvider);
        when(acmClient.listCertificates(any(ListCertificatesRequest.class))).thenThrow(noDetails);

        AwsAcmDiscoveryAdapter spy = org.mockito.Mockito.spy(adapter);
        doReturn(acmClient).when(spy).buildClient(eq("us-east-1"), eq(credentialsProvider));

        assertThatThrownBy(() -> spy.discover(buildMessage(
                "{\"authMode\":\"INSTANCE_PROFILE\",\"region\":\"us-east-1\"}")))
                .isInstanceOf(TransientAgentException.class);
    }

    @Test
    void discover_sdkException_throwsTransientSdkError() {
        when(awsCredentialResolver.resolve(any(), any(), any(), eq("AWS ACM Discovery")))
                .thenReturn(credentialsProvider);
        when(acmClient.listCertificates(any(ListCertificatesRequest.class)))
                .thenThrow(SdkClientException.create("connection reset"));

        AwsAcmDiscoveryAdapter spy = org.mockito.Mockito.spy(adapter);
        doReturn(acmClient).when(spy).buildClient(eq("us-east-1"), eq(credentialsProvider));

        assertThatThrownBy(() -> spy.discover(buildMessage(
                "{\"authMode\":\"INSTANCE_PROFILE\",\"region\":\"us-east-1\"}")))
                .isInstanceOf(TransientAgentException.class)
                .satisfies(e -> assertThat(((TransientAgentException) e).getErrorCode())
                        .isEqualTo("DISCOVERY_AWS_SDK_ERROR"));
    }

    @Test
    void discover_permanentAgentException_propagatesUnchanged() {
        when(awsCredentialResolver.resolve(any(), any(), any(), eq("AWS ACM Discovery")))
                .thenReturn(credentialsProvider);
        PermanentAgentException original = new PermanentAgentException("X", "x");
        when(acmClient.listCertificates(any(ListCertificatesRequest.class))).thenThrow(original);

        AwsAcmDiscoveryAdapter spy = org.mockito.Mockito.spy(adapter);
        doReturn(acmClient).when(spy).buildClient(eq("us-east-1"), eq(credentialsProvider));

        assertThatThrownBy(() -> spy.discover(buildMessage(
                "{\"authMode\":\"INSTANCE_PROFILE\",\"region\":\"us-east-1\"}")))
                .isSameAs(original);
    }

    @Test
    void buildClient_returnsAcmClient() {
        // Exercise the production buildClient() factory so its lines are covered.
        AcmClient client = adapter.buildClient("us-east-1", credentialsProvider);
        assertThat(client).isNotNull();
        client.close();
    }

    // -------- discoverCertificates extra branches ---------------------------

    @Test
    void discoverCertificates_describeCertificate_acmException_isSkipped() {
        String arn = "arn:aws:acm:us-east-1:123:certificate/broken";
        stubList(arn);
        when(acmClient.describeCertificate(any(DescribeCertificateRequest.class)))
                .thenThrow(AcmException.builder().message("not found").build());

        List<DiscoveredCertEntry> result = adapter.discoverCertificates(acmClient, "org-1");

        assertThat(result).isEmpty();
    }

    @Test
    void discoverCertificates_paginationUsesNextToken() {
        // First call returns nextToken=p2 + one ARN; second call returns no token + another ARN.
        when(acmClient.listCertificates(any(ListCertificatesRequest.class)))
                .thenReturn(ListCertificatesResponse.builder()
                        .certificateSummaryList(CertificateSummary.builder().certificateArn("arn:1").build())
                        .nextToken("p2")
                        .build())
                .thenReturn(ListCertificatesResponse.builder()
                        .certificateSummaryList(CertificateSummary.builder().certificateArn("arn:2").build())
                        .build());
        when(acmClient.describeCertificate(any(DescribeCertificateRequest.class)))
                .thenReturn(DescribeCertificateResponse.builder()
                        .certificate(CertificateDetail.builder()
                                .certificateArn("arn:x")
                                .keyAlgorithm(KeyAlgorithm.RSA_2048)
                                .build())
                        .build());

        List<DiscoveredCertEntry> result = adapter.discoverCertificates(acmClient, "org-1");

        assertThat(result).hasSize(2);
        verify(acmClient, org.mockito.Mockito.times(2))
                .listCertificates(any(ListCertificatesRequest.class));
    }

    @Test
    void discoverCertificates_fullyPopulatedDetail_mapsAllFields() {
        String arn = "arn:aws:acm:us-east-1:123:certificate/full";
        stubList(arn);
        Instant nb = Instant.parse("2026-01-01T00:00:00Z");
        Instant na = Instant.parse("2027-01-01T00:00:00Z");
        stubDescribe(CertificateDetail.builder()
                .certificateArn(arn)
                .domainName("full.example.com")
                .subject("CN=full.example.com")
                .subjectAlternativeNames("full.example.com", "alt.example.com")
                .keyAlgorithm(KeyAlgorithm.RSA_2048)
                .signatureAlgorithm("SHA256WITHRSA")
                .notBefore(nb)
                .notAfter(na)
                .issuer("Amazon")
                .serial("01:02:03")
                .status(CertificateStatus.ISSUED)
                .inUseBy("arn:aws:cloudfront::123:distribution/E1")
                .keyUsages(KeyUsage.builder().name(KeyUsageName.DIGITAL_SIGNATURE).build(),
                        KeyUsage.builder().name(KeyUsageName.KEY_ENCIPHERMENT).build())
                .extendedKeyUsages(
                        ExtendedKeyUsage.builder().name(ExtendedKeyUsageName.TLS_WEB_SERVER_AUTHENTICATION).build(),
                        ExtendedKeyUsage.builder().name(ExtendedKeyUsageName.NONE).build())
                .type(CertificateType.AMAZON_ISSUED)
                .build());

        List<DiscoveredCertEntry> result = adapter.discoverCertificates(acmClient, "org-1");

        assertThat(result).hasSize(1);
        DiscoveredCertEntry entry = result.get(0);
        assertThat(entry.getSanDomains()).containsExactly("full.example.com", "alt.example.com");
        assertThat(entry.getSignatureAlgorithm()).isEqualTo("SHA256WITHRSA");
        assertThat(entry.getNotBefore()).isEqualTo(nb.toString());
        assertThat(entry.getNotAfter()).isEqualTo(na.toString());
        assertThat(entry.getIssuer()).isEqualTo("Amazon");
        assertThat(entry.getSerialNumber()).isEqualTo("01:02:03");
        assertThat(entry.getCertStatus()).isEqualTo(CertificateStatus.ISSUED.toString());
        assertThat(entry.getInUseBy()).hasSize(1);
        assertThat(entry.getKeyUsage()).contains("DIGITAL_SIGNATURE").contains("KEY_ENCIPHERMENT");
        // ExtendedKeyUsage list filters out "NONE"
        assertThat(entry.getExtendedKeyUsage()).contains("TLS_WEB_SERVER_AUTHENTICATION")
                .doesNotContain("NONE");
        assertThat(entry.getCertType()).isEqualTo(CertificateType.AMAZON_ISSUED.toString());
    }

    @Test
    void discoverCertificates_minimalDetail_nullsOutOptionalFields() {
        String arn = "arn:aws:acm:us-east-1:123:certificate/minimal";
        stubList(arn);
        // No SANs, no inUseBy, no key/ext usages, no dates, no status, no type.
        stubDescribe(CertificateDetail.builder()
                .certificateArn(arn)
                .domainName("min.example.com")
                .build());

        List<DiscoveredCertEntry> result = adapter.discoverCertificates(acmClient, "org-1");

        assertThat(result).hasSize(1);
        DiscoveredCertEntry entry = result.get(0);
        assertThat(entry.getSanDomains()).isNull();
        assertThat(entry.getNotBefore()).isNull();
        assertThat(entry.getNotAfter()).isNull();
        assertThat(entry.getCertStatus()).isNull();
        assertThat(entry.getCertType()).isNull();
    }

    @Test
    void discoverCertificates_blankKeyAlgorithm_nonIssuedStatus_skipsLeafFetch() {
        // status=PENDING_VALIDATION → fallback path (resolveKeyAlgorithmFromLeaf) is NOT taken.
        String arn = "arn:aws:acm:us-east-1:123:certificate/pending";
        stubList(arn);
        stubDescribe(CertificateDetail.builder()
                .certificateArn(arn)
                .domainName("pending.example.com")
                .status(CertificateStatus.PENDING_VALIDATION)
                .build());

        List<DiscoveredCertEntry> result = adapter.discoverCertificates(acmClient, "org-1");

        assertThat(result).hasSize(1);
        assertThat(result.get(0).getKeyAlgorithm()).isNull();
        verify(acmClient, never()).getCertificate(any(GetCertificateRequest.class));
    }

    @Test
    void discoverCertificates_getCertificateReturnsBlankPem_leavesKeyAlgorithmNull() {
        String arn = "arn:aws:acm:us-east-1:123:certificate/blank-pem";
        stubList(arn);
        stubDescribe(CertificateDetail.builder()
                .certificateArn(arn)
                .domainName("blank.example.com")
                .status(CertificateStatus.ISSUED)
                .build());
        when(acmClient.getCertificate(any(GetCertificateRequest.class)))
                .thenReturn(GetCertificateResponse.builder().certificate("").build());

        List<DiscoveredCertEntry> result = adapter.discoverCertificates(acmClient, "org-1");

        assertThat(result).hasSize(1);
        assertThat(result.get(0).getKeyAlgorithm()).isNull();
    }

    private void stubList(String arn) {
        when(acmClient.listCertificates(any(ListCertificatesRequest.class)))
                .thenReturn(ListCertificatesResponse.builder()
                        .certificateSummaryList(CertificateSummary.builder().certificateArn(arn).build())
                        .build());
    }

    private void stubDescribe(CertificateDetail detail) {
        when(acmClient.describeCertificate(any(DescribeCertificateRequest.class)))
                .thenReturn(DescribeCertificateResponse.builder().certificate(detail).build());
    }

    private CertDiscoveryMessage buildMessage(String scopeJson) {
        CertDiscoveryMessage msg = new CertDiscoveryMessage();
        msg.setRequestId("req-test-001");
        msg.setCorrelationId("corr-test-001");
        msg.setOrganizationId("org-123");
        msg.setTargetType(TargetType.AWS_ACM);
        msg.setDeploymentCredHandle("https://kv-test.vault.azure.net/secrets/aws-acm-cred");
        msg.setCredentialScopeJson(scopeJson);
        msg.setRequestedAt("2026-05-05T00:00:00Z");
        return msg;
    }
}
