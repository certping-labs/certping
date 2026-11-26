// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.aws;

import com.certping.agent.deployment.CertificateBundle;
import com.certping.agent.deployment.cloud.aws.AwsCloudCredentialResolver;
import com.certping.agent.deployment.cloud.aws.AwsAuthMode;
import com.certping.agent.deployment.cloud.aws.AwsAuthScope;
import com.certping.agent.deployment.cloud.aws.AwsAuthSecret;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.model.enums.TargetType;
import com.certping.agent.model.message.CertDeploymentMessage;
import com.certping.agent.secrets.SecretStore;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.http.SdkHttpResponse;
import software.amazon.awssdk.services.acm.AcmClient;
import software.amazon.awssdk.services.acm.AcmClientBuilder;
import software.amazon.awssdk.services.acm.model.AcmException;
import software.amazon.awssdk.services.acm.model.DeleteCertificateResponse;
import software.amazon.awssdk.services.acm.model.Tag;
import software.amazon.awssdk.services.cloudfront.CloudFrontClient;
import software.amazon.awssdk.services.cloudfront.CloudFrontClientBuilder;
import software.amazon.awssdk.services.cloudfront.model.CloudFrontException;
import software.amazon.awssdk.services.cloudfront.model.Distribution;
import software.amazon.awssdk.services.cloudfront.model.DistributionConfig;
import software.amazon.awssdk.services.cloudfront.model.GetDistributionConfigResponse;
import software.amazon.awssdk.services.cloudfront.model.GetDistributionResponse;
import software.amazon.awssdk.services.cloudfront.model.MinimumProtocolVersion;
import software.amazon.awssdk.services.cloudfront.model.SSLSupportMethod;
import software.amazon.awssdk.services.cloudfront.model.UpdateDistributionResponse;
import software.amazon.awssdk.services.cloudfront.model.ViewerCertificate;

import java.lang.reflect.Method;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@org.mockito.junit.jupiter.MockitoSettings(strictness = org.mockito.quality.Strictness.LENIENT)
class AwsCloudFrontDeploymentAdapterTest {

    @Mock private SecretStore secretStore;
    @Mock private AwsAcmImportService acmImportService;
    @Mock private AwsCloudCredentialResolver awsCredentialResolver;

    private AwsCloudFrontDeploymentAdapter adapter;

    private static final String OLD_ACM_ARN = "arn:aws:acm:us-east-1:123456789012:certificate/old-uuid";
    private static final String NEW_ACM_ARN = "arn:aws:acm:us-east-1:123456789012:certificate/new-uuid";

    private static final String SCOPE_JSON =
            "{\"authMode\":\"INSTANCE_PROFILE\",\"distributionId\":\"E1ABCD2EFGHIJ\"}";

    @BeforeEach
    void setUp() {
        adapter = new AwsCloudFrontDeploymentAdapter(secretStore, acmImportService, awsCredentialResolver,
                JsonMapper.builderWithJackson2Defaults().build());
    }

    @Test
    void deploy_missingScopeJson_throwsPermanentCredentialInvalid() {
        assertThatThrownBy(() -> adapter.deploy(buildBundle(), buildMessage()))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void deploy_missingDistributionId_throwsPermanentCredentialInvalid() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson("{\"authMode\":\"INSTANCE_PROFILE\"}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"))
                .hasMessageContaining("distributionId");
    }

    @Test
    void deploy_readsCredentialFromKv_evenWhenJsonInvalid() {
        when(secretStore.read(anyString())).thenReturn("not-valid-json");

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class);

        verify(secretStore).read("https://kv-agent.vault.azure.net/secrets/cloudfront-cred");
    }

    @Test
    void deploy_invalidCredentialJson_throwsPermanentCredentialInvalid() {
        when(secretStore.read(anyString())).thenReturn("not-valid-json");

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void deploy_unknownAuthMode_throwsPermanentCredentialInvalid() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson("{\"authMode\":\"MAGIC_AUTH\",\"distributionId\":\"E1ABCD2EFGHIJ\"}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void helper_requireDomain_throwsWhenBlank() throws Exception {
        Method method = AwsCloudFrontDeploymentAdapter.class.getDeclaredMethod(
                "requireDomain", String.class, String.class);
        method.setAccessible(true);

        assertThatThrownBy(() -> method.invoke(adapter, "   ", "xref-1"))
                .hasCauseInstanceOf(PermanentAgentException.class)
                .satisfies(error -> assertThat(((PermanentAgentException) error.getCause()).getErrorCode())
                        .isEqualTo("DEPLOY_DOMAIN_REQUIRED"));
    }

    @Test
    void helper_requireDomain_returnsNormalisedDomain() throws Exception {
        Method method = AwsCloudFrontDeploymentAdapter.class.getDeclaredMethod(
                "requireDomain", String.class, String.class);
        method.setAccessible(true);

        Object domain = method.invoke(adapter, "  cdn.example.com  ", "xref-1");
        assertThat(domain).isEqualTo("cdn.example.com");
    }

    @Test
    void helper_swapCertArn_preservesExistingTlsSettings() {
        ViewerCertificate viewerCertificate = ViewerCertificate.builder()
                .acmCertificateArn(OLD_ACM_ARN)
                .sslSupportMethod(SSLSupportMethod.VIP)
                .minimumProtocolVersion(MinimumProtocolVersion.fromValue("TLSv1.2_2021"))
                .cloudFrontDefaultCertificate(false)
                .build();
        DistributionConfig existing = DistributionConfig.builder()
                .callerReference("caller-ref")
                .viewerCertificate(viewerCertificate)
                .build();

        DistributionConfig updated = adapter.swapCertArn(existing, NEW_ACM_ARN);

        assertThat(updated.viewerCertificate().acmCertificateArn()).isEqualTo(NEW_ACM_ARN);
        assertThat(updated.viewerCertificate().sslSupportMethod()).isEqualTo(SSLSupportMethod.VIP);
        assertThat(updated.viewerCertificate().minimumProtocolVersion())
                .isEqualTo(MinimumProtocolVersion.fromValue("TLSv1.2_2021"));
        assertThat(updated.viewerCertificate().cloudFrontDefaultCertificate()).isFalse();
    }

    @Test
    void helper_requireExistingAcmArn_rejectsDefaultCertificate() throws Exception {
        CloudFrontClient cf = mock(CloudFrontClient.class);
        ViewerCertificate viewerCertificate = ViewerCertificate.builder()
                .cloudFrontDefaultCertificate(true)
                .build();
        DistributionConfig config = DistributionConfig.builder()
                .callerReference("caller-ref")
                .viewerCertificate(viewerCertificate)
                .build();
        when(cf.getDistributionConfig(any(java.util.function.Consumer.class))).thenReturn(
                GetDistributionConfigResponse.builder()
                        .eTag("etag")
                        .distributionConfig(config)
                        .build());

        Method method = AwsCloudFrontDeploymentAdapter.class.getDeclaredMethod(
                "requireExistingAcmArn", CloudFrontClient.class, String.class);
        method.setAccessible(true);

        assertThatThrownBy(() -> method.invoke(adapter, cf, "E1ABC2DEF3GHI4"))
                .hasCauseInstanceOf(PermanentAgentException.class)
                .satisfies(error -> assertThat(((PermanentAgentException) error.getCause()).getErrorCode())
                        .isEqualTo("DEPLOY_CLOUDFRONT_DEFAULT_CERT"));
    }

    @Test
    void helper_requireExistingAcmArn_returnsArnWhenValid() throws Exception {
        CloudFrontClient cf = mock(CloudFrontClient.class);
        ViewerCertificate viewerCertificate = ViewerCertificate.builder()
                .acmCertificateArn("arn:aws:acm:us-east-1:123456789012:certificate/live-uuid")
                .cloudFrontDefaultCertificate(false)
                .build();
        DistributionConfig config = DistributionConfig.builder()
                .callerReference("caller-ref")
                .viewerCertificate(viewerCertificate)
                .build();
        when(cf.getDistributionConfig(any(java.util.function.Consumer.class))).thenReturn(
                GetDistributionConfigResponse.builder()
                        .eTag("etag")
                        .distributionConfig(config)
                        .build());

        Method method = AwsCloudFrontDeploymentAdapter.class.getDeclaredMethod(
                "requireExistingAcmArn", CloudFrontClient.class, String.class);
        method.setAccessible(true);

        Object arn = method.invoke(adapter, cf, "E1ABC2DEF3GHI4");
        assertThat(arn).isEqualTo("arn:aws:acm:us-east-1:123456789012:certificate/live-uuid");
    }

    @Test
    void helper_requireExistingAcmArn_rejectsIamCertificate() throws Exception {
        CloudFrontClient cf = mock(CloudFrontClient.class);
        ViewerCertificate viewerCertificate = ViewerCertificate.builder()
                .iamCertificateId("ASCAEXAMPLE")
                .cloudFrontDefaultCertificate(false)
                .build();
        DistributionConfig distConfig = DistributionConfig.builder()
                .callerReference("ref")
                .viewerCertificate(viewerCertificate)
                .build();
        when(cf.getDistributionConfig(any(java.util.function.Consumer.class))).thenReturn(
                GetDistributionConfigResponse.builder()
                        .eTag("e")
                        .distributionConfig(distConfig)
                        .build());

        Method method = AwsCloudFrontDeploymentAdapter.class.getDeclaredMethod(
                "requireExistingAcmArn", CloudFrontClient.class, String.class);
        method.setAccessible(true);

        assertThatThrownBy(() -> method.invoke(adapter, cf, "E1ID"))
                .hasCauseInstanceOf(PermanentAgentException.class)
                .satisfies(error -> assertThat(((PermanentAgentException) error.getCause()).getErrorCode())
                        .isEqualTo("DEPLOY_CLOUDFRONT_IAM_CERT"));
    }

    @Test
    void helper_requireExistingAcmArn_throwsWhenViewerCertificateNull() throws Exception {
        CloudFrontClient cf = mock(CloudFrontClient.class);
        DistributionConfig config = DistributionConfig.builder()
                .callerReference("caller-ref")
                .build();
        when(cf.getDistributionConfig(any(java.util.function.Consumer.class))).thenReturn(
                GetDistributionConfigResponse.builder()
                        .eTag("e")
                        .distributionConfig(config)
                        .build());

        Method method = AwsCloudFrontDeploymentAdapter.class.getDeclaredMethod(
                "requireExistingAcmArn", CloudFrontClient.class, String.class);
        method.setAccessible(true);

        assertThatThrownBy(() -> method.invoke(adapter, cf, "E1ID"))
                .hasCauseInstanceOf(PermanentAgentException.class)
                .satisfies(error -> assertThat(((PermanentAgentException) error.getCause()).getErrorCode())
                        .isEqualTo("DEPLOY_CLOUDFRONT_INVALID_CONFIG"));
    }

    @Test
    void helper_requireExistingAcmArn_rejectsMissingAcmArn() throws Exception {
        CloudFrontClient cf = mock(CloudFrontClient.class);
        ViewerCertificate viewerCertificate = ViewerCertificate.builder()
                .acmCertificateArn("  ")
                .cloudFrontDefaultCertificate(false)
                .build();
        DistributionConfig distConfig = DistributionConfig.builder()
                .callerReference("ref")
                .viewerCertificate(viewerCertificate)
                .build();
        when(cf.getDistributionConfig(any(java.util.function.Consumer.class))).thenReturn(
                GetDistributionConfigResponse.builder()
                        .eTag("e")
                        .distributionConfig(distConfig)
                        .build());

        Method method = AwsCloudFrontDeploymentAdapter.class.getDeclaredMethod(
                "requireExistingAcmArn", CloudFrontClient.class, String.class);
        method.setAccessible(true);

        assertThatThrownBy(() -> method.invoke(adapter, cf, "E1ID"))
                .hasCauseInstanceOf(PermanentAgentException.class)
                .satisfies(error -> assertThat(((PermanentAgentException) error.getCause()).getErrorCode())
                        .isEqualTo("DEPLOY_CLOUDFRONT_INVALID_CONFIG"));
    }

    @Test
    void helper_updateDistributionWithRetry_retriesOnPreconditionFailed() throws Exception {
        CloudFrontClient cf = mock(CloudFrontClient.class);
        when(cf.getDistributionConfig(any(java.util.function.Consumer.class))).thenReturn(
                distConfigResponseWithAcmArn(OLD_ACM_ARN));

        AtomicInteger updateCalls = new AtomicInteger();
        when(cf.updateDistribution(any(java.util.function.Consumer.class))).thenAnswer(inv -> {
            if (updateCalls.incrementAndGet() == 1) {
                CloudFrontException ex = mock(CloudFrontException.class);
                when(ex.awsErrorDetails()).thenReturn(
                        AwsErrorDetails.builder().errorCode("PreconditionFailed").build());
                throw ex;
            }
            return UpdateDistributionResponse.builder()
                    .distribution(Distribution.builder().id("E1ID").status("InProgress").build())
                    .build();
        });

        Method method = AwsCloudFrontDeploymentAdapter.class.getDeclaredMethod(
                "updateDistributionWithRetry", CloudFrontClient.class, String.class, String.class);
        method.setAccessible(true);

        method.invoke(adapter, cf, "E1ID", NEW_ACM_ARN);

        verify(cf, Mockito.times(2)).updateDistribution(any(java.util.function.Consumer.class));
    }

    @Test
    void helper_updateDistributionWithRetry_transientOnAccessDenied() throws Exception {
        CloudFrontClient cf = mock(CloudFrontClient.class);
        when(cf.getDistributionConfig(any(java.util.function.Consumer.class))).thenReturn(
                distConfigResponseWithAcmArn(OLD_ACM_ARN));

        CloudFrontException ex = mock(CloudFrontException.class);
        when(ex.awsErrorDetails()).thenReturn(AwsErrorDetails.builder().errorCode("AccessDenied").build());
        when(ex.getMessage()).thenReturn("denied");
        when(cf.updateDistribution(any(java.util.function.Consumer.class))).thenThrow(ex);

        Method method = AwsCloudFrontDeploymentAdapter.class.getDeclaredMethod(
                "updateDistributionWithRetry", CloudFrontClient.class, String.class, String.class);
        method.setAccessible(true);

        assertThatThrownBy(() -> method.invoke(adapter, cf, "E1ID", NEW_ACM_ARN))
                .hasCauseInstanceOf(TransientAgentException.class);
    }

    @Test
    void helper_updateDistributionWithRetry_transientOnSdkClientException() throws Exception {
        CloudFrontClient cf = mock(CloudFrontClient.class);
        when(cf.getDistributionConfig(any(java.util.function.Consumer.class))).thenReturn(
                distConfigResponseWithAcmArn(OLD_ACM_ARN));
        when(cf.updateDistribution(any(java.util.function.Consumer.class)))
                .thenThrow(SdkClientException.create("network error"));

        Method method = AwsCloudFrontDeploymentAdapter.class.getDeclaredMethod(
                "updateDistributionWithRetry", CloudFrontClient.class, String.class, String.class);
        method.setAccessible(true);

        assertThatThrownBy(() -> method.invoke(adapter, cf, "E1ID", NEW_ACM_ARN))
                .hasCauseInstanceOf(TransientAgentException.class);
    }

    @Test
    void helper_ensureDistributionUsesCert_throwsWhenArnMismatch() throws Exception {
        CloudFrontClient cf = mock(CloudFrontClient.class);
        when(cf.getDistributionConfig(any(java.util.function.Consumer.class))).thenReturn(
                distConfigResponseWithAcmArn(OLD_ACM_ARN));

        Method method = AwsCloudFrontDeploymentAdapter.class.getDeclaredMethod(
                "ensureDistributionUsesCert", CloudFrontClient.class, String.class, String.class);
        method.setAccessible(true);

        assertThatThrownBy(() -> method.invoke(adapter, cf, "E1ID", NEW_ACM_ARN))
                .hasCauseInstanceOf(PermanentAgentException.class)
                .satisfies(error -> assertThat(((PermanentAgentException) error.getCause()).getErrorCode())
                        .isEqualTo("DEPLOY_CLOUDFRONT_VERIFY_FAILED"));
    }

    @Test
    void helper_ensureDistributionUsesCert_noOpWhenMatch() throws Exception {
        CloudFrontClient cf = mock(CloudFrontClient.class);
        when(cf.getDistributionConfig(any(java.util.function.Consumer.class))).thenReturn(
                distConfigResponseWithAcmArn(NEW_ACM_ARN));

        Method method = AwsCloudFrontDeploymentAdapter.class.getDeclaredMethod(
                "ensureDistributionUsesCert", CloudFrontClient.class, String.class, String.class);
        method.setAccessible(true);

        method.invoke(adapter, cf, "E1ID", NEW_ACM_ARN);
        verify(cf).getDistributionConfig(any(java.util.function.Consumer.class));
    }

    @Test
    void helper_waitForDeployed_returnsWhenStatusDeployed() throws Exception {
        CloudFrontClient cf = mock(CloudFrontClient.class);
        when(cf.getDistribution(any(java.util.function.Consumer.class))).thenReturn(
                GetDistributionResponse.builder()
                        .distribution(Distribution.builder().id("E1ID").status("Deployed").build())
                        .build());

        AwsCloudFrontDeploymentAdapter spyAdapter = Mockito.spy(adapter);
        Mockito.doNothing().when(spyAdapter).sleepForDeployPoll();

        Method method = AwsCloudFrontDeploymentAdapter.class.getDeclaredMethod(
                "waitForDeployed", CloudFrontClient.class, String.class);
        method.setAccessible(true);

        method.invoke(spyAdapter, cf, "E1ID");

        verify(cf).getDistribution(any(java.util.function.Consumer.class));
    }

    @Test
    void helper_waitForDeployed_timesOut() throws Exception {
        CloudFrontClient cf = mock(CloudFrontClient.class);
        when(cf.getDistribution(any(java.util.function.Consumer.class))).thenReturn(
                GetDistributionResponse.builder()
                        .distribution(Distribution.builder().id("E1ID").status("InProgress").build())
                        .build());

        AwsCloudFrontDeploymentAdapter spyAdapter = Mockito.spy(adapter);
        Mockito.doNothing().when(spyAdapter).sleepForDeployPoll();

        Method method = AwsCloudFrontDeploymentAdapter.class.getDeclaredMethod(
                "waitForDeployed", CloudFrontClient.class, String.class);
        method.setAccessible(true);

        assertThatThrownBy(() -> method.invoke(spyAdapter, cf, "E1ID"))
                .hasCauseInstanceOf(TransientAgentException.class)
                .satisfies(error -> assertThat(((TransientAgentException) error.getCause()).getErrorCode())
                        .isEqualTo("DEPLOY_CLOUDFRONT_TIMEOUT"));
    }

    @Test
    void helper_deleteOldCert_logsWarningOnAcmException() throws Exception {
        AcmClient acm = mock(AcmClient.class);
        when(acm.deleteCertificate(any(java.util.function.Consumer.class)))
                .thenThrow(AcmException.builder().message("cannot delete").build());

        Method method = AwsCloudFrontDeploymentAdapter.class.getDeclaredMethod(
                "deleteOldCert", AcmClient.class, String.class);
        method.setAccessible(true);

        method.invoke(adapter, acm, OLD_ACM_ARN);

        verify(acm).deleteCertificate(any(java.util.function.Consumer.class));
    }

    @Test
    void helper_deleteOldCert_deletesArn() throws Exception {
        AcmClient acm = mock(AcmClient.class);
        lenient().when(acm.deleteCertificate(any(java.util.function.Consumer.class)))
                .thenReturn(DeleteCertificateResponse.builder().build());

        Method method = AwsCloudFrontDeploymentAdapter.class.getDeclaredMethod(
                "deleteOldCert", AcmClient.class, String.class);
        method.setAccessible(true);

        method.invoke(adapter, acm, OLD_ACM_ARN);

        verify(acm).deleteCertificate(any(java.util.function.Consumer.class));
    }

    @Test
    void helper_buildTags_includesDomainTagWhenDomainPresent() throws Exception {
        Method method = AwsCloudFrontDeploymentAdapter.class.getDeclaredMethod(
                "buildTags", String.class, CertDeploymentMessage.class);
        method.setAccessible(true);

        CertDeploymentMessage msg = new CertDeploymentMessage();
        msg.setOrganizationId("org-1");

        @SuppressWarnings("unchecked")
        List<Tag> tags = (List<Tag>) method.invoke(adapter, "cdn.example.com", msg);

        assertThat(tags).hasSize(3);
        assertThat(tags.stream().anyMatch(t -> "Domain".equals(t.key()) && "cdn.example.com".equals(t.value())))
                .isTrue();
    }

    @Test
    void helper_buildTags_omitsDomainTagWhenBlank() throws Exception {
        Method method = AwsCloudFrontDeploymentAdapter.class.getDeclaredMethod(
                "buildTags", String.class, CertDeploymentMessage.class);
        method.setAccessible(true);

        CertDeploymentMessage msg = new CertDeploymentMessage();

        @SuppressWarnings("unchecked")
        List<Tag> tags = (List<Tag>) method.invoke(adapter, "", msg);

        assertThat(tags).hasSize(2);
        assertThat(tags.stream().noneMatch(t -> "Domain".equals(t.key()))).isTrue();
    }

    @Test
    void helper_parseArn_returnsArnWhenPresent() throws Exception {
        Method m = AwsCloudFrontDeploymentAdapter.class.getDeclaredMethod("parsePriorArn", String.class);
        m.setAccessible(true);

        String arn = (String) m.invoke(adapter, "{\"arn\":\"" + NEW_ACM_ARN + "\"}");
        assertThat(arn).isEqualTo(NEW_ACM_ARN);
    }

    @Test
    void helper_toResultJson_roundTripsArnKey() throws Exception {
        Method toJson = AwsCloudFrontDeploymentAdapter.class.getDeclaredMethod("toResultJson", String.class);
        Method parse = AwsCloudFrontDeploymentAdapter.class.getDeclaredMethod("parsePriorArn", String.class);
        toJson.setAccessible(true);
        parse.setAccessible(true);

        String json = (String) toJson.invoke(adapter, NEW_ACM_ARN);
        String parsed = (String) parse.invoke(adapter, json);
        assertThat(parsed).isEqualTo(NEW_ACM_ARN);
    }

    @Test
    void deploy_cloudFrontThrottled_throwsRetryableWithRetryAfter() {
        // Arrange: rotation path (existing ARN present) so we skip requireExistingAcmArn and go
        // straight to updateDistributionWithRetry, where CloudFront throws a throttle.
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(mock(AwsCredentialsProvider.class));
        when(acmImportService.importCertificate(any(), anyString(), any(), any(), any()))
                .thenReturn(NEW_ACM_ARN);

        CloudFrontClient mockCfClient = mock(CloudFrontClient.class);
        // getDistributionConfig is called both before update (to fetch ETag) and possibly after.
        when(mockCfClient.getDistributionConfig(any(java.util.function.Consumer.class)))
                .thenReturn(distConfigResponseWithAcmArn(OLD_ACM_ARN));

        SdkHttpResponse httpResp = SdkHttpResponse.builder()
                .statusCode(400)
                .headers(Map.of("Retry-After", List.of("60")))
                .build();
        CloudFrontException throttle = (CloudFrontException) CloudFrontException.builder()
                .message("Rate exceeded")
                .statusCode(400)
                .awsErrorDetails(AwsErrorDetails.builder()
                        .errorCode("Throttling")
                        .errorMessage("Rate exceeded")
                        .sdkHttpResponse(httpResp)
                        .build())
                .build();
        when(mockCfClient.updateDistribution(any(java.util.function.Consumer.class))).thenThrow(throttle);

        CloudFrontClientBuilder cfBuilder = mock(CloudFrontClientBuilder.class, RETURNS_SELF);
        when(cfBuilder.build()).thenReturn(mockCfClient);

        AcmClient mockAcmClient = mock(AcmClient.class);
        AcmClientBuilder acmBuilder = mock(AcmClientBuilder.class, RETURNS_SELF);
        when(acmBuilder.build()).thenReturn(mockAcmClient);

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setConfigJson("{\"arn\":\"" + OLD_ACM_ARN + "\"}"); // rotation

        try (MockedStatic<CloudFrontClient> cfStatic = mockStatic(CloudFrontClient.class);
             MockedStatic<AcmClient> acmStatic = mockStatic(AcmClient.class)) {
            cfStatic.when(CloudFrontClient::builder).thenReturn(cfBuilder);
            acmStatic.when(AcmClient::builder).thenReturn(acmBuilder);

            assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                    .isInstanceOf(RetryableAgentException.class)
                    .satisfies(ex -> {
                        assertThat(((RetryableAgentException) ex).getErrorCode())
                                .isEqualTo("DEPLOY_PROVIDER_THROTTLED");
                        assertThat(((RetryableAgentException) ex).getRetryAfter())
                                .isEqualTo(Duration.ofSeconds(60));
                    });
        }
    }

    @Test
    void deploy_invalidScopeJson_throwsPermanent() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson("not-valid-json");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void deploy_blankDomain_throwsPermanent() {
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(mock(AwsCredentialsProvider.class));

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setDomain("  ");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_DOMAIN_REQUIRED"));
    }

    @Test
    void helper_parsePriorArn_blankJson_returnsNull() throws Exception {
        java.lang.reflect.Method m = AwsCloudFrontDeploymentAdapter.class.getDeclaredMethod("parsePriorArn", String.class);
        m.setAccessible(true);
        assertThat(m.invoke(adapter, "")).isNull();
        assertThat(m.invoke(adapter, (Object) null)).isNull();
    }

    @Test
    void helper_parsePriorArn_invalidJson_returnsNull() throws Exception {
        java.lang.reflect.Method m = AwsCloudFrontDeploymentAdapter.class.getDeclaredMethod("parsePriorArn", String.class);
        m.setAccessible(true);
        assertThat(m.invoke(adapter, "not-json")).isNull();
    }

    @Test
    void helper_parsePriorArn_missingArnKey_returnsNull() throws Exception {
        java.lang.reflect.Method m = AwsCloudFrontDeploymentAdapter.class.getDeclaredMethod("parsePriorArn", String.class);
        m.setAccessible(true);
        assertThat(m.invoke(adapter, "{\"other\":\"value\"}")).isNull();
    }

    @Test
    void helper_getDistributionCertArn_sdkException_returnsNull() throws Exception {
        CloudFrontClient cf = mock(CloudFrontClient.class);
        when(cf.getDistributionConfig(any(java.util.function.Consumer.class)))
                .thenThrow(software.amazon.awssdk.core.exception.SdkClientException.create("net"));

        java.lang.reflect.Method m = AwsCloudFrontDeploymentAdapter.class.getDeclaredMethod(
                "getDistributionCertArn", CloudFrontClient.class, String.class);
        m.setAccessible(true);
        assertThat(m.invoke(adapter, cf, "E1")).isNull();
    }

    @Test
    void helper_getDistributionCertArn_returnsArn() throws Exception {
        CloudFrontClient cf = mock(CloudFrontClient.class);
        when(cf.getDistributionConfig(any(java.util.function.Consumer.class)))
                .thenReturn(distConfigResponseWithAcmArn(NEW_ACM_ARN));

        java.lang.reflect.Method m = AwsCloudFrontDeploymentAdapter.class.getDeclaredMethod(
                "getDistributionCertArn", CloudFrontClient.class, String.class);
        m.setAccessible(true);
        assertThat(m.invoke(adapter, cf, "E1")).isEqualTo(NEW_ACM_ARN);
    }

    @Test
    void helper_updateDistributionWithRetry_failsAfterMaxAttempts_onPreconditionFailed() throws Exception {
        CloudFrontClient cf = mock(CloudFrontClient.class);
        when(cf.getDistributionConfig(any(java.util.function.Consumer.class)))
                .thenReturn(distConfigResponseWithAcmArn(OLD_ACM_ARN));

        CloudFrontException ex = mock(CloudFrontException.class);
        when(ex.awsErrorDetails()).thenReturn(AwsErrorDetails.builder().errorCode("PreconditionFailed").build());
        lenient().when(ex.getMessage()).thenReturn("etag");
        when(cf.updateDistribution(any(java.util.function.Consumer.class))).thenThrow(ex);

        java.lang.reflect.Method method = AwsCloudFrontDeploymentAdapter.class.getDeclaredMethod(
                "updateDistributionWithRetry", CloudFrontClient.class, String.class, String.class);
        method.setAccessible(true);

        assertThatThrownBy(() -> method.invoke(adapter, cf, "E1ID", NEW_ACM_ARN))
                .hasCauseInstanceOf(TransientAgentException.class);
    }

    @Test
    void deploy_outerCatch_genericException_throwsPermanentCloudFrontFailed() {
        // Force ACM import to succeed but the CloudFront builder to blow up with a generic
        // RuntimeException — exercises the bottom of the deploy() outer catch (no rate-limit
        // verdicts) which wraps as PermanentAgentException("DEPLOY_CLOUDFRONT_FAILED").
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(mock(AwsCredentialsProvider.class));
        when(acmImportService.importCertificate(any(), anyString(), any(), any(), any()))
                .thenReturn(NEW_ACM_ARN);

        CloudFrontClientBuilder cfBuilder = mock(CloudFrontClientBuilder.class, RETURNS_SELF);
        when(cfBuilder.build()).thenThrow(new IllegalStateException("CF builder boom"));

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);

        try (MockedStatic<CloudFrontClient> cfStatic = mockStatic(CloudFrontClient.class)) {
            cfStatic.when(CloudFrontClient::builder).thenReturn(cfBuilder);

            assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("DEPLOY_CLOUDFRONT_FAILED"));
        }
    }

    @Test
    void deploy_outerCatch_classifyThrottle_throwsRetryable() {
        // Wrap a throttle-shaped throwable that ISN'T AwsServiceException — exercises the
        // RateLimitClassifier.classify path inside the outer catch.
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(mock(AwsCredentialsProvider.class));
        when(acmImportService.importCertificate(any(), anyString(), any(), any(), any()))
                .thenReturn(NEW_ACM_ARN);

        CloudFrontClientBuilder cfBuilder = mock(CloudFrontClientBuilder.class, RETURNS_SELF);
        when(cfBuilder.build()).thenThrow(new RuntimeException("rate limit exceeded, try again later"));

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);

        try (MockedStatic<CloudFrontClient> cfStatic = mockStatic(CloudFrontClient.class)) {
            cfStatic.when(CloudFrontClient::builder).thenReturn(cfBuilder);

            assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                    .isInstanceOf(RetryableAgentException.class)
                    .satisfies(e -> assertThat(((RetryableAgentException) e).getErrorCode())
                            .isEqualTo("DEPLOY_PROVIDER_THROTTLED"));
        }
    }

    @Test
    void helper_updateDistributionWithRetry_sdkException_throttle_throwsRetryable() throws Exception {
        // SdkException catch → AwsServiceException-instance throttle branch.
        CloudFrontClient cf = mock(CloudFrontClient.class);
        when(cf.getDistributionConfig(any(java.util.function.Consumer.class))).thenReturn(
                distConfigResponseWithAcmArn(OLD_ACM_ARN));

        // A subtype of AwsServiceException that is NOT a CloudFrontException — falls into the
        // SdkException catch (since CloudFrontException is caught first).
        SdkHttpResponse httpResp = SdkHttpResponse.builder()
                .statusCode(429)
                .headers(Map.of("Retry-After", List.of("15")))
                .build();
        software.amazon.awssdk.awscore.exception.AwsServiceException ase =
                software.amazon.awssdk.awscore.exception.AwsServiceException.builder()
                .message("Rate exceeded")
                .statusCode(429)
                .awsErrorDetails(AwsErrorDetails.builder()
                        .errorCode("Throttling")
                        .sdkHttpResponse(httpResp)
                        .build())
                .build();
        when(cf.updateDistribution(any(java.util.function.Consumer.class))).thenThrow(ase);

        Method method = AwsCloudFrontDeploymentAdapter.class.getDeclaredMethod(
                "updateDistributionWithRetry", CloudFrontClient.class, String.class, String.class);
        method.setAccessible(true);

        assertThatThrownBy(() -> method.invoke(adapter, cf, "E1ID", NEW_ACM_ARN))
                .hasCauseInstanceOf(RetryableAgentException.class);
    }

    @Test
    void helper_updateDistributionWithRetry_sdkException_classifyThrottle_throwsRetryable() throws Exception {
        // SdkException whose message looks like a throttle but is NOT an AwsServiceException —
        // exercises the RateLimitClassifier.classify path inside the SdkException catch.
        CloudFrontClient cf = mock(CloudFrontClient.class);
        when(cf.getDistributionConfig(any(java.util.function.Consumer.class))).thenReturn(
                distConfigResponseWithAcmArn(OLD_ACM_ARN));
        when(cf.updateDistribution(any(java.util.function.Consumer.class)))
                .thenThrow(SdkClientException.create("too many requests"));

        Method method = AwsCloudFrontDeploymentAdapter.class.getDeclaredMethod(
                "updateDistributionWithRetry", CloudFrontClient.class, String.class, String.class);
        method.setAccessible(true);

        assertThatThrownBy(() -> method.invoke(adapter, cf, "E1ID", NEW_ACM_ARN))
                .hasCauseInstanceOf(RetryableAgentException.class);
    }

    @Test
    void helper_updateDistributionWithRetry_cloudFrontExceptionThrottle_throwsRetryable() throws Exception {
        // CloudFrontException catch with a throttle code → RateLimitClassifier.fromAws path.
        CloudFrontClient cf = mock(CloudFrontClient.class);
        when(cf.getDistributionConfig(any(java.util.function.Consumer.class))).thenReturn(
                distConfigResponseWithAcmArn(OLD_ACM_ARN));

        SdkHttpResponse httpResp = SdkHttpResponse.builder()
                .statusCode(400)
                .headers(Map.of("Retry-After", List.of("5")))
                .build();
        CloudFrontException throttle = (CloudFrontException) CloudFrontException.builder()
                .message("Throttling")
                .statusCode(400)
                .awsErrorDetails(AwsErrorDetails.builder()
                        .errorCode("Throttling")
                        .sdkHttpResponse(httpResp)
                        .build())
                .build();
        when(cf.updateDistribution(any(java.util.function.Consumer.class))).thenThrow(throttle);

        Method method = AwsCloudFrontDeploymentAdapter.class.getDeclaredMethod(
                "updateDistributionWithRetry", CloudFrontClient.class, String.class, String.class);
        method.setAccessible(true);

        assertThatThrownBy(() -> method.invoke(adapter, cf, "E1ID", NEW_ACM_ARN))
                .hasCauseInstanceOf(RetryableAgentException.class);
    }

    @Test
    void deploy_happyPath_rotation_updatesDistributionAndReturnsArn() {
        // Full happy-path through the rotation branch: existingArn != newArn so updateDistribution
        // runs; waitForDeployed and ensureDistributionUsesCert both pass.
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(mock(AwsCredentialsProvider.class));
        when(acmImportService.importCertificate(any(), anyString(), any(), any(), any()))
                .thenReturn(NEW_ACM_ARN);

        CloudFrontClient mockCf = mock(CloudFrontClient.class);
        // getDistributionConfig is called 3+ times: pre-update equality check, update fetch, post-update verify.
        when(mockCf.getDistributionConfig(any(java.util.function.Consumer.class)))
                .thenReturn(distConfigResponseWithAcmArn(OLD_ACM_ARN))  // currentArn != desired → update
                .thenReturn(distConfigResponseWithAcmArn(OLD_ACM_ARN))  // fetch in update loop
                .thenReturn(distConfigResponseWithAcmArn(NEW_ACM_ARN)); // verify after update
        when(mockCf.updateDistribution(any(java.util.function.Consumer.class)))
                .thenReturn(UpdateDistributionResponse.builder()
                        .distribution(Distribution.builder().id("E1ID").status("InProgress").build())
                        .build());
        when(mockCf.getDistribution(any(java.util.function.Consumer.class)))
                .thenReturn(GetDistributionResponse.builder()
                        .distribution(Distribution.builder().id("E1ID").status("Deployed").build())
                        .build());

        CloudFrontClientBuilder cfBuilder = mock(CloudFrontClientBuilder.class, RETURNS_SELF);
        when(cfBuilder.build()).thenReturn(mockCf);

        AcmClient mockAcm = mock(AcmClient.class);
        AcmClientBuilder acmBuilder = mock(AcmClientBuilder.class, RETURNS_SELF);
        when(acmBuilder.build()).thenReturn(mockAcm);

        AwsCloudFrontDeploymentAdapter spyAdapter = Mockito.spy(adapter);
        try {
            Mockito.doNothing().when(spyAdapter).sleepForDeployPoll();
        } catch (InterruptedException ignored) { }

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setConfigJson("{\"arn\":\"" + OLD_ACM_ARN + "\"}"); // rotation (skip requireExistingAcmArn)

        try (MockedStatic<CloudFrontClient> cfStatic = mockStatic(CloudFrontClient.class);
             MockedStatic<AcmClient> acmStatic = mockStatic(AcmClient.class)) {
            cfStatic.when(CloudFrontClient::builder).thenReturn(cfBuilder);
            acmStatic.when(AcmClient::builder).thenReturn(acmBuilder);

            assertThat(spyAdapter.deploy(buildBundle(), msg).targetResourceId())
                    .isEqualTo(NEW_ACM_ARN);
            verify(mockCf).updateDistribution(any(java.util.function.Consumer.class));
        }
    }

    @Test
    void deploy_happyPath_rotation_arnUnchanged_skipsUpdate() {
        // Rotation but desired arn equals existing-distribution arn → update is skipped entirely.
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(mock(AwsCredentialsProvider.class));
        when(acmImportService.importCertificate(any(), anyString(), any(), any(), any()))
                .thenReturn(NEW_ACM_ARN);

        CloudFrontClient mockCf = mock(CloudFrontClient.class);
        // getDistributionCertArn returns NEW_ACM_ARN → equality holds → skip update.
        when(mockCf.getDistributionConfig(any(java.util.function.Consumer.class)))
                .thenReturn(distConfigResponseWithAcmArn(NEW_ACM_ARN));

        CloudFrontClientBuilder cfBuilder = mock(CloudFrontClientBuilder.class, RETURNS_SELF);
        when(cfBuilder.build()).thenReturn(mockCf);

        AcmClient mockAcm = mock(AcmClient.class);
        AcmClientBuilder acmBuilder = mock(AcmClientBuilder.class, RETURNS_SELF);
        when(acmBuilder.build()).thenReturn(mockAcm);

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setConfigJson("{\"arn\":\"" + OLD_ACM_ARN + "\"}"); // rotation

        try (MockedStatic<CloudFrontClient> cfStatic = mockStatic(CloudFrontClient.class);
             MockedStatic<AcmClient> acmStatic = mockStatic(AcmClient.class)) {
            cfStatic.when(CloudFrontClient::builder).thenReturn(cfBuilder);
            acmStatic.when(AcmClient::builder).thenReturn(acmBuilder);

            assertThat(adapter.deploy(buildBundle(), msg).targetResourceId()).isEqualTo(NEW_ACM_ARN);
            verify(mockCf, never()).updateDistribution(any(java.util.function.Consumer.class));
        }
    }

    @Test
    void deploy_firstDeploy_importsWithTagsAndDeletesOldCert() {
        // First-deploy path: no prior configJson.arn → isFirstDeploy=true.
        // Call sequence to mockCf.getDistributionConfig:
        //   1) requireExistingAcmArn (returns OLD as the pre-existing distribution cert)
        //   2) [SKIPPED] getDistributionCertArn — short-circuited because isFirstDeploy=true
        //   3) updateDistributionWithRetry inner fetch (returns OLD → we swap+update)
        //   4) ensureDistributionUsesCert (must return NEW to pass verification)
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(mock(AwsCredentialsProvider.class));
        when(acmImportService.importCertificate(any(), anyString(), any(),
                org.mockito.ArgumentMatchers.isNull(), any()))
                .thenReturn(NEW_ACM_ARN);

        CloudFrontClient mockCf = mock(CloudFrontClient.class);
        when(mockCf.getDistributionConfig(any(java.util.function.Consumer.class)))
                .thenReturn(distConfigResponseWithAcmArn(OLD_ACM_ARN))  // #1 requireExistingAcmArn
                .thenReturn(distConfigResponseWithAcmArn(OLD_ACM_ARN))  // #2 updateDistributionWithRetry inner fetch
                .thenReturn(distConfigResponseWithAcmArn(NEW_ACM_ARN)); // #3 ensureDistributionUsesCert
        when(mockCf.updateDistribution(any(java.util.function.Consumer.class)))
                .thenReturn(UpdateDistributionResponse.builder()
                        .distribution(Distribution.builder().id("E1ID").status("InProgress").build())
                        .build());
        when(mockCf.getDistribution(any(java.util.function.Consumer.class)))
                .thenReturn(GetDistributionResponse.builder()
                        .distribution(Distribution.builder().id("E1ID").status("Deployed").build())
                        .build());

        CloudFrontClientBuilder cfBuilder = mock(CloudFrontClientBuilder.class, RETURNS_SELF);
        when(cfBuilder.build()).thenReturn(mockCf);

        AcmClient mockAcm = mock(AcmClient.class);
        lenient().when(mockAcm.deleteCertificate(any(java.util.function.Consumer.class)))
                .thenReturn(DeleteCertificateResponse.builder().build());
        AcmClientBuilder acmBuilder = mock(AcmClientBuilder.class, RETURNS_SELF);
        when(acmBuilder.build()).thenReturn(mockAcm);

        AwsCloudFrontDeploymentAdapter spyAdapter = Mockito.spy(adapter);
        try {
            Mockito.doNothing().when(spyAdapter).sleepForDeployPoll();
        } catch (InterruptedException ignored) { }

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setConfigJson(null); // isFirstDeploy=true

        try (MockedStatic<CloudFrontClient> cfStatic = mockStatic(CloudFrontClient.class);
             MockedStatic<AcmClient> acmStatic = mockStatic(AcmClient.class)) {
            cfStatic.when(CloudFrontClient::builder).thenReturn(cfBuilder);
            acmStatic.when(AcmClient::builder).thenReturn(acmBuilder);

            assertThat(spyAdapter.deploy(buildBundle(), msg).targetResourceId())
                    .isEqualTo(NEW_ACM_ARN);
            verify(mockCf).updateDistribution(any(java.util.function.Consumer.class));
            // deleteOldCert runs: isFirstDeploy && oldArn != null && !oldArn.equals(desiredArn)
            verify(mockAcm).deleteCertificate(any(java.util.function.Consumer.class));
        }
    }

    @Test
    void deploy_firstDeploy_oldArnEqualsNewArn_skipsDeleteOldCert() {
        // First-deploy where the pre-existing distribution ARN happens to equal the freshly-imported
        // ARN — the deleteOldCert branch (oldArn != null && !oldArn.equals(desiredArn)) is skipped.
        //
        // Call sequence: requireExistingAcmArn (returns NEW), updateDistributionWithRetry inner
        // fetch (returns NEW), ensureDistributionUsesCert (returns NEW). Update still runs because
        // isFirstDeploy short-circuits the `||`.
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(mock(AwsCredentialsProvider.class));
        when(acmImportService.importCertificate(any(), anyString(), any(),
                org.mockito.ArgumentMatchers.isNull(), any()))
                .thenReturn(NEW_ACM_ARN);

        CloudFrontClient mockCf = mock(CloudFrontClient.class);
        when(mockCf.getDistributionConfig(any(java.util.function.Consumer.class)))
                .thenReturn(distConfigResponseWithAcmArn(NEW_ACM_ARN));
        when(mockCf.updateDistribution(any(java.util.function.Consumer.class)))
                .thenReturn(UpdateDistributionResponse.builder()
                        .distribution(Distribution.builder().id("E1ID").status("InProgress").build())
                        .build());
        when(mockCf.getDistribution(any(java.util.function.Consumer.class)))
                .thenReturn(GetDistributionResponse.builder()
                        .distribution(Distribution.builder().id("E1ID").status("Deployed").build())
                        .build());

        CloudFrontClientBuilder cfBuilder = mock(CloudFrontClientBuilder.class, RETURNS_SELF);
        when(cfBuilder.build()).thenReturn(mockCf);

        AcmClient mockAcm = mock(AcmClient.class);
        AcmClientBuilder acmBuilder = mock(AcmClientBuilder.class, RETURNS_SELF);
        when(acmBuilder.build()).thenReturn(mockAcm);

        AwsCloudFrontDeploymentAdapter spyAdapter = Mockito.spy(adapter);
        try {
            Mockito.doNothing().when(spyAdapter).sleepForDeployPoll();
        } catch (InterruptedException ignored) { }

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setConfigJson(""); // blank → isFirstDeploy=true via existingArn.isBlank()

        try (MockedStatic<CloudFrontClient> cfStatic = mockStatic(CloudFrontClient.class);
             MockedStatic<AcmClient> acmStatic = mockStatic(AcmClient.class)) {
            cfStatic.when(CloudFrontClient::builder).thenReturn(cfBuilder);
            acmStatic.when(AcmClient::builder).thenReturn(acmBuilder);

            assertThat(spyAdapter.deploy(buildBundle(), msg).targetResourceId()).isEqualTo(NEW_ACM_ARN);
            // deleteOldCert is skipped because oldArn.equals(desiredArn).
            verify(mockAcm, never()).deleteCertificate(any(java.util.function.Consumer.class));
        }
    }

    private CertDeploymentMessage buildMessage() {
        CertDeploymentMessage msg = new CertDeploymentMessage();
        msg.setRequestId("req-cf-1");
        msg.setOrganizationId("organization-1");
        msg.setCertificateXref("xref-1");
        msg.setDomain("cdn.example.com");
        msg.setCertSecretHandle("https://kv.vault.azure.net/secrets/cert-xref-1");
        msg.setTargetType(TargetType.AWS_CLOUDFRONT);
        msg.setDeploymentCredHandle("https://kv-agent.vault.azure.net/secrets/cloudfront-cred");
        return msg;
    }

    private CertificateBundle buildBundle() {
        return new CertificateBundle(
                "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg==\n-----END PRIVATE KEY-----",
                "-----BEGIN CERTIFICATE-----\nMIILeaf==\n-----END CERTIFICATE-----",
                "-----BEGIN CERTIFICATE-----\nMIIIntermediate==\n-----END CERTIFICATE-----",
                """
                -----BEGIN CERTIFICATE-----
                MIILeaf==
                -----END CERTIFICATE-----
                -----BEGIN CERTIFICATE-----
                MIIIntermediate==
                -----END CERTIFICATE-----"""
        );
    }

    private static GetDistributionConfigResponse distConfigResponseWithAcmArn(String acmArn) {
        ViewerCertificate vc = ViewerCertificate.builder()
                .acmCertificateArn(acmArn)
                .cloudFrontDefaultCertificate(false)
                .sslSupportMethod(SSLSupportMethod.SNI_ONLY)
                .minimumProtocolVersion(MinimumProtocolVersion.fromValue("TLSv1.2_2021"))
                .build();
        return GetDistributionConfigResponse.builder()
                .eTag("etag")
                .distributionConfig(DistributionConfig.builder()
                        .callerReference("caller-ref")
                        .viewerCertificate(vc)
                        .build())
                .build();
    }
}
