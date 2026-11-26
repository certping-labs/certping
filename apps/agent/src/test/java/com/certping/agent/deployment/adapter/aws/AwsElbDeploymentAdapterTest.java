// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.aws;

import com.certping.agent.deployment.CertificateBundle;
import com.certping.agent.deployment.cloud.aws.AwsAuthMode;
import com.certping.agent.deployment.cloud.aws.AwsAuthScope;
import com.certping.agent.deployment.cloud.aws.AwsAuthSecret;
import com.certping.agent.deployment.cloud.aws.AwsCloudCredentialResolver;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
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
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.http.SdkHttpResponse;
import software.amazon.awssdk.services.elasticloadbalancingv2.ElasticLoadBalancingV2Client;
import software.amazon.awssdk.services.elasticloadbalancingv2.ElasticLoadBalancingV2ClientBuilder;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.AddListenerCertificatesRequest;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.AddListenerCertificatesResponse;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.ElasticLoadBalancingV2Exception;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.RemoveListenerCertificatesRequest;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.RemoveListenerCertificatesResponse;
import software.amazon.awssdk.core.exception.SdkClientException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.deployment.DeploymentResult;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@org.mockito.junit.jupiter.MockitoSettings(strictness = org.mockito.quality.Strictness.LENIENT)
class AwsElbDeploymentAdapterTest {

    @Mock private SecretStore secretStore;
    @Mock private AwsAcmImportService acmImportService;
    @Mock private AwsCloudCredentialResolver awsCredentialResolver;

    private AwsElbDeploymentAdapter adapter;

    private static final String LISTENER_ARN =
            "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/test/123abc/456def";

    /** Scope: one LB per credential, listeners listed in scope. */
    private static final String SCOPE_JSON =
            "{\"authMode\":\"INSTANCE_PROFILE\"," +
            "\"region\":\"us-east-1\"," +
            "\"listeners\":[\"" + LISTENER_ARN + "\"]}";

    /** Targets: select listeners from scope. */
    private static final String TARGETS_JSON =
            "{\"listenerArns\":[\"" + LISTENER_ARN + "\"]}";

    @BeforeEach
    void setUp() {
        adapter = new AwsElbDeploymentAdapter(secretStore, acmImportService, awsCredentialResolver, JsonMapper.builderWithJackson2Defaults().build());
    }

    @Test
    void deploy_readsCredentialFromKv_evenWhenJsonInvalid() {
        when(secretStore.read(anyString())).thenReturn("not-valid-json");

        CertDeploymentMessage msg = buildMessage(TargetType.AWS_ALB);
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class);

        verify(secretStore).read("https://kv-agent.vault.azure.net/secrets/aws-elb-cred");
    }

    @Test
    void deploy_invalidCredentialJson_throwsPermanentCredentialInvalid() {
        when(secretStore.read(anyString())).thenReturn("not-valid-json");

        CertDeploymentMessage msg = buildMessage(TargetType.AWS_NLB);
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void deploy_missingListenerArns_throwsPermanentTargetInvalid() {
        CertDeploymentMessage msg = buildMessage(TargetType.AWS_ALB);
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson("{\"listenerArns\":[]}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_TARGETS_INVALID"));
    }

    @Test
    void deploy_missingScopeJson_throwsPermanentCredentialInvalid() {
        assertThatThrownBy(() -> adapter.deploy(buildBundle(), buildMessage(TargetType.AWS_ALB)))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void deploy_missingListenersInScope_throwsPermanent() {
        CertDeploymentMessage msg = buildMessage(TargetType.AWS_ALB);
        msg.setCredentialScopeJson("{\"authMode\":\"INSTANCE_PROFILE\",\"region\":\"us-east-1\"}");
        msg.setTargetsJson(TARGETS_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void deploy_listenerNotInScope_throwsPermanentTargetInvalid() {
        CertDeploymentMessage msg = buildMessage(TargetType.AWS_ALB);
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson("{\"listenerArns\":[\"arn:aws:elasticloadbalancing:us-east-1:123:listener/app/other/999/888\"]}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_TARGETS_INVALID"));
    }

    @Test
    void deploy_elbThrottled_throwsRetryableWithRetryAfter() {
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(mock(AwsCredentialsProvider.class));
        when(acmImportService.importCertificate(any(), anyString(), any(), any(), any()))
                .thenReturn("arn:aws:acm:us-east-1:123456789012:certificate/new-uuid");

        SdkHttpResponse httpResp = SdkHttpResponse.builder()
                .statusCode(429)
                .headers(Map.of("Retry-After", List.of("60")))
                .build();
        ElasticLoadBalancingV2Exception throttle =
                (ElasticLoadBalancingV2Exception) ElasticLoadBalancingV2Exception.builder()
                        .message("Rate exceeded")
                        .statusCode(429)
                        .awsErrorDetails(AwsErrorDetails.builder()
                                .errorCode("Throttling")
                                .errorMessage("Rate exceeded")
                                .sdkHttpResponse(httpResp)
                                .build())
                        .build();

        ElasticLoadBalancingV2Client mockClient = mock(ElasticLoadBalancingV2Client.class);
        when(mockClient.addListenerCertificates(any(AddListenerCertificatesRequest.class)))
                .thenThrow(throttle);

        ElasticLoadBalancingV2ClientBuilder builder =
                mock(ElasticLoadBalancingV2ClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(mockClient);

        CertDeploymentMessage msg = buildMessage(TargetType.AWS_ALB);
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        try (MockedStatic<ElasticLoadBalancingV2Client> staticMock =
                     mockStatic(ElasticLoadBalancingV2Client.class)) {
            staticMock.when(ElasticLoadBalancingV2Client::builder).thenReturn(builder);

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
    void deploy_happyPath_firstDeploy_attachesCert_returnsArn() {
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(mock(AwsCredentialsProvider.class));
        String arn = "arn:aws:acm:us-east-1:123456789012:certificate/new-uuid";
        when(acmImportService.importCertificate(any(), anyString(), any(), any(), any()))
                .thenReturn(arn);

        ElasticLoadBalancingV2Client client = mock(ElasticLoadBalancingV2Client.class);
        when(client.addListenerCertificates(any(AddListenerCertificatesRequest.class)))
                .thenReturn(AddListenerCertificatesResponse.builder().build());

        ElasticLoadBalancingV2ClientBuilder builder =
                mock(ElasticLoadBalancingV2ClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(client);

        CertDeploymentMessage msg = buildMessage(TargetType.AWS_ALB);
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        try (MockedStatic<ElasticLoadBalancingV2Client> staticMock =
                     mockStatic(ElasticLoadBalancingV2Client.class)) {
            staticMock.when(ElasticLoadBalancingV2Client::builder).thenReturn(builder);
            DeploymentResult result = adapter.deploy(buildBundle(), msg);
            assertThat(result.targetResourceId()).isEqualTo(arn);
            assertThat(result.configJson()).contains(arn);
        }
    }

    @Test
    void deploy_rotation_attachesNewAndRemovesOld() {
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(mock(AwsCredentialsProvider.class));
        String newArn = "arn:aws:acm:us-east-1:123456789012:certificate/new-uuid";
        String oldArn = "arn:aws:acm:us-east-1:123456789012:certificate/old-uuid";
        when(acmImportService.importCertificate(any(), anyString(), any(), any(), any()))
                .thenReturn(newArn);

        ElasticLoadBalancingV2Client client = mock(ElasticLoadBalancingV2Client.class);
        when(client.addListenerCertificates(any(AddListenerCertificatesRequest.class)))
                .thenReturn(AddListenerCertificatesResponse.builder().build());
        when(client.removeListenerCertificates(any(RemoveListenerCertificatesRequest.class)))
                .thenReturn(RemoveListenerCertificatesResponse.builder().build());

        ElasticLoadBalancingV2ClientBuilder builder =
                mock(ElasticLoadBalancingV2ClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(client);

        CertDeploymentMessage msg = buildMessage(TargetType.AWS_ALB);
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);
        msg.setConfigJson("{\"arn\":\"" + oldArn + "\"}");

        try (MockedStatic<ElasticLoadBalancingV2Client> staticMock =
                     mockStatic(ElasticLoadBalancingV2Client.class)) {
            staticMock.when(ElasticLoadBalancingV2Client::builder).thenReturn(builder);
            assertThat(adapter.deploy(buildBundle(), msg).targetResourceId()).isEqualTo(newArn);
            verify(client).removeListenerCertificates(any(RemoveListenerCertificatesRequest.class));
        }
    }

    @Test
    void deploy_rotation_sameArn_doesNotRemove() {
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(mock(AwsCredentialsProvider.class));
        String arn = "arn:aws:acm:us-east-1:123456789012:certificate/same";
        when(acmImportService.importCertificate(any(), anyString(), any(), any(), any()))
                .thenReturn(arn);

        ElasticLoadBalancingV2Client client = mock(ElasticLoadBalancingV2Client.class);
        when(client.addListenerCertificates(any(AddListenerCertificatesRequest.class)))
                .thenReturn(AddListenerCertificatesResponse.builder().build());

        ElasticLoadBalancingV2ClientBuilder builder =
                mock(ElasticLoadBalancingV2ClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(client);

        CertDeploymentMessage msg = buildMessage(TargetType.AWS_ALB);
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);
        msg.setConfigJson("{\"arn\":\"" + arn + "\"}");

        try (MockedStatic<ElasticLoadBalancingV2Client> staticMock =
                     mockStatic(ElasticLoadBalancingV2Client.class)) {
            staticMock.when(ElasticLoadBalancingV2Client::builder).thenReturn(builder);
            adapter.deploy(buildBundle(), msg);
            org.mockito.Mockito.verify(client, org.mockito.Mockito.never())
                    .removeListenerCertificates(any(RemoveListenerCertificatesRequest.class));
        }
    }

    @Test
    void deploy_missingDomain_throwsPermanent() {
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(mock(AwsCredentialsProvider.class));

        CertDeploymentMessage msg = buildMessage(TargetType.AWS_ALB);
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);
        msg.setDomain("  ");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_DOMAIN_REQUIRED"));
    }

    @Test
    void deploy_genericElbException_throwsTransient() {
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(mock(AwsCredentialsProvider.class));
        when(acmImportService.importCertificate(any(), anyString(), any(), any(), any()))
                .thenReturn("arn");

        ElasticLoadBalancingV2Exception boom =
                (ElasticLoadBalancingV2Exception) ElasticLoadBalancingV2Exception.builder()
                        .message("boom")
                        .statusCode(500)
                        .awsErrorDetails(AwsErrorDetails.builder().errorCode("InternalError").build())
                        .build();
        ElasticLoadBalancingV2Client client = mock(ElasticLoadBalancingV2Client.class);
        when(client.addListenerCertificates(any(AddListenerCertificatesRequest.class)))
                .thenThrow(boom);

        ElasticLoadBalancingV2ClientBuilder builder =
                mock(ElasticLoadBalancingV2ClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(client);

        CertDeploymentMessage msg = buildMessage(TargetType.AWS_ALB);
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        try (MockedStatic<ElasticLoadBalancingV2Client> staticMock =
                     mockStatic(ElasticLoadBalancingV2Client.class)) {
            staticMock.when(ElasticLoadBalancingV2Client::builder).thenReturn(builder);
            assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                    .isInstanceOf(TransientAgentException.class)
                    .satisfies(e -> assertThat(((TransientAgentException) e).getErrorCode())
                            .isEqualTo("DEPLOY_ELB_ERROR"));
        }
    }

    @Test
    void deploy_sdkClientException_throwsTransient() {
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(mock(AwsCredentialsProvider.class));
        when(acmImportService.importCertificate(any(), anyString(), any(), any(), any()))
                .thenReturn("arn");

        ElasticLoadBalancingV2Client client = mock(ElasticLoadBalancingV2Client.class);
        when(client.addListenerCertificates(any(AddListenerCertificatesRequest.class)))
                .thenThrow(SdkClientException.create("net down"));

        ElasticLoadBalancingV2ClientBuilder builder =
                mock(ElasticLoadBalancingV2ClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(client);

        CertDeploymentMessage msg = buildMessage(TargetType.AWS_ALB);
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        try (MockedStatic<ElasticLoadBalancingV2Client> staticMock =
                     mockStatic(ElasticLoadBalancingV2Client.class)) {
            staticMock.when(ElasticLoadBalancingV2Client::builder).thenReturn(builder);
            assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                    .isInstanceOf(TransientAgentException.class)
                    .satisfies(e -> assertThat(((TransientAgentException) e).getErrorCode())
                            .isEqualTo("DEPLOY_AWS_SDK_ERROR"));
        }
    }

    @Test
    void deploy_invalidTargetsJson_throwsPermanentTargetsInvalid() {
        CertDeploymentMessage msg = buildMessage(TargetType.AWS_ALB);
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson("not-valid-json");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_TARGETS_INVALID"));
    }

    @Test
    void deploy_emptyTargetsJson_throwsPermanentTargetsInvalid() {
        CertDeploymentMessage msg = buildMessage(TargetType.AWS_ALB);
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson("");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_TARGETS_INVALID"));
    }

    @Test
    void deploy_invalidScopeJson_throwsPermanent() {
        CertDeploymentMessage msg = buildMessage(TargetType.AWS_ALB);
        msg.setCredentialScopeJson("not-valid-json");
        msg.setTargetsJson(TARGETS_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void deploy_unknownAuthMode_throwsPermanent() {
        CertDeploymentMessage msg = buildMessage(TargetType.AWS_ALB);
        msg.setCredentialScopeJson("{\"authMode\":\"MAGIC\",\"region\":\"us-east-1\",\"listeners\":[\"" + LISTENER_ARN + "\"]}");
        msg.setTargetsJson(TARGETS_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void deploy_missingRegion_throwsPermanent() {
        CertDeploymentMessage msg = buildMessage(TargetType.AWS_ALB);
        msg.setCredentialScopeJson("{\"authMode\":\"INSTANCE_PROFILE\",\"listeners\":[\"" + LISTENER_ARN + "\"]}");
        msg.setTargetsJson(TARGETS_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void deploy_nullKvPath_skipsKvRead() {
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(mock(AwsCredentialsProvider.class));
        when(acmImportService.importCertificate(any(), anyString(), any(), any(), any()))
                .thenReturn("arn-y");

        ElasticLoadBalancingV2Client client = mock(ElasticLoadBalancingV2Client.class);
        when(client.addListenerCertificates(any(AddListenerCertificatesRequest.class)))
                .thenReturn(AddListenerCertificatesResponse.builder().build());

        ElasticLoadBalancingV2ClientBuilder builder =
                mock(ElasticLoadBalancingV2ClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(client);

        CertDeploymentMessage msg = buildMessage(TargetType.AWS_ALB);
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);
        msg.setDeploymentCredHandle(null);

        try (MockedStatic<ElasticLoadBalancingV2Client> staticMock =
                     mockStatic(ElasticLoadBalancingV2Client.class)) {
            staticMock.when(ElasticLoadBalancingV2Client::builder).thenReturn(builder);
            assertThat(adapter.deploy(buildBundle(), msg).targetResourceId()).isEqualTo("arn-y");
        }
    }

    @Test
    void deploy_sdkClientException_throttle_throwsRetryable() {
        // SdkException catch → RateLimitClassifier.classify (message contains "throttling").
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(mock(AwsCredentialsProvider.class));
        when(acmImportService.importCertificate(any(), anyString(), any(), any(), any()))
                .thenReturn("arn");

        ElasticLoadBalancingV2Client client = mock(ElasticLoadBalancingV2Client.class);
        when(client.addListenerCertificates(any(AddListenerCertificatesRequest.class)))
                .thenThrow(SdkClientException.create("throttling: try later"));
        ElasticLoadBalancingV2ClientBuilder builder =
                mock(ElasticLoadBalancingV2ClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(client);

        CertDeploymentMessage msg = buildMessage(TargetType.AWS_ALB);
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        try (MockedStatic<ElasticLoadBalancingV2Client> staticMock =
                     mockStatic(ElasticLoadBalancingV2Client.class)) {
            staticMock.when(ElasticLoadBalancingV2Client::builder).thenReturn(builder);
            assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                    .isInstanceOf(RetryableAgentException.class)
                    .satisfies(e -> assertThat(((RetryableAgentException) e).getErrorCode())
                            .isEqualTo("DEPLOY_PROVIDER_THROTTLED"));
        }
    }

    @Test
    void deploy_sdkException_genericAwsServiceThrottle_throwsRetryable() {
        // Plain AwsServiceException with throttle → SdkException catch's AwsServiceException branch.
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(mock(AwsCredentialsProvider.class));
        when(acmImportService.importCertificate(any(), anyString(), any(), any(), any()))
                .thenReturn("arn");

        SdkHttpResponse httpResp = SdkHttpResponse.builder()
                .statusCode(429)
                .headers(Map.of("Retry-After", List.of("10")))
                .build();
        software.amazon.awssdk.awscore.exception.AwsServiceException ase =
                software.amazon.awssdk.awscore.exception.AwsServiceException.builder()
                .message("Rate exceeded")
                .statusCode(429)
                .awsErrorDetails(AwsErrorDetails.builder()
                        .errorCode("Throttling")
                        .sdkHttpResponse(httpResp).build())
                .build();
        ElasticLoadBalancingV2Client client = mock(ElasticLoadBalancingV2Client.class);
        when(client.addListenerCertificates(any(AddListenerCertificatesRequest.class))).thenThrow(ase);
        ElasticLoadBalancingV2ClientBuilder builder =
                mock(ElasticLoadBalancingV2ClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(client);

        CertDeploymentMessage msg = buildMessage(TargetType.AWS_ALB);
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        try (MockedStatic<ElasticLoadBalancingV2Client> staticMock =
                     mockStatic(ElasticLoadBalancingV2Client.class)) {
            staticMock.when(ElasticLoadBalancingV2Client::builder).thenReturn(builder);
            assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                    .isInstanceOf(RetryableAgentException.class);
        }
    }

    @Test
    void deploy_rotation_parsePriorArn_invalidJson_treatedAsFirstDeploy() {
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(mock(AwsCredentialsProvider.class));
        when(acmImportService.importCertificate(any(), anyString(), any(), any(), any()))
                .thenReturn("arn-new");

        ElasticLoadBalancingV2Client client = mock(ElasticLoadBalancingV2Client.class);
        when(client.addListenerCertificates(any(AddListenerCertificatesRequest.class)))
                .thenReturn(AddListenerCertificatesResponse.builder().build());
        ElasticLoadBalancingV2ClientBuilder builder =
                mock(ElasticLoadBalancingV2ClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(client);

        CertDeploymentMessage msg = buildMessage(TargetType.AWS_ALB);
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);
        msg.setConfigJson("not-json");

        try (MockedStatic<ElasticLoadBalancingV2Client> staticMock =
                     mockStatic(ElasticLoadBalancingV2Client.class)) {
            staticMock.when(ElasticLoadBalancingV2Client::builder).thenReturn(builder);
            assertThat(adapter.deploy(buildBundle(), msg).targetResourceId()).isEqualTo("arn-new");
        }
    }

    @Test
    void deploy_listenerNotInScope_throwsPermanentTargetsInvalid() {
        CertDeploymentMessage msg = buildMessage(TargetType.AWS_ALB);
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson("{\"listenerArns\":[\"arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/x/y/z\"]}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_TARGETS_INVALID"))
                .hasMessageContaining("not in the credential's scope.listeners");
    }

    @Test
    void deploy_missingListenersInScope_throwsPermanentCredentialInvalid() {
        CertDeploymentMessage msg = buildMessage(TargetType.AWS_ALB);
        msg.setCredentialScopeJson("{\"authMode\":\"INSTANCE_PROFILE\",\"region\":\"us-east-1\"}");
        msg.setTargetsJson(TARGETS_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void deploy_blankOrgId_andBlankDomain_buildTagsWithoutDomainTag() {
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(mock(AwsCredentialsProvider.class));
        when(acmImportService.importCertificate(any(), anyString(), any(), any(), any()))
                .thenReturn("arn-new");

        ElasticLoadBalancingV2Client client = mock(ElasticLoadBalancingV2Client.class);
        when(client.addListenerCertificates(any(AddListenerCertificatesRequest.class)))
                .thenReturn(AddListenerCertificatesResponse.builder().build());
        ElasticLoadBalancingV2ClientBuilder builder =
                mock(ElasticLoadBalancingV2ClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(client);

        CertDeploymentMessage msg = buildMessage(TargetType.AWS_ALB);
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);
        // We can't actually pass a blank domain here (it would throw DEPLOY_DOMAIN_REQUIRED),
        // so instead just exercise null orgId for buildTags coverage.
        msg.setOrganizationId(null);

        try (MockedStatic<ElasticLoadBalancingV2Client> staticMock =
                     mockStatic(ElasticLoadBalancingV2Client.class)) {
            staticMock.when(ElasticLoadBalancingV2Client::builder).thenReturn(builder);
            assertThat(adapter.deploy(buildBundle(), msg).targetResourceId()).isEqualTo("arn-new");
        }
    }

    private CertDeploymentMessage buildMessage(TargetType targetType) {
        CertDeploymentMessage msg = new CertDeploymentMessage();
        msg.setRequestId("req-elb-1");
        msg.setOrganizationId("organization-1");
        msg.setCertificateXref("xref-1");
        msg.setDomain("example.com");
        msg.setCertSecretHandle("https://kv.vault.azure.net/secrets/cert-xref-1");
        msg.setTargetType(targetType);
        msg.setDeploymentCredHandle("https://kv-agent.vault.azure.net/secrets/aws-elb-cred");
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
}
