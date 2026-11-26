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
import software.amazon.awssdk.services.apigateway.ApiGatewayClient;
import software.amazon.awssdk.services.apigateway.ApiGatewayClientBuilder;
import software.amazon.awssdk.services.apigateway.model.ApiGatewayException;
import software.amazon.awssdk.services.apigateway.model.EndpointConfiguration;
import software.amazon.awssdk.services.apigateway.model.EndpointType;
import software.amazon.awssdk.services.apigateway.model.GetDomainNameRequest;
import software.amazon.awssdk.services.apigateway.model.GetDomainNameResponse;
import software.amazon.awssdk.services.apigateway.model.UpdateDomainNameRequest;
import software.amazon.awssdk.services.apigateway.model.UpdateDomainNameResponse;
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
class AwsApiGatewayRestDeploymentAdapterTest {

    @Mock private SecretStore secretStore;
    @Mock private AwsAcmImportService acmImportService;
    @Mock private AwsCloudCredentialResolver awsCredentialResolver;

    private AwsApiGatewayRestDeploymentAdapter adapter;

    private static final String SCOPE_JSON =
            "{\"authMode\":\"INSTANCE_PROFILE\",\"region\":\"us-east-1\"," +
            "\"customDomains\":[\"api.example.com\",\"api-eu.example.com\"]}";

    private static final String TARGETS_JSON =
            "{\"domainNames\":[\"api.example.com\"]}";

    @BeforeEach
    void setUp() {
        adapter = new AwsApiGatewayRestDeploymentAdapter(
                secretStore, acmImportService, awsCredentialResolver, JsonMapper.builderWithJackson2Defaults().build());
    }

    @Test
    void deploy_readsCredentialFromKv_evenWhenJsonInvalid() {
        when(secretStore.read(anyString())).thenReturn("not-valid-json");

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class);

        verify(secretStore).read("https://kv-agent.vault.azure.net/secrets/aws-apigw-cred");
    }

    @Test
    void deploy_invalidCredentialJson_throwsPermanentCredentialInvalid() {
        when(secretStore.read(anyString())).thenReturn("not-valid-json");

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void deploy_missingScopeJson_throwsPermanentCredentialInvalid() {
        assertThatThrownBy(() -> adapter.deploy(buildBundle(), buildMessage()))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void deploy_missingRegion_throwsPermanentCredentialInvalid() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson("{\"authMode\":\"INSTANCE_PROFILE\",\"customDomains\":[\"api.example.com\"]}");
        msg.setTargetsJson(TARGETS_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void deploy_missingCustomDomainsInScope_throwsPermanentCredentialInvalid() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson("{\"authMode\":\"INSTANCE_PROFILE\",\"region\":\"us-east-1\"}");
        msg.setTargetsJson(TARGETS_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"))
                .hasMessageContaining("customDomains");
    }

    @Test
    void deploy_emptyDomainNamesList_throwsPermanentTargetsInvalid() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson("{\"domainNames\":[]}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_TARGETS_INVALID"));
    }

    @Test
    void deploy_domainNotInScope_throwsPermanentTargetsInvalid() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson("{\"domainNames\":[\"unknown.example.com\"]}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_TARGETS_INVALID"))
                .hasMessageContaining("not in the credential's scope.customDomains");
    }

    @Test
    void deploy_invalidTargetsJson_throwsPermanentTargetsInvalid() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson("not-valid-json");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_TARGETS_INVALID"));
    }

    @Test
    void deploy_unknownAuthMode_throwsPermanentCredentialInvalid() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(
                "{\"authMode\":\"MAGIC_AUTH\",\"region\":\"us-east-1\"," +
                "\"customDomains\":[\"api.example.com\"]}");
        msg.setTargetsJson(TARGETS_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void deploy_apiGwRestThrottled_throwsRetryableWithRetryAfter() {
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(mock(AwsCredentialsProvider.class));
        when(acmImportService.importCertificate(any(), anyString(), any(), any(), any()))
                .thenReturn("arn:aws:acm:us-east-1:123456789012:certificate/new-uuid");

        SdkHttpResponse httpResp = SdkHttpResponse.builder()
                .statusCode(429)
                .headers(Map.of("Retry-After", List.of("60")))
                .build();
        ApiGatewayException throttle = (ApiGatewayException) ApiGatewayException.builder()
                .message("Rate exceeded")
                .statusCode(429)
                .awsErrorDetails(AwsErrorDetails.builder()
                        .errorCode("Throttling")
                        .errorMessage("Rate exceeded")
                        .sdkHttpResponse(httpResp)
                        .build())
                .build();

        ApiGatewayClient mockClient = mock(ApiGatewayClient.class);
        // getDomainName succeeds so we reach updateDomainName
        when(mockClient.getDomainName(any(GetDomainNameRequest.class)))
                .thenReturn(GetDomainNameResponse.builder().build());
        when(mockClient.updateDomainName(any(UpdateDomainNameRequest.class)))
                .thenThrow(throttle);

        ApiGatewayClientBuilder builder = mock(ApiGatewayClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(mockClient);

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        try (MockedStatic<ApiGatewayClient> staticMock = mockStatic(ApiGatewayClient.class)) {
            staticMock.when(ApiGatewayClient::builder).thenReturn(builder);

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
    void deploy_happyPath_regionalEndpoint_returnsArn() {
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(mock(AwsCredentialsProvider.class));
        String arn = "arn:aws:acm:us-east-1:123456789012:certificate/new-uuid";
        when(acmImportService.importCertificate(any(), anyString(), any(), any(), any()))
                .thenReturn(arn);

        ApiGatewayClient mockClient = mock(ApiGatewayClient.class);
        when(mockClient.getDomainName(any(GetDomainNameRequest.class)))
                .thenReturn(GetDomainNameResponse.builder()
                        .endpointConfiguration(EndpointConfiguration.builder().typesWithStrings("REGIONAL").build())
                        .build());
        when(mockClient.updateDomainName(any(UpdateDomainNameRequest.class)))
                .thenReturn(UpdateDomainNameResponse.builder().build());

        ApiGatewayClientBuilder builder = mock(ApiGatewayClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(mockClient);

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        try (MockedStatic<ApiGatewayClient> staticMock = mockStatic(ApiGatewayClient.class)) {
            staticMock.when(ApiGatewayClient::builder).thenReturn(builder);
            DeploymentResult result = adapter.deploy(buildBundle(), msg);
            assertThat(result.targetResourceId()).isEqualTo(arn);
        }
    }

    @Test
    void deploy_happyPath_edgeEndpoint_usesCertificateArnPath() {
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(mock(AwsCredentialsProvider.class));
        String arn = "arn:aws:acm:us-east-1:123456789012:certificate/edge-uuid";
        when(acmImportService.importCertificate(any(), anyString(), any(), any(), any()))
                .thenReturn(arn);

        ApiGatewayClient mockClient = mock(ApiGatewayClient.class);
        when(mockClient.getDomainName(any(GetDomainNameRequest.class)))
                .thenReturn(GetDomainNameResponse.builder()
                        .endpointConfiguration(EndpointConfiguration.builder().types(EndpointType.EDGE).build())
                        .build());
        when(mockClient.updateDomainName(any(UpdateDomainNameRequest.class)))
                .thenReturn(UpdateDomainNameResponse.builder().build());

        ApiGatewayClientBuilder builder = mock(ApiGatewayClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(mockClient);

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        try (MockedStatic<ApiGatewayClient> staticMock = mockStatic(ApiGatewayClient.class)) {
            staticMock.when(ApiGatewayClient::builder).thenReturn(builder);
            assertThat(adapter.deploy(buildBundle(), msg).targetResourceId()).isEqualTo(arn);
        }
    }

    @Test
    void deploy_happyPath_getDomainName_fails_defaultsToRegional() {
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(mock(AwsCredentialsProvider.class));
        String arn = "arn:aws:acm:us-east-1:123456789012:certificate/x";
        when(acmImportService.importCertificate(any(), anyString(), any(), any(), any()))
                .thenReturn(arn);

        ApiGatewayClient mockClient = mock(ApiGatewayClient.class);
        when(mockClient.getDomainName(any(GetDomainNameRequest.class)))
                .thenThrow(SdkClientException.create("network"));
        when(mockClient.updateDomainName(any(UpdateDomainNameRequest.class)))
                .thenReturn(UpdateDomainNameResponse.builder().build());

        ApiGatewayClientBuilder builder = mock(ApiGatewayClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(mockClient);

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        try (MockedStatic<ApiGatewayClient> staticMock = mockStatic(ApiGatewayClient.class)) {
            staticMock.when(ApiGatewayClient::builder).thenReturn(builder);
            assertThat(adapter.deploy(buildBundle(), msg).targetResourceId()).isEqualTo(arn);
        }
    }

    @Test
    void deploy_happyPath_getDomainName_nullEndpointConfig_defaultsToRegional() {
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(mock(AwsCredentialsProvider.class));
        String arn = "arn:aws:acm:us-east-1:123456789012:certificate/x";
        when(acmImportService.importCertificate(any(), anyString(), any(), any(), any()))
                .thenReturn(arn);

        ApiGatewayClient mockClient = mock(ApiGatewayClient.class);
        when(mockClient.getDomainName(any(GetDomainNameRequest.class)))
                .thenReturn(GetDomainNameResponse.builder().build());
        when(mockClient.updateDomainName(any(UpdateDomainNameRequest.class)))
                .thenReturn(UpdateDomainNameResponse.builder().build());

        ApiGatewayClientBuilder builder = mock(ApiGatewayClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(mockClient);

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        try (MockedStatic<ApiGatewayClient> staticMock = mockStatic(ApiGatewayClient.class)) {
            staticMock.when(ApiGatewayClient::builder).thenReturn(builder);
            assertThat(adapter.deploy(buildBundle(), msg).targetResourceId()).isEqualTo(arn);
        }
    }

    @Test
    void deploy_rotation_existingArnPassed() {
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(mock(AwsCredentialsProvider.class));
        String arn = "arn:aws:acm:us-east-1:123456789012:certificate/exist";
        when(acmImportService.importCertificate(any(), anyString(), any(), any(), any()))
                .thenReturn(arn);

        ApiGatewayClient mockClient = mock(ApiGatewayClient.class);
        when(mockClient.getDomainName(any(GetDomainNameRequest.class)))
                .thenReturn(GetDomainNameResponse.builder().build());
        when(mockClient.updateDomainName(any(UpdateDomainNameRequest.class)))
                .thenReturn(UpdateDomainNameResponse.builder().build());

        ApiGatewayClientBuilder builder = mock(ApiGatewayClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(mockClient);

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);
        msg.setConfigJson("{\"arn\":\"" + arn + "\"}");

        try (MockedStatic<ApiGatewayClient> staticMock = mockStatic(ApiGatewayClient.class)) {
            staticMock.when(ApiGatewayClient::builder).thenReturn(builder);
            assertThat(adapter.deploy(buildBundle(), msg).targetResourceId()).isEqualTo(arn);
        }
    }

    @Test
    void deploy_accessDenied_throwsPermanentAccessDenied() {
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(mock(AwsCredentialsProvider.class));
        when(acmImportService.importCertificate(any(), anyString(), any(), any(), any()))
                .thenReturn("arn");

        ApiGatewayException denied = (ApiGatewayException) ApiGatewayException.builder()
                .message("denied")
                .statusCode(401)
                .awsErrorDetails(AwsErrorDetails.builder().errorCode("AccessDenied").build())
                .build();

        ApiGatewayClient mockClient = mock(ApiGatewayClient.class);
        when(mockClient.getDomainName(any(GetDomainNameRequest.class)))
                .thenReturn(GetDomainNameResponse.builder().build());
        when(mockClient.updateDomainName(any(UpdateDomainNameRequest.class))).thenThrow(denied);

        ApiGatewayClientBuilder builder = mock(ApiGatewayClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(mockClient);

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        try (MockedStatic<ApiGatewayClient> staticMock = mockStatic(ApiGatewayClient.class)) {
            staticMock.when(ApiGatewayClient::builder).thenReturn(builder);
            assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("DEPLOY_APIGW_ACCESS_DENIED"));
        }
    }

    @Test
    void deploy_400_throwsPermanentRequestInvalid() {
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(mock(AwsCredentialsProvider.class));
        when(acmImportService.importCertificate(any(), anyString(), any(), any(), any()))
                .thenReturn("arn");

        ApiGatewayException bad = (ApiGatewayException) ApiGatewayException.builder()
                .message("bad")
                .statusCode(400)
                .awsErrorDetails(AwsErrorDetails.builder().errorCode("BadRequest").build())
                .build();

        ApiGatewayClient mockClient = mock(ApiGatewayClient.class);
        when(mockClient.getDomainName(any(GetDomainNameRequest.class)))
                .thenReturn(GetDomainNameResponse.builder().build());
        when(mockClient.updateDomainName(any(UpdateDomainNameRequest.class))).thenThrow(bad);

        ApiGatewayClientBuilder builder = mock(ApiGatewayClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(mockClient);

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        try (MockedStatic<ApiGatewayClient> staticMock = mockStatic(ApiGatewayClient.class)) {
            staticMock.when(ApiGatewayClient::builder).thenReturn(builder);
            assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("DEPLOY_APIGW_REQUEST_INVALID"));
        }
    }

    @Test
    void deploy_500_throwsTransient() {
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(mock(AwsCredentialsProvider.class));
        when(acmImportService.importCertificate(any(), anyString(), any(), any(), any()))
                .thenReturn("arn");

        ApiGatewayException boom = (ApiGatewayException) ApiGatewayException.builder()
                .message("boom")
                .statusCode(500)
                .awsErrorDetails(AwsErrorDetails.builder().errorCode("InternalServerError").build())
                .build();

        ApiGatewayClient mockClient = mock(ApiGatewayClient.class);
        when(mockClient.getDomainName(any(GetDomainNameRequest.class)))
                .thenReturn(GetDomainNameResponse.builder().build());
        when(mockClient.updateDomainName(any(UpdateDomainNameRequest.class))).thenThrow(boom);

        ApiGatewayClientBuilder builder = mock(ApiGatewayClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(mockClient);

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        try (MockedStatic<ApiGatewayClient> staticMock = mockStatic(ApiGatewayClient.class)) {
            staticMock.when(ApiGatewayClient::builder).thenReturn(builder);
            assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                    .isInstanceOf(TransientAgentException.class)
                    .satisfies(e -> assertThat(((TransientAgentException) e).getErrorCode())
                            .isEqualTo("DEPLOY_APIGW_ERROR"));
        }
    }

    @Test
    void deploy_sdkClientException_throwsTransient() {
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(mock(AwsCredentialsProvider.class));
        when(acmImportService.importCertificate(any(), anyString(), any(), any(), any()))
                .thenReturn("arn");

        ApiGatewayClient mockClient = mock(ApiGatewayClient.class);
        when(mockClient.getDomainName(any(GetDomainNameRequest.class)))
                .thenReturn(GetDomainNameResponse.builder().build());
        when(mockClient.updateDomainName(any(UpdateDomainNameRequest.class)))
                .thenThrow(SdkClientException.create("net"));

        ApiGatewayClientBuilder builder = mock(ApiGatewayClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(mockClient);

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        try (MockedStatic<ApiGatewayClient> staticMock = mockStatic(ApiGatewayClient.class)) {
            staticMock.when(ApiGatewayClient::builder).thenReturn(builder);
            assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                    .isInstanceOf(TransientAgentException.class);
        }
    }

    @Test
    void deploy_emptyTargetsJson_throwsTargetsInvalid() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson("");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_TARGETS_INVALID"));
    }

    @Test
    void deploy_sdkClientException_throttle_throwsRetryable() {
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(mock(AwsCredentialsProvider.class));
        when(acmImportService.importCertificate(any(), anyString(), any(), any(), any()))
                .thenReturn("arn");

        ApiGatewayClient mockClient = mock(ApiGatewayClient.class);
        when(mockClient.getDomainName(any(GetDomainNameRequest.class)))
                .thenReturn(GetDomainNameResponse.builder().build());
        when(mockClient.updateDomainName(any(UpdateDomainNameRequest.class)))
                .thenThrow(SdkClientException.create("throttling: try again later"));
        ApiGatewayClientBuilder builder = mock(ApiGatewayClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(mockClient);

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        try (MockedStatic<ApiGatewayClient> staticMock = mockStatic(ApiGatewayClient.class)) {
            staticMock.when(ApiGatewayClient::builder).thenReturn(builder);
            assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                    .isInstanceOf(RetryableAgentException.class)
                    .satisfies(e -> assertThat(((RetryableAgentException) e).getErrorCode())
                            .isEqualTo("DEPLOY_PROVIDER_THROTTLED"));
        }
    }

    @Test
    void deploy_sdkException_genericAwsServiceThrottle_throwsRetryable() {
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(mock(AwsCredentialsProvider.class));
        when(acmImportService.importCertificate(any(), anyString(), any(), any(), any()))
                .thenReturn("arn");

        SdkHttpResponse httpResp = SdkHttpResponse.builder()
                .statusCode(429)
                .headers(Map.of("Retry-After", List.of("12")))
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
        ApiGatewayClient mockClient = mock(ApiGatewayClient.class);
        when(mockClient.getDomainName(any(GetDomainNameRequest.class)))
                .thenReturn(GetDomainNameResponse.builder().build());
        when(mockClient.updateDomainName(any(UpdateDomainNameRequest.class))).thenThrow(ase);
        ApiGatewayClientBuilder builder = mock(ApiGatewayClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(mockClient);

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        try (MockedStatic<ApiGatewayClient> staticMock = mockStatic(ApiGatewayClient.class)) {
            staticMock.when(ApiGatewayClient::builder).thenReturn(builder);
            assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                    .isInstanceOf(RetryableAgentException.class);
        }
    }

    @Test
    void deploy_invalidScopeJson_throwsPermanent() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson("not-json-at-all");
        msg.setTargetsJson(TARGETS_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void deploy_rotation_parsePriorArn_invalidJson_treatedAsFirstDeploy() {
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(mock(AwsCredentialsProvider.class));
        when(acmImportService.importCertificate(any(), anyString(), any(), any(), any()))
                .thenReturn("arn-new");

        ApiGatewayClient mockClient = mock(ApiGatewayClient.class);
        when(mockClient.getDomainName(any(GetDomainNameRequest.class)))
                .thenReturn(GetDomainNameResponse.builder().build());
        when(mockClient.updateDomainName(any(UpdateDomainNameRequest.class)))
                .thenReturn(UpdateDomainNameResponse.builder().build());
        ApiGatewayClientBuilder builder = mock(ApiGatewayClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(mockClient);

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);
        msg.setConfigJson("not-json");

        try (MockedStatic<ApiGatewayClient> staticMock = mockStatic(ApiGatewayClient.class)) {
            staticMock.when(ApiGatewayClient::builder).thenReturn(builder);
            assertThat(adapter.deploy(buildBundle(), msg).targetResourceId()).isEqualTo("arn-new");
        }
    }

    @Test
    void deploy_blankDomain_buildTagsWithoutDomainTag() {
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(mock(AwsCredentialsProvider.class));
        when(acmImportService.importCertificate(any(), anyString(), any(), any(), any()))
                .thenReturn("arn-new");

        ApiGatewayClient mockClient = mock(ApiGatewayClient.class);
        when(mockClient.getDomainName(any(GetDomainNameRequest.class)))
                .thenReturn(GetDomainNameResponse.builder().build());
        when(mockClient.updateDomainName(any(UpdateDomainNameRequest.class)))
                .thenReturn(UpdateDomainNameResponse.builder().build());
        ApiGatewayClientBuilder builder = mock(ApiGatewayClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(mockClient);

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);
        msg.setDomain("   ");
        msg.setOrganizationId(null);

        try (MockedStatic<ApiGatewayClient> staticMock = mockStatic(ApiGatewayClient.class)) {
            staticMock.when(ApiGatewayClient::builder).thenReturn(builder);
            assertThat(adapter.deploy(buildBundle(), msg).targetResourceId()).isEqualTo("arn-new");
        }
    }

    @Test
    void deploy_nullDeploymentCredHandle_skipsKvRead() {
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(mock(AwsCredentialsProvider.class));
        when(acmImportService.importCertificate(any(), anyString(), any(), any(), any()))
                .thenReturn("arn-x");

        ApiGatewayClient mockClient = mock(ApiGatewayClient.class);
        when(mockClient.getDomainName(any(GetDomainNameRequest.class)))
                .thenReturn(GetDomainNameResponse.builder().build());
        when(mockClient.updateDomainName(any(UpdateDomainNameRequest.class)))
                .thenReturn(UpdateDomainNameResponse.builder().build());
        ApiGatewayClientBuilder builder = mock(ApiGatewayClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(mockClient);

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);
        msg.setDeploymentCredHandle(null);

        try (MockedStatic<ApiGatewayClient> staticMock = mockStatic(ApiGatewayClient.class)) {
            staticMock.when(ApiGatewayClient::builder).thenReturn(builder);
            assertThat(adapter.deploy(buildBundle(), msg).targetResourceId()).isEqualTo("arn-x");
        }
    }

    private CertDeploymentMessage buildMessage() {
        CertDeploymentMessage msg = new CertDeploymentMessage();
        msg.setRequestId("req-apigw-1");
        msg.setOrganizationId("organization-1");
        msg.setCertificateXref("xref-1");
        msg.setDomain("api.example.com");
        msg.setCertSecretHandle("https://kv.vault.azure.net/secrets/cert-xref-1");
        msg.setTargetType(TargetType.AWS_API_GW_REST);
        msg.setDeploymentCredHandle("https://kv-agent.vault.azure.net/secrets/aws-apigw-cred");
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
