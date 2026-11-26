// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.aws;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.http.SdkHttpResponse;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.StsClientBuilder;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.AssumeRoleResponse;
import software.amazon.awssdk.services.sts.model.Credentials;
import software.amazon.awssdk.services.sts.model.StsException;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;

import java.time.Instant;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AwsAssumeRoleServiceTest {

    private AwsAssumeRoleService service;

    @BeforeEach
    void setUp() {
        AgentProperties props = new AgentProperties();
        props.getDeployment().getAws().setSessionName("certping-agent");
        props.getDeployment().getAws().setSessionDurationSeconds(3600);
        service = new AwsAssumeRoleService(props);
    }

    @Test
    void assumeRole_stsThrottled_throwsRetryableWithRetryAfter() {
        SdkHttpResponse httpResp = SdkHttpResponse.builder()
                .statusCode(429)
                .headers(Map.of("Retry-After", List.of("60")))
                .build();
        StsException throttle = (StsException) StsException.builder()
                .message("Rate exceeded")
                .statusCode(429)
                .awsErrorDetails(AwsErrorDetails.builder()
                        .errorCode("Throttling")
                        .errorMessage("Rate exceeded")
                        .sdkHttpResponse(httpResp)
                        .build())
                .build();

        StsClient mockClient = mock(StsClient.class);
        when(mockClient.assumeRole(any(AssumeRoleRequest.class))).thenThrow(throttle);

        StsClientBuilder builder = mock(StsClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(mockClient);

        String roleArn = "arn:aws:iam::123456789012:role/certping-deploy";

        try (MockedStatic<StsClient> staticMock = mockStatic(StsClient.class)) {
            staticMock.when(StsClient::builder).thenReturn(builder);

            assertThatThrownBy(() -> service.assumeRole(roleArn, "us-east-1", "AKIA", "secret"))
                    .isInstanceOf(RetryableAgentException.class)
                    .satisfies(ex -> {
                        assertThat(((RetryableAgentException) ex).getErrorCode())
                                .isEqualTo("DEPLOY_PROVIDER_THROTTLED");
                        assertThat(((RetryableAgentException) ex).getRetryAfter())
                                .isEqualTo(Duration.ofSeconds(60));
                    });
        }
    }

    private static final String ROLE_ARN = "arn:aws:iam::123456789012:role/certping-deploy";

    @Test
    void assumeRole_happyPath_returnsSessionCredentials() {
        Credentials creds = Credentials.builder()
                .accessKeyId("AK").secretAccessKey("SK").sessionToken("TOK")
                .expiration(Instant.now().plusSeconds(3600))
                .build();
        StsClient mockClient = mock(StsClient.class);
        when(mockClient.assumeRole(any(AssumeRoleRequest.class)))
                .thenReturn(AssumeRoleResponse.builder().credentials(creds).build());
        StsClientBuilder builder = mock(StsClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(mockClient);

        try (MockedStatic<StsClient> staticMock = mockStatic(StsClient.class)) {
            staticMock.when(StsClient::builder).thenReturn(builder);
            AwsSessionCredentials out = service.assumeRole(ROLE_ARN, "us-east-1", "AKIA", "secret");
            assertThat(out.accessKeyId()).isEqualTo("AK");
            assertThat(out.secretAccessKey()).isEqualTo("SK");
            assertThat(out.sessionToken()).isEqualTo("TOK");
        }
    }

    @Test
    void assumeRole_happyPath_noStaticKeys_usesDefaultProvider() {
        Credentials creds = Credentials.builder()
                .accessKeyId("AK").secretAccessKey("SK").sessionToken("TOK")
                .expiration(Instant.now().plusSeconds(3600))
                .build();
        StsClient mockClient = mock(StsClient.class);
        when(mockClient.assumeRole(any(AssumeRoleRequest.class)))
                .thenReturn(AssumeRoleResponse.builder().credentials(creds).build());
        StsClientBuilder builder = mock(StsClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(mockClient);

        try (MockedStatic<StsClient> staticMock = mockStatic(StsClient.class)) {
            staticMock.when(StsClient::builder).thenReturn(builder);
            AwsSessionCredentials out = service.assumeRole(ROLE_ARN, "us-east-1", null, null);
            assertThat(out.accessKeyId()).isEqualTo("AK");
        }
    }

    @Test
    void assumeRole_happyPath_blankStaticKeys_usesDefaultProvider() {
        Credentials creds = Credentials.builder()
                .accessKeyId("AK").secretAccessKey("SK").sessionToken("TOK")
                .expiration(Instant.now().plusSeconds(3600))
                .build();
        StsClient mockClient = mock(StsClient.class);
        when(mockClient.assumeRole(any(AssumeRoleRequest.class)))
                .thenReturn(AssumeRoleResponse.builder().credentials(creds).build());
        StsClientBuilder builder = mock(StsClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(mockClient);

        try (MockedStatic<StsClient> staticMock = mockStatic(StsClient.class)) {
            staticMock.when(StsClient::builder).thenReturn(builder);
            AwsSessionCredentials out = service.assumeRole(ROLE_ARN, "us-east-1", "  ", "  ");
            assertThat(out.accessKeyId()).isEqualTo("AK");
        }
    }

    @Test
    void awsProperties_defaultsAreAcceptedBySts() {
        AgentProperties.AwsProperties aws = new AgentProperties().getDeployment().getAws();
        assertThat(aws.getSessionDurationSeconds()).isBetween(900, 43200);
        assertThat(aws.getSessionName()).isNotBlank();
    }

    @Test
    void assumeRole_validationError_throwsPermanentCredentialInvalid() {
        StsException invalid = (StsException) StsException.builder()
                .message("invalid")
                .statusCode(400)
                .awsErrorDetails(AwsErrorDetails.builder()
                        .errorCode("ValidationError").errorMessage("bad request")
                        .build())
                .build();
        StsClient mockClient = mock(StsClient.class);
        when(mockClient.assumeRole(any(AssumeRoleRequest.class))).thenThrow(invalid);
        StsClientBuilder builder = mock(StsClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(mockClient);

        try (MockedStatic<StsClient> staticMock = mockStatic(StsClient.class)) {
            staticMock.when(StsClient::builder).thenReturn(builder);
            assertThatThrownBy(() -> service.assumeRole(ROLE_ARN, "us-east-1", "AKIA", "secret"))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(ex -> assertThat(((PermanentAgentException) ex).getErrorCode())
                            .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
        }
    }

    @Test
    void assumeRole_accessDenied_throwsPermanentStsDenied() {
        StsException denied = (StsException) StsException.builder()
                .message("denied")
                .statusCode(403)
                .awsErrorDetails(AwsErrorDetails.builder()
                        .errorCode("AccessDenied").errorMessage("no")
                        .build())
                .build();
        StsClient mockClient = mock(StsClient.class);
        when(mockClient.assumeRole(any(AssumeRoleRequest.class))).thenThrow(denied);
        StsClientBuilder builder = mock(StsClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(mockClient);

        try (MockedStatic<StsClient> staticMock = mockStatic(StsClient.class)) {
            staticMock.when(StsClient::builder).thenReturn(builder);
            assertThatThrownBy(() -> service.assumeRole(ROLE_ARN, "us-east-1", "AKIA", "secret"))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(ex -> assertThat(((PermanentAgentException) ex).getErrorCode())
                            .isEqualTo("DEPLOY_STS_DENIED"));
        }
    }

    @Test
    void assumeRole_authorizationError_throwsPermanentStsDenied() {
        StsException denied = (StsException) StsException.builder()
                .message("denied")
                .statusCode(403)
                .awsErrorDetails(AwsErrorDetails.builder()
                        .errorCode("AuthorizationError").errorMessage("no")
                        .build())
                .build();
        StsClient mockClient = mock(StsClient.class);
        when(mockClient.assumeRole(any(AssumeRoleRequest.class))).thenThrow(denied);
        StsClientBuilder builder = mock(StsClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(mockClient);

        try (MockedStatic<StsClient> staticMock = mockStatic(StsClient.class)) {
            staticMock.when(StsClient::builder).thenReturn(builder);
            assertThatThrownBy(() -> service.assumeRole(ROLE_ARN, "us-east-1", "AKIA", "secret"))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(ex -> assertThat(((PermanentAgentException) ex).getErrorCode())
                            .isEqualTo("DEPLOY_STS_DENIED"));
        }
    }

    @Test
    void assumeRole_genericStsError_throwsTransient() {
        StsException boom = (StsException) StsException.builder()
                .message("boom")
                .statusCode(500)
                .awsErrorDetails(AwsErrorDetails.builder().errorCode("InternalError").build())
                .build();
        StsClient mockClient = mock(StsClient.class);
        when(mockClient.assumeRole(any(AssumeRoleRequest.class))).thenThrow(boom);
        StsClientBuilder builder = mock(StsClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(mockClient);

        try (MockedStatic<StsClient> staticMock = mockStatic(StsClient.class)) {
            staticMock.when(StsClient::builder).thenReturn(builder);
            assertThatThrownBy(() -> service.assumeRole(ROLE_ARN, "us-east-1", "AKIA", "secret"))
                    .isInstanceOf(TransientAgentException.class)
                    .satisfies(ex -> assertThat(((TransientAgentException) ex).getErrorCode())
                            .isEqualTo("DEPLOY_STS_ERROR"));
        }
    }

    @Test
    void assumeRole_nullAwsErrorDetails_throwsTransient() {
        StsException boom = (StsException) StsException.builder().message("boom").build();
        StsClient mockClient = mock(StsClient.class);
        when(mockClient.assumeRole(any(AssumeRoleRequest.class))).thenThrow(boom);
        StsClientBuilder builder = mock(StsClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(mockClient);

        try (MockedStatic<StsClient> staticMock = mockStatic(StsClient.class)) {
            staticMock.when(StsClient::builder).thenReturn(builder);
            assertThatThrownBy(() -> service.assumeRole(ROLE_ARN, "us-east-1", "AKIA", "secret"))
                    .isInstanceOf(TransientAgentException.class);
        }
    }

    @Test
    void validateAwsRoleArn_validArn_doesNotThrow() {
        service.validateAwsRoleArn(ROLE_ARN);
    }

    @Test
    void validateAwsRoleArn_invalidArn_throws() {
        assertThatThrownBy(() -> service.validateAwsRoleArn("not-an-arn"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void validateAwsRegion_validRegion_doesNotThrow() {
        service.validateAwsRegion("us-east-1");
    }

    @Test
    void validateAwsRegion_invalidRegion_throws() {
        assertThatThrownBy(() -> service.validateAwsRegion("bogus"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void assumeRole_invalidRoleArn_throwsPermanent() {
        assertThatThrownBy(() -> service.assumeRole("bad-arn", "us-east-1", "AKIA", "secret"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void assumeRole_invalidRegion_throwsPermanent() {
        assertThatThrownBy(() -> service.assumeRole(ROLE_ARN, "BAD", "AKIA", "secret"))
                .isInstanceOf(PermanentAgentException.class);
    }
}
