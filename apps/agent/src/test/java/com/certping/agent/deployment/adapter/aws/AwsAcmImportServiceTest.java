// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.aws;

import com.certping.agent.deployment.CertificateBundle;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.http.SdkHttpResponse;
import software.amazon.awssdk.services.acm.AcmClient;
import software.amazon.awssdk.services.acm.AcmClientBuilder;
import software.amazon.awssdk.services.acm.model.AcmException;
import software.amazon.awssdk.services.acm.model.ImportCertificateRequest;
import software.amazon.awssdk.services.acm.model.ImportCertificateResponse;
import software.amazon.awssdk.services.acm.model.Tag;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

class AwsAcmImportServiceTest {

    private static final String NEW_ARN = "arn:aws:acm:us-east-1:123456789012:certificate/new";
    private static final String EXISTING_ARN = "arn:aws:acm:us-east-1:123456789012:certificate/existing";

    private static CertificateBundle bundle() {
        return new CertificateBundle("KEY", "LEAF", "CHAIN", "LEAF\nCHAIN");
    }

    private static CertificateBundle bundleNoChain() {
        return new CertificateBundle("KEY", "LEAF", null, "LEAF");
    }


    @Test
    void authErrorCodes_mapToPermanentAuthInvalid() {
        for (String code : new String[] {"InvalidSignatureException", "UnrecognizedClientException",
                "AccessDeniedException", "AuthFailure", "ExpiredTokenException"}) {
            RuntimeException mapped = AwsAcmImportService.mapAcmImportException(acm(code));
            assertThat(mapped)
                    .as("code %s", code)
                    .isInstanceOf(PermanentAgentException.class);
            assertThat(((PermanentAgentException) mapped).getErrorCode()).isEqualTo("DEPLOY_AUTH_INVALID");
        }
    }

    @Test
    void validationErrors_mapToPermanentCertFormatInvalid() {
        RuntimeException mapped = AwsAcmImportService.mapAcmImportException(acm("ValidationException"));
        assertThat(mapped).isInstanceOf(PermanentAgentException.class);
        assertThat(((PermanentAgentException) mapped).getErrorCode()).isEqualTo("DEPLOY_CERT_FORMAT_INVALID");
    }

    @Test
    void throttling_staysTransient() {
        // Over-demotion guard: throttling/5xx are recoverable and must NOT become permanent.
        RuntimeException mapped = AwsAcmImportService.mapAcmImportException(acm("ThrottlingException"));
        assertThat(mapped).isInstanceOf(TransientAgentException.class);
        assertThat(((TransientAgentException) mapped).getErrorCode()).isEqualTo("DEPLOY_ACM_ERROR");
    }

    @Test
    void nonServiceSdkError_staysTransient() {
        RuntimeException mapped = AwsAcmImportService.mapAcmImportException(
                SdkException.builder().message("connection reset").build());
        assertThat(mapped).isInstanceOf(TransientAgentException.class);
        assertThat(((TransientAgentException) mapped).getErrorCode()).isEqualTo("DEPLOY_AWS_SDK_ERROR");
    }

    private static AwsServiceException acm(String errorCode) {
        return AcmException.builder()
                .awsErrorDetails(AwsErrorDetails.builder().errorCode(errorCode).build())
                .message("simulated " + errorCode)
                .build();
    }

    @Test
    void importCertificate_happyPath_firstDeploy_withChainAndTags_returnsArn() {
        AwsAcmImportService svc = new AwsAcmImportService();
        AcmClient client = mock(AcmClient.class);
        when(client.importCertificate(any(ImportCertificateRequest.class)))
                .thenReturn(ImportCertificateResponse.builder().certificateArn(NEW_ARN).build());
        AcmClientBuilder builder = mock(AcmClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(client);

        List<Tag> tags = List.of(Tag.builder().key("k").value("v").build());

        try (MockedStatic<AcmClient> staticMock = mockStatic(AcmClient.class)) {
            staticMock.when(AcmClient::builder).thenReturn(builder);
            String arn = svc.importCertificate(bundle(), "us-east-1",
                    mock(AwsCredentialsProvider.class), null, tags);
            assertThat(arn).isEqualTo(NEW_ARN);
        }
    }

    @Test
    void importCertificate_happyPath_rotation_existingArnUsedNoTags_returnsArn() {
        AwsAcmImportService svc = new AwsAcmImportService();
        AcmClient client = mock(AcmClient.class);
        when(client.importCertificate(any(ImportCertificateRequest.class)))
                .thenReturn(ImportCertificateResponse.builder().certificateArn(EXISTING_ARN).build());
        AcmClientBuilder builder = mock(AcmClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(client);

        try (MockedStatic<AcmClient> staticMock = mockStatic(AcmClient.class)) {
            staticMock.when(AcmClient::builder).thenReturn(builder);
            String arn = svc.importCertificate(bundleNoChain(), "us-east-1",
                    mock(AwsCredentialsProvider.class), EXISTING_ARN, null);
            assertThat(arn).isEqualTo(EXISTING_ARN);
        }
    }

    @Test
    void importCertificate_blankExistingArn_treatedAsFirstDeploy() {
        AwsAcmImportService svc = new AwsAcmImportService();
        AcmClient client = mock(AcmClient.class);
        when(client.importCertificate(any(ImportCertificateRequest.class)))
                .thenReturn(ImportCertificateResponse.builder().certificateArn(NEW_ARN).build());
        AcmClientBuilder builder = mock(AcmClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(client);

        try (MockedStatic<AcmClient> staticMock = mockStatic(AcmClient.class)) {
            staticMock.when(AcmClient::builder).thenReturn(builder);
            String arn = svc.importCertificate(bundle(), "us-east-1",
                    mock(AwsCredentialsProvider.class), "  ", List.of());
            assertThat(arn).isEqualTo(NEW_ARN);
        }
    }

    @Test
    void importCertificate_nullArnReturned_throwsPermanent() {
        AwsAcmImportService svc = new AwsAcmImportService();
        AcmClient client = mock(AcmClient.class);
        when(client.importCertificate(any(ImportCertificateRequest.class)))
                .thenReturn(ImportCertificateResponse.builder().certificateArn(null).build());
        AcmClientBuilder builder = mock(AcmClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(client);

        try (MockedStatic<AcmClient> staticMock = mockStatic(AcmClient.class)) {
            staticMock.when(AcmClient::builder).thenReturn(builder);
            assertThatThrownBy(() -> svc.importCertificate(bundle(), "us-east-1",
                    mock(AwsCredentialsProvider.class), null, List.of()))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("DEPLOY_RESULT_NULL_ARN"));
        }
    }

    @Test
    void importCertificate_blankArnReturned_throwsPermanent() {
        AwsAcmImportService svc = new AwsAcmImportService();
        AcmClient client = mock(AcmClient.class);
        when(client.importCertificate(any(ImportCertificateRequest.class)))
                .thenReturn(ImportCertificateResponse.builder().certificateArn("  ").build());
        AcmClientBuilder builder = mock(AcmClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(client);

        try (MockedStatic<AcmClient> staticMock = mockStatic(AcmClient.class)) {
            staticMock.when(AcmClient::builder).thenReturn(builder);
            assertThatThrownBy(() -> svc.importCertificate(bundle(), "us-east-1",
                    mock(AwsCredentialsProvider.class), null, List.of()))
                    .isInstanceOf(PermanentAgentException.class);
        }
    }

    @Test
    void importCertificate_throttled_throwsRetryable_existingArnTarget() {
        AwsAcmImportService svc = new AwsAcmImportService();
        AcmClient client = mock(AcmClient.class);
        SdkHttpResponse httpResp = SdkHttpResponse.builder()
                .statusCode(429).headers(Map.of("Retry-After", List.of("30"))).build();
        AcmException throttle = (AcmException) AcmException.builder()
                .message("Rate exceeded")
                .statusCode(429)
                .awsErrorDetails(AwsErrorDetails.builder()
                        .errorCode("ThrottlingException")
                        .sdkHttpResponse(httpResp).build())
                .build();
        when(client.importCertificate(any(ImportCertificateRequest.class))).thenThrow(throttle);
        AcmClientBuilder builder = mock(AcmClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(client);

        try (MockedStatic<AcmClient> staticMock = mockStatic(AcmClient.class)) {
            staticMock.when(AcmClient::builder).thenReturn(builder);
            assertThatThrownBy(() -> svc.importCertificate(bundle(), "us-east-1",
                    mock(AwsCredentialsProvider.class), EXISTING_ARN, List.of()))
                    .isInstanceOf(RetryableAgentException.class)
                    .satisfies(ex -> assertThat(((RetryableAgentException) ex).getRetryAfter())
                            .isEqualTo(Duration.ofSeconds(30)));
        }
    }

    @Test
    void importCertificate_throttled_throwsRetryable_newImportTarget() {
        AwsAcmImportService svc = new AwsAcmImportService();
        AcmClient client = mock(AcmClient.class);
        SdkHttpResponse httpResp = SdkHttpResponse.builder()
                .statusCode(429).headers(Map.of("Retry-After", List.of("30"))).build();
        AcmException throttle = (AcmException) AcmException.builder()
                .message("Rate exceeded")
                .statusCode(429)
                .awsErrorDetails(AwsErrorDetails.builder()
                        .errorCode("ThrottlingException")
                        .sdkHttpResponse(httpResp).build())
                .build();
        when(client.importCertificate(any(ImportCertificateRequest.class))).thenThrow(throttle);
        AcmClientBuilder builder = mock(AcmClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(client);

        try (MockedStatic<AcmClient> staticMock = mockStatic(AcmClient.class)) {
            staticMock.when(AcmClient::builder).thenReturn(builder);
            assertThatThrownBy(() -> svc.importCertificate(bundle(), "us-east-1",
                    mock(AwsCredentialsProvider.class), null, List.of()))
                    .isInstanceOf(RetryableAgentException.class);
        }
    }

    @Test
    void importCertificate_sdkClientException_mappedToTransient() {
        AwsAcmImportService svc = new AwsAcmImportService();
        AcmClient client = mock(AcmClient.class);
        when(client.importCertificate(any(ImportCertificateRequest.class)))
                .thenThrow(SdkClientException.create("connection reset"));
        AcmClientBuilder builder = mock(AcmClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(client);

        try (MockedStatic<AcmClient> staticMock = mockStatic(AcmClient.class)) {
            staticMock.when(AcmClient::builder).thenReturn(builder);
            assertThatThrownBy(() -> svc.importCertificate(bundle(), "us-east-1",
                    mock(AwsCredentialsProvider.class), null, List.of()))
                    .isInstanceOf(TransientAgentException.class);
        }
    }

    @Test
    void importCertificate_validationException_mappedToPermanent() {
        AwsAcmImportService svc = new AwsAcmImportService();
        AcmClient client = mock(AcmClient.class);
        when(client.importCertificate(any(ImportCertificateRequest.class)))
                .thenThrow(acm("ValidationException"));
        AcmClientBuilder builder = mock(AcmClientBuilder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(client);

        try (MockedStatic<AcmClient> staticMock = mockStatic(AcmClient.class)) {
            staticMock.when(AcmClient::builder).thenReturn(builder);
            assertThatThrownBy(() -> svc.importCertificate(bundle(), "us-east-1",
                    mock(AwsCredentialsProvider.class), null, List.of()))
                    .isInstanceOf(PermanentAgentException.class);
        }
    }

    @Test
    void mapAcmImportException_invalidArn_mappedToCertFormatInvalid() {
        RuntimeException mapped = AwsAcmImportService.mapAcmImportException(acm("InvalidArnException"));
        assertThat(mapped).isInstanceOf(PermanentAgentException.class);
        assertThat(((PermanentAgentException) mapped).getErrorCode()).isEqualTo("DEPLOY_CERT_FORMAT_INVALID");
    }

    @Test
    void mapAcmImportException_nullAwsErrorDetails_unknownCode() {
        AwsServiceException ase = AcmException.builder().message("boom").build();
        RuntimeException mapped = AwsAcmImportService.mapAcmImportException(ase);
        assertThat(mapped).isInstanceOf(TransientAgentException.class);
        assertThat(((TransientAgentException) mapped).getErrorCode()).isEqualTo("DEPLOY_ACM_ERROR");
    }

    @Test
    void mapAcmImportException_internalServerError_stayTransient() {
        RuntimeException mapped = AwsAcmImportService.mapAcmImportException(acm("InternalServerError"));
        assertThat(mapped).isInstanceOf(TransientAgentException.class);
    }
}
