// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.secrets.aws;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.secrets.SecretStoreProperties;
import com.certping.agent.secrets.SecretStoreProperties.AwsAuthMode;
import com.certping.agent.secrets.SecretStoreProperties.AwsSecretsManagerProperties;
import com.certping.agent.secrets.SecretStoreProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.http.SdkHttpResponse;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.CreateSecretRequest;
import software.amazon.awssdk.services.secretsmanager.model.CreateSecretResponse;
import software.amazon.awssdk.services.secretsmanager.model.DeleteSecretRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.InvalidRequestException;
import software.amazon.awssdk.services.secretsmanager.model.PutSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.PutSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.ResourceExistsException;
import software.amazon.awssdk.services.secretsmanager.model.ResourceNotFoundException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AwsSecretsManagerDriverTest {

    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = "123456789012";
    private static final String PREFIX = "certping/test/";
    private static final String OWN_HANDLE =
            "arn:aws:secretsmanager:" + REGION + ":" + ACCOUNT + ":secret:" + PREFIX + "cert-1-AbCdEf";
    // Same region as own so the mocked ownRegionClient handles it; different
    // account so isOwnedByThisAgent returns false and the recovery-window path is exercised.
    private static final String FOREIGN_HANDLE =
            "arn:aws:secretsmanager:" + REGION + ":222222222222:secret:foreign/api-key-A1B2C3";

    private SecretStoreProperties props;
    private SecretsManagerClient client;
    private AwsSecretsManagerDriver driver;

    @BeforeEach
    void setUp() {
        props = new SecretStoreProperties();
        AwsSecretsManagerProperties aws = props.getAwsSecretsManager();
        aws.setRegion(REGION);
        aws.setOwnStoreNamePrefix(PREFIX);
        aws.setAuthMode(AwsAuthMode.STATIC);
        aws.setRecoveryWindowDays(7);
        client = mock(SecretsManagerClient.class);
        driver = new AwsSecretsManagerDriver(props, "test", client, ACCOUNT);
    }

    @Test
    void stsClient_usesSecretsManagerEndpointOverrideAndRegion() {
        props.getAwsSecretsManager().setEndpointOverride("http://localstack:4566");
        try (var sts = new AwsSecretsManagerDriver(props, "test", client, ACCOUNT).buildStsClient()) {
            assertThat(sts.serviceClientConfiguration().endpointOverride())
                    .contains(java.net.URI.create("http://localstack:4566"));
            assertThat(sts.serviceClientConfiguration().region().id()).isEqualTo(REGION);
        }
    }

    @Test
    void provider_returnsAwsSecretsManager() {
        assertThat(driver.provider()).isEqualTo(SecretStoreProvider.AWS_SECRETS_MANAGER);
    }

    @Test
    void parsesHandle_acceptsCanonicalArn() {
        assertThat(driver.parsesHandle(OWN_HANDLE)).isTrue();
        assertThat(driver.parsesHandle(FOREIGN_HANDLE)).isTrue();
    }

    @Test
    void parsesHandle_rejectsMalformed() {
        assertThat(driver.parsesHandle(null)).isFalse();
        assertThat(driver.parsesHandle("")).isFalse();
        assertThat(driver.parsesHandle("not-an-arn")).isFalse();
        assertThat(driver.parsesHandle("arn:aws:s3:::bucket")).isFalse();
    }

    @Test
    void parsesHandle_acceptsArnWithoutSuffix() {
        // AWS SDK accepts either full ARN or partial ARN (no suffix); the driver must too,
        // otherwise handleFor("startup-probe") — used by SecretStoreStartupValidator — gets
        // rejected before the probe reaches AWS.
        assertThat(driver.parsesHandle(
                "arn:aws:secretsmanager:us-east-1:123456789012:secret:certping/agent-1/startup-probe")).isTrue();
    }

    @Test
    void assertValidName_acceptsSubset() {
        assertThatCode(() -> driver.assertValidName("cert_1-abc")).doesNotThrowAnyException();
        assertThatCode(() -> driver.assertValidName("AZ09_-")).doesNotThrowAnyException();
    }

    @Test
    void assertValidName_rejectsForbidden() {
        assertThatThrownBy(() -> driver.assertValidName(null))
                .isInstanceOf(PermanentAgentException.class);
        assertThatThrownBy(() -> driver.assertValidName("has space"))
                .isInstanceOf(PermanentAgentException.class);
        assertThatThrownBy(() -> driver.assertValidName("has/slash"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void isOwnedByThisAgent_true_forOwnRegionAccountPrefix() {
        assertThat(driver.isOwnedByThisAgent(OWN_HANDLE)).isTrue();
    }

    @Test
    void isOwnedByThisAgent_false_forDifferentRegion() {
        String otherRegion = "arn:aws:secretsmanager:eu-west-1:" + ACCOUNT + ":secret:" + PREFIX + "cert-1-AbCdEf";
        assertThat(driver.isOwnedByThisAgent(otherRegion)).isFalse();
    }

    @Test
    void isOwnedByThisAgent_false_forDifferentAccount() {
        String otherAcct = "arn:aws:secretsmanager:" + REGION + ":999999999999:secret:" + PREFIX + "cert-1-AbCdEf";
        assertThat(driver.isOwnedByThisAgent(otherAcct)).isFalse();
    }

    @Test
    void isOwnedByThisAgent_false_forDifferentPrefix() {
        String otherPrefix = "arn:aws:secretsmanager:" + REGION + ":" + ACCOUNT + ":secret:other/cert-1-AbCdEf";
        assertThat(driver.isOwnedByThisAgent(otherPrefix)).isFalse();
    }

    @Test
    void isOwnedByThisAgent_false_forMalformed() {
        assertThat(driver.isOwnedByThisAgent(null)).isFalse();
        assertThat(driver.isOwnedByThisAgent("garbage")).isFalse();
    }

    @Test
    void handleFor_returnsPredictablePrefix() {
        String h = driver.handleFor("cert-1");
        assertThat(h).isEqualTo("arn:aws:secretsmanager:us-east-1:123456789012:secret:certping/test/cert-1");
    }

    @Test
    void handleFor_rejectsInvalidName() {
        assertThatThrownBy(() -> driver.handleFor("bad name"))
                .isInstanceOf(PermanentAgentException.class);
    }

    // ---- read ----

    @Test
    void read_returnsSecretString() {
        when(client.getSecretValue(any(GetSecretValueRequest.class)))
                .thenReturn(GetSecretValueResponse.builder().secretString("value").build());
        assertThat(driver.read(OWN_HANDLE)).isEqualTo("value");
    }

    @Test
    void read_notFound_throwsPermanent() {
        when(client.getSecretValue(any(GetSecretValueRequest.class)))
                .thenThrow(ResourceNotFoundException.builder().message("missing").build());
        assertThatThrownBy(() -> driver.read(OWN_HANDLE))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode()).isEqualTo("SM_SECRET_NOT_FOUND"));
    }

    @Test
    void read_accessDenied_throwsPermanent() {
        AwsServiceException denied = AwsServiceException.builder()
                .statusCode(403).message("no perms").build();
        when(client.getSecretValue(any(GetSecretValueRequest.class))).thenThrow(denied);
        assertThatThrownBy(() -> driver.read(OWN_HANDLE))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode()).isEqualTo("SM_ACCESS_DENIED"));
    }

    @Test
    void read_throttled_throwsRetryable() {
        AwsServiceException throttled = throttlingException();
        when(client.getSecretValue(any(GetSecretValueRequest.class))).thenThrow(throttled);
        assertThatThrownBy(() -> driver.read(OWN_HANDLE))
                .isInstanceOf(RetryableAgentException.class);
    }

    @Test
    void read_serviceError_throwsTransient() {
        AwsServiceException err = AwsServiceException.builder().statusCode(500).message("boom").build();
        when(client.getSecretValue(any(GetSecretValueRequest.class))).thenThrow(err);
        assertThatThrownBy(() -> driver.read(OWN_HANDLE)).isInstanceOf(TransientAgentException.class);
    }

    @Test
    void read_unexpectedError_throwsTransient() {
        when(client.getSecretValue(any(GetSecretValueRequest.class)))
                .thenThrow(new RuntimeException("net"));
        assertThatThrownBy(() -> driver.read(OWN_HANDLE)).isInstanceOf(TransientAgentException.class);
    }

    @Test
    void read_blankHandle_throwsPermanent() {
        assertThatThrownBy(() -> driver.read("")).isInstanceOf(PermanentAgentException.class);
        assertThatThrownBy(() -> driver.read(null)).isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void read_invalidHandleFormat_throwsPermanent() {
        assertThatThrownBy(() -> driver.read("garbage")).isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode()).isEqualTo("SM_HANDLE_INVALID"));
    }

    // ---- create ----

    @Test
    void create_returnsArn() {
        when(client.createSecret(any(CreateSecretRequest.class)))
                .thenReturn(CreateSecretResponse.builder().arn(OWN_HANDLE).build());
        String arn = driver.create("cert-1", "value");
        assertThat(arn).isEqualTo(OWN_HANDLE);
        ArgumentCaptor<CreateSecretRequest> cap = ArgumentCaptor.forClass(CreateSecretRequest.class);
        verify(client).createSecret(cap.capture());
        assertThat(cap.getValue().name()).isEqualTo(PREFIX + "cert-1");
    }

    @Test
    void create_fallsBackToPut_whenResourceExists() {
        when(client.createSecret(any(CreateSecretRequest.class)))
                .thenThrow(ResourceExistsException.builder().message("exists").build());
        when(client.putSecretValue(any(PutSecretValueRequest.class)))
                .thenReturn(PutSecretValueResponse.builder().arn(OWN_HANDLE).build());
        String arn = driver.create("cert-1", "value");
        assertThat(arn).isEqualTo(OWN_HANDLE);
        verify(client).putSecretValue(any(PutSecretValueRequest.class));
    }

    @Test
    void create_fallsBackToPut_thenPutFails_throwsTransient() {
        when(client.createSecret(any(CreateSecretRequest.class)))
                .thenThrow(ResourceExistsException.builder().message("exists").build());
        AwsServiceException err = AwsServiceException.builder().statusCode(500).message("boom").build();
        when(client.putSecretValue(any(PutSecretValueRequest.class))).thenThrow(err);
        assertThatThrownBy(() -> driver.create("cert-1", "value"))
                .isInstanceOf(TransientAgentException.class);
    }

    @Test
    void create_throttled_throwsRetryable() {
        when(client.createSecret(any(CreateSecretRequest.class))).thenThrow(throttlingException());
        assertThatThrownBy(() -> driver.create("cert-1", "value"))
                .isInstanceOf(RetryableAgentException.class);
    }

    @Test
    void create_serviceError_throwsTransient() {
        AwsServiceException err = AwsServiceException.builder().statusCode(500).message("boom").build();
        when(client.createSecret(any(CreateSecretRequest.class))).thenThrow(err);
        assertThatThrownBy(() -> driver.create("cert-1", "value"))
                .isInstanceOf(TransientAgentException.class);
    }

    @Test
    void create_unexpectedError_throwsTransient() {
        when(client.createSecret(any(CreateSecretRequest.class))).thenThrow(new RuntimeException("net"));
        assertThatThrownBy(() -> driver.create("cert-1", "value"))
                .isInstanceOf(TransientAgentException.class);
    }

    @Test
    void create_invalidName_throwsPermanent() {
        assertThatThrownBy(() -> driver.create("bad name", "v"))
                .isInstanceOf(PermanentAgentException.class);
    }

    // ---- update ----

    @Test
    void update_returnsNewArn() {
        when(client.putSecretValue(any(PutSecretValueRequest.class)))
                .thenReturn(PutSecretValueResponse.builder().arn(OWN_HANDLE).build());
        assertThat(driver.update(OWN_HANDLE, "v")).isEqualTo(OWN_HANDLE);
    }

    @Test
    void update_returnsHandle_whenArnMissing() {
        when(client.putSecretValue(any(PutSecretValueRequest.class)))
                .thenReturn(PutSecretValueResponse.builder().build());
        assertThat(driver.update(OWN_HANDLE, "v")).isEqualTo(OWN_HANDLE);
    }

    @Test
    void update_notFound_throwsPermanent() {
        when(client.putSecretValue(any(PutSecretValueRequest.class)))
                .thenThrow(ResourceNotFoundException.builder().message("gone").build());
        assertThatThrownBy(() -> driver.update(OWN_HANDLE, "v"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void update_accessDenied_throwsPermanent() {
        AwsServiceException denied = AwsServiceException.builder().statusCode(403).message("no").build();
        when(client.putSecretValue(any(PutSecretValueRequest.class))).thenThrow(denied);
        assertThatThrownBy(() -> driver.update(OWN_HANDLE, "v"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void update_throttled_throwsRetryable() {
        when(client.putSecretValue(any(PutSecretValueRequest.class))).thenThrow(throttlingException());
        assertThatThrownBy(() -> driver.update(OWN_HANDLE, "v"))
                .isInstanceOf(RetryableAgentException.class);
    }

    @Test
    void update_unexpectedError_throwsTransient() {
        when(client.putSecretValue(any(PutSecretValueRequest.class))).thenThrow(new RuntimeException("x"));
        assertThatThrownBy(() -> driver.update(OWN_HANDLE, "v"))
                .isInstanceOf(TransientAgentException.class);
    }

    @Test
    void update_serviceError_throwsTransient() {
        when(client.putSecretValue(any(PutSecretValueRequest.class)))
                .thenThrow(AwsServiceException.builder().statusCode(500).message("boom").build());
        assertThatThrownBy(() -> driver.update(OWN_HANDLE, "v"))
                .isInstanceOf(TransientAgentException.class);
    }

    // ---- delete ----

    @Test
    void delete_ownHandle_usesForceDelete() {
        driver.delete(OWN_HANDLE);
        ArgumentCaptor<DeleteSecretRequest> cap = ArgumentCaptor.forClass(DeleteSecretRequest.class);
        verify(client).deleteSecret(cap.capture());
        assertThat(cap.getValue().forceDeleteWithoutRecovery()).isTrue();
    }

    @Test
    void delete_foreignHandle_usesRecoveryWindow() {
        driver.delete(FOREIGN_HANDLE);
        ArgumentCaptor<DeleteSecretRequest> cap = ArgumentCaptor.forClass(DeleteSecretRequest.class);
        verify(client).deleteSecret(cap.capture());
        assertThat(cap.getValue().forceDeleteWithoutRecovery()).isNull();
        assertThat(cap.getValue().recoveryWindowInDays()).isEqualTo(7L);
    }

    @Test
    void delete_notFound_treatsAsSuccess() {
        doThrow(ResourceNotFoundException.builder().message("gone").build())
                .when(client).deleteSecret(any(DeleteSecretRequest.class));
        assertThatCode(() -> driver.delete(OWN_HANDLE)).doesNotThrowAnyException();
    }

    @Test
    void delete_alreadyScheduled_treatsAsSuccess() {
        doThrow(InvalidRequestException.builder().message("Secret is already scheduled for deletion").build())
                .when(client).deleteSecret(any(DeleteSecretRequest.class));
        assertThatCode(() -> driver.delete(OWN_HANDLE)).doesNotThrowAnyException();
    }

    @Test
    void delete_invalidRequestOther_throwsPermanent() {
        doThrow(InvalidRequestException.builder().message("nope").build())
                .when(client).deleteSecret(any(DeleteSecretRequest.class));
        assertThatThrownBy(() -> driver.delete(OWN_HANDLE))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void delete_throttled_throwsRetryable() {
        doThrow(throttlingException()).when(client).deleteSecret(any(DeleteSecretRequest.class));
        assertThatThrownBy(() -> driver.delete(OWN_HANDLE))
                .isInstanceOf(RetryableAgentException.class);
    }

    @Test
    void delete_serviceError_throwsTransient() {
        doThrow(AwsServiceException.builder().statusCode(500).message("boom").build())
                .when(client).deleteSecret(any(DeleteSecretRequest.class));
        assertThatThrownBy(() -> driver.delete(OWN_HANDLE))
                .isInstanceOf(TransientAgentException.class);
    }

    @Test
    void delete_unexpectedError_throwsTransient() {
        doThrow(new RuntimeException("net")).when(client).deleteSecret(any(DeleteSecretRequest.class));
        assertThatThrownBy(() -> driver.delete(OWN_HANDLE))
                .isInstanceOf(TransientAgentException.class);
    }

    // ---- auth-mode branch coverage via init() (skipping WEB_IDENTITY which needs a real token file) ----

    @Test
    void init_missingRegion_throws() {
        SecretStoreProperties p = new SecretStoreProperties();
        p.getAwsSecretsManager().setRegion(null);
        p.getAwsSecretsManager().setAuthMode(AwsAuthMode.PROFILE);
        AwsSecretsManagerDriver d = new AwsSecretsManagerDriver(p, "test");
        assertThatThrownBy(d::init)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("region is required");
    }

    @Test
    void init_webIdentity_missingRoleArn_throws() {
        props.getAwsSecretsManager().setAuthMode(AwsAuthMode.WEB_IDENTITY_TOKEN);
        props.getAwsSecretsManager().setRoleArn(null);
        AwsSecretsManagerDriver d = new AwsSecretsManagerDriver(props, "test");
        assertThatThrownBy(d::init).isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("role-arn");
    }

    @Test
    void init_static_missingKeys_throws() {
        props.getAwsSecretsManager().setAuthMode(AwsAuthMode.STATIC);
        AwsSecretsManagerDriver d = new AwsSecretsManagerDriver(props, "test");
        // Only fails when env has no AWS_ACCESS_KEY_ID; assume dev env doesn't set it.
        // If your env does set it, this test is a no-op — skip check.
        String envKey = System.getenv("AWS_ACCESS_KEY_ID");
        if (envKey == null || envKey.isBlank()) {
            assertThatThrownBy(d::init).isInstanceOf(IllegalStateException.class);
        }
    }

    // ---- helpers ----

    private static AwsServiceException throttlingException() {
        return AwsServiceException.builder()
                .statusCode(429)
                .awsErrorDetails(AwsErrorDetails.builder()
                        .errorCode("ThrottlingException")
                        .sdkHttpResponse(SdkHttpResponse.builder().statusCode(429).build())
                        .build())
                .message("throttled")
                .build();
    }
}
