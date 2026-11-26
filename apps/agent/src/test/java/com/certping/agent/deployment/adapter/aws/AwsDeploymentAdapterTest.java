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
import com.certping.agent.exception.TransientAgentException;
import tools.jackson.databind.json.JsonMapper;
import java.time.Duration;
import com.certping.agent.model.enums.TargetType;
import com.certping.agent.model.message.CertDeploymentMessage;
import com.certping.agent.secrets.SecretStore;
import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.anyList;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@org.mockito.junit.jupiter.MockitoSettings(strictness = org.mockito.quality.Strictness.LENIENT)
class AwsDeploymentAdapterTest {

    @Mock private SecretStore secretStore;
    @Mock private AwsAcmImportService acmImportService;
    @Mock private AwsCloudCredentialResolver awsCredentialResolver;
    @Mock private AwsCredentialsProvider credentialsProvider;

    private AwsDeploymentAdapter adapter;

    /** KV secret — empty for INSTANCE_PROFILE. */
    private static final String KV_EMPTY = "{}";

    /** Scope with INSTANCE_PROFILE auth. */
    private static final String SCOPE_JSON =
            "{\"authMode\":\"INSTANCE_PROFILE\",\"region\":\"us-east-1\"}";

    @BeforeEach
    void setUp() {
        adapter = new AwsDeploymentAdapter(secretStore, acmImportService, awsCredentialResolver, JsonMapper.builderWithJackson2Defaults().build());
    }

    @Test
    void deploy_readsCredentialFromKv() {
        when(secretStore.read(anyString())).thenReturn(KV_EMPTY);
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(credentialsProvider);
        when(acmImportService.importCertificate(any(), eq("us-east-1"), any(), isNull(), anyList()))
                .thenReturn("arn:aws:acm:us-east-1:123456789012:certificate/abc123");

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);

        assertThat(adapter.deploy(buildBundle(), msg).targetResourceId())
                .isEqualTo("arn:aws:acm:us-east-1:123456789012:certificate/abc123");

        verify(secretStore).read("https://kv-agent.vault.azure.net/secrets/aws-deploy-cred");
    }

    @Test
    void deploy_credentialReadFails_throwsTransient() {
        when(secretStore.read(anyString()))
                .thenThrow(new TransientAgentException("KV_READ_FAILED", "KV unavailable"));

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(TransientAgentException.class);
    }

    @Test
    void deploy_invalidCredentialJson_throwsPermanent() {
        when(secretStore.read(anyString())).thenReturn("not-valid-json");

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void deploy_missingScopeJson_throwsPermanent() {
        assertThatThrownBy(() -> adapter.deploy(buildBundle(), buildMessage()))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void deploy_missingRegion_throwsPermanent() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson("{\"authMode\":\"INSTANCE_PROFILE\"}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void deploy_rotation_existingArnPassedToImport_returnsArn() {
        when(secretStore.read(anyString())).thenReturn(KV_EMPTY);
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(credentialsProvider);
        when(acmImportService.importCertificate(any(), eq("us-east-1"), any(),
                eq("arn:aws:acm:us-east-1:123456789012:certificate/existing"), anyList()))
                .thenReturn("arn:aws:acm:us-east-1:123456789012:certificate/existing");

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setConfigJson("{\"arn\":\"arn:aws:acm:us-east-1:123456789012:certificate/existing\"}");

        assertThat(adapter.deploy(buildBundle(), msg).targetResourceId())
                .isEqualTo("arn:aws:acm:us-east-1:123456789012:certificate/existing");
    }

    @Test
    void deploy_invalidConfigJsonArn_treatedAsFirstDeploy() {
        when(secretStore.read(anyString())).thenReturn(KV_EMPTY);
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(credentialsProvider);
        when(acmImportService.importCertificate(any(), eq("us-east-1"), any(), isNull(), anyList()))
                .thenReturn("arn:aws:acm:us-east-1:123456789012:certificate/new");

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setConfigJson("not-valid-json");

        assertThat(adapter.deploy(buildBundle(), msg).targetResourceId())
                .isEqualTo("arn:aws:acm:us-east-1:123456789012:certificate/new");
    }

    @Test
    void deploy_missingDomain_throwsPermanent() {
        when(secretStore.read(anyString())).thenReturn(KV_EMPTY);

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setDomain("  ");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_DOMAIN_REQUIRED"));
    }

    @Test
    void deploy_unexpectedException_wrappedAsPermanentAwsFailed() {
        when(secretStore.read(anyString())).thenReturn(KV_EMPTY);
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(credentialsProvider);
        when(acmImportService.importCertificate(any(), eq("us-east-1"), any(), isNull(), anyList()))
                .thenThrow(new RuntimeException("oops"));

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_AWS_FAILED"));
    }

    @Test
    void deploy_permanentFromAcmImport_propagatesUnchanged() {
        when(secretStore.read(anyString())).thenReturn(KV_EMPTY);
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(credentialsProvider);
        PermanentAgentException original = new PermanentAgentException("DEPLOY_AUTH_INVALID", "nope");
        when(acmImportService.importCertificate(any(), eq("us-east-1"), any(), isNull(), anyList()))
                .thenThrow(original);

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg)).isSameAs(original);
    }

    @Test
    void deploy_transientFromAcmImport_propagatesUnchanged() {
        when(secretStore.read(anyString())).thenReturn(KV_EMPTY);
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(credentialsProvider);
        TransientAgentException original = new TransientAgentException("DEPLOY_ACM_ERROR", "nope");
        when(acmImportService.importCertificate(any(), eq("us-east-1"), any(), isNull(), anyList()))
                .thenThrow(original);

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg)).isSameAs(original);
    }

    @Test
    void deploy_kvPathNull_skipsKvRead() {
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(credentialsProvider);
        when(acmImportService.importCertificate(any(), eq("us-east-1"), any(), isNull(), anyList()))
                .thenReturn("arn:aws:acm:us-east-1:123456789012:certificate/abc");

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setDeploymentCredHandle(null);

        assertThat(adapter.deploy(buildBundle(), msg).targetResourceId())
                .isEqualTo("arn:aws:acm:us-east-1:123456789012:certificate/abc");
    }

    @Test
    void deploy_emptyOrgId_buildTagsWithoutNullOrgId() {
        when(secretStore.read(anyString())).thenReturn(KV_EMPTY);
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(credentialsProvider);
        when(acmImportService.importCertificate(any(), eq("us-east-1"), any(), isNull(), anyList()))
                .thenReturn("arn:aws:acm:us-east-1:123456789012:certificate/abc");

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setOrganizationId(null);

        assertThat(adapter.deploy(buildBundle(), msg).targetResourceId()).isNotNull();
    }

    @Test
    void deploy_retryableFromAcmImport_propagatesUnchanged() {
        when(secretStore.read(anyString())).thenReturn(KV_EMPTY);
        when(awsCredentialResolver.resolve(any(AwsAuthMode.class), any(AwsAuthScope.class),
                any(AwsAuthSecret.class), anyString()))
                .thenReturn(credentialsProvider);

        RetryableAgentException original = new RetryableAgentException(
                "DEPLOY_PROVIDER_THROTTLED",
                "aws ACM import was rate-limited",
                Duration.ofSeconds(45));
        when(acmImportService.importCertificate(any(), eq("us-east-1"), any(), isNull(), anyList()))
                .thenThrow(original);

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isSameAs(original)
                .isInstanceOf(RetryableAgentException.class)
                .satisfies(ex -> {
                    assertThat(((RetryableAgentException) ex).getErrorCode())
                            .isEqualTo("DEPLOY_PROVIDER_THROTTLED");
                    assertThat(((RetryableAgentException) ex).getRetryAfter())
                            .isEqualTo(Duration.ofSeconds(45));
                });
    }

    @Test
    void deploy_malformedScopeJson_throwsPermanentCredentialInvalid() {
        // credentialScopeJson is itself not parseable as AwsAcmScope → hits the parseScope
        // catch block (DEPLOY_CREDENTIAL_INVALID with "Failed to parse" message).
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson("not-valid-json");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> {
                    assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("DEPLOY_CREDENTIAL_INVALID");
                    assertThat(e.getMessage()).contains("Failed to parse");
                });
    }

    @Test
    void deploy_missingAuthMode_throwsPermanentCredentialInvalid() {
        // authMode null → AwsScopeSupport.parseAuthMode throws DEPLOY_CREDENTIAL_INVALID
        // ("missing 'authMode'") — exercises a branch not otherwise covered.
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson("{\"region\":\"us-east-1\"}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> {
                    assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("DEPLOY_CREDENTIAL_INVALID");
                    assertThat(e.getMessage()).contains("authMode");
                });
    }

    @Test
    void deploy_unknownAuthMode_throwsPermanentCredentialInvalid() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson("{\"authMode\":\"MAGIC\",\"region\":\"us-east-1\"}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    private CertDeploymentMessage buildMessage() {
        CertDeploymentMessage msg = new CertDeploymentMessage();
        msg.setRequestId("req-3");
        msg.setOrganizationId("organization-1");
        msg.setCertificateXref("xref-1");
        msg.setDomain("example.com");
        msg.setCertSecretHandle("https://kv.vault.azure.net/secrets/cert-xref-1");
        msg.setTargetType(TargetType.AWS_ACM);
        msg.setDeploymentCredHandle("https://kv-agent.vault.azure.net/secrets/aws-deploy-cred");
        return msg;
    }

    private CertificateBundle buildBundle() {
        return new CertificateBundle(
                "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg==\n-----END PRIVATE KEY-----",
                "-----BEGIN CERTIFICATE-----\nMIILeaf==\n-----END CERTIFICATE-----",
                "-----BEGIN CERTIFICATE-----\nMIIIntermediate==\n-----END CERTIFICATE-----",
                "-----BEGIN CERTIFICATE-----\nMIILeaf==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIIntermediate==\n-----END CERTIFICATE-----"
        );
    }
}
