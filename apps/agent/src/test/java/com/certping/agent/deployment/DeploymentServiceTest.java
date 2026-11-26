// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment;

import com.certping.agent.deployment.adapter.DeploymentAdapter;
import com.certping.agent.deployment.adapter.DeploymentAdapterFactory;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.enums.TargetType;
import com.certping.agent.model.message.CertDeploymentMessage;
import com.certping.agent.secrets.SecretStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DeploymentServiceTest {

    @Mock SecretStore secretStore;
    @Mock DeploymentAdapterFactory adapterFactory;
    @Mock DeploymentAdapter adapter;

    private DeploymentService service;

    private static final String LEAF_CERT =
            "-----BEGIN CERTIFICATE-----\nMIILeaf==\n-----END CERTIFICATE-----";
    private static final String PRIVATE_KEY =
            "-----BEGIN PRIVATE KEY-----\nMIIKey==\n-----END PRIVATE KEY-----";
    private static final String RAW_BUNDLE = LEAF_CERT + "\n" + PRIVATE_KEY;

    @BeforeEach
    void setUp() {
        service = new DeploymentService(secretStore, adapterFactory);
    }

    // ── Azure KV flow ─────────────────────────────────────────────────────────

    @Test
    void deploy_azureKv_readsBundleFromKvAndCallsAdapter() {
        CertDeploymentMessage msg = buildMessage(TargetType.AZURE_KV);
        when(secretStore.read("https://kv.vault.azure.net/secrets/cert-xref1"))
                .thenReturn(RAW_BUNDLE);
        when(adapterFactory.create(TargetType.AZURE_KV)).thenReturn(adapter);
        when(adapter.deploy(any(), eq(msg))).thenReturn(DeploymentResult.of("https://kv.vault.azure.net/certificates/cert-xref1/v1"));

        DeploymentResult result = service.deploy(msg);

        assertThat(result.targetResourceId()).contains("certificates/cert-xref1");
        verify(secretStore).read("https://kv.vault.azure.net/secrets/cert-xref1");
        verify(adapterFactory).create(TargetType.AZURE_KV);
        verify(adapter).deploy(any(CertificateBundle.class), eq(msg));
    }

    // ── AWS ACM flow ──────────────────────────────────────────────────────────

    @Test
    void deploy_awsAcm_readsBundleAndCallsAwsAdapter() {
        CertDeploymentMessage msg = buildMessage(TargetType.AWS_ACM);
        when(secretStore.read(msg.getCertSecretHandle())).thenReturn(RAW_BUNDLE);
        when(adapterFactory.create(TargetType.AWS_ACM)).thenReturn(adapter);
        when(adapter.deploy(any(), eq(msg))).thenReturn(
                DeploymentResult.of("arn:aws:acm:us-east-1:123456789012:certificate/abc-123"));

        DeploymentResult result = service.deploy(msg);

        assertThat(result.targetResourceId()).startsWith("arn:aws:acm:");
        verify(adapterFactory).create(TargetType.AWS_ACM);
    }

    @Test
    void deploy_kubernetesSecrets_readsBundleAndCallsKubernetesAdapter() {
        CertDeploymentMessage msg = buildMessage(TargetType.KUBERNETES_SECRETS);
        msg.setDeploymentCredHandle(null);
        msg.setConfigJson("{\"clusterName\":\"prod-cluster\"}");
        when(secretStore.read(msg.getCertSecretHandle())).thenReturn(RAW_BUNDLE);
        when(adapterFactory.create(TargetType.KUBERNETES_SECRETS)).thenReturn(adapter);
        when(adapter.deploy(any(), eq(msg))).thenReturn(
                DeploymentResult.of("k8s://prod-cluster/tls-secrets/3"));

        DeploymentResult result = service.deploy(msg);

        assertThat(result.targetResourceId()).isEqualTo("k8s://prod-cluster/tls-secrets/3");
        verify(adapterFactory).create(TargetType.KUBERNETES_SECRETS);
    }

    // ── Bundle parsing passed to adapter ─────────────────────────────────────

    @Test
    void deploy_parsedBundleHasLeafAndKey() {
        CertDeploymentMessage msg = buildMessage(TargetType.AZURE_KV);
        when(secretStore.read(any())).thenReturn(RAW_BUNDLE);
        when(adapterFactory.create(any())).thenReturn(adapter);
        when(adapter.deploy(any(), any())).thenAnswer(invocation -> {
            CertificateBundle bundle = invocation.getArgument(0);
            assertThat(bundle.leafCertificate()).contains("MIILeaf==");
            assertThat(bundle.privateKey()).contains("MIIKey==");
            return DeploymentResult.of("cert-id");
        });

        service.deploy(msg);

        verify(adapter).deploy(any(CertificateBundle.class), any());
    }

    // ── Error propagation ─────────────────────────────────────────────────────

    @Test
    void deploy_invalidBundle_throwsPermanentException() {
        CertDeploymentMessage msg = buildMessage(TargetType.AZURE_KV);
        when(secretStore.read(any())).thenReturn("not-a-pem-bundle");

        assertThatThrownBy(() -> service.deploy(msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("CERT_FORMAT_INVALID"));
    }

    @Test
    void deploy_kvReadFails_exceptionPropagates() {
        CertDeploymentMessage msg = buildMessage(TargetType.AZURE_KV);
        when(secretStore.read(any()))
                .thenThrow(new PermanentAgentException("KV_SECRET_NOT_FOUND", "not found"));

        assertThatThrownBy(() -> service.deploy(msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("KV_SECRET_NOT_FOUND"));
    }

    // ── Helper ────────────────────────────────────────────────────────────────

    private CertDeploymentMessage buildMessage(TargetType targetType) {
        CertDeploymentMessage msg = new CertDeploymentMessage();
        msg.setRequestId("req-1");
        msg.setCorrelationId("corr-1");
        msg.setOrganizationId("organization-1");
        msg.setCertificateXref("xref-1");
        msg.setDomain("example.com");
        msg.setCertSecretHandle("https://kv.vault.azure.net/secrets/cert-xref1");
        msg.setTargetType(targetType);
        msg.setDeploymentCredHandle("https://kv.vault.azure.net/secrets/azure-deploy-spn");
        return msg;
    }
}
