// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.f5;

import com.certping.agent.deployment.CertificateBundle;
import com.certping.agent.deployment.DeploymentResult;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.enums.TargetType;
import com.certping.agent.model.message.CertDeploymentMessage;
import com.certping.agent.secrets.SecretStore;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class F5BigIpDeploymentAdapterTest {

    @Mock private SecretStore secretStore;
    @Mock private F5BigIpCertRotator rotator;

    private F5BigIpDeploymentAdapter adapter;

    private static final String KV_SECRET =
            "{\"username\":\"certping-api\",\"password\":\"secret\"}";

    /** Scope with bootstrap profile list. */
    private static final String SCOPE_JSON =
            "{\"bigipHost\":\"10.0.0.10\",\"bigipPort\":443," +
            "\"verifySsl\":true,\"partition\":\"Common\"," +
            "\"clientSslProfiles\":[\"api-clientssl\"]}";

    /** Empty targets — all config is in scope. */
    private static final String TARGETS_JSON = "{}";

    @BeforeEach
    void setUp() {
        adapter = new F5BigIpDeploymentAdapter(secretStore, JsonMapper.builderWithJackson2Defaults().build(), rotator);
    }

    @Test
    void deploy_validScopeAndEmptyTargets_callsRotatorWithBootstrapProfiles() {
        when(secretStore.read("https://kv.vault.azure.net/secrets/f5-cred"))
                .thenReturn(KV_SECRET);
        when(rotator.rotate(any(), any(), any(), any()))
                .thenReturn(new F5BigIpCertRotator.RotationResult(List.of("api-clientssl"), List.of()));

        DeploymentResult result = adapter.deploy(buildBundle(), buildMessage(SCOPE_JSON, TARGETS_JSON, null));

        assertThat(result.targetResourceId()).contains("Common");
        assertThat(result.configJson()).contains("certName").contains("profilesPatched");

        ArgumentCaptor<F5BigIpConfig> cfg = ArgumentCaptor.forClass(F5BigIpConfig.class);
        verify(rotator).rotate(any(), any(), cfg.capture(), any());
        assertThat(cfg.getValue().bigipHost()).isEqualTo("10.0.0.10");
        assertThat(cfg.getValue().username()).isEqualTo("certping-api");
        assertThat(cfg.getValue().partition()).isEqualTo("Common");
        assertThat(cfg.getValue().clientSslProfiles()).containsExactly("api-clientssl");
        assertThat(cfg.getValue().installOnly()).isFalse();
    }

    @Test
    void deploy_withPriorResult_usesPriorProfilesAndBumpsVersion() {
        when(secretStore.read("https://kv.vault.azure.net/secrets/f5-cred"))
                .thenReturn(KV_SECRET);
        when(rotator.rotate(any(), any(), any(), any()))
                .thenReturn(new F5BigIpCertRotator.RotationResult(
                        List.of("api-clientssl", "www-clientssl"), List.of()));

        String prior = "{\"certName\":\"cert-0001_v1\",\"keyName\":\"cert-0001_v1\",\"version\":1," +
                "\"profilesPatched\":[\"api-clientssl\",\"www-clientssl\"]}";

        adapter.deploy(buildBundle(), buildMessage(SCOPE_JSON, TARGETS_JSON, prior));

        ArgumentCaptor<F5BigIpConfig> cfg = ArgumentCaptor.forClass(F5BigIpConfig.class);
        ArgumentCaptor<String> priorCert = ArgumentCaptor.forClass(String.class);
        verify(rotator).rotate(any(), any(), cfg.capture(), priorCert.capture());
        assertThat(cfg.getValue().certName()).endsWith("_v2");
        assertThat(cfg.getValue().clientSslProfiles())
                .containsExactly("api-clientssl", "www-clientssl");
        assertThat(priorCert.getValue()).isEqualTo("cert-0001_v1");
    }

    @Test
    void deploy_installOnlyScope_passesInstallOnlyToRotator() {
        when(secretStore.read(any())).thenReturn(KV_SECRET);
        when(rotator.rotate(any(), any(), any(), any()))
                .thenReturn(new F5BigIpCertRotator.RotationResult(List.of(), List.of()));

        String scopeInstallOnly = "{\"bigipHost\":\"10.0.0.10\",\"partition\":\"Common\",\"installOnly\":true}";

        adapter.deploy(buildBundle(), buildMessage(scopeInstallOnly, TARGETS_JSON, null));

        ArgumentCaptor<F5BigIpConfig> cfg = ArgumentCaptor.forClass(F5BigIpConfig.class);
        verify(rotator).rotate(any(), any(), cfg.capture(), any());
        assertThat(cfg.getValue().installOnly()).isTrue();
        assertThat(cfg.getValue().clientSslProfiles()).isEmpty();
    }

    @Test
    void deploy_explicitDeviceGroup_callsSync() {
        when(secretStore.read(any())).thenReturn(KV_SECRET);
        when(rotator.rotate(any(), any(), any(), any()))
                .thenReturn(new F5BigIpCertRotator.RotationResult(List.of("api-clientssl"), List.of()));

        String scopeWithGroup =
                "{\"bigipHost\":\"10.0.0.10\",\"partition\":\"Common\"," +
                "\"clientSslProfiles\":[\"api-clientssl\"],\"deviceGroup\":\"dg-ha\"}";

        DeploymentResult result = adapter.deploy(buildBundle(),
                buildMessage(scopeWithGroup, TARGETS_JSON, null));

        verify(rotator).syncDeviceGroup(any(), any());
        assertThat(result.configJson()).contains("lastSyncedAt");
    }

    @Test
    void deploy_autoDetectsDeviceGroupsFromRotator_callsSyncForEach() {
        when(secretStore.read(any())).thenReturn(KV_SECRET);
        when(rotator.rotate(any(), any(), any(), any()))
                .thenReturn(new F5BigIpCertRotator.RotationResult(
                        List.of("api-clientssl"), List.of("dg-ha")));

        adapter.deploy(buildBundle(), buildMessage(SCOPE_JSON, TARGETS_JSON, null));

        verify(rotator).syncDeviceGroup(any(), any());
    }

    @Test
    void deploy_standaloneNoGroupOverride_skipsSync() {
        when(secretStore.read(any())).thenReturn(KV_SECRET);
        when(rotator.rotate(any(), any(), any(), any()))
                .thenReturn(new F5BigIpCertRotator.RotationResult(List.of("api-clientssl"), List.of()));

        adapter.deploy(buildBundle(), buildMessage(SCOPE_JSON, TARGETS_JSON, null));

        verify(rotator, never()).syncDeviceGroup(any(), any());
    }

    @Test
    void deploy_missingDeploymentCredHandle_throwsPermanent() {
        CertDeploymentMessage msg = buildMessage(SCOPE_JSON, TARGETS_JSON, null);
        msg.setDeploymentCredHandle(null);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_MISSING"));
    }

    @Test
    void deploy_missingScopeJson_throwsPermanent() {
        when(secretStore.read(any())).thenReturn(KV_SECRET);
        CertDeploymentMessage msg = buildMessage(null, TARGETS_JSON, null);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void deploy_missingPartition_throwsPermanent() {
        when(secretStore.read(any())).thenReturn(KV_SECRET);
        String scopeNoPart = "{\"bigipHost\":\"10.0.0.10\"}";

        assertThatThrownBy(() -> adapter.deploy(buildBundle(),
                buildMessage(scopeNoPart, TARGETS_JSON, null)))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("partition");
    }

    @Test
    void deploy_missingHost_throwsPermanent() {
        when(secretStore.read(any())).thenReturn(KV_SECRET);
        String scopeNoHost = "{\"partition\":\"Common\"}";

        assertThatThrownBy(() -> adapter.deploy(buildBundle(),
                buildMessage(scopeNoHost, TARGETS_JSON, null)))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("bigipHost");
    }

    @Test
    void deploy_missingCertPem_throwsPermanent() {
        when(secretStore.read(any())).thenReturn(KV_SECRET);
        CertificateBundle bundle = new CertificateBundle(
                "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----",
                "", null, null);

        assertThatThrownBy(() -> adapter.deploy(bundle, buildMessage(SCOPE_JSON, TARGETS_JSON, null)))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("leaf/fullChain");
    }

    @Test
    void deploy_missingKeyPem_throwsPermanent() {
        when(secretStore.read(any())).thenReturn(KV_SECRET);
        CertificateBundle bundle = new CertificateBundle(
                "", "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----", null, null);

        assertThatThrownBy(() -> adapter.deploy(bundle, buildMessage(SCOPE_JSON, TARGETS_JSON, null)))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("private key");
    }

    @Test
    void deploy_invalidCredentialJson_throwsPermanent() {
        when(secretStore.read(any())).thenReturn("not valid json");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(),
                buildMessage(SCOPE_JSON, TARGETS_JSON, null)))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("KV secret JSON");
    }

    @Test
    void deploy_missingPassword_throwsPermanent() {
        when(secretStore.read(any())).thenReturn("{\"username\":\"admin\"}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(),
                buildMessage(SCOPE_JSON, TARGETS_JSON, null)))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("password");
    }

    @Test
    void validateScope_allFieldsPresent_doesNotThrow() {
        F5Scope scope = new F5Scope("10.0.0.10", 443, true,
                "Common", List.of("api-clientssl"), null, null);
        adapter.validateScope(scope);
    }

    @Test
    void validateScope_missingHost_throws() {
        F5Scope scope = new F5Scope(null, 443, true, "Common", null, null, null);
        assertThatThrownBy(() -> adapter.validateScope(scope))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("bigipHost");
    }

    @Test
    void validateScope_missingPartition_throws() {
        F5Scope scope = new F5Scope("10.0.0.10", 443, true, null, List.of("p"), null, null);
        assertThatThrownBy(() -> adapter.validateScope(scope))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("partition");
    }

    @Test
    void deploy_blankDeploymentCredHandle_throws() {
        CertDeploymentMessage msg = buildMessage(SCOPE_JSON, TARGETS_JSON, null);
        msg.setDeploymentCredHandle("");
        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void deploy_invalidScopeJson_throwsPermanent() {
        when(secretStore.read(any())).thenReturn(KV_SECRET);
        CertDeploymentMessage msg = buildMessage("{not json}", TARGETS_JSON, null);
        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("credentialScopeJson");
    }

    @Test
    void deploy_invalidTargetsJson_throwsPermanent() {
        when(secretStore.read(any())).thenReturn(KV_SECRET);
        CertDeploymentMessage msg = buildMessage(SCOPE_JSON, "{not json}", null);
        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_TARGETS_INVALID"));
    }

    @Test
    void deploy_nullTargetsJson_isOk() {
        when(secretStore.read(any())).thenReturn(KV_SECRET);
        when(rotator.rotate(any(), any(), any(), any()))
                .thenReturn(new F5BigIpCertRotator.RotationResult(List.of("api-clientssl"), List.of()));

        adapter.deploy(buildBundle(), buildMessage(SCOPE_JSON, null, null));
        verify(rotator).rotate(any(), any(), any(), any());
    }

    @Test
    void deploy_unparseablePriorConfigJson_treatsAsFirstDeploy() {
        when(secretStore.read(any())).thenReturn(KV_SECRET);
        when(rotator.rotate(any(), any(), any(), any()))
                .thenReturn(new F5BigIpCertRotator.RotationResult(List.of("api-clientssl"), List.of()));

        adapter.deploy(buildBundle(), buildMessage(SCOPE_JSON, TARGETS_JSON, "{garbage"));

        ArgumentCaptor<F5BigIpConfig> cfg = ArgumentCaptor.forClass(F5BigIpConfig.class);
        verify(rotator).rotate(any(), any(), cfg.capture(), any());
        assertThat(cfg.getValue().certName()).endsWith("_v1");
    }

    @Test
    void deploy_targetsCertBaseName_wins() {
        when(secretStore.read(any())).thenReturn(KV_SECRET);
        when(rotator.rotate(any(), any(), any(), any()))
                .thenReturn(new F5BigIpCertRotator.RotationResult(List.of("api-clientssl"), List.of()));

        String targets = "{\"certBaseName\":\"my-custom-base\"}";
        adapter.deploy(buildBundle(), buildMessage(SCOPE_JSON, targets, null));

        ArgumentCaptor<F5BigIpConfig> cfg = ArgumentCaptor.forClass(F5BigIpConfig.class);
        verify(rotator).rotate(any(), any(), cfg.capture(), any());
        assertThat(cfg.getValue().certName()).isEqualTo("my-custom-base_v1");
    }

    @Test
    void deploy_renamedBase_resetsVersionToOne() {
        when(secretStore.read(any())).thenReturn(KV_SECRET);
        when(rotator.rotate(any(), any(), any(), any()))
                .thenReturn(new F5BigIpCertRotator.RotationResult(List.of("api-clientssl"), List.of()));

        String prior = "{\"certName\":\"old-base_v5\",\"version\":5,\"profilesPatched\":[]}";
        String targets = "{\"certBaseName\":\"new-base\"}";
        adapter.deploy(buildBundle(), buildMessage(SCOPE_JSON, targets, prior));

        ArgumentCaptor<F5BigIpConfig> cfg = ArgumentCaptor.forClass(F5BigIpConfig.class);
        verify(rotator).rotate(any(), any(), cfg.capture(), any());
        assertThat(cfg.getValue().certName()).isEqualTo("new-base_v1");
    }

    @Test
    void deploy_priorWithoutVersionField_startsAtV1() {
        when(secretStore.read(any())).thenReturn(KV_SECRET);
        when(rotator.rotate(any(), any(), any(), any()))
                .thenReturn(new F5BigIpCertRotator.RotationResult(List.of(), List.of()));

        String prior = "{\"certName\":\"cert-0001_v0\",\"profilesPatched\":[]}";
        adapter.deploy(buildBundle(), buildMessage(SCOPE_JSON, TARGETS_JSON, prior));

        ArgumentCaptor<F5BigIpConfig> cfg = ArgumentCaptor.forClass(F5BigIpConfig.class);
        verify(rotator).rotate(any(), any(), cfg.capture(), any());
        // priorVersion null/<1 → next version = 1
        assertThat(cfg.getValue().certName()).endsWith("_v1");
    }

    @Test
    void deploy_priorCertNameWithoutSuffix_keepsBaseName() {
        when(secretStore.read(any())).thenReturn(KV_SECRET);
        when(rotator.rotate(any(), any(), any(), any()))
                .thenReturn(new F5BigIpCertRotator.RotationResult(List.of(), List.of()));

        // No _vN suffix — base = entire name = "cert-0001", same as derived xref.
        String prior = "{\"certName\":\"cert-0001\",\"version\":3,\"profilesPatched\":[]}";
        adapter.deploy(buildBundle(), buildMessage(SCOPE_JSON, TARGETS_JSON, prior));

        ArgumentCaptor<F5BigIpConfig> cfg = ArgumentCaptor.forClass(F5BigIpConfig.class);
        verify(rotator).rotate(any(), any(), cfg.capture(), any());
        assertThat(cfg.getValue().certName()).isEqualTo("cert-0001_v4");
    }

    @Test
    void deploy_invalidPort_throwsPermanent() {
        when(secretStore.read(any())).thenReturn(KV_SECRET);
        String scope = "{\"bigipHost\":\"10.0.0.10\",\"bigipPort\":99999,\"partition\":\"Common\"}";
        assertThatThrownBy(() -> adapter.deploy(buildBundle(), buildMessage(scope, TARGETS_JSON, null)))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("bigipPort");
    }

    @Test
    void deploy_negativePort_throwsPermanent() {
        when(secretStore.read(any())).thenReturn(KV_SECRET);
        String scope = "{\"bigipHost\":\"10.0.0.10\",\"bigipPort\":-1,\"partition\":\"Common\"}";
        assertThatThrownBy(() -> adapter.deploy(buildBundle(), buildMessage(scope, TARGETS_JSON, null)))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("bigipPort");
    }

    @Test
    void deploy_encryptedKey_throwsPermanent() {
        when(secretStore.read(any())).thenReturn(KV_SECRET);
        CertificateBundle bundle = new CertificateBundle(
                "-----BEGIN ENCRYPTED PRIVATE KEY-----\ndata\n-----END ENCRYPTED PRIVATE KEY-----",
                "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----", null, null);

        assertThatThrownBy(() -> adapter.deploy(bundle, buildMessage(SCOPE_JSON, TARGETS_JSON, null)))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_KEY_ENCRYPTED"));
    }

    @Test
    void deploy_missingUsername_throws() {
        when(secretStore.read(any())).thenReturn("{\"password\":\"x\"}");
        assertThatThrownBy(() -> adapter.deploy(buildBundle(), buildMessage(SCOPE_JSON, TARGETS_JSON, null)))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("username");
    }

    @Test
    void deploy_xrefDerivesName_whenNoTargetsNoPrior() {
        when(secretStore.read(any())).thenReturn(KV_SECRET);
        when(rotator.rotate(any(), any(), any(), any()))
                .thenReturn(new F5BigIpCertRotator.RotationResult(List.of("api-clientssl"), List.of()));

        adapter.deploy(buildBundle(), buildMessage(SCOPE_JSON, TARGETS_JSON, null));

        ArgumentCaptor<F5BigIpConfig> cfg = ArgumentCaptor.forClass(F5BigIpConfig.class);
        verify(rotator).rotate(any(), any(), cfg.capture(), any());
        assertThat(cfg.getValue().certName()).startsWith("cert-0001_v");
    }

    @Test
    void deploy_noXrefNoDomain_fallsBackToCert() {
        when(secretStore.read(any())).thenReturn(KV_SECRET);
        when(rotator.rotate(any(), any(), any(), any()))
                .thenReturn(new F5BigIpCertRotator.RotationResult(List.of(), List.of()));

        CertDeploymentMessage msg = buildMessage(SCOPE_JSON, TARGETS_JSON, null);
        msg.setCertificateXref(null);
        msg.setDomain(null);
        adapter.deploy(buildBundle(), msg);

        ArgumentCaptor<F5BigIpConfig> cfg = ArgumentCaptor.forClass(F5BigIpConfig.class);
        verify(rotator).rotate(any(), any(), cfg.capture(), any());
        assertThat(cfg.getValue().certName()).startsWith("cert_v");
    }

    @Test
    void deploy_domainFallback_whenNoXref() {
        when(secretStore.read(any())).thenReturn(KV_SECRET);
        when(rotator.rotate(any(), any(), any(), any()))
                .thenReturn(new F5BigIpCertRotator.RotationResult(List.of(), List.of()));

        CertDeploymentMessage msg = buildMessage(SCOPE_JSON, TARGETS_JSON, null);
        msg.setCertificateXref(null);
        adapter.deploy(buildBundle(), msg);

        ArgumentCaptor<F5BigIpConfig> cfg = ArgumentCaptor.forClass(F5BigIpConfig.class);
        verify(rotator).rotate(any(), any(), cfg.capture(), any());
        // Domain "api.example.com" → sanitized base "api.example.com"
        assertThat(cfg.getValue().certName()).startsWith("api.example.com_v");
    }

    @Test
    void deploy_leafOnlyBundle_usesLeaf() {
        when(secretStore.read(any())).thenReturn(KV_SECRET);
        when(rotator.rotate(any(), any(), any(), any()))
                .thenReturn(new F5BigIpCertRotator.RotationResult(List.of(), List.of()));

        CertificateBundle bundle = new CertificateBundle(
                "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----",
                "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----",
                null, null);
        adapter.deploy(bundle, buildMessage(SCOPE_JSON, TARGETS_JSON, null));
        verify(rotator).rotate(any(), any(), any(), any());
    }

    @Test
    void deploy_emptyTargetBaseName_isFallback() {
        when(secretStore.read(any())).thenReturn(KV_SECRET);
        when(rotator.rotate(any(), any(), any(), any()))
                .thenReturn(new F5BigIpCertRotator.RotationResult(List.of(), List.of()));

        String targets = "{\"certBaseName\":\"\"}";
        adapter.deploy(buildBundle(), buildMessage(SCOPE_JSON, targets, null));

        ArgumentCaptor<F5BigIpConfig> cfg = ArgumentCaptor.forClass(F5BigIpConfig.class);
        verify(rotator).rotate(any(), any(), cfg.capture(), any());
        assertThat(cfg.getValue().certName()).startsWith("cert-0001_v");
    }

    private CertDeploymentMessage buildMessage(String scopeJson, String targetsJson, String configJson) {
        CertDeploymentMessage msg = new CertDeploymentMessage();
        msg.setRequestId("req-1");
        msg.setCorrelationId("corr-1");
        msg.setOrganizationId("42");
        msg.setCertificateXref("cert-0001");
        msg.setDomain("api.example.com");
        msg.setCertSecretHandle("https://kv.vault.azure.net/secrets/cert-cert-0001");
        msg.setTargetType(TargetType.F5_BIGIP);
        msg.setDeploymentCredHandle("https://kv.vault.azure.net/secrets/f5-cred");
        msg.setRequestedAt("2026-05-01T00:00:00Z");
        msg.setCredentialScopeJson(scopeJson);
        msg.setTargetsJson(targetsJson);
        msg.setConfigJson(configJson);
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
