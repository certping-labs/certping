// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.secret.agent.azure;

import com.certmanagement.exception.BadRequestException;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStoreProperties;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStoreProvider;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Pure-logic tests — driver runs without initializing the SDK client (unset vaultUri path).
 * IO-heavy paths (setSecret / getSecret / beginDeleteSecret) are covered by integration tests
 * against the KV emulator, not here.
 */
class AzureKeyVaultAgentDriverTest {

    private AzureKeyVaultAgentDriver driverWithoutInit() {
        AgentSecretStoreProperties props = new AgentSecretStoreProperties();
        // vaultUri left blank → initialize() logs and skips client construction.
        AzureKeyVaultAgentDriver d = new AzureKeyVaultAgentDriver(props);
        d.initialize();
        return d;
    }

    @Test
    void provider_returnsAzureKv() {
        assertThat(driverWithoutInit().provider()).isEqualTo(AgentSecretStoreProvider.AZURE_KV);
    }

    @Test
    void handleFor_throwsWhenNotConfigured() {
        assertThatThrownBy(() -> driverWithoutInit().handleFor("name"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not configured");
    }

    @Test
    void isOwnedByThisCertManager_falseForNullHandle() {
        assertThat(driverWithoutInit().isOwnedByThisCertManager(null)).isFalse();
    }

    @Test
    void isOwnedByThisCertManager_falseForNonMatchingUri() {
        AgentSecretStoreProperties props = new AgentSecretStoreProperties();
        props.getAzureKv().setVaultUri("https://kv-mine.vault.azure.net/");
        props.getAzureKv().setDisableChallengeResourceVerification(true);
        AzureKeyVaultAgentDriver d = new AzureKeyVaultAgentDriver(props);
        d.initialize();
        assertThat(d.isOwnedByThisCertManager("https://kv-other.vault.azure.net/secrets/foo")).isFalse();
    }

    @Test
    void isOwnedByThisCertManager_trueForMatchingUri() {
        AgentSecretStoreProperties props = new AgentSecretStoreProperties();
        props.getAzureKv().setVaultUri("https://kv-mine.vault.azure.net/");
        props.getAzureKv().setDisableChallengeResourceVerification(true);
        AzureKeyVaultAgentDriver d = new AzureKeyVaultAgentDriver(props);
        d.initialize();
        assertThat(d.isOwnedByThisCertManager("https://kv-mine.vault.azure.net/secrets/foo")).isTrue();
    }

    @Test
    void handleFor_producesExpectedUri() {
        AgentSecretStoreProperties props = new AgentSecretStoreProperties();
        props.getAzureKv().setVaultUri("https://kv-mine.vault.azure.net/");
        props.getAzureKv().setDisableChallengeResourceVerification(true);
        AzureKeyVaultAgentDriver d = new AzureKeyVaultAgentDriver(props);
        d.initialize();
        assertThat(d.handleFor("my-name-1"))
                .isEqualTo("https://kv-mine.vault.azure.net/secrets/my-name-1");
    }

    @Test
    void handleFor_rejectsInvalidName() {
        AgentSecretStoreProperties props = new AgentSecretStoreProperties();
        props.getAzureKv().setVaultUri("https://kv-mine.vault.azure.net/");
        props.getAzureKv().setDisableChallengeResourceVerification(true);
        AzureKeyVaultAgentDriver d = new AzureKeyVaultAgentDriver(props);
        d.initialize();
        assertThatThrownBy(() -> d.handleFor("Bad Name!"))
                .isInstanceOf(BadRequestException.class);
    }

    @Test
    void deleteIfOwned_noopForForeignOrBlankHandle() {
        AzureKeyVaultAgentDriver d = driverWithoutInit();
        d.deleteIfOwned(null); // no-op, no throw
        d.deleteIfOwned("");   // no-op
        d.deleteIfOwned("https://kv-other.vault.azure.net/secrets/foo"); // no-op — foreign or no client
    }

    @Test
    void useEmulatorCredentialBranch_initializesWithoutThrowing() {
        AgentSecretStoreProperties props = new AgentSecretStoreProperties();
        props.getAzureKv().setVaultUri("https://kv-mine.vault.azure.net/");
        props.getAzureKv().setUseEmulatorCredential(true);
        AzureKeyVaultAgentDriver d = new AzureKeyVaultAgentDriver(props);
        d.initialize();
        assertThat(d.provider()).isEqualTo(AgentSecretStoreProvider.AZURE_KV);
    }

    @Test
    void isAgentCertificateHandle_acceptsOnlyTheCertsOwnSecretInOurVault() {
        AgentSecretStoreProperties props = new AgentSecretStoreProperties();
        props.getAzureKv().setVaultUri("https://kv-mine.vault.azure.net/");
        props.getAzureKv().setDisableChallengeResourceVerification(true);
        AzureKeyVaultAgentDriver d = new AzureKeyVaultAgentDriver(props);
        d.initialize();

        assertThat(d.isAgentCertificateHandle("https://kv-mine.vault.azure.net/secrets/cert-123", "cert-123")).isTrue();
        assertThat(d.isAgentCertificateHandle("https://kv-mine.vault.azure.net/secrets/cert-123/abc123", "cert-123"))
                .isTrue();
        // An org credential secret in the same vault must never be read on a certificate's behalf.
        assertThat(d.isAgentCertificateHandle(
                "https://kv-mine.vault.azure.net/secrets/certping-org7-cred-1", "cert-123")).isFalse();
        assertThat(d.isAgentCertificateHandle("https://kv-other.vault.azure.net/secrets/cert-123", "cert-123")).isFalse();
        assertThat(d.isAgentCertificateHandle("https://kv-mine.vault.azure.net/secrets/cert-1234", "cert-123")).isFalse();
        assertThat(d.isAgentCertificateHandle(null, "cert-123")).isFalse();
        assertThat(d.isAgentCertificateHandle("https://kv-mine.vault.azure.net/secrets/cert-123", null)).isFalse();
    }

    @Test
    void isAgentCertificateHandle_falseWhenVaultNotConfigured() {
        assertThat(driverWithoutInit().isAgentCertificateHandle(
                "https://kv-mine.vault.azure.net/secrets/cert-123", "cert-123")).isFalse();
    }
}
