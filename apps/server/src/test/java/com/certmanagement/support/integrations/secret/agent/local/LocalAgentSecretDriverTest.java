// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.secret.agent.local;

import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStoreProperties;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStoreProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LocalAgentSecretDriverTest {

    private static final String KEY = Base64.getEncoder().encodeToString(new byte[32]);

    @TempDir
    Path dir;

    private LocalAgentSecretDriver driver() {
        AgentSecretStoreProperties properties = new AgentSecretStoreProperties();
        properties.setProvider(AgentSecretStoreProvider.LOCAL);
        properties.getLocal().setDirectory(dir.toString());
        properties.getLocal().setKey(KEY);
        assertThat(properties.isConfigured()).isTrue();
        return new LocalAgentSecretDriver(properties);
    }

    @Test
    void writesSecretsTheAgentCanRead() throws Exception {
        LocalAgentSecretDriver driver = driver();
        String handle = driver.create("cred-1", "{\"apiToken\":\"abc\"}");

        assertThat(handle).isEqualTo("local:certping-cred-1").isEqualTo(driver.handleFor("cred-1"));
        assertThat(driver.read(handle)).isEqualTo("{\"apiToken\":\"abc\"}");
        assertThat(driver.provider()).isEqualTo(AgentSecretStoreProvider.LOCAL);
        // Same on-disk format the agent's driver reads.
        assertThat(new LocalSecretFiles(dir, KEY).read("certping-cred-1")).contains("{\"apiToken\":\"abc\"}");
        assertThat(Files.list(dir).map(p -> p.getFileName().toString())).contains("certping-cred-1.secret");

        assertThat(driver.update(handle, "v2")).isEqualTo(handle);
        assertThat(driver.read(handle)).isEqualTo("v2");
        driver.deleteIfOwned(handle);
        assertThatThrownBy(() -> driver.read(handle)).isInstanceOf(ResourceNotFoundException.class);
        assertThatThrownBy(() -> driver.update(handle, "v3")).isInstanceOf(ResourceNotFoundException.class);
    }

    @Test
    void ownershipAndCertificateHandles() {
        LocalAgentSecretDriver driver = driver();
        assertThat(driver.isOwnedByThisCertManager("local:certping-x")).isTrue();
        assertThat(driver.isOwnedByThisCertManager("local:agent-x")).isFalse();
        assertThat(driver.isOwnedByThisCertManager(null)).isFalse();
        assertThat(driver.isAgentCertificateHandle("local:certping-cert-9", "cert-9")).isTrue();
        assertThat(driver.isAgentCertificateHandle("local:certping-cert-9", "cert-8")).isFalse();
        assertThat(driver.isAgentCertificateHandle("local:certping-cert-9", null)).isFalse();
        assertThatThrownBy(() -> driver.update("local:agent-x", "v")).isInstanceOf(BadRequestException.class);
        assertThatThrownBy(() -> driver.read("https://kv/secrets/x")).isInstanceOf(BadRequestException.class);
        assertThatThrownBy(() -> driver.create("bad/name", "v")).isInstanceOf(BadRequestException.class);
        assertThatThrownBy(() -> driver.create(null, "v")).isInstanceOf(BadRequestException.class);
        driver.deleteIfOwned("local:agent-x");
        driver.deleteIfOwned("local:certping-never-written");
    }

    @Test
    void anUnsetKeyIsReportedClearly() {
        AgentSecretStoreProperties properties = new AgentSecretStoreProperties();
        properties.setProvider(AgentSecretStoreProvider.LOCAL);
        properties.getLocal().setDirectory(dir.toString());
        assertThat(properties.isConfigured()).isFalse();
        assertThatThrownBy(() -> new LocalAgentSecretDriver(properties))
                .hasMessageContaining("CERTPING_LOCAL_SECRET_KEY");
    }
}
