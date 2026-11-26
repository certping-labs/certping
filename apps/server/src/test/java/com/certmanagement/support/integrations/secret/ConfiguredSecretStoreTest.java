// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.secret;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.certmanagement.support.integrations.secret.agent.AgentSecretStore;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStoreProperties;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStoreProvider;
import com.certmanagement.support.integrations.secret.agent.local.LocalAgentSecretDriver;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.ObjectProvider;

/** Integration secrets on a single-server install: the LOCAL store, with no cloud vault. */
class ConfiguredSecretStoreTest {

    private static final String NAME = "integration-5-slack-webhook-url";
    private static final String WEBHOOK = "https://hooks.slack.com/services/T000/B000/XXXX";

    @TempDir
    Path directory;

    private LocalAgentSecretDriver local;
    private ConfiguredSecretStore store;

    @BeforeEach
    void setUp() {
        AgentSecretStoreProperties properties = new AgentSecretStoreProperties();
        properties.setProvider(AgentSecretStoreProvider.LOCAL);
        properties.getLocal().setDirectory(directory.toString());
        properties.getLocal().setKey(Base64.getEncoder().encodeToString(new byte[32]));
        local = new LocalAgentSecretDriver(properties);
        store = new ConfiguredSecretStore(provider(local));
    }

    @Test
    void aWrittenSecretReadsBackAndIsEncryptedOnDisk() throws IOException {
        String ref = store.writeSecret(null, NAME, WEBHOOK);

        assertThat(ref).isEqualTo("local:certping-" + NAME);
        assertThat(store.readSecret(ref)).isEqualTo(WEBHOOK);
        try (Stream<Path> files = Files.list(directory)) {
            for (Path file : files.toList()) {
                assertThat(new String(Files.readAllBytes(file), StandardCharsets.ISO_8859_1)).doesNotContain("hooks.slack.com");
            }
        }
    }

    @Test
    void aSecretWrittenBeforeIsRotatedAtItsReference() {
        String ref = store.writeSecret(null, NAME, WEBHOOK);

        String rotated = store.writeSecret(ref, NAME, WEBHOOK + "-new");

        assertThat(rotated).isEqualTo(ref);
        assertThat(store.readSecret(ref)).isEqualTo(WEBHOOK + "-new");
    }

    @Test
    void aReferenceThisStoreDoesNotOwnIsReplacedByANewSecret() {
        String ref = store.writeSecret("integration-5-slack-webhook-url-from-another-store", NAME, WEBHOOK);

        assertThat(ref).isEqualTo("local:certping-" + NAME);
        assertThat(store.readSecret(ref)).isEqualTo(WEBHOOK);
    }

    @Test
    void aSecretDeletedOutsideCertPingIsWrittenAgain() {
        String ref = store.writeSecret(null, NAME, WEBHOOK);
        local.deleteIfOwned(ref);

        assertThat(store.writeSecret(ref, NAME, WEBHOOK + "-new")).isEqualTo(ref);
        assertThat(store.readSecret(ref)).isEqualTo(WEBHOOK + "-new");
    }

    @Test
    void withoutAConfiguredStoreAWriteSaysWhatToSet() {
        ConfiguredSecretStore none = new ConfiguredSecretStore(provider(null));

        assertThatThrownBy(() -> none.writeSecret(null, NAME, WEBHOOK))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("certping.agent-secret-store.provider");
    }

    @SuppressWarnings("unchecked")
    private static ObjectProvider<AgentSecretStore> provider(AgentSecretStore store) {
        ObjectProvider<AgentSecretStore> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(store);
        return provider;
    }
}
