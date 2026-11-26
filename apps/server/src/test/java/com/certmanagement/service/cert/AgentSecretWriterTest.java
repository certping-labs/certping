// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.exception.BadRequestException;
import com.certmanagement.messaging.model.AgentInfo;
import com.certmanagement.service.agent.AgentInfoStore;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStore;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStoreProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;

import java.time.OffsetDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AgentSecretWriterTest {

    @Mock
    @SuppressWarnings("unchecked")
    private ObjectProvider<AgentSecretStore> storeProvider;

    @Test
    void isAvailable_falseWhenNoStoreWired() {
        when(storeProvider.getIfAvailable()).thenReturn(null);
        AgentSecretWriter writer = new AgentSecretWriter(storeProvider);
        assertThat(writer.isAvailable()).isFalse();
    }

    @Test
    void isAvailable_trueWhenStoreWiredAndReady() {
        AgentSecretStore store = mock(AgentSecretStore.class);
        when(storeProvider.getIfAvailable()).thenReturn(store);
        when(store.isReady()).thenReturn(true);
        AgentSecretWriter writer = new AgentSecretWriter(storeProvider);
        assertThat(writer.isAvailable()).isTrue();
    }

    @Test
    void isAvailable_falseWhenStoreWiredButNotReady() {
        AgentSecretStore store = mock(AgentSecretStore.class);
        when(storeProvider.getIfAvailable()).thenReturn(store);
        when(store.isReady()).thenReturn(false);
        AgentSecretWriter writer = new AgentSecretWriter(storeProvider);
        assertThat(writer.isAvailable()).isFalse();
    }

    @Test
    void writeSecret_delegatesToStore() {
        AgentSecretStore store = mock(AgentSecretStore.class);
        when(storeProvider.getIfAvailable()).thenReturn(store);
        when(store.create("name", "value")).thenReturn("handle:name");
        AgentSecretWriter writer = new AgentSecretWriter(storeProvider);

        assertThat(writer.writeSecret("name", "value")).isEqualTo("handle:name");
        verify(store).create("name", "value");
    }

    @Test
    void writeSecret_throwsWhenNoStoreWired() {
        when(storeProvider.getIfAvailable()).thenReturn(null);
        AgentSecretWriter writer = new AgentSecretWriter(storeProvider);

        assertThatThrownBy(() -> writer.writeSecret("n", "v"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("No AgentSecretStore driver available");
    }

    @Test
    void overwriteAtHandle_delegatesToStore() {
        AgentSecretStore store = mock(AgentSecretStore.class);
        when(storeProvider.getIfAvailable()).thenReturn(store);
        when(store.update("h", "v2")).thenReturn("h-new");
        AgentSecretWriter writer = new AgentSecretWriter(storeProvider);

        assertThat(writer.overwriteAtHandle("h", "v2")).isEqualTo("h-new");
    }

    @Test
    void deleteIfOwned_delegatesWhenStoreWired() {
        AgentSecretStore store = mock(AgentSecretStore.class);
        when(storeProvider.getIfAvailable()).thenReturn(store);
        AgentSecretWriter writer = new AgentSecretWriter(storeProvider);

        writer.deleteIfOwned("handle-x");
        verify(store).deleteIfOwned("handle-x");
    }

    @Test
    void deleteIfOwned_noopWhenNoStore() {
        when(storeProvider.getIfAvailable()).thenReturn(null);
        AgentSecretWriter writer = new AgentSecretWriter(storeProvider);
        writer.deleteIfOwned("handle-x"); // should not throw
    }

    @Test
    void buildSecretName_producesLowercaseKebabWithinLimits() {
        AgentSecretWriter writer = new AgentSecretWriter(storeProvider);
        String name = writer.buildSecretName(42L, "cred-741779318527164");
        assertThat(name).matches("^[a-z0-9-]{1,127}$");
        assertThat(name).isEqualTo("certping-org42-cred-741779318527164");
    }

    @Test
    void buildSecretName_stripsIllegalCharsAndCollapsesRuns() {
        AgentSecretWriter writer = new AgentSecretWriter(storeProvider);
        String name = writer.buildSecretName(1L, "@@cred--wild!@#$");
        assertThat(name).matches("^[a-z0-9-]{1,127}$");
        assertThat(name).doesNotContain("--");
        assertThat(name).doesNotStartWith("-");
        assertThat(name).doesNotEndWith("-");
    }

    @Test
    void buildSecretName_truncatesTo127Chars() {
        AgentSecretWriter writer = new AgentSecretWriter(storeProvider);
        String longXref = "cred-" + "a".repeat(200);
        String name = writer.buildSecretName(1L, longXref);
        assertThat(name.length()).isLessThanOrEqualTo(127);
    }

    private static AgentInfoStore.AgentRow agent(String name, String store, boolean bundled, OffsetDateTime revokedAt) {
        return new AgentInfoStore.AgentRow(1L, name, "cpa_x", "admin", null, null, revokedAt, null, null,
                AgentInfo.builder().secretStore(store).bundled(bundled).build(), null);
    }

    private AgentSecretWriter writerOverLocalStoreWith(AgentInfoStore.AgentRow... agents) {
        AgentSecretStore store = mock(AgentSecretStore.class);
        when(storeProvider.getIfAvailable()).thenReturn(store);
        when(store.provider()).thenReturn(AgentSecretStoreProvider.LOCAL);
        AgentInfoStore agentInfo = mock(AgentInfoStore.class);
        when(agentInfo.list(7L)).thenReturn(List.of(agents));
        AgentSecretWriter writer = new AgentSecretWriter(storeProvider);
        writer.setAgentInfoStore(agentInfo);
        return writer;
    }

    @Test
    void requireReadableByAgents_onlyTheBundledAgent_allowsPasting() {
        writerOverLocalStoreWith(agent("bundled", "LOCAL", true, null)).requireReadableByAgents(7L);
    }

    @Test
    void requireReadableByAgents_aRemoteAgentOnAnotherStore_refusesAndNamesIt() {
        AgentSecretWriter writer = writerOverLocalStoreWith(
                agent("bundled", "LOCAL", true, null), agent("dc-east", "AWS_SECRETS_MANAGER", false, null));

        assertThatThrownBy(() -> writer.requireReadableByAgents(7L))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("dc-east (AWS_SECRETS_MANAGER)");
    }

    @Test
    void requireReadableByAgents_aRemoteAgentWithItsOwnLocalStore_isRefused() {
        AgentSecretWriter writer = writerOverLocalStoreWith(agent("edge", "LOCAL", false, null));

        assertThatThrownBy(() -> writer.requireReadableByAgents(7L))
                .hasMessageContaining("edge (its own LOCAL store)");
    }

    @Test
    void requireReadableByAgents_aRevokedAgent_isNotCounted() {
        writerOverLocalStoreWith(agent("bundled", "LOCAL", true, null),
                agent("old", "AZURE_KV", false, OffsetDateTime.now())).requireReadableByAgents(7L);
    }
}
