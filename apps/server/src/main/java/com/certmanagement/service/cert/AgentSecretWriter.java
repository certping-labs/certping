// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.exception.BadRequestException;
import com.certmanagement.messaging.model.AgentInfo;
import com.certmanagement.service.agent.AgentInfoStore;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStore;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStoreProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Locale;

/**
 * Materializes credential payloads (credJson) into the agent's secret store — provider-neutral.
 *
 * <p>Delegates all IO to the active {@link AgentSecretStore} driver so the same call site works
 * against Azure KV, AWS Secrets Manager, or GCP Secret Manager depending on
 * {@code certping.agent-secret-store.provider}. Only holds the deterministic naming policy — every
 * driver produces a shape acceptable to the naming rules baked in below.
 *
 * <p>This bean is only wired when an
 * {@link AgentSecretStore} is available in the context — that is, when a provider is selected.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AgentSecretWriter {

    private final ObjectProvider<AgentSecretStore> storeProvider;
    private AgentInfoStore agentInfoStore;

    @Autowired(required = false)
    void setAgentInfoStore(AgentInfoStore agentInfoStore) {
        this.agentInfoStore = agentInfoStore;
    }

    /**
     * Refuses a pasted secret that one of the organization's agents could not read: its jobs can go to
     * any of them. LOCAL is readable by the bundled agent only, which shares the server's volume; a cloud
     * store by agents reporting that same store. An agent that has not reported yet is not counted.
     */
    public void requireReadableByAgents(Long organizationId) {
        AgentSecretStore store = storeProvider.getIfAvailable();
        if (store == null || agentInfoStore == null || organizationId == null) {
            return;
        }
        AgentSecretStoreProvider serverStore = store.provider();
        OffsetDateTime now = OffsetDateTime.now();
        List<String> unreachable = agentInfoStore.list(organizationId).stream()
                .filter(row -> row.revokedAt() == null
                        && (row.tokenExpiresAt() == null || row.tokenExpiresAt().isAfter(now)))
                .filter(row -> row.agentInfo() != null && !canRead(serverStore, row.agentInfo()))
                .map(row -> row.name() + " (" + describe(row.agentInfo()) + ")")
                .toList();
        if (!unreachable.isEmpty()) {
            throw new BadRequestException("A pasted secret is kept in this server's " + serverStore
                    + " store, which these agents cannot read: " + String.join(", ", unreachable)
                    + ". Store the secret in that agent's vault and enter its address instead.");
        }
    }

    static boolean canRead(AgentSecretStoreProvider serverStore, AgentInfo agent) {
        return serverStore.name().equals(agent.getSecretStore())
                && (serverStore != AgentSecretStoreProvider.LOCAL || Boolean.TRUE.equals(agent.getBundled()));
    }

    private static String describe(AgentInfo agent) {
        if (agent.getSecretStore() == null) {
            return "store unknown";
        }
        return AgentSecretStoreProvider.LOCAL.name().equals(agent.getSecretStore())
                ? "its own LOCAL store" : agent.getSecretStore();
    }

    /** True when a driver is wired AND it holds enough config to actually serve reads/writes. */
    public boolean isAvailable() {
        AgentSecretStore store = storeProvider.getIfAvailable();
        return store != null && store.isReady();
    }

    /**
     * Writes {@code value} at a deterministic address derived from {@code name} and returns the
     * handle the agent will use to read it back. Idempotent — overwrites if the name already exists.
     */
    public String writeSecret(String name, String value) {
        return requireStore().create(name, value);
    }

    /**
     * Overwrites the value at {@code handle} in place — used by credJson rotation so the persisted
     * handle stays stable. Returns the refreshed handle (versioned providers return a new version
     * segment; Azure returns the same handle).
     */
    public String overwriteAtHandle(String handle, String value) {
        return requireStore().update(handle, value);
    }

    /**
     * Purges the secret behind {@code handle} — only if this server's store owns it. Foreign
     * handles (customer-supplied URIs, other-provider ARNs) no-op silently.
     */
    public void deleteIfOwned(String handle) {
        AgentSecretStore store = storeProvider.getIfAvailable();
        if (store != null) {
            store.deleteIfOwned(handle);
        }
    }

    /**
     * Deterministic, lowercase kebab-case name that satisfies every driver's naming rules
     * (Azure: {@code [a-z0-9-]{1,127}}, AWS: {@code [A-Za-z0-9_/-]{1,127}}, GCP:
     * {@code [A-Za-z0-9_-]{1,127}}) — so the same (orgId, credentialXref) pair always addresses
     * the same secret across re-writes on every provider.
     */
    public String buildSecretName(Long organizationId, String credentialXref) {
        String raw = ("certping-org" + organizationId + "-" + credentialXref).toLowerCase(Locale.ROOT)
                .replaceAll("[^a-z0-9-]", "-")
                .replaceAll("-{2,}", "-")
                .replaceAll("^-+", "")
                .replaceAll("-+$", "");
        if (raw.length() > 127) {
            raw = raw.substring(0, 127).replaceAll("-+$", "");
        }
        return raw;
    }

    private AgentSecretStore requireStore() {
        AgentSecretStore store = storeProvider.getIfAvailable();
        if (store == null) {
            throw new IllegalStateException(
                    "No AgentSecretStore driver available — set certping.agent-secret-store.provider");
        }
        return store;
    }
}
