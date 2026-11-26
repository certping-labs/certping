// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.agent;

import com.certmanagement.dto.agent.AgentView;
import com.certmanagement.messaging.model.AgentCaStatus;
import com.certmanagement.messaging.model.AgentHealthHeartbeat;
import com.certmanagement.messaging.model.AgentInfo;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AgentDirectoryServiceTest {

    private static final ObjectMapper JSON = JsonMapper.builderWithJackson2Defaults().build();
    private static final Instant NOW = Instant.parse("2026-10-31T12:00:00Z");
    private static final OffsetDateTime T = OffsetDateTime.ofInstant(NOW, ZoneOffset.UTC);

    private final AgentInfoStore store = mock(AgentInfoStore.class);
    private final AgentHealthService health = mock(AgentHealthService.class);
    private final AgentDirectoryService service =
            new AgentDirectoryService(store, health, Clock.fixed(NOW, ZoneOffset.UTC));

    private static AgentInfoStore.AgentRow row(long id, String name, String createdBy, OffsetDateTime revokedAt,
                                               OffsetDateTime expiresAt, OffsetDateTime lastUsed,
                                               OffsetDateTime lastHeartbeat, AgentInfo info, AgentCaStatus ca) {
        return new AgentInfoStore.AgentRow(id, name, "cpa_abcdef", createdBy, T.minusDays(10), expiresAt, revokedAt,
                lastUsed, lastHeartbeat, info, ca);
    }

    private static AgentInfo info(boolean bundled) {
        return AgentInfo.builder().version("0.2.0").hostname("edge-1").os("Linux aarch64").javaVersion("25.0.1")
                .secretStore("LOCAL").maxConcurrentJobs(8).proxyConfigured(false).bundled(bundled)
                .capabilities(AgentInfo.Capabilities.builder().deploymentTargets(List.of("AZURE_KEYVAULT"))
                        .discoveryTargets(List.of("KUBERNETES_SECRETS")).dnsProviders(List.of("CLOUDFLARE")).build())
                .build();
    }

    @Test
    void onlineWithinThreeCadencePeriods_offlineAfter_neverSeenWithoutContact() {
        when(health.getHeartbeatCadenceMinutes(10L)).thenReturn(5);
        when(store.list(10L)).thenReturn(List.of(
                row(1, "late", null, null, null, null, T.minusMinutes(15), info(false), null),
                row(2, "never", null, null, null, null, null, null, null),
                row(3, "fresh", null, null, null, null, T.minusMinutes(14), info(false), null),
                row(4, "polling", null, null, null, T.minusMinutes(1), null, null, null)));

        List<AgentView> agents = service.list(10L);

        assertThat(agents).extracting(AgentView::name, AgentView::status).containsExactly(
                org.assertj.core.groups.Tuple.tuple("fresh", "ONLINE"),
                org.assertj.core.groups.Tuple.tuple("polling", "ONLINE"),
                org.assertj.core.groups.Tuple.tuple("late", "OFFLINE"),
                org.assertj.core.groups.Tuple.tuple("never", "NEVER_SEEN"));
        assertThat(agents.get(1).lastSeenAt()).isEqualTo(T.minusMinutes(1).toString());
        assertThat(agents.get(3).lastSeenAt()).isNull();
    }

    @Test
    void usesTheOrganizationsCadence() {
        when(health.getHeartbeatCadenceMinutes(10L)).thenReturn(1);
        when(store.list(10L)).thenReturn(List.of(
                row(1, "a", null, null, null, null, T.minusMinutes(4), info(false), null)));
        assertThat(service.list(10L).get(0).status()).isEqualTo("OFFLINE");

        when(health.getHeartbeatCadenceMinutes(10L)).thenReturn(60);
        assertThat(service.list(10L).get(0).status()).isEqualTo("ONLINE");
    }

    @Test
    void revokedAndExpiredTokensAreListedOffline() {
        when(health.getHeartbeatCadenceMinutes(10L)).thenReturn(5);
        when(store.list(10L)).thenReturn(List.of(
                row(1, "revoked", null, T.minusHours(1), null, null, T.minusMinutes(1), info(false), null),
                row(2, "expired", null, null, T.minusMinutes(1), null, T.minusMinutes(1), info(false), null),
                row(3, "ok", null, null, T.plusDays(1), null, T.minusMinutes(1), info(false), null)));

        List<AgentView> agents = service.list(10L);

        assertThat(agents.get(0).name()).isEqualTo("ok");
        assertThat(agents.get(0).revoked()).isFalse();
        assertThat(agents.get(0).tokenExpiresAt()).isEqualTo(T.plusDays(1).toString());
        assertThat(agents.subList(1, 3)).allSatisfy(a -> {
            assertThat(a.status()).isEqualTo("OFFLINE");
            assertThat(a.revoked()).isTrue();
        });
    }

    @Test
    void bundledFromTheBootstrapTokenOrTheAgentsReport() {
        when(health.getHeartbeatCadenceMinutes(10L)).thenReturn(5);
        when(store.list(10L)).thenReturn(List.of(
                row(1, "bundled-agent", "bootstrap", null, null, null, null, null, null),
                row(2, "reported", "a@b.com", null, null, null, null, info(true), null),
                row(3, "remote", "a@b.com", null, null, null, null, info(false), null)));

        assertThat(service.list(10L)).extracting(AgentView::name, AgentView::bundled).containsExactlyInAnyOrder(
                org.assertj.core.groups.Tuple.tuple("bundled-agent", true),
                org.assertj.core.groups.Tuple.tuple("reported", true),
                org.assertj.core.groups.Tuple.tuple("remote", false));
    }

    @Test
    void mapsTheReportAndTheCaStatus() {
        when(health.getHeartbeatCadenceMinutes(10L)).thenReturn(5);
        AgentCaStatus ca = AgentCaStatus.builder()
                .acme(AgentCaStatus.Acme.builder().directoryUrl("https://acme/dir").environment("CUSTOM")
                        .contactEmail("ops@example.com").build())
                .globalsign(new AgentCaStatus.Configured(false))
                .build();
        when(store.find(10L, 7L)).thenReturn(Optional.of(
                row(7, "edge", null, null, null, null, T.minusMinutes(1), info(false), ca)));

        AgentView view = service.get(10L, 7L).orElseThrow();

        assertThat(view.agentId()).isEqualTo("7");
        assertThat(view.tokenPrefix()).isEqualTo("cpa_abcdef");
        assertThat(view.version()).isEqualTo("0.2.0");
        assertThat(view.hostname()).isEqualTo("edge-1");
        assertThat(view.os()).isEqualTo("Linux aarch64");
        assertThat(view.javaVersion()).isEqualTo("25.0.1");
        assertThat(view.secretStore()).isEqualTo("LOCAL");
        assertThat(view.maxConcurrentJobs()).isEqualTo(8);
        assertThat(view.proxyConfigured()).isFalse();
        assertThat(view.acme()).isEqualTo(new AgentView.Acme("https://acme/dir", "CUSTOM", "ops@example.com"));
        assertThat(view.globalsignConfigured()).isFalse();
        assertThat(view.capabilities().deploymentTargets()).containsExactly("AZURE_KEYVAULT");
        assertThat(view.capabilities().discoveryTargets()).containsExactly("KUBERNETES_SECRETS");
        assertThat(view.capabilities().dnsProviders()).containsExactly("CLOUDFLARE");
    }

    @Test
    void anAgentThatNeverReportedHasEmptyCapabilitiesAndNullFields() {
        when(health.getHeartbeatCadenceMinutes(10L)).thenThrow(new IllegalArgumentException("gone"));
        when(store.find(10L, 7L)).thenReturn(Optional.of(row(7, "edge", null, null, null, null, null, null, null)));

        AgentView view = service.get(10L, 7L).orElseThrow();

        assertThat(view.status()).isEqualTo("NEVER_SEEN");
        assertThat(view.version()).isNull();
        assertThat(view.acme()).isNull();
        assertThat(view.globalsignConfigured()).isNull();
        assertThat(view.capabilities().deploymentTargets()).isEmpty();
        assertThat(view.capabilities().dnsProviders()).isEmpty();
    }

    @Test
    void onlyReadsTheRequestedOrganization() {
        when(health.getHeartbeatCadenceMinutes(10L)).thenReturn(5);
        when(store.list(10L)).thenReturn(List.of());
        when(store.find(10L, 99L)).thenReturn(Optional.empty());

        assertThat(service.list(10L)).isEmpty();
        assertThat(service.get(10L, 99L)).isEmpty();
        verify(store).list(10L);
        verify(store).find(10L, 99L);
    }

    /** A heartbeat stuffed with secrets, as a hostile or buggy agent might send it. */
    static final String HOSTILE_HEARTBEAT = """
            {"organizationId":"10","listening":true,
             "caStatus":{"acme":{"directoryUrl":"https://acme/dir","environment":"CUSTOM","contactEmail":"",
                                 "accountKey":"-----BEGIN PRIVATE KEY-----MIIEvQ"},
                         "otherCa":{"configured":true,"loginPassword":"hunter2-otherCa"},
                         "globalsign":{"configured":true,"apiSecret":"gs-secret-value"}},
             "agentInfo":{"version":"cpa_LEAKEDTOKENVALUE0123456789abcdefghijklmn",
                          "hostname":"-----BEGIN PRIVATE KEY-----",
                          "agentToken":"cpa_LEAKEDTOKENVALUE0123456789abcdefghijklmn",
                          "os":"Linux aarch64",
                          "javaVersion":"25.0.1",
                          "secretStore":"LOCAL",
                          "secretStoreKey":"c2VjcmV0LWtleS1zZWNyZXQ=",
                          "clientSecret":"azure-client-secret-value",
                          "proxyUrl":"http://user:proxy-pass@proxy:3128",
                          "maxConcurrentJobs":8,
                          "proxyConfigured":true,
                          "env":{"CERTPING_AGENT_TOKEN":"cpa_LEAKEDTOKENVALUE0123456789abcdefghijklmn"},
                          "capabilities":{"deploymentTargets":["AZURE_KEYVAULT","apiKey=abc123secret"],
                                          "discoveryTargets":[],
                                          "dnsProviders":["CLOUDFLARE","cpa_LEAKED"],
                                          "credentials":{"CLOUDFLARE":"cf-api-token-value"}}}}
            """;

    @Test
    void neverReturnsASecretWhateverTheHeartbeatCarried() {
        AgentHealthHeartbeat heartbeat = JSON.readValue(HOSTILE_HEARTBEAT, AgentHealthHeartbeat.class);
        when(health.getHeartbeatCadenceMinutes(10L)).thenReturn(5);
        when(store.list(10L)).thenReturn(List.of(row(1, "edge", null, null, null, null, T.minusMinutes(1),
                heartbeat.getAgentInfo(), heartbeat.getCaStatus())));

        String body = JSON.writeValueAsString(new AgentView.AgentList(service.list(10L)));

        assertThat(body).doesNotContain("LEAKED", "PRIVATE KEY", "hunter2", "otherCa", "gs-secret", "c2VjcmV0",
                "azure-client-secret", "proxy-pass", "abc123secret", "cf-api-token",
                "accountKey", "loginPassword", "apiSecret", "secretStoreKey", "clientSecret", "proxyUrl",
                "credentials", "agentToken", "\"env\"", "accounts");
        AgentView view = service.list(10L).get(0);
        assertThat(view.version()).isNull();
        assertThat(view.hostname()).isNull();
        assertThat(view.os()).isEqualTo("Linux aarch64");
        assertThat(view.secretStore()).isEqualTo("LOCAL");
        assertThat(view.proxyConfigured()).isTrue();
        assertThat(view.capabilities().deploymentTargets()).containsExactly("AZURE_KEYVAULT");
        assertThat(view.capabilities().dnsProviders()).containsExactly("CLOUDFLARE");
    }

    @Test
    void responseHasExactlyTheDocumentedFields() {
        when(health.getHeartbeatCadenceMinutes(10L)).thenReturn(5);
        when(store.list(10L)).thenReturn(List.of(row(1, "edge", null, null, null, null, null, null, null)));

        var node = JSON.readTree(JSON.writeValueAsString(new AgentView.AgentList(service.list(10L))));

        assertThat(node.propertyNames()).containsExactly("agents");
        assertThat(node.get("agents").get(0).propertyNames()).containsExactlyInAnyOrder(
                "agentId", "name", "tokenPrefix", "tokenCreatedAt", "tokenExpiresAt", "revoked", "status",
                "lastSeenAt", "version", "hostname", "os", "javaVersion", "secretStore", "maxConcurrentJobs",
                "proxyConfigured", "bundled", "acme", "globalsignConfigured", "capabilities");
        assertThat(node.get("agents").get(0).get("capabilities").propertyNames())
                .containsExactlyInAnyOrder("deploymentTargets", "discoveryTargets", "dnsProviders");
    }
}
