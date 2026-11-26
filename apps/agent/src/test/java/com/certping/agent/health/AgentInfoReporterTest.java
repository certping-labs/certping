// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.health;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.config.InboundConsumerLifecycle;
import com.certping.agent.deployment.adapter.DeploymentAdapterFactory;
import com.certping.agent.discovery.DiscoveryAdapterFactory;
import com.certping.agent.listener.AgentMessageSender;
import com.certping.agent.model.enums.TargetType;
import com.certping.agent.model.message.AgentHealthHeartbeat;
import com.certping.agent.model.message.AgentInfo;
import com.certping.agent.secrets.SecretStoreProperties;
import com.certping.agent.secrets.SecretStoreProvider;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import tools.jackson.databind.json.JsonMapper;

import java.util.EnumSet;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AgentInfoReporterTest {

    private static final String SECRET_KEY = "c2VjcmV0LWtleS1zZWNyZXQta2V5LXNlY3JldC1rZXk=";
    private static final String TOKEN = "cpa_doNotLeakThisTokenValue1234567890abcdefgh";
    private static final String PROXY = "http://user:proxypass@proxy.internal:3128";

    private final DeploymentAdapterFactory deployments = mock(DeploymentAdapterFactory.class);
    private final DiscoveryAdapterFactory discoveries = mock(DiscoveryAdapterFactory.class);

    private AgentProperties properties() {
        AgentProperties properties = new AgentProperties();
        properties.getTransport().setMaxConcurrentJobs(8);
        properties.getTransport().setToken(TOKEN);
        properties.getGlobalsign().setApiSecret("gs-api-secret");
        return properties;
    }

    private SecretStoreProperties secretStore(SecretStoreProvider provider) {
        SecretStoreProperties store = new SecretStoreProperties();
        store.setProvider(provider);
        store.getLocal().setKey(SECRET_KEY);
        store.getAzureKv().setClientSecret("azure-client-secret");
        return store;
    }

    private AgentInfoReporter reporter(AgentProperties properties, SecretStoreProvider provider,
                                       Map<String, String> env, String version) {
        when(deployments.supportedTargetTypes()).thenReturn(EnumSet.of(TargetType.values()[0]));
        when(discoveries.supportedTargetTypes()).thenReturn(EnumSet.of(TargetType.values()[1]));
        return new AgentInfoReporter(properties, secretStore(provider), deployments, discoveries, env, () -> version);
    }

    @Test
    void reportsWhatTheAgentIsAndCanDo() {
        AgentProperties properties = properties();
        properties.setBundled(true);
        AgentInfo info = reporter(properties, SecretStoreProvider.LOCAL,
                Map.of("HOSTNAME", "agent-host", "HTTPS_PROXY", PROXY), "1.2.3").current();

        assertThat(info.getVersion()).isEqualTo("1.2.3");
        assertThat(info.getHostname()).isEqualTo("agent-host");
        assertThat(info.getOs()).isEqualTo(System.getProperty("os.name") + " " + System.getProperty("os.arch"));
        assertThat(info.getJavaVersion()).isEqualTo(System.getProperty("java.version"));
        assertThat(info.getSecretStore()).isEqualTo("LOCAL");
        assertThat(info.getMaxConcurrentJobs()).isEqualTo(8);
        assertThat(info.getProxyConfigured()).isTrue();
        assertThat(info.getBundled()).isTrue();
        assertThat(info.getCapabilities().getDeploymentTargets()).containsExactly(TargetType.values()[0].name());
        assertThat(info.getCapabilities().getDiscoveryTargets()).containsExactly(TargetType.values()[1].name());
        assertThat(info.getCapabilities().getDnsProviders()).contains("CLOUDFLARE", "AWS_ROUTE53", "CERTPING");
    }

    @Test
    void defaultsWhenTheBuildSaysNothing() {
        AgentInfo info = reporter(properties(), SecretStoreProvider.AWS_SECRETS_MANAGER, Map.of(), null).current();

        assertThat(info.getVersion()).isEqualTo("dev");
        assertThat(info.getSecretStore()).isEqualTo("AWS_SECRETS_MANAGER");
        assertThat(info.getProxyConfigured()).isFalse();
        assertThat(info.getBundled()).isFalse();
    }

    @Test
    void lowerCaseProxyCountsToo() {
        AgentInfo info = reporter(properties(), SecretStoreProvider.GCP_SECRET_MANAGER,
                Map.of("https_proxy", "proxy:3128"), "0.1.0").current();
        assertThat(info.getProxyConfigured()).isTrue();
    }

    @Test
    void isBuiltOnceAndCached() {
        AtomicInteger calls = new AtomicInteger();
        when(deployments.supportedTargetTypes()).thenReturn(EnumSet.noneOf(TargetType.class));
        when(discoveries.supportedTargetTypes()).thenReturn(EnumSet.noneOf(TargetType.class));
        AgentInfoReporter reporter = new AgentInfoReporter(properties(), secretStore(SecretStoreProvider.LOCAL),
                deployments, discoveries, Map.of(), () -> {
                    calls.incrementAndGet();
                    return "1.0.0";
                });
        AgentInfo first = reporter.current();
        AgentInfo second = reporter.current();
        assertThat(second).isSameAs(first);
        assertThat(calls).hasValue(1);
    }

    @Test
    void neverCarriesASecret() {
        AgentInfo info = reporter(properties(), SecretStoreProvider.LOCAL,
                Map.of("HTTPS_PROXY", PROXY, "CERTPING_AGENT_TOKEN", TOKEN), "1.0.0").current();
        String json = JsonMapper.builder().build().writeValueAsString(info);
        assertThat(json).doesNotContain(TOKEN, SECRET_KEY, "proxypass", "proxy.internal",
                "gs-api-secret", "azure-client-secret");
    }

    @Test
    void heartbeatCarriesTheAgentInfo() {
        AgentProperties properties = properties();
        properties.setOrganizationId("org");
        AgentMessageSender sender = mock(AgentMessageSender.class);
        InboundConsumerLifecycle inbound = mock(InboundConsumerLifecycle.class);
        when(inbound.isRunning()).thenReturn(true);
        AgentInfoReporter reporter = reporter(properties, SecretStoreProvider.LOCAL, Map.of(), "1.0.0");

        new AgentHeartbeatPublisher(properties, new HeartbeatCadenceState(properties), sender, inbound, null, reporter)
                .publishHeartbeat();

        ArgumentCaptor<AgentHealthHeartbeat> captor = ArgumentCaptor.forClass(AgentHealthHeartbeat.class);
        verify(sender).sendHealthHeartbeat(captor.capture());
        assertThat(captor.getValue().getAgentInfo()).isSameAs(reporter.current());
    }

    @Test
    void heartbeatGoesOutWithoutInfoWhenItCannotBeBuilt() {
        AgentProperties properties = properties();
        properties.setOrganizationId("org");
        AgentMessageSender sender = mock(AgentMessageSender.class);
        InboundConsumerLifecycle inbound = mock(InboundConsumerLifecycle.class);
        AgentInfoReporter broken = mock(AgentInfoReporter.class);
        when(broken.current()).thenThrow(new IllegalStateException("boom"));

        new AgentHeartbeatPublisher(properties, new HeartbeatCadenceState(properties), sender, inbound, null, broken)
                .publishHeartbeat();

        ArgumentCaptor<AgentHealthHeartbeat> captor = ArgumentCaptor.forClass(AgentHealthHeartbeat.class);
        verify(sender).sendHealthHeartbeat(captor.capture());
        assertThat(captor.getValue().getAgentInfo()).isNull();
    }
}
