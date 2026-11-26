// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.health;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.deployment.adapter.DeploymentAdapterFactory;
import com.certping.agent.discovery.DiscoveryAdapterFactory;
import com.certping.agent.model.message.AgentInfo;
import com.certping.agent.secrets.SecretStoreProperties;
import com.certping.agent.ssl.dns.DnsProviderFactory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Builds the {@link AgentInfo} sent with each heartbeat. Everything in it is fixed for the life of
 * the process, so it is built once and reused.
 *
 * <p>Settings stay on the agent: the server only shows what this reports, and this reports no
 * secret. The proxy is a yes or no, the secret store is its provider name only.
 */
@Slf4j
@Component
public class AgentInfoReporter {

    static final String UNKNOWN_VERSION = "dev";

    private final AgentProperties properties;
    private final SecretStoreProperties secretStore;
    private final DeploymentAdapterFactory deploymentAdapters;
    private final DiscoveryAdapterFactory discoveryAdapters;
    private final Map<String, String> env;
    private final Supplier<String> buildVersion;

    private AgentInfo cached;

    @Autowired
    public AgentInfoReporter(AgentProperties properties, SecretStoreProperties secretStore,
                             DeploymentAdapterFactory deploymentAdapters, DiscoveryAdapterFactory discoveryAdapters) {
        this(properties, secretStore, deploymentAdapters, discoveryAdapters, System.getenv(),
                () -> AgentInfoReporter.class.getPackage().getImplementationVersion());
    }

    AgentInfoReporter(AgentProperties properties, SecretStoreProperties secretStore,
                      DeploymentAdapterFactory deploymentAdapters, DiscoveryAdapterFactory discoveryAdapters,
                      Map<String, String> env, Supplier<String> buildVersion) {
        this.properties = properties;
        this.secretStore = secretStore;
        this.deploymentAdapters = deploymentAdapters;
        this.discoveryAdapters = discoveryAdapters;
        this.env = env;
        this.buildVersion = buildVersion;
    }

    /** The info for the next heartbeat; built on the first call and cached. */
    public synchronized AgentInfo current() {
        if (cached == null) {
            cached = build();
        }
        return cached;
    }

    private AgentInfo build() {
        return AgentInfo.builder()
                .version(version())
                .hostname(hostname())
                .os(System.getProperty("os.name", "") + " " + System.getProperty("os.arch", ""))
                .javaVersion(System.getProperty("java.version"))
                .secretStore(secretStore.getProvider() == null ? null : secretStore.getProvider().name())
                .maxConcurrentJobs(properties.getTransport().getMaxConcurrentJobs() > 0
                        ? properties.getTransport().getMaxConcurrentJobs() : 8)
                .proxyConfigured(notBlank(env.getOrDefault("HTTPS_PROXY", env.get("https_proxy"))))
                .bundled(properties.isBundled())
                .capabilities(AgentInfo.Capabilities.builder()
                        .deploymentTargets(deploymentAdapters == null ? List.of()
                                : deploymentAdapters.supportedTargetTypes().stream().map(Enum::name).toList())
                        .discoveryTargets(discoveryAdapters == null ? List.of()
                                : discoveryAdapters.supportedTargetTypes().stream().map(Enum::name).toList())
                        .dnsProviders(DnsProviderFactory.SUPPORTED_PROVIDERS)
                        .build())
                .build();
    }

    private String version() {
        String version = null;
        try {
            version = buildVersion.get();
        } catch (RuntimeException e) {
            log.debug("No build version: {}", e.getMessage());
        }
        return notBlank(version) ? version.trim() : UNKNOWN_VERSION;
    }

    private String hostname() {
        String fromEnv = env.get("HOSTNAME");
        if (notBlank(fromEnv)) {
            return fromEnv.trim();
        }
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (Exception e) {
            return null;
        }
    }

    private static boolean notBlank(String value) {
        return value != null && !value.isBlank();
    }
}
