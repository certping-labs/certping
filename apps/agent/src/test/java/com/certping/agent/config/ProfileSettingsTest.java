// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.ClassPathResource;
import org.springframework.util.ClassUtils;

import java.io.IOException;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** What the agent's profile YAML files configure, read without the shell's environment. */
class ProfileSettingsTest {

    private static final String PROMETHEUS_REGISTRY = "io.micrometer.prometheusmetrics.PrometheusMeterRegistry";

    private static StandardEnvironment environment(String profile, Map<String, Object> variables) throws IOException {
        StandardEnvironment environment = new StandardEnvironment();
        var sources = environment.getPropertySources();
        sources.remove(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME);
        sources.remove(StandardEnvironment.SYSTEM_PROPERTIES_PROPERTY_SOURCE_NAME);
        sources.addFirst(new MapPropertySource("variables", variables));
        YamlPropertySourceLoader loader = new YamlPropertySourceLoader();
        if (profile != null) {
            loader.load(profile, new ClassPathResource("application-" + profile + ".yml")).forEach(sources::addLast);
        }
        loader.load("base", new ClassPathResource("application.yml")).forEach(sources::addLast);
        return environment;
    }

    private static AgentProperties selfhosted(Map<String, Object> variables) throws IOException {
        Map<String, Object> all = new java.util.HashMap<>(Map.of(
                "CERTPING_SERVER_URL", "https://certping.example.com",
                "CERTPING_AGENT_TOKEN", "cpa_test"));
        all.putAll(variables);
        return Binder.get(environment("selfhosted", all)).bind("agent", AgentProperties.class).get();
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "selfhosted"})
    void exposesOnlyActuatorEndpointsThatExist(String profile) throws IOException {
        String include = environment(profile.isEmpty() ? null : profile, Map.of())
                .getProperty("management.endpoints.web.exposure.include", "");
        List<String> endpoints = Arrays.stream(include.split(",")).map(String::trim).toList();

        assertThat(endpoints).contains("health");
        if (endpoints.contains("prometheus")) {
            assertThat(ClassUtils.isPresent(PROMETHEUS_REGISTRY, getClass().getClassLoader()))
                    .as("prometheus is exposed but micrometer-registry-prometheus is not on the classpath")
                    .isTrue();
        }
    }

    @Test
    void selfHostedConfiguresTheCaEndpointsWithTheAccountsLeftEmpty() throws IOException {
        AgentProperties properties = selfhosted(Map.of());

        assertThat(properties.getDigicert().getApiBaseUrl()).isEqualTo("https://www.digicert.com/services/v2");
        assertThat(properties.getDigicert().getOrderPollIntervalMs()).isPositive();
        assertThat(properties.getDigicert().getOrderDeadline()).isEqualTo(Duration.ofMinutes(30));

        assertThat(properties.getGlobalsign().getApiBaseUrl()).startsWith("https://");
        assertThat(properties.getGlobalsign().getApiKey()).isNullOrEmpty();
        assertThat(properties.getGlobalsign().getApiSecret()).isNullOrEmpty();
    }

    @Test
    void selfHostedTakesTheGlobalSignAccountFromTheEnvironment() throws IOException {
        AgentProperties properties = selfhosted(Map.of(
                "AGENT_GLOBALSIGN_API_KEY", "gs-key",
                "AGENT_GLOBALSIGN_API_SECRET", "gs-secret",
                "AGENT_GLOBALSIGN_CLIENT_CERT_PEM_BASE64", "Y2VydA==",
                "AGENT_GLOBALSIGN_CLIENT_PRIVATE_KEY_PEM_BASE64", "a2V5"));

        assertThat(properties.getGlobalsign().getApiKey()).isEqualTo("gs-key");
        assertThat(properties.getGlobalsign().getApiSecret()).isEqualTo("gs-secret");
        assertThat(properties.getGlobalsign().getClientCertPemBase64()).isEqualTo("Y2VydA==");
        assertThat(properties.getGlobalsign().getClientPrivateKeyPemBase64()).isEqualTo("a2V5");
    }
}
