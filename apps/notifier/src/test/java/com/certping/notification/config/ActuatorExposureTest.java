// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.config;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.ClassPathResource;
import org.springframework.util.ClassUtils;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Every actuator endpoint a profile exposes must exist. "prometheus" needs the Micrometer
 * Prometheus registry on the classpath; without it the endpoint is listed but never served.
 */
class ActuatorExposureTest {

    private static final String PROMETHEUS_REGISTRY = "io.micrometer.prometheusmetrics.PrometheusMeterRegistry";

    @ParameterizedTest
    @ValueSource(strings = {"", "selfhosted"})
    void exposesOnlyEndpointsThatExist(String profile) throws Exception {
        StandardEnvironment environment = new StandardEnvironment();
        var sources = environment.getPropertySources();
        sources.remove(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME);
        sources.remove(StandardEnvironment.SYSTEM_PROPERTIES_PROPERTY_SOURCE_NAME);
        YamlPropertySourceLoader loader = new YamlPropertySourceLoader();
        if (!profile.isEmpty()) {
            loader.load(profile, new ClassPathResource("application-" + profile + ".yaml")).forEach(sources::addLast);
        }
        loader.load("base", new ClassPathResource("application.yaml")).forEach(sources::addLast);

        String include = environment.getProperty("management.endpoints.web.exposure.include", "");
        List<String> endpoints = Arrays.stream(include.split(",")).map(String::trim).toList();

        assertThat(endpoints).contains("health");
        if (endpoints.contains("prometheus")) {
            assertThat(ClassUtils.isPresent(PROMETHEUS_REGISTRY, getClass().getClassLoader()))
                    .as("prometheus is exposed but micrometer-registry-prometheus is not on the classpath")
                    .isTrue();
        }
    }
}
