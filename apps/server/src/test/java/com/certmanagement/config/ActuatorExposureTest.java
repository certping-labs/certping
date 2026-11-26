// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.config;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.util.ClassUtils;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

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
        String include = ProfileEnvironment.of(profile.isEmpty() ? null : profile, Map.of())
                .getProperty("management.endpoints.web.exposure.include", "");
        List<String> endpoints = Arrays.stream(include.split(",")).map(String::trim).toList();

        assertThat(endpoints).contains("health");
        if (endpoints.contains("prometheus")) {
            assertThat(ClassUtils.isPresent(PROMETHEUS_REGISTRY, getClass().getClassLoader()))
                    .as("prometheus is exposed but micrometer-registry-prometheus is not on the classpath")
                    .isTrue();
        }
    }
}
