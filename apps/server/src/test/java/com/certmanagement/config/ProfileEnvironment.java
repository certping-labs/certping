// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.config;

import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.util.Map;

/**
 * The environment a profile's YAML produces, with {@code variables} standing in for the process
 * environment. The real environment and system properties are left out, so a variable exported in
 * the shell running the tests can neither fail them nor hide a YAML regression.
 */
final class ProfileEnvironment {

    private ProfileEnvironment() {
    }

    /** {@code profile} null loads application.yaml alone. */
    static StandardEnvironment of(String profile, Map<String, Object> variables) throws IOException {
        StandardEnvironment environment = new StandardEnvironment();
        var sources = environment.getPropertySources();
        sources.remove(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME);
        sources.remove(StandardEnvironment.SYSTEM_PROPERTIES_PROPERTY_SOURCE_NAME);
        sources.addFirst(new MapPropertySource("variables", variables));
        YamlPropertySourceLoader loader = new YamlPropertySourceLoader();
        if (profile != null) {
            loader.load(profile, new ClassPathResource("application-" + profile + ".yaml")).forEach(sources::addLast);
        }
        loader.load("base", new ClassPathResource("application.yaml")).forEach(sources::addLast);
        return environment;
    }
}
