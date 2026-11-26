// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.config;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Every pooled connection carries all three database timeouts. lock_timeout used to be the
 * only one: a runaway query or an abandoned transaction held its connection until the pool drained.
 */
class DatabaseTimeoutsTest {

    private static final String INIT_SQL = "spring.datasource.hikari.connection-init-sql";

    @ParameterizedTest
    @ValueSource(strings = {"selfhosted"})
    void everyConnectionGetsTheThreeTimeouts(String profile) throws IOException {
        assertThat(initSql(profile, Map.of())).isEqualTo(
                "SELECT set_config('lock_timeout', '5s', false),"
                        + " set_config('statement_timeout', '30s', false),"
                        + " set_config('idle_in_transaction_session_timeout', '30min', false)");
    }

    @ParameterizedTest
    @ValueSource(strings = {"selfhosted"})
    void eachTimeoutCanBeTunedPerEnvironment(String profile) throws IOException {
        String sql = initSql(profile, Map.of(
                "DB_LOCK_TIMEOUT", "2s",
                "DB_STATEMENT_TIMEOUT", "15s",
                "DB_IDLE_IN_TRANSACTION_TIMEOUT", "20s"));

        assertThat(sql).contains("'lock_timeout', '2s'", "'statement_timeout', '15s'",
                "'idle_in_transaction_session_timeout', '20s'");
    }

    static String initSql(String profile, Map<String, Object> variables) throws IOException {
        StandardEnvironment environment = new StandardEnvironment();
        var sources = environment.getPropertySources();
        sources.remove(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME);
        sources.remove(StandardEnvironment.SYSTEM_PROPERTIES_PROPERTY_SOURCE_NAME);
        sources.addFirst(new MapPropertySource("variables", variables));
        new YamlPropertySourceLoader()
                .load(profile, new ClassPathResource("application-" + profile + ".yaml"))
                .forEach(sources::addLast);
        return Binder.get(environment).bind(INIT_SQL, String.class).get().replaceAll("\\s+", " ");
    }
}
