// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.config;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * What Postgres actually applies from the selfhosted profile's connection-init-sql through Hikari, not just what the
 * YAML says: a later edit could keep the text valid and still lose a setting (is_local = true, for
 * one, drops it when the statement's implicit transaction ends).
 */
@Testcontainers(disabledWithoutDocker = true)
class DatabaseTimeoutsAppliedTest {

    @Container
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16-alpine");

    @Test
    void everyPooledConnectionCarriesTheThreeTimeouts() throws Exception {
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(POSTGRES.getJdbcUrl());
        config.setUsername(POSTGRES.getUsername());
        config.setPassword(POSTGRES.getPassword());
        config.setAutoCommit(true);
        config.setMaximumPoolSize(1);
        config.setConnectionInitSql(DatabaseTimeoutsTest.initSql("selfhosted", Map.of()));

        try (HikariDataSource pool = new HikariDataSource(config)) {
            for (int borrow = 0; borrow < 2; borrow++) {
                try (Connection connection = pool.getConnection()) {
                    assertThat(show(connection, "lock_timeout")).isEqualTo("5s");
                    assertThat(show(connection, "statement_timeout")).isEqualTo("30s");
                    assertThat(show(connection, "idle_in_transaction_session_timeout")).isEqualTo("30min");
                }
            }
        }
    }

    private static String show(Connection connection, String setting) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery("SHOW " + setting)) {
            result.next();
            return result.getString(1);
        }
    }
}
