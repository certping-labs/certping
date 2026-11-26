// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.status;

import org.springframework.boot.sql.init.dependency.DependsOnDatabaseInitialization;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;

/**
 * Whether the application's own pool hands out a working connection. The pool's wait
 * (connection-timeout) is longer than a status check may take; {@link PublicStatusRefresher} bounds
 * the whole check and interrupts a borrow that outlives it.
 */
@Component
@DependsOnDatabaseInitialization
public class DatabaseCheck {

    static final int VALIDATION_TIMEOUT_SECONDS = 2;

    private final DataSource dataSource;

    public DatabaseCheck(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    public boolean answers() throws SQLException {
        try (Connection connection = dataSource.getConnection()) {
            return connection.isValid(VALIDATION_TIMEOUT_SECONDS);
        }
    }
}
