// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.status;

import org.junit.jupiter.api.Test;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class DatabaseCheckTest {

    private final DataSource dataSource = mock(DataSource.class);
    private final Connection connection = mock(Connection.class);
    private final DatabaseCheck check = new DatabaseCheck(dataSource);

    @Test
    void answersWhenAPooledConnectionIsValidAndReturnsIt() throws SQLException {
        when(dataSource.getConnection()).thenReturn(connection);
        when(connection.isValid(anyInt())).thenReturn(true);

        assertThat(check.answers()).isTrue();
        verify(connection).isValid(DatabaseCheck.VALIDATION_TIMEOUT_SECONDS);
        verify(connection).close();
    }

    @Test
    void anInvalidConnectionDoesNotAnswerAndIsReturned() throws SQLException {
        when(dataSource.getConnection()).thenReturn(connection);
        when(connection.isValid(anyInt())).thenReturn(false);

        assertThat(check.answers()).isFalse();
        verify(connection).close();
    }

    @Test
    void aFailedBorrowPropagatesForTheRefresherToCountAsAFailure() throws SQLException {
        SQLException exhausted = new SQLException("pool exhausted");
        when(dataSource.getConnection()).thenThrow(exhausted);

        assertThatThrownBy(check::answers).isSameAs(exhausted);
    }
}
