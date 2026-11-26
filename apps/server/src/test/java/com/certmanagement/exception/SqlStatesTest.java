// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.exception;

import org.junit.jupiter.api.Test;

import java.sql.SQLException;

import static org.assertj.core.api.Assertions.assertThat;

class SqlStatesTest {

    @Test
    void readsTheFirstSqlStateInTheCauseChain() {
        Throwable wrapped = new RuntimeException("outer",
                new IllegalStateException("middle", new SQLException("lock", "55P03", new SQLException("inner", "57014"))));

        assertThat(SqlStates.sqlStateOf(wrapped)).isEqualTo("55P03");
        assertThat(SqlStates.isLockNotAvailable(wrapped)).isTrue();
        assertThat(SqlStates.isQueryCanceled(wrapped)).isFalse();
    }

    @Test
    void noSqlExceptionMeansNoState() {
        assertThat(SqlStates.sqlStateOf(new RuntimeException("plain"))).isNull();
        assertThat(SqlStates.isLockNotAvailable(null)).isFalse();
        assertThat(SqlStates.isQueryCanceled(new SQLException("no state"))).isFalse();
    }
}
