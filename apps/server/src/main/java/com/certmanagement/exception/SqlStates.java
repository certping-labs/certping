// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.exception;

import java.sql.SQLException;

/** PostgreSQL SQL states the service reacts to, read from the first {@link SQLException} in a cause chain. */
public final class SqlStates {

    /** A {@code lock_timeout} cancelled the wait for a lock. */
    public static final String LOCK_NOT_AVAILABLE = "55P03";
    /** A {@code statement_timeout} cancelled the query. */
    public static final String QUERY_CANCELED = "57014";

    private SqlStates() {
    }

    public static boolean isLockNotAvailable(Throwable failure) {
        return LOCK_NOT_AVAILABLE.equals(sqlStateOf(failure));
    }

    public static boolean isQueryCanceled(Throwable failure) {
        return QUERY_CANCELED.equals(sqlStateOf(failure));
    }

    public static String sqlStateOf(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof SQLException sql && sql.getSQLState() != null) {
                return sql.getSQLState();
            }
        }
        return null;
    }
}
