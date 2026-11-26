// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * The database the audit tests run on: PostgreSQL 15, so partitioning, ATTACH and trigger behaviour are
 * also tested on an older major version. The rest of the suite stays on 16.
 */
final class AuditPostgres {

    static final String IMAGE = "postgres:15-alpine";

    private AuditPostgres() {
    }

    static PostgreSQLContainer container() {
        return new PostgreSQLContainer(IMAGE);
    }
}
