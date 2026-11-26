// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest(properties = "spring.jpa.hibernate.ddl-auto=none")
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.ANY)
class RenewalScheduleRepositoryTest {

    @Autowired private RenewalScheduleRepository renewalScheduleRepository;
    @Autowired private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void setUpSchema() {
        jdbcTemplate.execute("drop table if exists renewal_schedule");
        jdbcTemplate.execute("""
                create table renewal_schedule (
                    id bigint primary key,
                    certificate_xref varchar(100) not null unique,
                    domain_credential_config_id bigint not null,
                    valid_to timestamp with time zone not null,
                    renewal_eligible_at timestamp with time zone not null,
                    renewal_window_days integer not null,
                    ca_provider varchar(50) not null,
                    acme_account_handle varchar(500),
                    ca_credential_handle varchar(500),
                    order_id varchar(64),
                    cert_secret_handle varchar(500),
                    enabled boolean not null,
                    last_renewal_at timestamp with time zone,
                    last_renewal_status varchar(50),
                    next_attempt_at timestamp with time zone,
                    consecutive_failures integer not null default 0,
                    is_deleted boolean not null,
                    created_at timestamp with time zone not null,
                    updated_at timestamp with time zone not null
                )
                """);
    }

    @Test
    void findEligibleForRenewal_retriesOnlyFailedSchedulesWithDueNextAttempt() {
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        insertFailedSchedule(1L, "cert-parked", null, now);
        insertFailedSchedule(2L, "cert-future", now.plusDays(2), now);
        insertFailedSchedule(3L, "cert-due", now.minusDays(2), now);

        assertThat(renewalScheduleRepository.findEligibleForRenewal(now))
                .extracting(schedule -> schedule.getCertificateXref())
                .containsExactly("cert-due");
    }

    private void insertFailedSchedule(
            long id, String certificateXref, OffsetDateTime nextAttemptAt, OffsetDateTime now) {
        jdbcTemplate.update("""
                insert into renewal_schedule (
                    id, certificate_xref, domain_credential_config_id, valid_to,
                    renewal_eligible_at, renewal_window_days, ca_provider, enabled,
                    last_renewal_status, next_attempt_at, is_deleted, created_at, updated_at)
                values (?, ?, 10, ?, ?, 30, 'LETS_ENCRYPT', true, 'FAILED', ?, false, ?, ?)
                """,
                id, certificateXref, now.plusDays(30), now.minusDays(1), nextAttemptAt, now, now);
    }
}
