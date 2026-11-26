// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/** The configuration checks; the statement itself runs against PostgreSQL in AccountLockoutPostgresTest. */
class LoginAttemptServiceTest {

    private final NamedParameterJdbcTemplate jdbc = mock(NamedParameterJdbcTemplate.class);

    @Test
    void rejectsALimitBelowOne() {
        assertThatThrownBy(() -> new LoginAttemptService(jdbc, 0, Duration.ofMinutes(15)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsANonPositiveDuration() {
        assertThatThrownBy(() -> new LoginAttemptService(jdbc, 5, Duration.ZERO))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
