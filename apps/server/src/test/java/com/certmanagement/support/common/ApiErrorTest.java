// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.common;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class ApiErrorTest {

    @Test
    void of_withoutIssues_setsLabelAndNullIssues() {
        ApiError error = ApiError.of(400, "BAD", "Bad request", "req-1");
        assertThat(error.status()).isEqualTo(400);
        assertThat(error.error()).isEqualTo("Bad Request");
        assertThat(error.code()).isEqualTo("BAD");
        assertThat(error.message()).isEqualTo("Bad request");
        assertThat(error.requestId()).isEqualTo("req-1");
        assertThat(error.issues()).isNull();
    }

    @Test
    void of_withIssues_keepsIssues() {
        Object issues = java.util.List.of("field is required");
        ApiError error = ApiError.of(409, "CONFLICT", "Conflict", "req-2", issues);
        assertThat(error.error()).isEqualTo("Conflict");
        assertThat(error.issues()).isEqualTo(issues);
    }

    @Test
    void label_coversKnownAndUnknownStatuses() {
        assertThat(ApiError.of(401, "c", "m", "r").error()).isEqualTo("Unauthorized");
        assertThat(ApiError.of(403, "c", "m", "r").error()).isEqualTo("Forbidden");
        assertThat(ApiError.of(404, "c", "m", "r").error()).isEqualTo("Not Found");
        assertThat(ApiError.of(412, "c", "m", "r").error()).isEqualTo("Precondition Failed");
        assertThat(ApiError.of(429, "c", "m", "r").error()).isEqualTo("Too Many Requests");
        assertThat(ApiError.of(502, "c", "m", "r").error()).isEqualTo("Bad Gateway");
        assertThat(ApiError.of(504, "c", "m", "r").error()).isEqualTo("Gateway Timeout");
        assertThat(ApiError.of(500, "c", "m", "r").error()).isEqualTo("Internal Server Error");
        assertThat(ApiError.of(418, "c", "m", "r").error()).isEqualTo("Request Failed");
    }
}
