// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.certmanagement.util.UserFacingErrorMessages;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

class AuditReasonTest {

    @Test
    void keepsAWellFormedCodeNormalised() {
        assertThat(AuditReason.of("DEPLOY_AZURE_KV_IMPORT_FAILED").code()).isEqualTo("DEPLOY_AZURE_KV_IMPORT_FAILED");
        assertThat(AuditReason.of("  permission_denied ").code()).isEqualTo("PERMISSION_DENIED");
        assertThat(AuditReason.of("A" + "_".repeat(63)).code()).as("64 characters, the longest code").hasSize(64);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"Connection refused: jdbc:postgresql://db.internal.example:5432",
            "example-vault-prod secret not found", "A", "9LIVES", "BAD-CODE", "TOO_LONG_TOO_LONG_TOO_LONG_TOO_LONG_TOO_LONG_TOO_LONG_TOO_LONG_XY",
            "java.lang.IllegalStateException"})
    void storesAnythingElseAsAnInternalError(String raw) {
        assertThat(AuditReason.of(raw)).isEqualTo(AuditReason.INTERNAL_ERROR);
    }

    @Test
    void ofIsTheOnlyWayInAndNeverThrows() {
        assertThat(AuditReason.class).isFinal();
        assertThat(AuditReason.class.getConstructors()).as("no public constructor").isEmpty();
        assertThatCode(() -> AuditReason.of("Azure said: forbidden \u0000 \n at com.example.Foo(Foo.java:1)"))
                .doesNotThrowAnyException();
        assertThat(AuditReason.of("Azure said: forbidden")).isEqualTo(AuditReason.INTERNAL_ERROR)
                .hasToString("AuditReason[INTERNAL_ERROR]");
        assertThat(AuditReason.of("dns_auth_failed")).isEqualTo(AuditReason.of("DNS_AUTH_FAILED"))
                .hasSameHashCodeAs(AuditReason.of("DNS_AUTH_FAILED"));
    }

    @Test
    void anAgentFailureUnwrapsTheRetryWrapper() {
        assertThat(AuditReason.fromAgent("RETRY_GIVE_UP", "DNS_AUTH_FAILED").code()).isEqualTo("DNS_AUTH_FAILED");
        assertThat(AuditReason.fromAgent("KV_URI_INVALID", null).code()).isEqualTo("KV_URI_INVALID");
        assertThat(AuditReason.fromAgent(null, null)).isEqualTo(AuditReason.INTERNAL_ERROR);
    }

    @Test
    void rendersApiCodesHereAndAgentCodesThroughTheUserFacingMessages() {
        assertThat(AuditReason.of("PERMISSION_DENIED").message("req-1")).isEqualTo("You don't have permission to do this.");
        assertThat(AuditReason.of("DEPLOY_AZURE_KV_IMPORT_FAILED").message("req-1"))
                .isEqualTo(UserFacingErrorMessages.forCode("DEPLOY_AZURE_KV_IMPORT_FAILED"));
        assertThat(AuditReason.of("SOMETHING_NOBODY_MAPPED").message(null)).isNotBlank()
                .doesNotContain("SOMETHING_NOBODY_MAPPED");
    }

    @Test
    void anInternalErrorNamesTheRequestToQuote() {
        assertThat(AuditReason.INTERNAL_ERROR.message("req-abc123")).contains("req-abc123").contains("administrator");
        assertThat(AuditReason.INTERNAL_ERROR.message(null)).doesNotContain("null").contains("administrator");
    }
}
