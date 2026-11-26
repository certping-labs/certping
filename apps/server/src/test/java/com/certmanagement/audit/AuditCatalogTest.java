// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.security.SignInFailures;
import com.certmanagement.util.UserFacingErrorMessages;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The reason catalog as customers read it. Every reason a sign-in, sign-out or password flow records has a
 * sentence of its own: never the "something went wrong" of an internal error, nor the generic fallback a
 * code without copy gets.
 */
class AuditCatalogTest {

    @Test
    void everyReasonTheAuthFlowsRecordHasASentenceOfItsOwn() {
        String internalError = AuditReason.INTERNAL_ERROR.message(null);
        String fallback = UserFacingErrorMessages.forCode("NO_SUCH_REASON_CODE_FOR_TEST");
        Set<String> sentences = new HashSet<>();

        assertThat(SignInFailures.REASONS).extracting(AuditReason::code).contains("INVALID_CREDENTIALS",
                "ACCOUNT_DISABLED", "ACCOUNT_LOCKED", "ORGANIZATION_SUSPENDED", "SIGN_IN_METHOD_NOT_ALLOWED",
                "SSO_REJECTED", "SSO_MISCONFIGURED", "SSO_MEMBER_NOT_PROVISIONED", "SIGN_IN_CANCELLED");
        assertThat(SignInFailures.REASONS).allSatisfy(reason -> {
            String message = reason.message("req-123");
            assertThat(message).as(reason.code()).isNotBlank()
                    .isNotEqualTo(internalError)
                    .isNotEqualTo(fallback)
                    .doesNotContain(reason.code())
                    .doesNotContain("req-123")
                    .endsWith(".");
            assertThat(sentences.add(message)).as("%s has a sentence no other auth reason shares", reason.code())
                    .isTrue();
        });
    }

    @Test
    void anAuthFailureOfAnyOtherKindNamesTheRequestToQuote() {
        assertThat(AuditReason.INTERNAL_ERROR.message("req-123")).contains("req-123");
        assertThat(List.of(SignInFailures.reasonOf(new IllegalStateException("x"))))
                .containsExactly(AuditReason.INTERNAL_ERROR);
    }

    /** Every event belongs to a feature the flags know, or is core (always shown); and reads as a sentence. */
    @Test
    void everyEventIsCoreOrOwnedByAKnownFeatureAndHasSentences() {
        Set<String> flags = new HashSet<>();
        for (Field field : FeatureFlags.class.getDeclaredFields()) {
            if (Modifier.isStatic(field.getModifiers()) && field.getType() == String.class) {
                try {
                    flags.add((String) field.get(null));
                } catch (IllegalAccessException e) {
                    throw new AssertionError(e);
                }
            }
        }
        assertThat(Arrays.asList(AuditEventType.values())).allSatisfy(type -> {
            assertThat(type.isCore() || flags.contains(type.featureKey()))
                    .as("%s: feature %s", type.key(), type.featureKey()).isTrue();
            assertThat(type.resourceType()).as(type.key()).isNotNull();
            assertThat(type.summary(AuditSubject.NONE)).as(type.key()).isNotBlank().doesNotContain("null");
            assertThat(type.failure(AuditSubject.NONE)).as(type.key()).isNotBlank().doesNotContain("null");
        });
    }

    /** The Access view's events are customer reads; nothing else is filed under it. */
    @Test
    void theAccessCategoryHoldsTheSensitiveReadsOnly() {
        assertThat(Arrays.asList(AuditEventType.values())).allSatisfy(type -> {
            boolean access = type.category() == AuditCategory.ACCESS;
            assertThat(type.sensitivity() == AuditSensitivity.SENSITIVE_READ).as(type.key()).isEqualTo(access);
            assertThat(!access || type.visibility() == AuditVisibility.CUSTOMER).as(type.key()).isTrue();
            assertThat(access == type.key().startsWith("access.")).as(type.key()).isTrue();
        });
    }

    /** Internal events are the platform's: filed under the platform category, never a customer one. */
    @Test
    void internalEventsAreFiledUnderThePlatform() {
        assertThat(Arrays.asList(AuditEventType.values()))
                .filteredOn(type -> type.visibility() == AuditVisibility.INTERNAL)
                .allSatisfy(type -> assertThat(type.category()).as(type.key()).isEqualTo(AuditCategory.PLATFORM));
    }

    /** The reasons the delivery and discovery flows record have sentences of their own, not the generic fallback. */
    @Test
    void theDeliveryAndDiscoveryReasonsHaveSentencesOfTheirOwn() {
        String fallback = UserFacingErrorMessages.forCode("NO_SUCH_REASON_CODE_FOR_TEST");
        String internalError = AuditReason.INTERNAL_ERROR.message(null);
        assertThat(List.of("PARTIALLY_DELIVERED", "ESCALATION_NOT_DELIVERED", "INTEGRATION_DELIVERY_FAILED",
                "DISCOVERY_FAILED", "DISCOVERY_NOT_PICKED_UP", "PAYMENT_FAILED")).allSatisfy(code ->
                assertThat(AuditReason.of(code).message("req-1")).as(code).isNotBlank().isNotEqualTo(fallback)
                        .isNotEqualTo(internalError).doesNotContain(code).endsWith("."));
    }
}
