// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.ConflictException;
import com.certmanagement.exception.DuplicateResourceException;
import com.certmanagement.exception.FeatureDisabledException;
import com.certmanagement.exception.FeatureInUseException;
import com.certmanagement.exception.ForbiddenException;
import com.certmanagement.exception.LastOrganizationAdminException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.exception.ServiceUnavailableException;
import com.certmanagement.util.UserFacingErrorMessages;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.server.ResponseStatusException;

import java.sql.SQLException;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/** A refusal's reason comes from the exception's type (or status, or code), never from its message. */
class AuditReasonsTest {

    /** Text no stored reason may ever carry: what a JDBC, Azure or vault error says about itself. */
    private static final String LEAKY = "jdbc:postgresql://db-prod.internal:5432/certping example-vault-prod "
            + "alice@acme.test at com.certmanagement.Foo.bar(Foo.java:12)";

    @Test
    void eachRefusalMapsToItsCodeByTypeAlone() {
        Map<Throwable, String> expected = Map.ofEntries(
                Map.entry(new AccessDeniedException(LEAKY), "PERMISSION_DENIED"),
                Map.entry(new ForbiddenException(LEAKY), "PERMISSION_DENIED"),
                Map.entry(new FeatureDisabledException("DISCOVERY", "FEATURE_DISABLED", LEAKY), "FEATURE_DISABLED"),
                Map.entry(new ResourceNotFoundException(LEAKY), "NOT_FOUND"),
                Map.entry(new BadRequestException(LEAKY), "INVALID_INPUT"),
                Map.entry(new IllegalArgumentException(LEAKY), "INVALID_INPUT"),
                Map.entry(new ConflictException(LEAKY), "CONFLICT"),
                Map.entry(new ObjectOptimisticLockingFailureException(LEAKY, null), "CONFLICT"),
                Map.entry(new DuplicateResourceException(LEAKY), "DUPLICATE"),
                Map.entry(new LastOrganizationAdminException(), "LAST_ORGANIZATION_ADMIN"),
                Map.entry(new ServiceUnavailableException(LEAKY), "SERVICE_UNAVAILABLE"),
                Map.entry(new ResponseStatusException(HttpStatus.NOT_FOUND, LEAKY), "NOT_FOUND"),
                Map.entry(new IllegalStateException(LEAKY), "INTERNAL_ERROR"),
                Map.entry(new RuntimeException(LEAKY), "INTERNAL_ERROR"));

        expected.forEach((failure, code) -> {
            AuditReason reason = AuditReasons.of(failure);
            assertThat(reason.code()).as(failure.getClass().getSimpleName()).isEqualTo(code);
            assertThat(reason.message("req-1")).doesNotContain("jdbc").doesNotContain("example-vault")
                    .doesNotContain("alice");
        });
        assertThat(AuditReasons.of(null)).isEqualTo(AuditReason.INTERNAL_ERROR);
    }

    @Test
    void aUniqueViolationIsADuplicateByItsSqlStateAndAnyOtherConstraintIsInternal() {
        assertThat(AuditReasons.of(new DataIntegrityViolationException(LEAKY,
                new SQLException(LEAKY, "23505")))).isEqualTo(AuditReasons.DUPLICATE);
        assertThat(AuditReasons.of(new DataIntegrityViolationException(LEAKY,
                new SQLException(LEAKY, "23503")))).isEqualTo(AuditReason.INTERNAL_ERROR);
    }

    @Test
    void aResponseStatusMapsToTheSameCodes() {
        assertThat(AuditReasons.ofStatus(200)).isNull();
        assertThat(AuditReasons.ofStatus(204)).isNull();
        assertThat(AuditReasons.ofStatus(400)).isEqualTo(AuditReasons.INVALID_INPUT);
        assertThat(AuditReasons.ofStatus(403)).isEqualTo(AuditReasons.PERMISSION_DENIED);
        assertThat(AuditReasons.ofStatus(404)).isEqualTo(AuditReasons.NOT_FOUND);
        assertThat(AuditReasons.ofStatus(409)).isEqualTo(AuditReasons.CONFLICT);
        assertThat(AuditReasons.ofStatus(423)).isEqualTo(AuditReasons.FEATURE_DISABLED);
        assertThat(AuditReasons.ofStatus(429)).isEqualTo(AuditReasons.RATE_LIMITED);
        assertThat(AuditReasons.ofStatus(500)).isEqualTo(AuditReason.INTERNAL_ERROR);
        assertThat(AuditReasons.ofStatus(503)).isEqualTo(AuditReasons.SERVICE_UNAVAILABLE);
    }


}
