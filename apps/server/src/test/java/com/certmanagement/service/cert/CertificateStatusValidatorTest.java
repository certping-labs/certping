// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.enums.CaProvider;
import com.certmanagement.enums.CertificateStatus;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.DuplicateResourceException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CertificateStatusValidatorTest {

    private CertificateStatusValidator validator;

    @BeforeEach
    void setUp() {
        validator = new CertificateStatusValidator();
    }

    @Test
    void validateForManualRenewal_softDeleted_throwsBadRequest() {
        CertificateEntity cert = certWithStatus("ACTIVE");
        cert.setDeletedAt(OffsetDateTime.now());

        assertThatThrownBy(() -> validator.validateForManualRenewal(cert, "cert-1"))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("deleted");
    }

    @Test
    void validateForManualRenewal_pending_throwsDuplicateResource() {
        CertificateEntity cert = certWithStatus("PENDING");

        assertThatThrownBy(() -> validator.validateForManualRenewal(cert, "cert-1"))
                .isInstanceOf(DuplicateResourceException.class)
                .hasMessageContaining("issuance")
                .hasMessageContaining("PENDING");
    }

    @Test
    void validateForManualRenewal_failed_throwsBadRequest() {
        CertificateEntity cert = certWithStatus("FAILED");

        assertThatThrownBy(() -> validator.validateForManualRenewal(cert, "cert-1"))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("cannot be renewed in current state: FAILED")
            .hasMessageContaining("Allowed:")
            .hasMessageContaining("ACTIVE")
            .hasMessageContaining("EXPIRED");
    }

    @Test
    void isEligibleForScheduledRenewal_renewing_returnsFalse() {
        boolean eligible = validator.isEligibleForScheduledRenewal(certWithStatus("RENEWING"), "cert-1");
        assertThat(eligible).isFalse();
    }

    @Test
    void isEligibleForScheduledRenewal_expired_returnsTrue() {
        boolean eligible = validator.isEligibleForScheduledRenewal(certWithStatus("EXPIRED"), "cert-1");
        assertThat(eligible).isTrue();
    }

    @Test
    void allowedStatusesFor_manualDnsValidation_containsAwaitingDnsAndFailed() {
        assertThat(validator.allowedStatusesFor(CertificateStatusValidator.CertOperation.ISSUE_MANUAL_VALIDATE_DNS))
                .containsExactlyInAnyOrder(CertificateStatus.AWAITING_DNS, CertificateStatus.FAILED);
    }

    @Test
    void validateForOperation_convertToAutomated_renewSuccess_throwsBadRequest() {
        CertificateEntity cert = certWithStatus("RENEW_SUCCESS");

        assertThatThrownBy(() -> validator.validateForOperation(
                cert,
                "cert-1",
                CertificateStatusValidator.CertOperation.CONVERT_TO_AUTOMATED))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("CONVERT_TO_AUTOMATED")
                .hasMessageContaining("RENEW_SUCCESS");
    }

    private CertificateEntity certWithStatus(String status) {
        return CertificateEntity.builder()
                .certificateXref("cert-1")
                .caProvider(CaProvider.LETS_ENCRYPT)
                .status(status)
                .build();
    }
}
