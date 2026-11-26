// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.enums.CertificateStatus;
import com.certmanagement.messaging.CertAgentPublisher;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.RenewalScheduleRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.Optional;

/**
 * Ends a renewal attempt whose agent result never arrived: its draft fails and the certificate it
 * was renewing leaves {@code RENEWING}. Runs inside the caller's transaction.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AbandonedRenewalCleanup {

    /**
     * How long a renewal may stay in flight before it counts as lost: the {@code CERT_RENEWAL} time to live,
     * which matches the agent's renewal attempt-age bound ({@code agent.retry.max-attempt-age-renewal}), plus
     * 12 hours for clock skew and a last delivery. Past it no agent can still answer the attempt.
     */
    public static final Duration IN_FLIGHT_HORIZON = CertAgentPublisher.RENEWAL_TIME_TO_LIVE.plusHours(12);

    public static final String RESPONSE_TIMEOUT = "RENEWAL_RESPONSE_TIMEOUT";

    /** Counts results that arrive for an attempt already ended; the certificate the CA issued is not used. */
    public static final String RESULT_AFTER_TIMEOUT_METRIC = "certping.certificate.result.after.timeout";

    private final CertificateRepository certificateRepository;
    private final RenewalScheduleRepository renewalScheduleRepository;

    /**
     * What ending an attempt changed.
     *
     * @param draftXref      the failed draft, or {@code null} when the attempt left none
     * @param restoredStatus the status {@code source} left {@code RENEWING} for, or {@code null} when it was not
     *                       {@code RENEWING}
     */
    public record Outcome(String draftXref, String restoredStatus) {

        /** Whether the certificate went back to a status its schedule can renew from. */
        public boolean renewable() {
            return CertificateStatus.ACTIVE.name().equals(restoredStatus)
                    || CertificateStatus.EXPIRED.name().equals(restoredStatus);
        }
    }

    /** Whether {@code draft} belongs to an attempt this cleanup ended. */
    public static boolean endedByTimeout(CertificateEntity draft) {
        return CertificateStatus.RENEWAL_FAILED.name().equals(draft.getStatus())
                && RESPONSE_TIMEOUT.equals(draft.getLastErrorCode());
    }

    /**
     * Fails the newest {@code PENDING} draft of {@code source}'s domain and takes {@code source} out of
     * {@code RENEWING}: back to {@code ACTIVE}, to {@code EXPIRED} past its {@code validTo}, or to
     * {@code RENEW_SUCCESS} with its schedule disabled when another certificate became the domain's active one
     * meanwhile (the rule an issuance applies to the active certificate it supersedes).
     */
    public Outcome abandon(CertificateEntity source, OffsetDateTime now) {
        String draftXref = failNewestDraft(source, now).orElse(null);
        if (!CertificateStatus.RENEWING.name().equals(source.getStatus())) {
            return new Outcome(draftXref, null);
        }
        String restored = statusAfterRenewing(source, now);
        certificateRepository.updateStatus(source.getCertificateXref(), restored);
        if (CertificateStatus.RENEW_SUCCESS.name().equals(restored)) {
            renewalScheduleRepository.disableSchedule(source.getCertificateXref());
        }
        log.info("[AbandonedRenewalCleanup] xref={} left RENEWING for {}", source.getCertificateXref(), restored);
        return new Outcome(draftXref, restored);
    }

    private Optional<String> failNewestDraft(CertificateEntity source, OffsetDateTime now) {
        return certificateRepository.findTopByUserDomainCertIdAndStatusAndDeletedAtIsNullOrderByCreatedAtDesc(
                        source.getUserDomainCertId(), CertificateStatus.PENDING.name())
                .map(draft -> {
                    draft.setStatus(CertificateStatus.RENEWAL_FAILED.name());
                    draft.setLastErrorCode(RESPONSE_TIMEOUT);
                    draft.setLastErrorMessage("No agent result within " + IN_FLIGHT_HORIZON.toHours()
                            + " hours; the attempt was ended");
                    draft.setLastErrorAt(now);
                    certificateRepository.save(draft);
                    return draft.getCertificateXref();
                });
    }

    private String statusAfterRenewing(CertificateEntity source, OffsetDateTime now) {
        boolean superseded = certificateRepository
                .findTopByUserDomainCertIdAndStatusAndDeletedAtIsNullOrderByCreatedAtDesc(
                        source.getUserDomainCertId(), CertificateStatus.ACTIVE.name())
                .filter(active -> !active.getCertificateXref().equals(source.getCertificateXref()))
                .isPresent();
        if (superseded) {
            return CertificateStatus.RENEW_SUCCESS.name();
        }
        boolean expired = source.getValidTo() != null && source.getValidTo().isBefore(now);
        return expired ? CertificateStatus.EXPIRED.name() : CertificateStatus.ACTIVE.name();
    }
}
