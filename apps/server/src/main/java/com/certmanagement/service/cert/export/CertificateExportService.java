// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert.export;

import com.certmanagement.dto.cert.CertExportRequest;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.exception.CertExportException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.exception.ServiceUnavailableException;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.support.integrations.secret.agent.AgentSecretGoneException;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Set;

/**
 * Exports a certificate the platform stores, from any CA, as PEM or PKCS#12.
 *
 * <p>Deliberately not {@code @Transactional}: the certificate is read by an org-scoped finder in its
 * own read-only transaction, the secret store is called with no transaction open, and the audit rows
 * are written afterwards in short ones ({@link CertExportAuditRecorder}). Every refusal except a 400
 * is audited.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CertificateExportService {

    static final String KEY_EXPORT_PAUSED_MESSAGE =
            "Downloads that include the private key are temporarily unavailable. Try again shortly.";
    private static final String STORE_UNAVAILABLE_MESSAGE = "The certificate store is unavailable. Try again shortly.";

    private final CertificateRepository certificateRepository;
    private final CertExportEligibilityPolicy eligibilityPolicy;
    private final ObjectProvider<AgentSecretStore> secretStoreProvider;
    private final CertExportRateLimiter rateLimiter;
    private final CertExportAuditRecorder auditRecorder;

    /**
     * Validates, checks the caller may download the format, rate-limits, re-checks eligibility, reads
     * and verifies the stored material, renders the file and audits the export.
     *
     * @param callerPermissions the caller's permission authorities; a format carrying the private key
     *                          needs {@code certificate:deploy} on top of the endpoint's
     *                          {@code certificate:read}
     * @throws CertExportException         400, 403, 409, 410, 429 or 502 as the export contract defines
     * @throws ResourceNotFoundException   when the certificate is not in {@code organizationId}
     * @throws ServiceUnavailableException 503: the secret store is unreachable, or the rate limiter is
     *                                     and the format carries the private key
     * @throws AccessDeniedException       when the request has no user to rate-limit and audit
     */
    public ExportedCertificateFile export(Long organizationId, Integer userId, Set<String> callerPermissions,
                                          String certificateXref, CertExportRequest request) {
        if (userId == null) {
            throw new AccessDeniedException("Certificate export requires a user context.");
        }
        try (CertExportOptions options = CertExportOptions.from(request)) {
            requireKeyPermission(organizationId, userId, callerPermissions, options.format());
            enforceRateLimit(organizationId, userId, options.format());
            CertificateEntity cert = findInCallersOrg(organizationId, certificateXref, options.format());
            try {
                ExportedCertificateFile file = exportVerified(cert, options);
                log.info("[CERT_EXPORT] xref={} format={} userId={} organizationId={}",
                        certificateXref, options.format(), userId, organizationId);
                return file;
            } catch (CertExportException e) {
                auditRecorder.recordRefusal(organizationId, cert, options.format(), e.getCode());
                if (e.getCode().equals(CertExportException.CERT_MATERIAL_MISMATCH)) {
                    log.warn("[CERT_EXPORT_MATERIAL_MISMATCH] xref={} organizationId={}: {}",
                            certificateXref, organizationId, e.getMessage());
                }
                throw e;
            } catch (ServiceUnavailableException e) {
                auditRecorder.recordRefusal(organizationId, cert, options.format(),
                        CertExportAuditRecorder.OUTCOME_UNAVAILABLE);
                throw e;
            }
        }
    }

    /**
     * Runs before the rate limiter and the certificate lookup, so a refused caller spends no export
     * token and learns nothing about whether the certificate exists.
     */
    private void requireKeyPermission(Long organizationId, Integer userId, Set<String> callerPermissions,
                                      CertExportFormat format) {
        if (format.isPermittedFor(callerPermissions)) {
            return;
        }
        auditRecorder.recordKeyNotPermitted(organizationId, userId, format);
        throw CertExportException.keyNotPermitted();
    }

    private void enforceRateLimit(Long organizationId, Integer userId, CertExportFormat format) {
        switch (rateLimiter.tryAcquire(userId, format)) {
            case CertExportRateLimitDecision.Allowed allowed -> {
            }
            case CertExportRateLimitDecision.Limited limited -> {
                if (limited.firstRefusalInWindow()) {
                    auditRecorder.recordRateLimited(organizationId, userId, format);
                }
                throw CertExportException.rateLimited(limited.retryAfterSeconds());
            }
            case CertExportRateLimitDecision.LimiterUnavailable unavailable -> {
                auditRecorder.recordLimiterUnavailable(organizationId, userId, format);
                throw new ServiceUnavailableException(KEY_EXPORT_PAUSED_MESSAGE);
            }
        }
    }

    private CertificateEntity findInCallersOrg(Long organizationId, String certificateXref, CertExportFormat format) {
        return certificateRepository.findByCertificateXrefAndOrganizationId(certificateXref, organizationId)
                .orElseThrow(() -> {
                    auditRecorder.recordNotFound(organizationId, format, certificateXref);
                    return new ResourceNotFoundException(
                            "Certificate '" + certificateXref + "' not found for organization");
                });
    }

    private ExportedCertificateFile exportVerified(CertificateEntity cert, CertExportOptions options) {
        requireEligible(cert);
        AgentCertificateBundle bundle = AgentCertificateBundleParser.parse(readSecret(cert));
        CertificateMaterialVerifier.verify(bundle, cert.getFingerprintSha256());
        if (options.format().includesPrivateKey() && !bundle.hasPrivateKey()) {
            throw CertExportException.notExportable(CertExportUnavailableReason.KEY_HELD_EXTERNALLY.name(),
                    "The private key for this certificate is not held by the platform.");
        }
        String stem = CertExportFileNames.stemFor(bundle.leaf(), cert.getDomain(),
                Boolean.TRUE.equals(cert.getWildcard()));
        byte[] content = render(bundle, options, stem);
        auditRecorder.recordExport(cert, options);
        return new ExportedCertificateFile(content, options.format().mediaType(),
                stem + options.format().fileNameSuffix());
    }

    private void requireEligible(CertificateEntity cert) {
        CertExportEligibility eligibility = eligibilityPolicy.evaluate(cert);
        if (eligibility.available()) {
            return;
        }
        if (eligibility.reason() == CertExportUnavailableReason.EXPIRED) {
            throw CertExportException.materialGone("This certificate has expired and its material was removed.");
        }
        throw CertExportException.notExportable(eligibility.reason().name(),
                "This certificate cannot be exported.");
    }

    /**
     * Called only after the policy confirmed the handle names this certificate's secret in our store.
     * Missing, destroyed, disabled or deletion-scheduled material is gone for good (410); anything
     * else, permissions and throttling included, may recover (503).
     */
    private String readSecret(CertificateEntity cert) {
        AgentSecretStore store = secretStoreProvider.getIfAvailable();
        if (store == null) {
            throw new ServiceUnavailableException(STORE_UNAVAILABLE_MESSAGE);
        }
        try {
            return store.read(cert.getCertSecretHandle());
        } catch (ResourceNotFoundException | AgentSecretGoneException e) {
            throw CertExportException.materialGone("The certificate material is no longer stored.");
        } catch (RuntimeException e) {
            log.warn("[CERT_EXPORT_STORE_UNAVAILABLE] xref={}: {}", cert.getCertificateXref(),
                    e.getClass().getSimpleName());
            throw new ServiceUnavailableException(STORE_UNAVAILABLE_MESSAGE);
        }
    }

    private static byte[] render(AgentCertificateBundle bundle, CertExportOptions options, String alias) {
        try {
            return CertExportFileRenderer.render(bundle, options, alias);
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalStateException("Certificate export could not be rendered", e);
        }
    }
}
