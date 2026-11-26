// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.enums.KeyCustody;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.entity.DomainCredentialConfigEntity;
import com.certmanagement.entity.RenewalScheduleEntity;
import com.certmanagement.enums.CertificateStatus;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.ServiceUnavailableException;
import com.certmanagement.messaging.CertAgentPublisher;
import com.certmanagement.messaging.model.CertIssuanceCommand;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.RenewalScheduleRepository;
import com.certmanagement.service.OrgTypeResolver;
import com.certmanagement.util.MdcIds;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;

/**
 * Orchestrates issuance of "special" certificates whose CSR must be obtained from
 * a third-party CDN rather than generated locally.
 *
 * <p>Currently supports Akamai CPS (specialCertType = "AKAMAI_CPS").
 * The flow is:
 * <ol>
 *   <li>Persist a new PENDING certificate record and renewal schedule.</li>
 *   <li>Publish a {@code CertIssuanceCommand} with specialCertType set so the agent
 *       knows to fetch the CSR from Akamai, sign it with the CA, and store the
 *       resulting cert in the agent's secret store.</li>
 *   <li>After the agent responds, {@link com.certmanagement.messaging.CertResponseProcessor}
 *       promotes the cert to ACTIVE and dispatches a deployment command to the
 *       Akamai credential — completing the rotation.</li>
 * </ol>
 *
 * <p>Persistence is committed before the queue publish to avoid the dual-write race.
 * On publish failure the cert is marked FAILED via a separate transaction.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AkamaiSpecialIssuanceService {

    public static final String AKAMAI_CPS = "AKAMAI_CPS";

    private final CertificateRepository    certificateRepository;
    private final RenewalScheduleRepository renewalScheduleRepository;
    private final CredentialReferenceService credentialReferenceService;
    private final CertAgentPublisher       publisher;
    private final OrgTypeResolver          orgTypeResolver;
    private final PlatformTransactionManager transactionManager;

    /**
     * Persists a new AKAMAI_CPS special cert record (PENDING) and its renewal schedule,
     * then publishes the issuance command.
     *
     * @param organizationId  owning org
     * @param regularCert     the active non-special cert for the same UDC — provides CA/DNS context
     * @param regularSchedule the renewal schedule of {@code regularCert}
     * @param credConfig      the domain credential config for the UDC — provides DNS credential mapping
     * @param akamaiCred      the AKAMAI_CPS deployment credential — its secretHandle goes into the command
     */
    public void triggerAkamaiSpecialIssuance(
            Long organizationId,
            CertificateEntity regularCert,
            RenewalScheduleEntity regularSchedule,
            DomainCredentialConfigEntity credConfig,
            CredentialReferenceEntity akamaiCred) {
        // Resolve primary DNS credential for the issuance command
        String domain = regularCert.getDomain();
        String primaryDnsCredXref = SanDomainHelper.lookupRootCredXref(credConfig.getDnsConfig(), domain);
        if (primaryDnsCredXref == null) {
            throw new BadRequestException(
                    "Cannot trigger Akamai-special issuance for domain '" + domain +
                    "': no DNS credential configured. A managed cert requires DNS credentials.");
        }
        CredentialReferenceEntity primaryDnsCred =
                credentialReferenceService.getByXref(organizationId, primaryDnsCredXref);

        String certXref      = CertificateXrefs.newXref();
        String requestId     = MdcIds.requestId();
        String correlationId = MdcIds.correlationId();

        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            persistSpecialCertAndSchedule(certXref, requestId, correlationId,
                    regularCert, regularSchedule, credConfig);
        });

        CertIssuanceCommand command = CertIssuanceCommand.builder()
                .organizationId(organizationId.toString())
                .orgType(orgTypeResolver.resolve(organizationId))
                .requestId(requestId)
                .correlationId(correlationId)
                .certificateXref(certXref)
                .domain(domain)
                .wildcard(regularCert.getWildcard())
                .san(regularCert.getSan())
                .caProvider(regularCert.getCaProvider())
                .dnsProvider(primaryDnsCred.getProvider())
                .dnsCredentialHandle(primaryDnsCred.getSecretHandle())
                .acmeAccountHandle(regularSchedule.getAcmeAccountHandle())
                .caCredentialHandle(regularSchedule.getCaCredentialHandle())
                .specialCertType(AKAMAI_CPS)
                .specialDeploymentCredHandle(akamaiCred.getSecretHandle())
                .build();

        try {
            publisher.publishIssuance(command);
            log.info("Akamai-special issuance command published: certXref={}, domain={}, org={}",
                    certXref, domain, organizationId);
        } catch (Exception e) {
            log.error("queue publish failed for Akamai-special CERT_ISSUANCE xref={}: {}",
                    certXref, e.getMessage(), e);
            markFailed(certXref, e.getMessage());
            throw new ServiceUnavailableException(
                    "Failed to dispatch Akamai-special issuance command. Cert " + certXref +
                    " has been marked FAILED — please retry.", e);
        }
    }

    // ------------------------------------------------------------------ //
    //  Private helpers
    // ------------------------------------------------------------------ //

    @Transactional
    void persistSpecialCertAndSchedule(String certXref, String requestId, String correlationId,
                                       CertificateEntity regularCert,
                                       RenewalScheduleEntity regularSchedule,
                                       DomainCredentialConfigEntity credConfig) {

        CertificateEntity specialCert = CertificateEntity.builder()
                .certificateXref(certXref)
                .userDomainCertId(regularCert.getUserDomainCertId())
                .userDomainCert(regularCert.getUserDomainCert())
                .wildcard(regularCert.getWildcard())
                .san(regularCert.getSan())
                .sanDomains(regularCert.getSanDomains())
                .caProvider(regularCert.getCaProvider())
                .status(CertificateStatus.PENDING.name())
                .acmeAccountHandle(regularCert.getAcmeAccountHandle())
                .caCredentialHandle(regularCert.getCaCredentialHandle())
                .specialCertificateType(AKAMAI_CPS)
                .keyCustody(KeyCustody.CUSTOMER_HELD)
                .build();
        certificateRepository.save(specialCert);

        RenewalScheduleEntity schedule = RenewalScheduleEntity.builder()
                .certificateXref(certXref)
                .domainCredentialConfigId(credConfig.getId())
                .caProvider(regularCert.getCaProvider())
                .acmeAccountHandle(regularSchedule.getAcmeAccountHandle())
                .caCredentialHandle(regularSchedule.getCaCredentialHandle())
                .certSecretHandle(null)
                .validTo(OffsetDateTime.now(ZoneOffset.UTC).plusYears(1))
                .renewalEligibleAt(OffsetDateTime.now(ZoneOffset.UTC).plusDays(335))
                .enabled(false)
                .build();
        renewalScheduleRepository.save(schedule);

        log.info("Akamai-special cert persisted as PENDING: certXref={}, udcId={}",
                certXref, regularCert.getUserDomainCertId());
    }

    @Transactional
    void markFailed(String certXref, String errorMessage) {
        certificateRepository.findByCertificateXref(certXref).ifPresent(c -> {
            c.setStatus(CertificateStatus.FAILED.name());
            c.setLastErrorCode("AKAMAI_SPECIAL_ISSUANCE_PUBLISH_FAILED");
            c.setLastErrorMessage(errorMessage);
            c.setLastErrorAt(OffsetDateTime.now(ZoneOffset.UTC));
            certificateRepository.save(c);
        });
    }
}
