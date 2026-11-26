// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.entity.RenewalScheduleEntity;
import com.certmanagement.enums.CertificateStatus;
import com.certmanagement.exception.MissingDnsCredentialConfigurationException;
import com.certmanagement.messaging.model.CertRenewalCommand;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

@Component
public class RenewalDraftHelper {

    public CertificateEntity buildRenewedDraft(CertificateEntity previousCert,
                                               String renewedXref,
                                               String renewedCertSecretHandle) {
        return CertificateEntity.builder()
                .certificateXref(renewedXref)
                .userDomainCertId(previousCert.getUserDomainCertId())
                .userDomainCert(previousCert.getUserDomainCert())
                .wildcard(previousCert.getWildcard())
                .san(previousCert.getSan())
                .sanDomains(previousCert.getSanDomains())
                .caProvider(previousCert.getCaProvider())
                .status(CertificateStatus.PENDING.name())
                .targetResourceId(previousCert.getTargetResourceId())
                .certSecretHandle(renewedCertSecretHandle)
                .acmeAccountHandle(previousCert.getAcmeAccountHandle())
                .caCredentialHandle(previousCert.getCaCredentialHandle())
                .orderId(previousCert.getOrderId())
                .build();
    }

    public String deriveRenewedCertSecretHandle(String scheduleCertSecretHandle,
                                          String currentCertSecretHandle,
                                          String renewedXref) {
        String basePath = (scheduleCertSecretHandle != null && !scheduleCertSecretHandle.isBlank())
                ? scheduleCertSecretHandle
                : currentCertSecretHandle;
        if (basePath == null || basePath.isBlank()) {
            return null;
        }
        try {
            var components = UriComponentsBuilder.fromUriString(basePath).build();
            List<String> segments = new ArrayList<>(components.getPathSegments());
            for (int i = 0; i < segments.size() - 1; i++) {
                String segment = segments.get(i);
                if ("secrets".equalsIgnoreCase(segment) || "certificates".equalsIgnoreCase(segment)) {
                    segments.set(i + 1, renewedXref);
                    String normalizedPath = "/" + String.join("/", segments);
                    return UriComponentsBuilder.newInstance()
                            .scheme(components.getScheme())
                            .host(components.getHost())
                            .port(components.getPort())
                            .path(normalizedPath)
                            .build(true)
                            .toUriString();
                }
            }
        } catch (Exception ignored) {
            // Caller can log with flow context if needed.
        }
        return basePath;
    }

    /**
     * The renewal's SAN entries: exactly the certificate's stored SANs, each with the DNS credential the configuration
     * holds for its root, or for the name itself (a conversion keeps names as keys). The primary root's other names
     * use the primary credential. Keys that match none of the certificate's names add nothing.
     *
     * @throws MissingDnsCredentialConfigurationException when a SAN has no credential, rather than renewing without it
     */
    public List<CertRenewalCommand.SanDomainEntry> buildRenewalSanEntriesFromConfig(
            String primaryDomain,
            String[] sanDomains,
            Map<String, String> dnsConfig,
            CredentialReferenceEntity primaryDnsCred,
            Function<String, CredentialReferenceEntity> credentialResolver) {

        SanDomainHelper.SanNamesByConfigKey names =
                SanDomainHelper.sanNamesByConfigKey(primaryDomain, sanDomains, dnsConfig);
        List<CertRenewalCommand.SanDomainEntry> entries = new ArrayList<>();
        names.byConfigKey().forEach((key, patterns) ->
                entries.add(sanEntry(credentialResolver.apply(dnsConfig.get(key)), patterns)));
        if (!names.primaryRootNames().isEmpty()) {
            entries.add(sanEntry(primaryDnsCred, names.primaryRootNames()));
        }
        return entries;
    }

    /**
     * The DNS credentials a renewal of the certificate publishes through: the primary root's, and the one each other
     * name resolves to as in {@link #buildRenewalSanEntriesFromConfig}. A name with no credential adds nothing; the
     * renewal itself refuses it.
     */
    public Set<String> renewalDnsCredentialXrefs(String primaryDomain, String[] sanDomains,
                                                 Map<String, String> dnsConfig) {
        Set<String> xrefs = new HashSet<>();
        String primaryXref = SanDomainHelper.lookupRootCredXref(dnsConfig, primaryDomain);
        if (primaryXref != null) {
            xrefs.add(primaryXref);
        }
        String primaryRoot = SanDomainHelper.extractRootDomain(primaryDomain);
        SanDomainHelper.groupNonPrimarySansByRoot(primaryDomain, sanDomains).forEach((root, patterns) -> {
            if (!root.equals(primaryRoot)) {
                patterns.forEach(pattern -> SanDomainHelper.configKeyCovering(dnsConfig, pattern)
                        .map(dnsConfig::get)
                        .ifPresent(xrefs::add));
            }
        });
        return xrefs;
    }

    private static CertRenewalCommand.SanDomainEntry sanEntry(CredentialReferenceEntity cred, List<String> patterns) {
        return CertRenewalCommand.SanDomainEntry.builder()
                .dnsProvider(cred.getProvider())
                .dnsCredentialHandle(cred.getSecretHandle())
                .dnsCredentialConfigJson(cred.getConfigJson())
                .patterns(new ArrayList<>(patterns))
                .build();
    }

    public CertRenewalCommand buildRenewalCommand(
            CertificateEntity cert,
            CertificateEntity renewedDraft,
            RenewalScheduleEntity schedule,
            String primaryDomain,
            Long organizationId,
            String orgType,
            String requestId,
            String correlationId,
            CredentialReferenceEntity primaryDnsCred,
            List<CertRenewalCommand.SanDomainEntry> sanEntries) {
        return CertRenewalCommand.builder()
                .organizationId(organizationId != null ? organizationId.toString() : "")
                .orgType(orgType)
                .requestId(requestId)
                .correlationId(correlationId)
                .certificateXref(renewedDraft.getCertificateXref())
                .domain(primaryDomain)
                .wildcard(cert.getWildcard())
                .caProvider(cert.getCaProvider())
                .validityDays(cert.getRequestedValidityDays())
                .dnsProvider(primaryDnsCred.getProvider())
                .certSecretHandle(renewedDraft.getCertSecretHandle())
                .previousCertSecretHandle(cert.getCertSecretHandle())
                .dnsCredentialHandle(primaryDnsCred.getSecretHandle())
                .dnsCredentialConfigJson(primaryDnsCred.getConfigJson())
                .acmeAccountHandle(schedule.getAcmeAccountHandle())
                .caCredentialHandle(schedule.getCaCredentialHandle())
                .sanDomainEntries(sanEntries.isEmpty() ? null : sanEntries)
                .currentValidTo(cert.getValidTo() != null ? cert.getValidTo().toString() : null)
                .orderId(schedule.getOrderId())
                .renewalWindowDays(schedule.getRenewalWindowDays())
                .build();
    }
}
