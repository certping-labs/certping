// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl;

import com.certping.agent.deployment.adapter.akamai.AkamaiCpsIssuanceService;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.enums.CaProvider;
import com.certping.agent.model.message.CertIssuanceMessage;
import com.certping.agent.model.message.SanDomainEntry;
import com.certping.agent.service.CredentialAccessService;
import com.certping.agent.ssl.acme.LetsEncryptAcmeService;
import com.certping.agent.ssl.digicert.DigiCertIssuanceService;
import com.certping.agent.ssl.dns.DnsProvider;
import com.certping.agent.ssl.dns.DnsProviderFactory;
import com.certping.agent.ssl.globalsign.GlobalSignIssuanceService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class SslIssuanceService {

    private final LetsEncryptAcmeService leService;
    private final DigiCertIssuanceService digicertService;
    private final GlobalSignIssuanceService globalSignService;
    private final AkamaiCpsIssuanceService akamaiCpsIssuanceService;
    private final CredentialAccessService credentialAccessService;
    private final DnsProviderFactory dnsProviderFactory;

    public IssuanceResult issue(CertIssuanceMessage msg) {
        if ("AKAMAI_CPS".equals(msg.getSpecialCertType())) {
            return akamaiCpsIssuanceService.issue(msg);
        }

        CaProvider ca = msg.getCaProvider();
        log.info("SslIssuanceService routing: caProvider={}, domain={}, xref={}",
                ca, msg.getDomain(), msg.getCertificateXref());

        List<String> sanDomains = flattenPatterns(msg.getSanDomainEntries());
        if (KeyCustody.fromMessage(msg.getKeyCustody()) == KeyCustody.CUSTOMER_HELD) {
            return issueFromCustomerCsr(msg, ca, sanDomains);
        }

        return switch (ca) {
            case GLOBALSIGN -> {
                DnsProvider rootDns = buildRootDnsProvider(msg.getDnsProvider(), msg.getDnsCredentialHandle());
                Map<String, DnsProvider> sanDns = buildSanDnsProviders(msg.getSanDomainEntries());
                yield globalSignService.issue(
                        msg.getCertificateXref(),
                        msg.getDomain(),
                        msg.isWildcard(),
                        sanDomains,
                        rootDns,
                        sanDns,
                        msg.getValidityDays(),
                        msg.getCheckpoint(),
                        msg.isFinalPropagationWait(),
                        msg.getCheckpointRecorder());
            }

            case LETS_ENCRYPT -> {
                DnsProvider rootDns = buildRootDnsProvider(msg.getDnsProvider(), msg.getDnsCredentialHandle());
                Map<String, DnsProvider> sanDns = buildSanDnsProviders(msg.getSanDomainEntries());
                // msg.checkpoint is populated by CertIssuanceProcessor from Checkpoint.* message properties
                // on a retry delivery; null on first attempt.
                yield leService.issue(
                        msg.getOrganizationId(),
                        msg.getCertificateXref(),
                        msg.getDomain(),
                        msg.isWildcard(),
                        sanDomains,
                        rootDns,
                        sanDns,
                        msg.getAcmeAccountHandle(),
                        msg.getValidityDays(),
                        msg.getCheckpoint(),
                        null,
                        msg.isFinalPropagationWait(),
                        msg.getCheckpointRecorder());
            }

            case DIGICERT -> {
                DnsProvider rootDns = buildRootDnsProvider(msg.getDnsProvider(), msg.getDnsCredentialHandle());
                Map<String, DnsProvider> sanDns = buildSanDnsProviders(msg.getSanDomainEntries());
                yield digicertService.issue(
                        msg.getCertificateXref(),
                        msg.getDomain(),
                        sanDomains,
                        rootDns,
                        sanDns,
                        msg.getCaCredentialHandle(),
                        msg.getValidityDays(),
                        msg.getCheckpoint(),
                        msg.getCheckpointRecorder());
            }

            default -> throw new PermanentAgentException("UNKNOWN_CA_PROVIDER",
                    "Unsupported caProvider for issuance: " + ca);
        };
    }

    /** The customer holds the key: the CA gets their CSR, no key is generated or staged, the chain alone is stored. */
    private IssuanceResult issueFromCustomerCsr(CertIssuanceMessage msg, CaProvider ca, List<String> sanDomains) {
        String csrPem = msg.getCsrPem();
        if (csrPem == null || csrPem.isBlank()) {
            throw new PermanentAgentException("CSR_MISSING",
                    "A customer-held key needs the customer's CSR on the message for " + msg.getCertificateXref());
        }
        log.info("Customer-held key: issuing from the customer's CSR, caProvider={}, xref={}", ca, msg.getCertificateXref());
        return switch (ca) {
            case DIGICERT -> digicertService.issueWithExternalCsr(
                    msg.getCertificateXref(), msg.getDomain(), sanDomains,
                    buildRootDnsProvider(msg.getDnsProvider(), msg.getDnsCredentialHandle()),
                    buildSanDnsProviders(msg.getSanDomainEntries()),
                    msg.getCaCredentialHandle(), csrPem, msg.getValidityDays(),
                    msg.getCheckpoint(), msg.getCheckpointRecorder());
            case LETS_ENCRYPT -> leService.issueWithExternalCsr(
                    msg.getOrganizationId(), msg.getCertificateXref(), msg.getDomain(), msg.isWildcard(), sanDomains,
                    buildRootDnsProvider(msg.getDnsProvider(), msg.getDnsCredentialHandle()),
                    buildSanDnsProviders(msg.getSanDomainEntries()),
                    msg.getAcmeAccountHandle(), csrPem, msg.isFinalPropagationWait(),
                    msg.getCheckpoint(), msg.getCheckpointRecorder());
            case GLOBALSIGN -> globalSignService.issueWithExternalCsr(
                    msg.getCertificateXref(), msg.getDomain(), msg.isWildcard(), sanDomains,
                    buildRootDnsProvider(msg.getDnsProvider(), msg.getDnsCredentialHandle()),
                    buildSanDnsProviders(msg.getSanDomainEntries()),
                    csrPem, msg.getValidityDays(), msg.isFinalPropagationWait(),
                    msg.getCheckpoint(), msg.getCheckpointRecorder());
            default -> throw new PermanentAgentException("UNKNOWN_CA_PROVIDER",
                    "Unsupported caProvider for issuance: " + ca);
        };
    }

    private DnsProvider buildRootDnsProvider(String dnsProvider, String dnsCredentialHandle) {
        String rawCred = credentialAccessService.readSecret(dnsCredentialHandle);
        return dnsProviderFactory.create(dnsProvider, rawCred);
    }

    /**
     * Builds a domain-pattern → DnsProvider map for SAN multi-provider routing.
     *
     * <p>Keyed by each domain pattern string (e.g. {@code "api.example.com"} or
     * {@code "*.example.com"}) so that {@code DnsProviderSelector.selectProvider()}
     * can match an ACME authorization domain to the correct DNS provider.
     *
     * <p>Previously keyed by {@code dnsCredentialHandle}, which made pattern-based
     * lookup impossible when more than one SAN provider was present.
     */
    private Map<String, DnsProvider> buildSanDnsProviders(List<SanDomainEntry> entries) {
        if (entries == null || entries.isEmpty()) {
            return Collections.emptyMap();
        }
        Map<String, DnsProvider> map = new HashMap<>();
        for (SanDomainEntry entry : entries) {
            String raw = credentialAccessService.readSecret(entry.getDnsCredentialHandle());
            DnsProvider provider = dnsProviderFactory.create(entry.getDnsProvider(), raw);
            if (entry.getPatterns() != null) {
                for (String pattern : entry.getPatterns()) {
                    if (pattern != null && !pattern.isBlank()) {
                        map.put(pattern, provider);
                    }
                }
            }
        }
        return map;
    }

    private List<String> flattenPatterns(List<SanDomainEntry> entries) {
        if (entries == null || entries.isEmpty()) {
            return Collections.emptyList();
        }
        return entries.stream()
                .filter(e -> e.getPatterns() != null)
                .flatMap(e -> e.getPatterns().stream())
                .distinct()
                .toList();
    }
}
