// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.enums.CaProvider;
import com.certping.agent.model.message.CertRenewalMessage;
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
public class SslRenewalService {

    private final LetsEncryptAcmeService leService;
    private final DigiCertIssuanceService digicertService;
    private final GlobalSignIssuanceService globalSignService;
    private final CredentialAccessService credentialAccessService;
    private final DnsProviderFactory dnsProviderFactory;

    public IssuanceResult renew(CertRenewalMessage msg) {
        CaProvider ca = msg.getCaProvider();
        log.info("SslRenewalService routing: caProvider={}, domain={}, xref={}",
                ca, msg.getDomain(), msg.getCertificateXref());

        List<String> sanDomains = flattenPatterns(msg.getSanDomainEntries());

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
                        msg.getPreviousCertSecretHandle(),
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
                    "Unsupported caProvider for renewal: " + ca);
        };
    }

    private DnsProvider buildRootDnsProvider(String dnsProvider, String dnsCredentialHandle) {
        String rawCred = credentialAccessService.readSecret(dnsCredentialHandle);
        return dnsProviderFactory.create(dnsProvider, rawCred);
    }

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
