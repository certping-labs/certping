// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.dto.credconfig.credjson.dns.CertPingDnsKeyConfig;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.repository.CredentialReferenceRepository;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;

import java.time.Instant;
import java.util.Collection;
import java.util.Comparator;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * When the CertPing DNS keys behind an organization's credentials stop working, read from each credential's
 * {@code config} ({@link CertPingDnsKeyConfig}). A key registered without its details has no known expiry.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CertPingDnsKeys {

    private final CredentialReferenceRepository credentials;
    private final ObjectMapper objectMapper;

    /** The details of {@code credential}'s CertPing DNS key; empty for another provider or unreadable details. */
    public Optional<CertPingDnsKeyConfig> details(CredentialReferenceEntity credential) {
        if (DnsCredentialAvailability.isThirdParty(credential.getProvider()) || credential.getConfigJson() == null) {
            return Optional.empty();
        }
        try {
            return Optional.ofNullable(objectMapper.readValue(credential.getConfigJson(), CertPingDnsKeyConfig.class));
        } catch (JacksonException e) {
            log.warn("CertPing DNS key details of credential {} could not be read: {}",
                    credential.getCredentialXref(), e.getOriginalMessage());
            return Optional.empty();
        }
    }

    /** When {@code credential}'s CertPing DNS key expires; empty for another provider or unknown details. */
    public Optional<Instant> expiresAt(CredentialReferenceEntity credential) {
        return details(credential).map(CertPingDnsKeyConfig::getExpiresAt);
    }

    /**
     * The earliest expiry, at or before {@code now}, among the organization's CertPing DNS keys named by
     * {@code credentialXrefs}; empty when none of them has expired.
     */
    public Optional<Instant> earliestExpired(long organizationId, Collection<String> credentialXrefs, Instant now) {
        if (credentialXrefs.isEmpty()) {
            return Optional.empty();
        }
        return credentials.findByCredentialXrefIn(Set.copyOf(credentialXrefs)).stream()
                .filter(credential -> Objects.equals(credential.getOrganizationId(), organizationId))
                .map(this::expiresAt)
                .flatMap(Optional::stream)
                .filter(expiry -> !expiry.isAfter(now))
                .min(Comparator.naturalOrder());
    }
}
