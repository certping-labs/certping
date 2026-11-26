// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.exception.FeatureDisabledException;
import com.certmanagement.repository.CredentialReferenceRepository;
import com.certmanagement.service.FeatureFlagResolver;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Objects;
import java.util.Set;

/**
 * Which DNS credentials an organization may use. {@code DNS_CREDENTIALS} governs credentials for third-party DNS
 * hosts; CertPing DNS (provider {@value #CERTPING_PROVIDER}) is always available. Automatic renewal still requires
 * {@code DNS_CREDENTIALS} whatever the credential ({@link FeatureFlags#AUTOMATIC_WORK_REQUIRES}).
 */
@Component
@RequiredArgsConstructor
public class DnsCredentialAvailability {

    public static final String CERTPING_PROVIDER = "CERTPING";

    private final CredentialReferenceRepository credentials;
    private final FeatureFlagResolver featureFlagResolver;

    /** Whether a DNS credential of {@code provider} is for a third-party DNS host, so needs DNS_CREDENTIALS. */
    public static boolean isThirdParty(String provider) {
        return !CERTPING_PROVIDER.equals(provider);
    }

    /**
     * Refuses {@code credentialXrefs} while DNS credentials are off for the organization (read past the cache),
     * unless every one is an active CertPing DNS credential of the organization.
     *
     * @throws FeatureDisabledException for {@code DNS_CREDENTIALS}
     */
    public void assertUsable(long organizationId, Collection<String> credentialXrefs) {
        Set<String> xrefs = Set.copyOf(credentialXrefs);
        if (xrefs.isEmpty() || featureFlagResolver.resolveUncached(FeatureFlags.DNS_CREDENTIALS, organizationId)
                || allCertPing(organizationId, xrefs)) {
            return;
        }
        throw new FeatureDisabledException(FeatureFlags.DNS_CREDENTIALS);
    }

    private boolean allCertPing(long organizationId, Set<String> xrefs) {
        return credentials.findByCredentialXrefIn(xrefs).stream()
                .filter(credential -> isUsableCertPing(credential, organizationId))
                .count() == xrefs.size();
    }

    private static boolean isUsableCertPing(CredentialReferenceEntity credential, long organizationId) {
        return Objects.equals(credential.getOrganizationId(), organizationId)
                && !isThirdParty(credential.getProvider())
                && "DNS".equals(credential.getType())
                && "ACTIVE".equals(credential.getStatus())
                && !Boolean.TRUE.equals(credential.getIsDeleted());
    }
}
