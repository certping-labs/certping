// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.repository.CredentialReferenceRepository;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertPingDnsKeysTest {

    private static final long ORG = 7L;
    private static final Instant NOW = Instant.parse("2026-10-20T12:00:00Z");

    @Mock private CredentialReferenceRepository credentials;

    private CertPingDnsKeys keys() {
        return new CertPingDnsKeys(credentials, JsonMapper.builderWithJackson2Defaults().findAndAddModules().build());
    }

    @Test
    void aCertPingKeysExpiryIsReadFromItsConfig() {
        assertThat(keys().expiresAt(certPing("cred-1", ORG, "2027-01-01T00:00:00Z")))
                .contains(Instant.parse("2027-01-01T00:00:00Z"));
    }

    @Test
    void anotherProvidersConfigOrMissingOrUnreadableDetailsHaveNoExpiry() {
        CredentialReferenceEntity cloudflare = certPing("cred-1", ORG, "2027-01-01T00:00:00Z");
        cloudflare.setProvider("CLOUDFLARE");
        CredentialReferenceEntity noDetails = certPing("cred-2", ORG, null);
        CredentialReferenceEntity unreadable = certPing("cred-3", ORG, null);
        unreadable.setConfigJson("{\"expiresAt\":\"next year\"}");

        assertThat(List.of(cloudflare, noDetails, unreadable)).allSatisfy(c -> assertThat(keys().expiresAt(c)).isEmpty());
    }

    @Test
    void theEarliestExpiredKeyOfTheOrganizationIsReported() {
        when(credentials.findByCredentialXrefIn(Set.of("a", "b", "c", "d"))).thenReturn(List.of(
                certPing("a", ORG, "2026-10-19T00:00:00Z"),
                certPing("b", ORG, "2026-10-01T00:00:00Z"),
                certPing("c", ORG, "2026-12-01T00:00:00Z"),
                certPing("d", ORG + 1, "2026-09-01T00:00:00Z")));

        assertThat(keys().earliestExpired(ORG, List.of("a", "b", "c", "d"), NOW))
                .contains(Instant.parse("2026-10-01T00:00:00Z"));
    }

    @Test
    void noKeyHasExpiredWhenEveryExpiryIsAhead() {
        when(credentials.findByCredentialXrefIn(Set.of("c"))).thenReturn(List.of(certPing("c", ORG, "2026-10-20T12:00:01Z")));

        assertThat(keys().earliestExpired(ORG, List.of("c", "c"), NOW)).isEmpty();
    }

    @Test
    void noCredentialsAreReadForNoXrefs() {
        assertThat(keys().earliestExpired(ORG, List.of(), NOW)).isEmpty();
        verifyNoInteractions(credentials);
    }

    static CredentialReferenceEntity certPing(String xref, long organizationId, String expiresAt) {
        return CredentialReferenceEntity.builder().id((long) xref.hashCode()).credentialXref(xref)
                .organizationId(organizationId).provider("CERTPING").type("DNS").description("CertPing DNS for " + xref)
                .configJson(expiresAt == null ? null
                        : "{\"tokenId\":41,\"tokenPrefix\":\"cpk_live_ab12cd34\",\"expiresAt\":\"" + expiresAt + "\"}")
                .build();
    }
}
