// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.platform.intune;

import com.certping.agent.model.message.CertificateCorrelationCandidate;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class IntuneCertificateProfileCorrelatorTest {

    @Test
    void exactThumbprintMatchWinsOverIssuerSerialFallback() {
        var correlator = new IntuneCertificateProfileCorrelator(List.of(
                candidate("cert_1", "aa".repeat(20))));
        correlator.accept("fallback-profile", "#microsoft.graph.macOSScepCertificateProfile",
                Map.of("certificateIssuer", "CN=Test CA", "certificateSerialNumber", "01"));
        correlator.accept("exact-profile", "#microsoft.graph.macOSScepCertificateProfile",
                Map.of("certificateThumbprint", "AA:".repeat(19) + "AA"));

        assertThat(correlator.results()).singleElement().satisfies(result -> {
            assertThat(result.status()).isEqualTo("MATCHED");
            assertThat(result.providerProfileId()).isEqualTo("exact-profile");
            assertThat(result.matchMethod()).isEqualTo("SHA1");
        });
    }

    @Test
    void reportsAmbiguousWhenTheSameThumbprintAppearsUnderTwoProfiles() {
        var correlator = new IntuneCertificateProfileCorrelator(List.of(
                candidate("cert_1", "ab".repeat(20))));
        Map<String, Object> state = Map.of("certificateThumbprint", "ab".repeat(20));
        correlator.accept("profile-1", "#microsoft.graph.macOSScepCertificateProfile", state);
        correlator.accept("profile-2", "#microsoft.graph.macOSScepCertificateProfile", state);

        assertThat(correlator.results()).singleElement().satisfies(result -> {
            assertThat(result.status()).isEqualTo("AMBIGUOUS");
            assertThat(result.providerProfileId()).isNull();
        });
    }

    @Test
    void fallsBackToCanonicalIssuerAndSerialOnlyWhenReportThumbprintIsAbsent() {
        var correlator = new IntuneCertificateProfileCorrelator(List.of(
                candidate("cert_1", "cd".repeat(20))));
        correlator.accept("profile-1", "#microsoft.graph.windows81SCEPCertificateProfile",
                Map.of("certificateIssuer", "CN=Test CA", "certificateSerialNumber", "00:01"));

        assertThat(correlator.results()).singleElement().satisfies(result -> {
            assertThat(result.status()).isEqualTo("MATCHED");
            assertThat(result.matchMethod()).isEqualTo("ISSUER_SERIAL");
        });
    }

    @Test
    void legacyCandidateWithoutSha1MatchesIssuerSerialEvenWhenReportHasThumbprint() {
        var correlator = new IntuneCertificateProfileCorrelator(List.of(
                candidate("cert_legacy", null)));

        correlator.accept("profile-1", "#microsoft.graph.macOSScepCertificateProfile",
                Map.of(
                        "certificateThumbprint", "ef".repeat(20),
                        "certificateIssuer", "CN=Test CA",
                        "certificateSerialNumber", "01"));

        assertThat(correlator.results()).singleElement().satisfies(result -> {
            assertThat(result.status()).isEqualTo("MATCHED");
            assertThat(result.providerProfileId()).isEqualTo("profile-1");
            assertThat(result.matchMethod()).isEqualTo("ISSUER_SERIAL");
        });
    }

    private static CertificateCorrelationCandidate candidate(String xref, String sha1) {
        return new CertificateCorrelationCandidate(xref, sha1, "CN=Test CA", "1");
    }
}
