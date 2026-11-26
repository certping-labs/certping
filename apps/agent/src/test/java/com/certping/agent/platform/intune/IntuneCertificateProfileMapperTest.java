// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.platform.intune;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.message.CertificateProfileMessage;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IntuneCertificateProfileMapperTest {
    private final IntuneCertificateProfileMapper mapper = new IntuneCertificateProfileMapper(
            Clock.fixed(Instant.parse("2026-08-25T00:00:00Z"), ZoneOffset.UTC));

    @Test
    void mapsWindowsScepIntentWithoutIncludingIntuneCredentials() {
        Map<String, Object> payload = mapper.toWindowsScepPayload(command(),
                List.of("https://scep.example.test/certsrv/mscep/mscep.dll"));

        assertThat(payload)
                .containsEntry("@odata.type", "#microsoft.graph.windows81SCEPCertificateProfile")
                .containsEntry("keySize", "size2048")
                .containsEntry("hashAlgorithm", "sha2")
                .containsEntry("certificateStore", "machine");
        assertThat(payload.get("scepServerUrls")).isEqualTo(
                List.of("https://scep.example.test/certsrv/mscep/mscep.dll"));
        assertThat(payload.toString()).doesNotContain("clientSecret", "tenantId");
    }

    @Test
    void observedSnapshotStoresScepHostsButNotFullUrls() {
        var observed = mapper.fromGraph(Map.ofEntries(
                Map.entry("@odata.type", "#microsoft.graph.windows81SCEPCertificateProfile"),
                Map.entry("id", "2daf8af2-8af2-2daf-f28a-af2df28aaf2d"),
                Map.entry("displayName", "Corporate Windows"),
                Map.entry("description", "Managed by CertPing [certping:profile_1]"),
                Map.entry("version", 7),
                Map.entry("lastModifiedDateTime", "2026-08-24T00:00:00Z"),
                Map.entry("renewalThresholdPercentage", 20),
                Map.entry("keyStorageProvider", "useSoftwareKsp"),
                Map.entry("subjectNameFormatString", "CN={{AAD_Device_ID}}"),
                Map.entry("certificateValidityPeriodValue", 12),
                Map.entry("certificateValidityPeriodScale", "months"),
                Map.entry("scepServerUrls", List.of("https://scep.example.test/private/path")),
                Map.entry("keyUsage", "digitalSignature,keyEncipherment"),
                Map.entry("keySize", "size2048"),
                Map.entry("hashAlgorithm", "sha2"),
                Map.entry("certificateStore", "machine")));

        assertThat(observed.getProviderCorrelationMarker()).isEqualTo("certping:profile_1");
        assertThat(observed.getConfiguration()).containsEntry("keySize", 2048);
        assertThat(observed.getProviderResponse()).containsEntry(
                "scepServerHosts", List.of("scep.example.test"));
        assertThat(observed.getProviderResponse().toString()).doesNotContain("/private/path");
    }

    @Test
    void rejectsNonHttpsScepEndpoint() {
        assertThatThrownBy(() -> mapper.toWindowsScepPayload(
                command(), List.of("http://scep.example.test/mscep")))
                .isInstanceOfSatisfying(PermanentAgentException.class,
                        error -> assertThat(error.getErrorCode()).isEqualTo("SCEP_ENDPOINT_INVALID"));
    }

    @Test
    void rejectsScepEndpointWithEmbeddedUserInfoOrFragment() {
        assertThatThrownBy(() -> mapper.toWindowsScepPayload(
                command(), List.of("https://user:password@scep.example.test/mscep")))
                .isInstanceOfSatisfying(PermanentAgentException.class,
                        error -> assertThat(error.getErrorCode()).isEqualTo("SCEP_ENDPOINT_INVALID"));
        assertThatThrownBy(() -> mapper.toWindowsScepPayload(
                command(), List.of("https://scep.example.test/mscep#private")))
                .isInstanceOfSatisfying(PermanentAgentException.class,
                        error -> assertThat(error.getErrorCode()).isEqualTo("SCEP_ENDPOINT_INVALID"));
    }

    @Test
    void rejectsMissingCertificateScopeInsteadOfDefaultingToUserStore() {
        CertificateProfileMessage command = command();
        command.getConfiguration().remove("certificateScope");

        assertThatThrownBy(() -> mapper.toWindowsScepPayload(
                command, List.of("https://scep.example.test/mscep")))
                .isInstanceOfSatisfying(PermanentAgentException.class,
                        error -> assertThat(error.getErrorCode())
                                .isEqualTo("PROFILE_CONFIGURATION_INVALID"));
    }

    @Test
    void acceptsIntegralJsonNumberForProviderInteger() {
        CertificateProfileMessage command = command();
        @SuppressWarnings("unchecked")
        Map<String, Object> provider = (Map<String, Object>) command.getConfiguration()
                .get("providerConfig");
        provider.put("renewalThresholdPercentage", 20.0d);

        Map<String, Object> payload = mapper.toWindowsScepPayload(
                command, List.of("https://scep.example.test/mscep"));

        assertThat(payload).containsEntry("renewalThresholdPercentage", 20);
    }

    @Test
    void mapsProviderNeutralSansToMicrosoftGraphEnumValues() {
        CertificateProfileMessage command = command();
        command.getConfiguration().put("subjectAltNameFormats", List.of(
                Map.of("type", "DNS", "format", "{{DeviceName}}.devices.example.com"),
                Map.of("type", "URI", "format", "urn:device:{{AAD_Device_ID}}")));

        Map<String, Object> payload = mapper.toWindowsScepPayload(
                command, List.of("https://scep.example.test/mscep"));

        assertThat(payload.get("customSubjectAlternativeNames")).isEqualTo(List.of(
                Map.of("sanType", "domainNameService",
                        "name", "{{DeviceName}}.devices.example.com"),
                Map.of("sanType", "universalResourceIdentifier",
                        "name", "urn:device:{{AAD_Device_ID}}")));
        assertThat(payload).containsEntry(
                "subjectAlternativeNameType",
                "domainNameService,universalResourceIdentifier");
    }

    @Test
    void normalizesMicrosoftGraphSansBackToProviderNeutralValues() {
        Map<String, Object> raw = graphProfile();
        raw.put("customSubjectAlternativeNames", List.of(
                Map.of("sanType", "domainNameService",
                        "name", "{{DeviceName}}.devices.example.com"),
                Map.of("sanType", "universalResourceIdentifier",
                        "name", "urn:device:{{AAD_Device_ID}}")));

        var observed = mapper.fromGraph(raw);

        assertThat(observed.getConfiguration().get("subjectAltNameFormats")).isEqualTo(List.of(
                Map.of("type", "DNS", "format", "{{DeviceName}}.devices.example.com"),
                Map.of("type", "URI", "format", "urn:device:{{AAD_Device_ID}}")));
    }

    @Test
    void rejectsMalformedDesiredSubjectAlternativeName() {
        CertificateProfileMessage command = command();
        command.getConfiguration().put("subjectAltNameFormats", List.of(Map.of("type", "DNS")));

        assertThatThrownBy(() -> mapper.toWindowsScepPayload(
                command, List.of("https://scep.example.test/mscep")))
                .isInstanceOfSatisfying(PermanentAgentException.class,
                        error -> assertThat(error.getErrorCode())
                                .isEqualTo("PROFILE_CONFIGURATION_INVALID"));
    }

    @Test
    void rejectsUnknownCertificateStoreFromGraph() {
        Map<String, Object> raw = graphProfile();
        raw.put("certificateStore", "unknownFutureValue");

        assertThatThrownBy(() -> mapper.fromGraph(raw))
                .isInstanceOfSatisfying(PermanentAgentException.class,
                        error -> assertThat(error.getErrorCode())
                                .isEqualTo("PROFILE_RESPONSE_INVALID"));
    }

    @Test
    void rejectsMarkerLookingTextInUserDescription() {
        CertificateProfileMessage command = command();
        command.setDescription("Please reuse [certping:another_profile]");

        assertThatThrownBy(() -> mapper.toWindowsScepPayload(
                command, List.of("https://scep.example.test/mscep")))
                .isInstanceOfSatisfying(PermanentAgentException.class, error -> {
                    assertThat(error.getErrorCode()).isEqualTo("PROFILE_CONFIGURATION_INVALID");
                    assertThat(error).hasMessageContaining("ownership marker");
                });
    }

    @Test
    void readsOwnershipOnlyFromTheCanonicalFinalManagedMarker() {
        Map<String, Object> raw = graphProfile();
        raw.put("description", """
                User text [certping:spoof]
                Managed by CertPing [certping:profile_1]""");

        var observed = mapper.fromGraph(raw);

        assertThat(observed.getProviderCorrelationMarker()).isEqualTo("certping:profile_1");
    }

    @Test
    void discoveryPreservesUnknownProviderEnumsWithoutFailingTheProfile() {
        Map<String, Object> raw = graphProfile();
        raw.put("@odata.type", "#microsoft.graph.futureCertificateProfile");
        raw.put("certificateStore", "futureStore");
        raw.put("customSubjectAlternativeNames", List.of(
                Map.of("sanType", "futureSanType", "name", "provider-expression")));

        var observed = mapper.fromGraphForDiscovery(raw);

        assertThat(observed.getTargetPlatform()).isEqualTo("UNKNOWN");
        assertThat(observed.getConfiguration()).doesNotContainKey("certificateScope");
        assertThat(observed.getConfiguration().get("subjectAltNameFormats")).isEqualTo(List.of(
                Map.of("type", "OTHER", "format", "provider-expression",
                        "providerType", "futureSanType")));
        assertThat(observed.getProviderResponse())
                .containsEntry("certificateStore", "futureStore");
    }

    @Test
    void managedOperationGetStillRejectsUnknownProviderSanEnum() {
        Map<String, Object> raw = graphProfile();
        raw.put("customSubjectAlternativeNames", List.of(
                Map.of("sanType", "futureSanType", "name", "provider-expression")));

        assertThatThrownBy(() -> mapper.fromGraph(raw))
                .isInstanceOfSatisfying(PermanentAgentException.class,
                        error -> assertThat(error.getErrorCode())
                                .isEqualTo("PROFILE_RESPONSE_INVALID"));
    }

    private static Map<String, Object> graphProfile() {
        return new java.util.HashMap<>(Map.ofEntries(
                Map.entry("@odata.type", "#microsoft.graph.windows81SCEPCertificateProfile"),
                Map.entry("id", "2daf8af2-8af2-2daf-f28a-af2df28aaf2d"),
                Map.entry("displayName", "Corporate Windows"),
                Map.entry("description", "Managed by CertPing [certping:profile_1]"),
                Map.entry("renewalThresholdPercentage", 20),
                Map.entry("keyStorageProvider", "useSoftwareKsp"),
                Map.entry("subjectNameFormatString", "CN={{AAD_Device_ID}}"),
                Map.entry("certificateValidityPeriodValue", 12),
                Map.entry("certificateValidityPeriodScale", "months"),
                Map.entry("scepServerUrls", List.of("https://scep.example.test/private/path")),
                Map.entry("keyUsage", "digitalSignature,keyEncipherment"),
                Map.entry("keySize", "size2048"),
                Map.entry("hashAlgorithm", "sha2"),
                Map.entry("certificateStore", "machine")));
    }

    @Test
    void trustedRootPayloadCarriesTheRootDerAndTheRootMarker() throws Exception {
        java.security.cert.X509Certificate root = org.mockito.Mockito.mock(
                java.security.cert.X509Certificate.class);
        org.mockito.Mockito.when(root.getEncoded()).thenReturn(new byte[] {1, 2, 3});

        Map<String, Object> payload = mapper.toWindowsTrustedRootPayload(
                command(), "certping:profile_1:root", root);

        assertThat(payload)
                .containsEntry("@odata.type", "#microsoft.graph.windows81TrustedRootCertificate")
                .containsEntry("trustedRootCertificate", "AQID")
                .containsEntry("destinationStore", "computerCertStoreRoot")
                .containsEntry("certFileName", "certping-scep-root.cer");
        assertThat(IntuneProfileMarker.extract(payload.get("description").toString()))
                .isEqualTo("certping:profile_1:root");
        assertThat(mapper.holdsTrustedRoot(Map.of("trustedRootCertificate", "AQID"), root)).isTrue();
        assertThat(mapper.holdsTrustedRoot(Map.of("trustedRootCertificate", "AQIE"), root)).isFalse();
        assertThat(mapper.holdsTrustedRoot(Map.of(), root)).isFalse();
    }

    @Test
    void assignmentGroupIdsAreOptionalAndMustBeGuids() {
        assertThat(mapper.assignmentGroupIds(command())).isNull();

        CertificateProfileMessage assigned = command();
        providerConfig(assigned).put("assignmentGroupIds", List.of(
                "8F6E0E4C-3C1A-4B8E-9D0F-2A1B3C4D5E6F", "8f6e0e4c-3c1a-4b8e-9d0f-2a1b3c4d5e6f"));
        assertThat(mapper.assignmentGroupIds(assigned))
                .containsExactly("8f6e0e4c-3c1a-4b8e-9d0f-2a1b3c4d5e6f");

        CertificateProfileMessage invalid = command();
        providerConfig(invalid).put("assignmentGroupIds", List.of("All devices"));
        assertThatThrownBy(() -> mapper.assignmentGroupIds(invalid))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("Entra group object IDs");
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> providerConfig(CertificateProfileMessage message) {
        return (Map<String, Object>) message.getConfiguration().get("providerConfig");
    }

    private static CertificateProfileMessage command() {
        return CertificateProfileMessage.builder()
                .name("Corporate Windows")
                .providerProfileType("#microsoft.graph.windows81SCEPCertificateProfile")
                .providerCorrelationMarker("certping:profile_1")
                .targetPlatform("WINDOWS")
                .enrollmentMethod("SCEP")
                .configuration(new java.util.HashMap<>(Map.ofEntries(
                        Map.entry("certificateScope", "DEVICE"),
                        Map.entry("keySize", 2048),
                        Map.entry("signatureHash", "SHA2"),
                        Map.entry("subjectNameFormat", "CN={{AAD_Device_ID}}"),
                        Map.entry("validityValue", 12),
                        Map.entry("validityUnit", "MONTHS"),
                        Map.entry("keyUsages", List.of("digitalSignature", "keyEncipherment")),
                        Map.entry("extendedKeyUsages", List.of(Map.of(
                                "name", "Client Authentication",
                                "objectIdentifier", "1.3.6.1.5.5.7.3.2"))),
                        Map.entry("providerConfig", new java.util.HashMap<>(Map.of(
                                "renewalThresholdPercentage", 20,
                                "keyStorageProvider", "useSoftwareKsp"))))))
                .build();
    }
}
