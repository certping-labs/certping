// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.entity.RenewalScheduleEntity;
import com.certmanagement.enums.CaProvider;
import com.certmanagement.exception.MissingDnsCredentialConfigurationException;
import com.certmanagement.dto.cert.CertIssuanceRequest;
import com.certmanagement.messaging.model.CertRenewalCommand;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.time.OffsetDateTime;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RenewalDraftHelperTest {

    private static final String ORDER = "123456";

    private final RenewalDraftHelper helper = new RenewalDraftHelper();

    @Test
    void renewal_carriesTheScheduledOrderAndWindow() {
        CertRenewalCommand command = command(certificate(CaProvider.DIGICERT, "example.com", "www.example.com"),
                schedule(ORDER), List.of(sans("www.example.com", "example.com")));

        assertThat(command.getOrderId()).isEqualTo(ORDER);
        assertThat(command.getRenewalWindowDays()).isEqualTo(45);
    }

    @Test
    void renewal_sendsTheValidityItWasIssuedWith() {
        CertificateEntity certificate = certificate(CaProvider.DIGICERT, "example.com");
        certificate.setRequestedValidityDays(199);

        assertThat(command(certificate, schedule(ORDER), List.of()).getValidityDays()).isEqualTo(199);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("issuedCertificates")
    void aCertificateRenewedFromItsOwnConfig_keepsItsNames(String name, String domain, boolean wildcard,
                                                           List<List<String>> sanPatterns, Map<String, String> dnsConfig) {
        List<CertIssuanceRequest.SanDomainEntry> issued = sanPatterns.stream().map(patterns -> {
            CertIssuanceRequest.SanDomainEntry entry = new CertIssuanceRequest.SanDomainEntry();
            entry.setPatterns(patterns);
            return entry;
        }).toList();
        String[] certificateSans = SanDomainHelper.buildCertSanDomains(domain, wildcard, issued,
                CertIssuanceRequest.SanDomainEntry::getPatterns);
        CredentialReferenceEntity dns = CredentialReferenceEntity.builder()
                .provider("CLOUDFLARE").secretHandle("kv://dns").build();
        List<CertRenewalCommand.SanDomainEntry> renewal = helper.buildRenewalSanEntriesFromConfig(
                domain, certificateSans, dnsConfig, dns, xref -> dns);

        String primary = wildcard ? "*." + domain : domain;
        Set<String> renewing = new HashSet<>(Set.of(primary));
        renewal.forEach(entry -> renewing.addAll(entry.getPatterns()));
        Set<String> certificateNames = new HashSet<>(Set.of(primary));
        certificateNames.addAll(List.of(certificateSans));
        assertThat(renewing).isEqualTo(certificateNames);
    }

    @Test
    void aDnsCredentialForARootWithNoSan_addsNoNameToTheRenewal() {
        CredentialReferenceEntity dns = CredentialReferenceEntity.builder()
                .provider("CLOUDFLARE").secretHandle("kv://dns").build();

        List<CertRenewalCommand.SanDomainEntry> renewal = helper.buildRenewalSanEntriesFromConfig("example.com",
                new String[]{"example.com", "www.example.com"},
                Map.of("example.com", "cred-a", "example.net", "cred-c"), dns, xref -> dns);

        assertThat(renewal).flatExtracting(CertRenewalCommand.SanDomainEntry::getPatterns)
                .containsExactlyInAnyOrder("example.com", "www.example.com");
    }

    @Test
    void anIssuanceBuiltConfig_givesOneEntryPerConfiguredRootThenThePrimaryRootsOtherNames() {
        List<CertRenewalCommand.SanDomainEntry> renewal = helper.buildRenewalSanEntriesFromConfig("example.com",
                new String[]{"example.com", "www.example.com", "shop.example.org", "*.example.tech"},
                orderedConfig("example.com", "cred-a", "example.org", "cred-b", "example.tech", "cred-c"),
                credential("cred-a"), RenewalDraftHelperTest::credential);

        assertThat(renewal).extracting(CertRenewalCommand.SanDomainEntry::getDnsCredentialHandle)
                .containsExactly("cred-b", "cred-c", "cred-a");
        assertThat(renewal).extracting(CertRenewalCommand.SanDomainEntry::getPatterns).containsExactly(
                List.of("shop.example.org"), List.of("*.example.tech"), List.of("example.com", "www.example.com"));
    }

    @Test
    void aConversionKeyForASubdomain_keepsThatName() {
        List<CertRenewalCommand.SanDomainEntry> renewal = helper.buildRenewalSanEntriesFromConfig("foo.com",
                new String[]{"foo.com", "api.bar.com"}, orderedConfig("foo.com", "cred-a", "api.bar.com", "cred-b"),
                credential("cred-a"), RenewalDraftHelperTest::credential);

        assertThat(renewal).extracting(CertRenewalCommand.SanDomainEntry::getDnsCredentialHandle)
                .containsExactly("cred-b", "cred-a");
        assertThat(renewal).extracting(CertRenewalCommand.SanDomainEntry::getPatterns)
                .containsExactly(List.of("api.bar.com"), List.of("foo.com"));
    }

    @Test
    void aKeyForTheNameItself_winsOverItsRootsKey() {
        List<CertRenewalCommand.SanDomainEntry> renewal = helper.buildRenewalSanEntriesFromConfig("foo.com",
                new String[]{"foo.com", "api.bar.com", "www.bar.com", "*.app.bar.com"},
                orderedConfig("foo.com", "cred-a", "bar.com", "cred-b", "api.bar.com", "cred-c", "app.bar.com",
                        "cred-d"),
                credential("cred-a"), RenewalDraftHelperTest::credential);

        assertThat(renewal).extracting(CertRenewalCommand.SanDomainEntry::getDnsCredentialHandle)
                .containsExactly("cred-b", "cred-c", "cred-d", "cred-a");
        assertThat(renewal).extracting(CertRenewalCommand.SanDomainEntry::getPatterns).containsExactly(
                List.of("www.bar.com"), List.of("api.bar.com"), List.of("*.app.bar.com"), List.of("foo.com"));
    }

    @Test
    void aSanWithNoCredential_failsInsteadOfBeingDropped() {
        assertThatThrownBy(() -> helper.buildRenewalSanEntriesFromConfig("example.com",
                new String[]{"example.com", "api.other.org"}, orderedConfig("example.com", "cred-a"),
                credential("cred-a"), RenewalDraftHelperTest::credential))
                .isInstanceOf(MissingDnsCredentialConfigurationException.class)
                .hasMessageContaining("api.other.org");
    }

    @Test
    void theRenewalsDnsCredentials_areThePrimaryRootsAndEachNamesResolvedOneOnly() {
        Map<String, String> config = orderedConfig("foo.com", "cred-a", "bar.com", "cred-b", "api.bar.com", "cred-c",
                "app.bar.com", "cred-d", "unused.org", "cred-unused", "stale.bar.com", "cred-stale");

        assertThat(helper.renewalDnsCredentialXrefs("foo.com",
                new String[]{"foo.com", "www.foo.com", "api.bar.com", "*.app.bar.com"}, config))
                .containsExactlyInAnyOrder("cred-a", "cred-c", "cred-d");
    }

    @Test
    void aNameWithNoCredential_addsNothingToTheRenewalsDnsCredentials() {
        assertThat(helper.renewalDnsCredentialXrefs("example.com",
                new String[]{"example.com", "api.other.org"}, orderedConfig("example.com", "cred-a")))
                .containsExactly("cred-a");
    }

    private static Map<String, String> orderedConfig(String... keysAndXrefs) {
        Map<String, String> config = new LinkedHashMap<>();
        for (int i = 0; i < keysAndXrefs.length; i += 2) {
            config.put(keysAndXrefs[i], keysAndXrefs[i + 1]);
        }
        return config;
    }

    private static CredentialReferenceEntity credential(String xref) {
        return CredentialReferenceEntity.builder().provider("CLOUDFLARE").secretHandle(xref).build();
    }

    static Stream<Arguments> issuedCertificates() {
        return Stream.of(
                Arguments.of("single name", "example.com", false, List.of(), Map.of("example.com", "cred-a")),
                Arguments.of("wildcard with its apex", "example.com", true, List.of(List.of("example.com")),
                        Map.of("example.com", "cred-a")),
                Arguments.of("SANs under two roots", "example.com", false,
                        List.of(List.of("www.example.com", "api.example.com"), List.of("shop.example.org")),
                        Map.of("example.com", "cred-a", "example.org", "cred-b")),
                Arguments.of("a DNS credential for a root with no SAN", "example.com", false,
                        List.of(List.of("www.example.com")),
                        Map.of("example.com", "cred-a", "example.net", "cred-c")));
    }

    private CertRenewalCommand command(CertificateEntity certificate, RenewalScheduleEntity schedule,
                                       List<CertRenewalCommand.SanDomainEntry> sanEntries) {
        CertificateEntity draft = CertificateEntity.builder().certificateXref("cert-2").build();
        CredentialReferenceEntity dns = CredentialReferenceEntity.builder()
                .provider("CLOUDFLARE").secretHandle("kv://dns").build();
        return helper.buildRenewalCommand(certificate, draft, schedule, "example.com", 7L, "B2B", "req-1",
                "corr-1", dns, sanEntries);
    }

    private static CertificateEntity certificate(CaProvider ca, String... sans) {
        return CertificateEntity.builder()
                .certificateXref("cert-1")
                .caProvider(ca)
                .wildcard(false)
                .sanDomains(sans)
                .validTo(OffsetDateTime.now().plusDays(20))
                .build();
    }

    private static RenewalScheduleEntity schedule(String orderId) {
        return RenewalScheduleEntity.builder().orderId(orderId).renewalWindowDays(45).build();
    }

    private static CertRenewalCommand.SanDomainEntry sans(String... patterns) {
        return CertRenewalCommand.SanDomainEntry.builder().dnsProvider("CLOUDFLARE").patterns(List.of(patterns)).build();
    }
}
