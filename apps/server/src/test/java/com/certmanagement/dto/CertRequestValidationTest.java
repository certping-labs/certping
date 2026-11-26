// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto;

import com.certmanagement.dto.cert.CertIssuanceRequest;
import com.certmanagement.dto.cert.ConvertToAutomatedRequest;
import com.certmanagement.dto.cert.IssueManualRequest;
import com.certmanagement.enums.CaProvider;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Bean Validation tests for the three request DTOs that carry user-supplied domain
 * and SAN pattern data:
 *
 * <ul>
 *   <li>{@link CertIssuanceRequest}  — automated issuance</li>
 *   <li>{@link IssueManualRequest}   — manual issuance</li>
 *   <li>{@link ConvertToAutomatedRequest} — manual-to-automated conversion</li>
 * </ul>
 *
 * <p>User-triggered renewal ({@code CertRenewalRequest}) and scheduler renewal take
 * no domain/pattern fields from the caller — they read from the stored certificate —
 * so there is nothing to validate at the DTO layer for those flows.
 */
class CertRequestValidationTest {

    private static Validator validator;

    @BeforeAll
    static void setUpValidator() {
        validator = Validation.buildDefaultValidatorFactory().getValidator();
    }

    // ====================================================================== //
    //  CertIssuanceRequest — automated issuance
    // ====================================================================== //

    @Test
    void certIssuanceRequest_valid_noViolations() {
        assertThat(violations(validIssuanceRequest())).isEmpty();
    }

    @Test
    void certIssuanceRequest_missingDomain_violation() {
        CertIssuanceRequest req = validIssuanceRequest();
        req.setDomain(null);
        assertThat(violationPaths(req)).contains("domain");
    }

    @Test
    void certIssuanceRequest_blankDomain_violation() {
        CertIssuanceRequest req = validIssuanceRequest();
        req.setDomain("  ");
        assertThat(violationPaths(req)).contains("domain");
    }

    @ParameterizedTest
    @ValueSource(strings = {"localhost", "*.example.com", "example", "-bad.com", "bad-.com", "exam ple.com"})
    void certIssuanceRequest_invalidDomainFormat_violation(String domain) {
        CertIssuanceRequest req = validIssuanceRequest();
        req.setDomain(domain);
        assertThat(violationPaths(req)).contains("domain");
    }

    @Test
    void certIssuanceRequest_missingWildcard_violation() {
        CertIssuanceRequest req = validIssuanceRequest();
        req.setWildcard(null);
        assertThat(violationPaths(req)).contains("wildcard");
    }

    @Test
    void certIssuanceRequest_missingCaProvider_violation() {
        CertIssuanceRequest req = validIssuanceRequest();
        req.setCaProvider(null);
        assertThat(violationPaths(req)).contains("caProvider");
    }

    @Test
    void certIssuanceRequest_missingDnsCredentialXref_violation() {
        CertIssuanceRequest req = validIssuanceRequest();
        req.setDnsCredentialXref(null);
        assertThat(violationPaths(req)).contains("dnsCredentialXref");
    }

    @Test
    void certIssuanceRequest_sanEntry_emptyPatterns_violation() {
        CertIssuanceRequest req = validIssuanceRequest();
        CertIssuanceRequest.SanDomainEntry entry = new CertIssuanceRequest.SanDomainEntry();
        entry.setPatterns(List.of());
        entry.setDnsCredentialXref("cred-xref");
        req.setSanDomainEntries(List.of(entry));
        assertThat(violationPaths(req)).anyMatch(p -> p.contains("patterns"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"localhost", "*.*.example.com", "*example.com", "-bad.com", "exam ple.com"})
    void certIssuanceRequest_sanEntry_invalidPattern_violation(String pattern) {
        CertIssuanceRequest req = validIssuanceRequest();
        CertIssuanceRequest.SanDomainEntry entry = new CertIssuanceRequest.SanDomainEntry();
        entry.setPatterns(List.of(pattern));
        entry.setDnsCredentialXref("cred-xref");
        req.setSanDomainEntries(List.of(entry));
        assertThat(violationPaths(req)).anyMatch(p -> p.contains("patterns"));
    }

    @Test
    void certIssuanceRequest_sanEntry_missingCredentialXref_violation() {
        CertIssuanceRequest req = validIssuanceRequest();
        CertIssuanceRequest.SanDomainEntry entry = new CertIssuanceRequest.SanDomainEntry();
        entry.setPatterns(List.of("*.example.com", "example.com"));
        entry.setDnsCredentialXref(null);
        req.setSanDomainEntries(List.of(entry));
        assertThat(violationPaths(req)).anyMatch(p -> p.contains("dnsCredentialXref"));
    }

    @Test
    void certIssuanceRequest_canonicalSanRequest_noViolations() {
        CertIssuanceRequest req = validIssuanceRequest();
        req.setDomain("auto.example.pro");
        req.setWildcard(true);
        req.setSan(true);

        CertIssuanceRequest.SanDomainEntry entry1 = new CertIssuanceRequest.SanDomainEntry();
        entry1.setPatterns(List.of("app.auto.example.pro", "*.auto.example.pro",
                                   "app.example.pro", "example.pro", "*.example.pro"));
        entry1.setDnsCredentialXref("cred-example");

        CertIssuanceRequest.SanDomainEntry entry2 = new CertIssuanceRequest.SanDomainEntry();
        entry2.setPatterns(List.of("example.tech", "app.example.tech", "*.example.tech"));
        entry2.setDnsCredentialXref("cred-example");

        req.setSanDomainEntries(List.of(entry1, entry2));

        assertThat(violations(req)).isEmpty();
    }

    // ====================================================================== //
    //  IssueManualRequest — manual issuance
    // ====================================================================== //

    @Test
    void issueManualRequest_valid_noViolations() {
        assertThat(violations(validManualRequest())).isEmpty();
    }

    @Test
    void issueManualRequest_missingDomain_violation() {
        IssueManualRequest req = validManualRequest();
        req.setDomain(null);
        assertThat(violationPaths(req)).contains("domain");
    }

    @ParameterizedTest
    @ValueSource(strings = {"localhost", "*.example.com", "example", ".bad.com"})
    void issueManualRequest_invalidDomainFormat_violation(String domain) {
        IssueManualRequest req = validManualRequest();
        req.setDomain(domain);
        assertThat(violationPaths(req)).contains("domain");
    }

    @Test
    void issueManualRequest_sanEntry_emptyPatterns_violation() {
        IssueManualRequest req = validManualRequest();
        IssueManualRequest.SanDomainEntry entry = new IssueManualRequest.SanDomainEntry();
        entry.setPatterns(List.of());
        req.setSanDomainEntries(List.of(entry));
        assertThat(violationPaths(req)).anyMatch(p -> p.contains("patterns"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"localhost", "*.*.example.com", "*example.com"})
    void issueManualRequest_sanEntry_invalidPattern_violation(String pattern) {
        IssueManualRequest req = validManualRequest();
        IssueManualRequest.SanDomainEntry entry = new IssueManualRequest.SanDomainEntry();
        entry.setPatterns(List.of(pattern));
        req.setSanDomainEntries(List.of(entry));
        assertThat(violationPaths(req)).anyMatch(p -> p.contains("patterns"));
    }

    @Test
    void issueManualRequest_canonicalSanRequest_noViolations() {
        IssueManualRequest req = validManualRequest();
        req.setDomain("auto.example.pro");
        req.setWildcard(true);
        req.setSan(true);

        IssueManualRequest.SanDomainEntry entry1 = new IssueManualRequest.SanDomainEntry();
        entry1.setPatterns(List.of("app.auto.example.pro", "*.auto.example.pro",
                                   "app.example.pro", "example.pro", "*.example.pro"));

        IssueManualRequest.SanDomainEntry entry2 = new IssueManualRequest.SanDomainEntry();
        entry2.setPatterns(List.of("example.tech", "app.example.tech", "*.example.tech"));

        req.setSanDomainEntries(List.of(entry1, entry2));

        assertThat(violations(req)).isEmpty();
    }

    // ====================================================================== //
    //  ConvertToAutomatedRequest — manual-to-automated conversion
    // ====================================================================== //

    @Test
    void convertToAutomatedRequest_valid_noViolations() {
        assertThat(violations(validConversionRequest())).isEmpty();
    }

    @Test
    void convertToAutomatedRequest_emptyDnsMappings_violation() {
        ConvertToAutomatedRequest req = validConversionRequest();
        req.setDnsMappings(List.of());
        assertThat(violationPaths(req)).contains("dnsMappings");
    }

    @Test
    void convertToAutomatedRequest_nullDnsMappings_violation() {
        ConvertToAutomatedRequest req = validConversionRequest();
        req.setDnsMappings(null);
        assertThat(violationPaths(req)).contains("dnsMappings");
    }

    @ParameterizedTest
    @ValueSource(strings = {"localhost", "*.example.com", "-bad.com", "bad-.com", "exam ple.com"})
    void convertToAutomatedRequest_mapping_invalidDomain_violation(String domain) {
        ConvertToAutomatedRequest req = validConversionRequest();
        ConvertToAutomatedRequest.DnsCredentialMapping mapping = new ConvertToAutomatedRequest.DnsCredentialMapping();
        mapping.setDomain(domain);
        mapping.setCredentialXref("cred-xref");
        req.setDnsMappings(List.of(mapping));
        assertThat(violationPaths(req)).anyMatch(p -> p.contains("domain"));
    }

    @Test
    void convertToAutomatedRequest_mapping_missingCredentialXref_violation() {
        ConvertToAutomatedRequest req = validConversionRequest();
        ConvertToAutomatedRequest.DnsCredentialMapping mapping = new ConvertToAutomatedRequest.DnsCredentialMapping();
        mapping.setDomain("example.pro");
        mapping.setCredentialXref(null);
        req.setDnsMappings(List.of(mapping));
        assertThat(violationPaths(req)).anyMatch(p -> p.contains("credentialXref"));
    }

    @Test
    void convertToAutomatedRequest_canonicalRequest_noViolations() {
        ConvertToAutomatedRequest req = new ConvertToAutomatedRequest();

        ConvertToAutomatedRequest.DnsCredentialMapping m1 = new ConvertToAutomatedRequest.DnsCredentialMapping();
        m1.setDomain("example.pro");
        m1.setCredentialXref("cred-example");

        ConvertToAutomatedRequest.DnsCredentialMapping m2 = new ConvertToAutomatedRequest.DnsCredentialMapping();
        m2.setDomain("example.tech");
        m2.setCredentialXref("cred-example");

        req.setDnsMappings(List.of(m1, m2));
        req.setInFlightPolicy(ConvertToAutomatedRequest.InFlightPolicy.CANCEL_AND_REISSUE);

        assertThat(violations(req)).isEmpty();
    }

    // ====================================================================== //
    //  Helpers
    // ====================================================================== //

    private <T> Set<ConstraintViolation<T>> violations(T obj) {
        return validator.validate(obj);
    }

    private <T> List<String> violationPaths(T obj) {
        return validator.validate(obj).stream()
                .map(v -> v.getPropertyPath().toString())
                .toList();
    }

    private CertIssuanceRequest validIssuanceRequest() {
        CertIssuanceRequest req = new CertIssuanceRequest();
        req.setDomain("example.com");
        req.setWildcard(false);
        req.setSan(false);
        req.setCaProvider(CaProvider.LETS_ENCRYPT);
        req.setDnsCredentialXref("cred-dns");
        return req;
    }

    private IssueManualRequest validManualRequest() {
        IssueManualRequest req = new IssueManualRequest();
        req.setDomain("example.com");
        req.setWildcard(false);
        req.setSan(false);
        return req;
    }

    private ConvertToAutomatedRequest validConversionRequest() {
        ConvertToAutomatedRequest req = new ConvertToAutomatedRequest();
        ConvertToAutomatedRequest.DnsCredentialMapping mapping = new ConvertToAutomatedRequest.DnsCredentialMapping();
        mapping.setDomain("example.com");
        mapping.setCredentialXref("cred-dns");
        req.setDnsMappings(List.of(mapping));
        return req;
    }
}
