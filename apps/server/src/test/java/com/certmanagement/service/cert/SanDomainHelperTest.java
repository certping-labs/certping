// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.MissingDnsCredentialConfigurationException;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link SanDomainHelper}.
 *
 * <p>The canonical scenario used across the consistency tests mirrors the real request:
 * <pre>
 *   domain      = "auto.example.pro",  wildcard = true
 *   sanEntry[0] = ["app.auto.example.pro", "*.auto.example.pro",
 *                  "app.example.pro", "example.pro", "*.example.pro"]
 *   sanEntry[1] = ["example.tech", "app.example.tech", "*.example.tech"]
 * </pre>
 * After all processing the five-domain set
 * {@code *.auto.example.pro, example.pro, *.example.pro, example.tech, *.example.tech}
 * must be identical regardless of which flow (automated, manual, renewal,
 * manual-to-automated) produced or reconstructed it.
 */
class SanDomainHelperTest {

    // ================================================================== //
    //  extractRootDomain
    // ================================================================== //

    @Test
    void extractRootDomain_subdomain_returnsLastTwoLabels() {
        assertThat(SanDomainHelper.extractRootDomain("app.auto.example.pro")).isEqualTo("example.pro");
        assertThat(SanDomainHelper.extractRootDomain("auto.example.pro")).isEqualTo("example.pro");
        assertThat(SanDomainHelper.extractRootDomain("example.tech")).isEqualTo("example.tech");
    }

    @Test
    void extractRootDomain_wildcardPattern_stripsStarDotBeforeExtract() {
        assertThat(SanDomainHelper.extractRootDomain("*.auto.example.pro")).isEqualTo("example.pro");
        assertThat(SanDomainHelper.extractRootDomain("*.example.pro")).isEqualTo("example.pro");
        assertThat(SanDomainHelper.extractRootDomain("*.example.tech")).isEqualTo("example.tech");
    }

    @Test
    void extractRootDomain_twoLabelDomain_returnedAsIs() {
        assertThat(SanDomainHelper.extractRootDomain("example.pro")).isEqualTo("example.pro");
        assertThat(SanDomainHelper.extractRootDomain("example.com")).isEqualTo("example.com");
    }

    @Test
    void extractRootDomain_nullOrBlank_returnsEmpty() {
        assertThat(SanDomainHelper.extractRootDomain(null)).isEmpty();
    }

    // ================================================================== //
    //  pruneWithinGroup
    // ================================================================== //

    @Test
    void pruneWithinGroup_wildcardCoveredEntry_removed() {
        List<String> result = SanDomainHelper.pruneWithinGroup(
                List.of("*.example.com", "api.example.com", "example.com"));

        // api.example.com is covered by *.example.com (one extra label); example.com is the base → kept
        assertThat(result).containsExactly("*.example.com", "example.com");
    }

    @Test
    void pruneWithinGroup_baseDomainOfWildcard_notCovered() {
        // example.com is NOT covered by *.example.com — wildcard requires exactly one more label
        List<String> result = SanDomainHelper.pruneWithinGroup(List.of("*.example.com", "example.com"));

        assertThat(result).containsExactly("*.example.com", "example.com");
    }

    @Test
    void pruneWithinGroup_deepSubdomain_notCoveredByOneLabelWildcard() {
        // deep.api.example.com has two labels above example.com — *.example.com does NOT cover it
        List<String> result = SanDomainHelper.pruneWithinGroup(
                List.of("*.example.com", "deep.api.example.com"));

        assertThat(result).containsExactly("*.example.com", "deep.api.example.com");
    }

    @Test
    void pruneWithinGroup_nullAndBlankInputs_skipped() {
        List<String> result = SanDomainHelper.pruneWithinGroup(List.of("*.example.com", "", "api.example.com"));

        assertThat(result).containsExactly("*.example.com");
    }

    @Test
    void pruneWithinGroup_canonicalEntry1_removesAppSubdomainsButKeepsWildcardsAndBase() {
        // The first SAN entry from the canonical request
        List<String> result = SanDomainHelper.pruneWithinGroup(List.of(
                "app.auto.example.pro",   // covered by *.auto.example.pro → removed
                "*.auto.example.pro",     // wildcard → kept
                "app.example.pro",        // covered by *.example.pro → removed
                "example.pro",            // base of *.example.pro → NOT covered → kept
                "*.example.pro"));        // wildcard → kept

        assertThat(result).containsExactly("*.auto.example.pro", "example.pro", "*.example.pro");
    }

    @Test
    void pruneWithinGroup_canonicalEntry2_removesAppSubdomainButKeepsBaseAndWildcard() {
        List<String> result = SanDomainHelper.pruneWithinGroup(List.of(
                "example.tech",           // base of *.example.tech → NOT covered → kept
                "app.example.tech",       // covered by *.example.tech → removed
                "*.example.tech"));       // wildcard → kept

        assertThat(result).containsExactly("example.tech", "*.example.tech");
    }

    // ================================================================== //
    //  buildCertSanDomains
    // ================================================================== //

    @Test
    void buildCertSanDomains_primaryAlwaysIncluded_noSanEntries() {
        String[] result = SanDomainHelper.buildCertSanDomains(
                "example.com", false, null, (TestEntry e) -> e.patterns());

        assertThat(result).containsExactly("example.com");
    }

    @Test
    void buildCertSanDomains_wildcardPrimary_prefixedWithStarDot() {
        String[] result = SanDomainHelper.buildCertSanDomains(
                "example.com", true, null, (TestEntry e) -> e.patterns());

        assertThat(result).containsExactly("*.example.com");
    }

    @Test
    void buildCertSanDomains_canonicalRequest_returnsExpectedFiveDomains() {
        // THE canonical scenario: issuance stores exactly this set
        List<TestEntry> entries = List.of(
                new TestEntry(List.of("app.auto.example.pro", "*.auto.example.pro",
                                      "app.example.pro", "example.pro", "*.example.pro")),
                new TestEntry(List.of("example.tech", "app.example.tech", "*.example.tech")));

        String[] result = SanDomainHelper.buildCertSanDomains(
                "auto.example.pro", true, entries, TestEntry::patterns);

        assertThat(result).containsExactly(
                "*.auto.example.pro",
                "example.pro",
                "*.example.pro",
                "example.tech",
                "*.example.tech");
    }

    @Test
    void buildCertSanDomains_globalPrune_removesPatternsCoveredByAnotherGroupsWildcard() {
        // If a later entry adds *.foo.com, an earlier entry's foo.bar.com-style entry would be covered.
        // Here: entry1 has *.api.example.com; entry2 has sub.api.example.com (globally covered)
        List<TestEntry> entries = List.of(
                new TestEntry(List.of("*.api.example.com")),
                new TestEntry(List.of("sub.api.example.com"))); // covered globally

        String[] result = SanDomainHelper.buildCertSanDomains(
                "example.com", false, entries, TestEntry::patterns);

        assertThat(result).containsExactly("example.com", "*.api.example.com");
        // sub.api.example.com removed by global one-label pruning
    }

    @Test
    void buildCertSanDomains_primaryAlwaysKeptEvenIfCoveredBySanWildcard() {
        // primary = example.com; SAN adds *.example.com — primary must still appear
        List<TestEntry> entries = List.of(new TestEntry(List.of("*.example.com")));

        String[] result = SanDomainHelper.buildCertSanDomains(
                "example.com", false, entries, TestEntry::patterns);

        assertThat(result).contains("example.com", "*.example.com");
    }

    // ================================================================== //
    //  groupNonPrimarySansByRoot
    // ================================================================== //

    @Test
    void groupNonPrimarySansByRoot_excludesOnlyPrimaryWildcard() {
        // Only *.auto.example.pro (the CN wildcard form) is excluded.
        // auto.example.pro (the apex) is retained — for wildcard certs it is a genuine SAN
        // because *.auto.example.pro does not cover the apex itself.
        String[] sanDomains = {"*.auto.example.pro", "auto.example.pro", "example.pro"};

        Map<String, List<String>> result =
                SanDomainHelper.groupNonPrimarySansByRoot("auto.example.pro", sanDomains);

        assertThat(result).containsOnlyKeys("example.pro");
        // apex "auto.example.pro" is grouped under its two-label root alongside "example.pro"
        assertThat(result.get("example.pro")).containsExactly("auto.example.pro", "example.pro");
        }

        @Test
        void groupNonPrimarySansByRoot_wildcardCert_apexDomainRetainedAsSan() {
        // Regression test for: wildcard cert (CN=*.six.example.tech) where the apex
        // six.example.tech appears in stored san_domains because it was explicitly requested
        // as a SAN pattern. Previously it was incorrectly excluded (treated as the "primary"),
        // causing it to be dropped from the automated-renewal CSR.
        String[] sanDomains = {
            "*.six.example.tech",      // primary wildcard — excluded
            "*.app.six.example.tech",  // sub-wildcard SAN
            "six.example.tech",        // apex SAN — must be retained
            "*.example.pro",
            "example.pro"
        };

        Map<String, List<String>> result =
            SanDomainHelper.groupNonPrimarySansByRoot("six.example.tech", sanDomains);

        // example.tech root: apex + sub-wildcard (not the primary wildcard)
        assertThat(result.get("example.tech"))
            .containsExactlyInAnyOrder("*.app.six.example.tech", "six.example.tech");
        // example.pro root unchanged
        assertThat(result.get("example.pro")).containsExactlyInAnyOrder("*.example.pro", "example.pro");
        assertThat(result).hasSize(2);
    }

    @Test
    void groupNonPrimarySansByRoot_groupsByRootDomain() {
        String[] sanDomains = {"api.example.com", "*.example.com", "foo.other.com", "*.other.com"};

        Map<String, List<String>> result =
                SanDomainHelper.groupNonPrimarySansByRoot("primary.com", sanDomains);

        assertThat(result.get("example.com")).containsExactly("api.example.com", "*.example.com");
        assertThat(result.get("other.com")).containsExactly("foo.other.com", "*.other.com");
    }

    @Test
    void groupNonPrimarySansByRoot_canonicalStoredSanDomains_groupsIntoTwoRoots() {
        // Input: the five san_domains stored after canonical issuance
        String[] sanDomains = {
                "*.auto.example.pro",  // ← primary wildcard, excluded
                "example.pro",
                "*.example.pro",
                "example.tech",
                "*.example.tech"
        };

        Map<String, List<String>> result =
                SanDomainHelper.groupNonPrimarySansByRoot("auto.example.pro", sanDomains);

        // "example.pro" root gets the two non-primary SANs from that zone
        assertThat(result.get("example.pro")).containsExactly("example.pro", "*.example.pro");
        // "example.tech" root gets its two patterns
        assertThat(result.get("example.tech")).containsExactly("example.tech", "*.example.tech");
        // Only two roots — primary wildcard excluded
        assertThat(result).hasSize(2);
    }

    // ================================================================== //
    //  lookupRootCredXref
    // ================================================================== //

    @Test
    void lookupRootCredXref_findsCredentialByRootDomain() {
        Map<String, String> dnsConfig = Map.of("example.pro", "cred-example");

        // Any subdomain of example.pro should resolve to cred-example via root-domain key
        assertThat(SanDomainHelper.lookupRootCredXref(dnsConfig, "auto.example.pro")).isEqualTo("cred-example");
        assertThat(SanDomainHelper.lookupRootCredXref(dnsConfig, "app.auto.example.pro")).isEqualTo("cred-example");
        assertThat(SanDomainHelper.lookupRootCredXref(dnsConfig, "example.pro")).isEqualTo("cred-example");
    }

    @Test
    void lookupRootCredXref_missingRoot_returnsNull() {
        Map<String, String> dnsConfig = Map.of("example.pro", "cred-example");

        assertThat(SanDomainHelper.lookupRootCredXref(dnsConfig, "example.tech")).isNull();
        assertThat(SanDomainHelper.lookupRootCredXref(null, "example.pro")).isNull();
        assertThat(SanDomainHelper.lookupRootCredXref(dnsConfig, null)).isNull();
    }

    // ================================================================== //
    //  Consistency proof: issuance → storage → renewal/conversion
    // ================================================================== //

    /**
     * Proves that the SAN patterns sent to the agent by renewal and manual-to-automated
     * conversion are derived from the same groups as the original issuance.
     *
     * <p>The chain:
     * <ol>
     *   <li>Issuance applies {@code pruneWithinGroup} per entry, which defines the groups
     *       sent to the agent.</li>
     *   <li>{@code buildCertSanDomains} stores the post-prune, globally-pruned domain set.</li>
     *   <li>Renewal/conversion calls {@code groupNonPrimarySansByRoot} on the stored domains.</li>
     *   <li>The resulting groups must match the original pruned groups (excluding the primary entry).</li>
     * </ol>
     */
    @Test
    void consistency_storedSanDomains_reconstructToSameGroupsAsOriginalIssuance() {
        String primaryDomain = "auto.example.pro";

        List<TestEntry> sanEntries = List.of(
                new TestEntry(List.of("app.auto.example.pro", "*.auto.example.pro",
                                      "app.example.pro", "example.pro", "*.example.pro")),
                new TestEntry(List.of("example.tech", "app.example.tech", "*.example.tech")));

        // Step 1 — what issuance stores in san_domains
        String[] storedSanDomains = SanDomainHelper.buildCertSanDomains(
                primaryDomain, true, sanEntries, TestEntry::patterns);

        assertThat(storedSanDomains).containsExactly(
                "*.auto.example.pro", "example.pro", "*.example.pro",
                "example.tech", "*.example.tech");

        // Step 2 — what renewal / manual-to-automated reconstructs from stored san_domains
        Map<String, List<String>> reconstructed =
                SanDomainHelper.groupNonPrimarySansByRoot(primaryDomain, storedSanDomains);

        // Step 3 — what issuance sent as SAN entries (after per-group pruning)
        List<String> issuancePrunedEntry1 = SanDomainHelper.pruneWithinGroup(sanEntries.get(0).patterns());
        List<String> issuancePrunedEntry2 = SanDomainHelper.pruneWithinGroup(sanEntries.get(1).patterns());

        // example.pro root: pruned entry1 minus the primary entry itself (*.auto.example.pro)
        // → the non-primary patterns from that zone
        assertThat(reconstructed.get("example.pro"))
                .containsExactlyInAnyOrderElementsOf(
                        issuancePrunedEntry1.stream()
                                .filter(p -> !p.equalsIgnoreCase("*.auto.example.pro"))
                                .toList());

        // example.tech root: exact match with pruned entry2
        assertThat(reconstructed.get("example.tech"))
                .containsExactlyInAnyOrderElementsOf(issuancePrunedEntry2);
    }

    @Test
    void consistency_manualAndAutomatedProduceSameSanDomains() {
        // Both flows call buildCertSanDomains — test it is deterministic with identical inputs
        String primary = "auto.example.pro";
        List<TestEntry> entries = List.of(
                new TestEntry(List.of("app.auto.example.pro", "*.auto.example.pro",
                                      "app.example.pro", "example.pro", "*.example.pro")),
                new TestEntry(List.of("example.tech", "app.example.tech", "*.example.tech")));

        String[] automated = SanDomainHelper.buildCertSanDomains(primary, true, entries, TestEntry::patterns);
        String[] manual    = SanDomainHelper.buildCertSanDomains(primary, true, entries, TestEntry::patterns);

        assertThat(automated).isEqualTo(manual);
    }

    // ================================================================== //
    //  Legacy extractSanDomains
    // ================================================================== //

    @Test
    void extractSanDomains_flattensAndDeduplicatesPatterns() {
        List<TestEntry> entries = List.of(
                new TestEntry(List.of("example.com", "*.example.com", "")),
                new TestEntry(List.of("*.example.com", "api.example.com"))
        );

        String[] result = SanDomainHelper.extractSanDomains(entries, TestEntry::patterns);

        assertThat(result).containsExactly("example.com", "*.example.com", "api.example.com");
    }

    @Test
    void extractSanDomains_nullOrEmptyReturnsEmptyArray() {
        assertThat(SanDomainHelper.extractSanDomains(null, TestEntry::patterns)).isEmpty();
        assertThat(SanDomainHelper.extractSanDomains(List.of(), TestEntry::patterns)).isEmpty();
    }

    private record TestEntry(List<String> patterns) {}

    @Test
    void anEntryWhoseNamesShareOneRootIsAccepted() {
        SanDomainHelper.requireOneRootPerEntry(
                List.of(List.of("*.api.example.com", "api.example.com", "Example.com", " "), List.of("shop.example.org")),
                patterns -> patterns);
        SanDomainHelper.requireOneRootPerEntry(null, (List<String> patterns) -> patterns);
    }

    @Test
    void anEntryWhoseNamesSpanTwoRootsIsRefused() {
        assertThatThrownBy(() -> SanDomainHelper.requireOneRootPerEntry(
                List.of(List.of("example.com"), List.of("www.bar.com", "api.baz.org")), patterns -> patterns))
                .isInstanceOf(BadRequestException.class)
                .hasMessage("Each additional domain group must use names under one domain.");
    }

    @Test
    void sanNamesGoUnderTheMostSpecificKeyCoveringThem_andKeysNoNameUsesAddNothing() {
        Map<String, String> config = new LinkedHashMap<>();
        config.put("foo.com", "cred-a");
        config.put("bar.com", "cred-b");
        config.put("api.bar.com", "cred-c");
        config.put("app.bar.com", "cred-d");
        config.put("unused.org", "cred-unused");

        SanDomainHelper.SanNamesByConfigKey names = SanDomainHelper.sanNamesByConfigKey("foo.com",
                new String[]{"foo.com", "www.foo.com", "api.bar.com", "www.bar.com", "*.app.bar.com"}, config);

        assertThat(names.byConfigKey()).containsExactly(
                Map.entry("bar.com", List.of("www.bar.com")),
                Map.entry("api.bar.com", List.of("api.bar.com")),
                Map.entry("app.bar.com", List.of("*.app.bar.com")));
        assertThat(names.primaryRootNames()).containsExactly("foo.com", "www.foo.com");
    }

    @Test
    void aSanNameNoKeyCovers_isRefusedRatherThanDropped() {
        assertThatThrownBy(() -> SanDomainHelper.sanNamesByConfigKey("example.com",
                new String[]{"example.com", "api.other.org"}, Map.of("example.com", "cred-a")))
                .isInstanceOf(MissingDnsCredentialConfigurationException.class)
                .hasMessageContaining("api.other.org");
    }

    @Test
    void theKeyCoveringANameIsTheNameThenItsBareNameThenItsRoot() {
        Map<String, String> config = Map.of("api.bar.com", "c1", "app.bar.com", "c2", "bar.com", "c3");

        assertThat(SanDomainHelper.configKeyCovering(config, "API.bar.com")).contains("api.bar.com");
        assertThat(SanDomainHelper.configKeyCovering(config, "*.app.bar.com")).contains("app.bar.com");
        assertThat(SanDomainHelper.configKeyCovering(config, "www.bar.com")).contains("bar.com");
        assertThat(SanDomainHelper.configKeyCovering(config, "www.baz.org")).isEmpty();
    }
}
