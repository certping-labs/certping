// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.MissingDnsCredentialConfigurationException;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Stream;

/**
 * Shared SAN-domain helpers for certificate issuance flows.
 *
 * <p><b>Key behaviours:</b>
 * <ul>
 *   <li>{@link #pruneWithinGroup} — removes patterns inside a single SAN entry that are already
 *       covered by a wildcard in the same list (one-label rule). Applied before sending to the
 *       agent in every flow (automated issuance, renewal, manual).</li>
 *   <li>{@link #buildCertSanDomains} — builds the canonical SAN list stored on
 *       {@code CertificateEntity}. Includes the primary domain, applies per-group pruning, then
 *       applies the same one-label global pruning the agent uses when constructing the ACME order.
 *       Used by both automated and manual issuance flows.</li>
 *   <li>{@link #groupNonPrimarySansByRoot} — groups stored {@code san_domains} by root domain,
 *       excluding the primary entry and its wildcard form. Used by renewal and manual-to-automated
 *       conversion to reconstruct agent command SAN entries from stored state.</li>
 *   <li>{@link #lookupRootCredXref} — looks up a DNS credential xref from {@code dns_config}
 *       using the root-domain key. Single authoritative lookup used across all flows.</li>
 *   <li>{@link #extractRootDomain} — extracts the eTLD+1-style root (last two labels) for use as
 *       the key in {@code dns_config}. All subdomains under the same root share one credential.</li>
 *   <li>{@link #requireOneRootPerEntry} — refuses a requested SAN entry whose names span two roots.</li>
 * </ul>
 */
public final class SanDomainHelper {

    static final String ONE_ROOT_PER_ENTRY = "Each additional domain group must use names under one domain.";

    private SanDomainHelper() {
    }

    // ------------------------------------------------------------------ //
    //  Public API
    // ------------------------------------------------------------------ //

    /**
     * Removes patterns from {@code patterns} that are covered by a wildcard in the same list
     * (one-label rule: {@code foo.example.com} is covered by {@code *.example.com}).
     *
     * <p>Wildcards are always kept. Non-wildcards are kept only if no wildcard in the same list
     * covers them. The base domain of a wildcard (e.g. {@code example.com} for
     * {@code *.example.com}) is NOT covered — the one-label rule requires one additional label.
     */
    public static List<String> pruneWithinGroup(List<String> patterns) {
        if (patterns == null || patterns.isEmpty()) {
            return List.of();
        }
        Set<String> wildcards = new LinkedHashSet<>();
        for (String p : patterns) {
            if (p != null && p.startsWith("*.")) {
                wildcards.add(p.trim().toLowerCase());
            }
        }
        List<String> result = new ArrayList<>();
        for (String p : patterns) {
            if (p == null || p.isBlank()) {
                continue;
            }
            String normalized = p.trim().toLowerCase();
            if (normalized.startsWith("*.")) {
                result.add(p); // wildcards always kept (preserve original casing)
            } else if (!isCoveredByAnyWildcard(normalized, wildcards)) {
                result.add(p);
            }
        }
        return result;
    }

    /**
     * Builds the canonical domain list stored on {@code CertificateEntity.sanDomains}.
     *
     * <p>Algorithm:
     * <ol>
     *   <li>Start with the primary domain (prefixed with {@code *.} when {@code wildcardPrimary}).</li>
     *   <li>For each SAN entry, prune patterns within the group, then add survivors.</li>
     *   <li>Apply global one-label wildcard coverage pruning across all collected patterns —
     *       same logic the agent's {@code DnsValidationDomainService} applies at order time.</li>
     *   <li>The primary domain entry is always retained regardless of SAN wildcards.</li>
     * </ol>
     */
    public static <T> String[] buildCertSanDomains(
            String primaryDomain,
            boolean wildcardPrimary,
            List<T> sanEntries,
            Function<T, List<String>> patternsExtractor) {

        String primary = normalize(primaryDomain);
        if (primary.isEmpty()) {
            return new String[0];
        }
        String primaryEntry = wildcardPrimary ? "*." + primary : primary;

        LinkedHashSet<String> collected = new LinkedHashSet<>();
        LinkedHashSet<String> allWildcards = new LinkedHashSet<>();

        collected.add(primaryEntry);
        if (primaryEntry.startsWith("*.")) {
            allWildcards.add(primaryEntry);
        }

        if (sanEntries != null) {
            for (T entry : sanEntries) {
                if (entry == null) {
                    continue;
                }
                List<String> patterns = patternsExtractor.apply(entry);
                for (String p : pruneWithinGroup(patterns)) {
                    String normalized = normalize(p);
                    if (normalized.isEmpty() || normalized.equals(primaryEntry)) {
                        continue;
                    }
                    if (normalized.startsWith("*.")) {
                        if (collected.add(normalized)) {
                            allWildcards.add(normalized);
                        }
                    } else {
                        collected.add(normalized);
                    }
                }
            }
        }

        // Global one-label pruning — same rule as DnsValidationDomainService.buildCertificateDomains.
        // Primary entry is always kept even if theoretically covered by a SAN wildcard.
        LinkedHashSet<String> result = new LinkedHashSet<>();
        for (String candidate : collected) {
            if (candidate.startsWith("*.")) {
                result.add(candidate);
            } else if (candidate.equals(primaryEntry) || !isCoveredByAnyWildcard(candidate, allWildcards)) {
                result.add(candidate);
            }
        }

        return result.toArray(String[]::new);
    }

    /**
     * Groups all non-primary SAN domain patterns by root domain.
     *
     * <p>The wildcard form of the primary domain ({@code *.primaryDomain}) is excluded — it is
     * handled as the CN at the top level of any command. The apex form ({@code primaryDomain}
     * itself) is intentionally <em>not</em> excluded: for wildcard certs the apex is a genuine SAN
     * (because {@code *.primaryDomain} does not cover {@code primaryDomain}), and for non-wildcard
     * certs the apex cannot appear in stored {@code san_domains} so the distinction is moot.
     *
     * <p>Used identically by renewal reconstruction and manual-to-automated conversion so that
     * both flows produce the same agent command inputs from the same stored {@code san_domains}.
     */
    public static Map<String, List<String>> groupNonPrimarySansByRoot(String primaryDomain, String[] sanDomains) {
        String primaryLower         = normalize(primaryDomain);
        String primaryWildcardLower = "*." + primaryLower;
        Map<String, List<String>> result = new LinkedHashMap<>();
        if (sanDomains != null) {
            for (String san : sanDomains) {
                if (san == null || san.isBlank()) {
                    continue;
                }
                String normalized = normalize(san);
                if (normalized.equals(primaryWildcardLower)) {
                    continue;
                }
                result.computeIfAbsent(extractRootDomain(normalized), k -> new ArrayList<>()).add(san);
            }
        }
        return result;
    }

    /**
     * The certificate's SAN names, other than its primary root's, grouped by the {@code dns_config} key whose
     * credential covers each ({@link #configKeyCovering}), in {@code dns_config} order; and the primary root's other
     * names, which use the primary credential. Keys that cover none of the names add nothing, so a certificate built
     * from this has exactly the names it had.
     *
     * @throws MissingDnsCredentialConfigurationException when a name has no credential, rather than dropping it
     */
    public static SanNamesByConfigKey sanNamesByConfigKey(String primaryDomain, String[] sanDomains,
                                                          Map<String, String> dnsConfig) {
        String primaryRoot = extractRootDomain(primaryDomain);
        Map<String, List<String>> patternsByRoot = groupNonPrimarySansByRoot(primaryDomain, sanDomains);
        Map<String, List<String>> byKey = new LinkedHashMap<>();
        dnsConfig.keySet().forEach(key -> byKey.put(key, new ArrayList<>()));
        patternsByRoot.forEach((root, patterns) -> {
            if (!root.equals(primaryRoot)) {
                patterns.forEach(pattern -> byKey.get(configKeyCovering(dnsConfig, pattern).orElseThrow(() ->
                        new MissingDnsCredentialConfigurationException(
                                "No DNS credential configured for certificate name '" + pattern + "'")))
                        .add(pattern));
            }
        });
        byKey.values().removeIf(List::isEmpty);
        return new SanNamesByConfigKey(byKey, patternsByRoot.getOrDefault(primaryRoot, List.of()));
    }

    /** {@link #sanNamesByConfigKey}'s answer. */
    public record SanNamesByConfigKey(Map<String, List<String>> byConfigKey, List<String> primaryRootNames) {
    }

    /** The most specific {@code dns_config} key covering {@code name}: the name, then without {@code *.}, then its root. */
    public static Optional<String> configKeyCovering(Map<String, String> dnsConfig, String name) {
        String normalized = name.trim().toLowerCase(Locale.ROOT);
        String bareName = normalized.startsWith("*.") ? normalized.substring(2) : normalized;
        return Stream.of(normalized, bareName, extractRootDomain(normalized))
                .filter(dnsConfig::containsKey)
                .findFirst();
    }

    /**
     * Looks up the DNS credential xref for {@code domain} in {@code dnsConfig} using the
     * root-domain key ({@link #extractRootDomain}).
     *
     * <p>Returns {@code null} when no entry is found — callers must decide whether to throw
     * or tolerate absence.
     */
    public static String lookupRootCredXref(Map<String, String> dnsConfig, String domain) {
        if (dnsConfig == null || domain == null) {
            return null;
        }
        return dnsConfig.get(extractRootDomain(domain));
    }

    /**
     * Extracts the root domain (last two labels) from a domain or wildcard pattern.
     * Used as the key in {@code dns_config} so that all subdomains of the same root
     * map to a single credential entry.
     *
     * <p><b>Limitation:</b> does not account for multi-part public suffixes (e.g. {@code .co.uk}).
     */
    public static String extractRootDomain(String domainOrPattern) {
        if (domainOrPattern == null) {
            return "";
        }
        String d = domainOrPattern.trim().toLowerCase();
        if (d.startsWith("*.")) {
            d = d.substring(2);
        }
        String[] labels = d.split("\\.");
        if (labels.length <= 2) {
            return d;
        }
        return labels[labels.length - 2] + "." + labels[labels.length - 1];
    }

    /**
     * Refuses SAN entries whose names are under more than one root domain ({@link #extractRootDomain}). An entry is
     * stored and renewed under one root's DNS credential, so the names under any other root would never renew.
     *
     * @throws BadRequestException for the first entry whose names span two roots
     */
    public static <T> void requireOneRootPerEntry(List<T> sanEntries, Function<T, List<String>> patternsExtractor) {
        if (sanEntries == null) {
            return;
        }
        for (T entry : sanEntries) {
            List<String> patterns = entry == null ? null : patternsExtractor.apply(entry);
            if (patterns == null) {
                continue;
            }
            long roots = patterns.stream()
                    .filter(pattern -> pattern != null && !pattern.isBlank())
                    .map(SanDomainHelper::extractRootDomain)
                    .distinct()
                    .count();
            if (roots > 1) {
                throw new BadRequestException(ONE_ROOT_PER_ENTRY);
            }
        }
    }

    /**
     * Legacy flat-extraction helper retained for tests and any callers that only need
     * the raw pattern strings without primary-domain or pruning logic.
     */
    public static <T> String[] extractSanDomains(List<T> sanEntries, Function<T, List<String>> patternsExtractor) {
        if (sanEntries == null || sanEntries.isEmpty()) {
            return new String[0];
        }
        return sanEntries.stream()
                .filter(Objects::nonNull)
                .flatMap(entry -> {
                    List<String> patterns = patternsExtractor.apply(entry);
                    return patterns != null ? patterns.stream() : Stream.empty();
                })
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(p -> !p.isBlank())
                .distinct()
                .toArray(String[]::new);
    }

    // ------------------------------------------------------------------ //
    //  Private helpers
    // ------------------------------------------------------------------ //

    private static boolean isCoveredByAnyWildcard(String domain, Set<String> wildcards) {
        for (String wildcard : wildcards) {
            if (coversOneLabel(domain, wildcard)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns true when {@code wildcard} covers {@code domain} under the one-label rule:
     * {@code wildcard} must be {@code *.BASE}, {@code domain} must end with {@code .BASE},
     * and {@code domain} must have exactly one more label than {@code BASE}.
     * The base domain itself (e.g. {@code example.com} for {@code *.example.com}) is NOT covered.
     */
    private static boolean coversOneLabel(String domain, String wildcard) {
        if (domain == null || wildcard == null || !wildcard.startsWith("*.")) {
            return false;
        }
        if (domain.startsWith("*.")) {
            return false; // wildcards don't cover other wildcards
        }
        String base = wildcard.substring(2);
        if (domain.equals(base)) {
            return false; // base domain itself is not covered
        }
        int domainDots = dotCount(domain);
        int baseDots   = dotCount(base);
        if (domainDots != baseDots + 1) {
            return false;
        }
        return domain.endsWith("." + base);
    }

    private static int dotCount(String value) {
        int count = 0;
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) == '.') {
                count++;
            }
        }
        return count;
    }

    private static String normalize(String value) {
        if (value == null) {
            return "";
        }
        String normalized = value.trim().toLowerCase();
        while (normalized.endsWith(".")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }
}
