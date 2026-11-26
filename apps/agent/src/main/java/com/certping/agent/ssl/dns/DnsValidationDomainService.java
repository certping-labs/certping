// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.dns;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

@Component
public class DnsValidationDomainService {

    public List<String> buildValidationDomains(String primaryDomain, List<String> sanDomains) {
        return buildCertificateDomains(primaryDomain, false, sanDomains);
    }

    /**
     * Builds the canonical domain identifier list for CA order + CSR.
     *
     * <p>The returned list is normalized and de-duplicated, keeps wildcard identifiers,
     * and prunes one-label hosts covered by any wildcard SAN. A wildcard primary covers its
     * apex too: {@code *.primary} first (it stays the CN), then {@code primary}.
     */
    public List<String> buildCertificateDomains(String primaryDomain,
                                                boolean wildcardPrimary,
                                                List<String> sanDomains) {
        String primary = normalize(primaryDomain);
        if (primary.isEmpty()) {
            throw new IllegalArgumentException("Primary domain is empty");
        }

        String primaryEntry = wildcardPrimary ? "*." + primary : primary;

        LinkedHashSet<String> collected = new LinkedHashSet<>();
        LinkedHashSet<String> wildcards = new LinkedHashSet<>();
        collected.add(primaryEntry);
        if (primaryEntry.startsWith("*.")) {
            wildcards.add(primaryEntry);
        }
        if (wildcardPrimary) {
            collected.add(primary);
        }

        if (sanDomains != null) {
            for (String san : sanDomains) {
                String normalized = normalize(san);
                if (normalized.isEmpty() || normalized.equals(primaryEntry)) {
                    continue;
                }
                if (normalized.startsWith("*.")) {
                    if (collected.add(normalized)) {
                        wildcards.add(normalized);
                    }
                } else {
                    collected.add(normalized);
                }
            }
        }

        LinkedHashSet<String> result = new LinkedHashSet<>();
        for (String candidate : collected) {
            if (candidate.startsWith("*.")) {
                result.add(candidate);
                continue;
            }
            if (!isCoveredByAnyWildcardOneLabel(candidate, wildcards)) {
                result.add(candidate);
            }
        }
        return new ArrayList<>(result);
    }

    public String toRecordDomain(String domain) {
        if (domain == null) {
            return null;
        }
        return domain.startsWith("*.") ? domain.substring(2) : domain;
    }

    private boolean isCoveredByAnyWildcardOneLabel(String domain, Set<String> wildcards) {
        for (String wildcard : wildcards) {
            if (coversOneLabel(domain, wildcard)) {
                return true;
            }
        }
        return false;
    }

    private boolean coversOneLabel(String domain, String wildcard) {
        if (domain == null || wildcard == null || !wildcard.startsWith("*.")) {
            return false;
        }
        if (domain.startsWith("*.")) {
            return false;
        }
        String base = wildcard.substring(2);
        if (domain.equals(base)) {
            return false;
        }
        int domainDots = dotCount(domain);
        int baseDots = dotCount(base);
        if (domainDots != baseDots + 1) {
            return false;
        }
        return domain.endsWith("." + base);
    }

    private int dotCount(String value) {
        int count = 0;
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) == '.') {
                count++;
            }
        }
        return count;
    }

    private String normalize(String value) {
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