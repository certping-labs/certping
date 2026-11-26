// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.util;

import lombok.extern.slf4j.Slf4j;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/**
 * Helpers for deriving deterministic certificate identity (domain) from PEM.
 *
 * We use this to create stable names/tags so CI/CD can reliably locate the "current" certificate.
 */
@Slf4j
public final class CertificateIdentityUtils {

    private CertificateIdentityUtils() {}

    /**
     * Extract a "primary domain" from the leaf certificate.
     *
     * Preference order:
     * - First DNS SAN
     * - Subject CN
     *
     * Returns empty if parsing fails.
     */
    public static Optional<String> extractPrimaryDomainFromPem(String leafPem) {
        try {
            X509Certificate cert = parseLeafCertificate(leafPem);
            Optional<String> san = firstDnsSan(cert);
            if (san.isPresent()) {
                return san.map(CertificateIdentityUtils::normaliseDomain);
            }
            Optional<String> cn = subjectCn(cert);
            return cn.map(CertificateIdentityUtils::normaliseDomain);
        } catch (Exception e) {
            log.warn("Failed to extract primary domain from PEM: {}", e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Normalizes a domain-like value for consistent tagging/lookup.
     * - lowercases
     * - trims
     * - strips any trailing dot
     */
    public static String normaliseDomain(String domain) {
        if (domain == null) return "";
        String d = domain.trim().toLowerCase(Locale.ROOT);
        while (d.endsWith(".")) d = d.substring(0, d.length() - 1);
        return d;
    }

    /**
     * Converts a domain (e.g. api.example.com or *.example.com) into a valid Azure Key Vault
     * certificate name (1-127 chars; alphanumeric + hyphen).
     */
    public static String toAzureKvCertificateName(String domainOrCn) {
        String d = normaliseDomain(domainOrCn);
        if (d.isBlank()) return "";

        // Common wildcard CNs: *.example.com -> wildcard-example-com
        if (d.startsWith("*.")) {
            d = "wildcard-" + d.substring(2);
        } else if (d.startsWith("*")) {
            d = "wildcard-" + d.substring(1);
        }

        // Replace dots/underscores/spaces with hyphen, then drop anything else.
        d = d.replace('.', '-').replace('_', '-').replace(' ', '-');
        d = d.replaceAll("[^a-z0-9-]", "-");
        d = d.replaceAll("-{2,}", "-");
        d = d.replaceAll("^-+", "").replaceAll("-+$", "");

        if (d.isBlank()) return "";
        if (d.length() > 127) d = d.substring(0, 127);
        return d;
    }

    /**
     * Wildcard-aware DNS hostname match. Returns true if {@code a} and {@code b} refer to
     * the same DNS identity, treating either side as a possibly-wildcard hostname. A wildcard
     * {@code *.foo.bar} covers exactly one extra DNS label (so {@code api.foo.bar} matches but
     * {@code shop.api.foo.bar} does not), per RFC 6125 §6.4.3 / browser conventions.
     *
     * <p>Examples:
     * <ul>
     *   <li>{@code hostnameMatches("api.example.com", "api.example.com")} → true (exact)</li>
     *   <li>{@code hostnameMatches("*.example.com", "api.example.com")} → true (new wildcard covers literal)</li>
     *   <li>{@code hostnameMatches("api.example.com", "*.example.com")} → true (existing wildcard covers literal)</li>
     *   <li>{@code hostnameMatches("*.example.com", "shop.api.example.com")} → false (two labels)</li>
     *   <li>{@code hostnameMatches("*.example.com", "example.com")} → false (no label)</li>
     * </ul>
     */
    public static boolean hostnameMatches(String a, String b) {
        String na = normaliseDomain(a);
        String nb = normaliseDomain(b);
        if (na.isBlank() || nb.isBlank()) return false;
        if (na.equals(nb)) return true;
        return wildcardCovers(na, nb) || wildcardCovers(nb, na);
    }

    private static boolean wildcardCovers(String wildcard, String literal) {
        if (!wildcard.startsWith("*.")) return false;
        String suffix = wildcard.substring(1); // ".example.com"
        if (!literal.endsWith(suffix)) return false;
        String prefix = literal.substring(0, literal.length() - suffix.length());
        if (prefix.isEmpty()) return false;       // literal == bare domain — no label substituted
        if (prefix.contains(".")) return false;   // multiple labels — wildcard covers one only
        if (prefix.equals("*")) return false;     // both wildcards but different — handled by exact equality already
        return true;
    }

    /**
     * Extract every DNS hostname the leaf cert covers — Subject CN (if present) plus all
     * dNSName SANs — normalized, deduped, in stable order. Hostnames retain their literal
     * form including wildcards (e.g. {@code *.example.com}).
     *
     * <p>Returns an empty list if parsing fails or the cert has no DNS identities.
     */
    public static List<String> extractAllHostnames(String leafPem) {
        try {
            X509Certificate cert = parseLeafCertificate(leafPem);
            Set<String> ordered = new LinkedHashSet<>();
            // Some CAs still emit CN-only certs; include CN first so it appears before SANs.
            subjectCn(cert).map(CertificateIdentityUtils::normaliseDomain)
                    .filter(s -> !s.isBlank())
                    .ifPresent(ordered::add);
            for (String san : allDnsSans(cert)) {
                String n = normaliseDomain(san);
                if (!n.isBlank()) ordered.add(n);
            }
            return new ArrayList<>(ordered);
        } catch (Exception e) {
            log.warn("Failed to extract hostnames from PEM: {}", e.getMessage());
            return List.of();
        }
    }

    private static X509Certificate parseLeafCertificate(String leafPem) throws CertificateException {
        byte[] der = pemToDer(leafPem);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
    }

    private static byte[] pemToDer(String pem) throws CertificateException {
        if (pem == null || pem.isBlank()) {
            throw new CertificateException("Empty PEM input");
        }
        String s = pem;
        s = s.replace("-----BEGIN CERTIFICATE-----", "");
        s = s.replace("-----END CERTIFICATE-----", "");
        s = s.replaceAll("\\s", "");
        try {
            return Base64.getDecoder().decode(s.getBytes(StandardCharsets.US_ASCII));
        } catch (IllegalArgumentException e) {
            throw new CertificateException("PEM base64 decode failed: " + e.getMessage(), e);
        }
    }

    private static List<String> allDnsSans(X509Certificate cert) {
        try {
            Collection<List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans == null) return List.of();
            List<String> out = new ArrayList<>();
            for (List<?> entry : sans) {
                if (entry == null || entry.size() < 2) continue;
                Object type = entry.get(0);
                Object value = entry.get(1);
                if (type instanceof Integer integer && integer == 2 && value instanceof String s && !s.isBlank()) {
                    out.add(s);
                }
            }
            return out;
        } catch (Exception e) {
            return List.of();
        }
    }

    private static Optional<String> firstDnsSan(X509Certificate cert) {
        try {
            Collection<List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans == null) return Optional.empty();
            for (List<?> entry : sans) {
                if (entry == null || entry.size() < 2) continue;
                Object type = entry.get(0);
                Object value = entry.get(1);
                // Per RFC 5280 / JCA: type 2 = dNSName
                if (type instanceof Integer integer && integer == 2 && value instanceof String s && !s.isBlank()) {
                    return Optional.of(s);
                }
            }
            return Optional.empty();
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    private static Optional<String> subjectCn(X509Certificate cert) {
        try {
            LdapName ldapName = new LdapName(cert.getSubjectX500Principal().getName());
            for (Rdn rdn : ldapName.getRdns()) {
                if ("CN".equalsIgnoreCase(rdn.getType())) {
                    Object v = rdn.getValue();
                    if (v != null) {
                        String s = v.toString();
                        if (!s.isBlank()) return Optional.of(s);
                    }
                }
            }
            return Optional.empty();
        } catch (InvalidNameException e) {
            return Optional.empty();
        }
    }
}
