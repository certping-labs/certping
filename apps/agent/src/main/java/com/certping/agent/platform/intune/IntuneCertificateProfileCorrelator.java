// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.platform.intune;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.message.CertificateCorrelationCandidate;
import com.certping.agent.model.message.CertificateCorrelationResult;

import javax.security.auth.x500.X500Principal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Matches a bounded candidate set from the server without retaining Intune device report rows. */
final class IntuneCertificateProfileCorrelator {
    private static final int MAX_CANDIDATES = 50;

    private final List<Candidate> candidates;
    private final Map<String, Set<ProfileKey>> sha1Matches = new LinkedHashMap<>();
    private final Map<String, Set<ProfileKey>> issuerSerialMatches = new LinkedHashMap<>();

    IntuneCertificateProfileCorrelator(List<CertificateCorrelationCandidate> rawCandidates) {
        if (rawCandidates.size() > MAX_CANDIDATES) {
            throw new PermanentAgentException("PROFILE_CORRELATION_REQUEST_INVALID",
                    "At most 50 certificate correlation candidates are accepted");
        }
        Set<String> xrefs = new LinkedHashSet<>();
        List<Candidate> validated = new ArrayList<>(rawCandidates.size());
        for (CertificateCorrelationCandidate candidate : rawCandidates) {
            if (candidate == null || !validXref(candidate.certificateXref())
                    || !xrefs.add(candidate.certificateXref())) {
                throw new PermanentAgentException("PROFILE_CORRELATION_REQUEST_INVALID",
                        "Certificate correlation candidates require unique valid xrefs");
            }
            String sha1 = normalizeSha1(candidate.fingerprintSha1());
            String serial = normalizeSerial(candidate.serialNumber());
            String issuer = normalizeIssuer(candidate.issuerDn());
            if (sha1 == null && (serial == null || issuer == null)) {
                throw new PermanentAgentException("PROFILE_CORRELATION_REQUEST_INVALID",
                        "A candidate requires SHA-1 or an issuer and serial number");
            }
            validated.add(new Candidate(candidate.certificateXref(), sha1, issuer, serial));
            sha1Matches.put(candidate.certificateXref(), new LinkedHashSet<>());
            issuerSerialMatches.put(candidate.certificateXref(), new LinkedHashSet<>());
        }
        candidates = List.copyOf(validated);
    }

    void accept(String profileId, String profileType, Map<String, Object> state) {
        ProfileKey profile = ProfileKey.validated(profileId, profileType);
        String stateSha1 = normalizeSha1(string(state.get("certificateThumbprint")));
        String stateIssuer = normalizeIssuer(string(state.get("certificateIssuer")));
        String stateSerial = normalizeSerial(string(state.get("certificateSerialNumber")));
        for (Candidate candidate : candidates) {
            if (stateSha1 != null && stateSha1.equals(candidate.sha1())) {
                sha1Matches.get(candidate.xref()).add(profile);
            } else if ((stateSha1 == null || candidate.sha1() == null)
                    && stateIssuer != null && stateSerial != null
                    && stateIssuer.equals(candidate.issuer())
                    && stateSerial.equals(candidate.serial())) {
                issuerSerialMatches.get(candidate.xref()).add(profile);
            }
        }
    }

    List<CertificateCorrelationResult> results() {
        return candidates.stream().map(candidate -> {
            Set<ProfileKey> matches = sha1Matches.get(candidate.xref());
            String method = "SHA1";
            if (matches.isEmpty()) {
                matches = issuerSerialMatches.get(candidate.xref());
                method = matches.isEmpty() ? null : "ISSUER_SERIAL";
            }
            if (matches.size() == 1) {
                ProfileKey profile = matches.iterator().next();
                return new CertificateCorrelationResult(candidate.xref(), "MATCHED",
                        profile.id(), profile.type(), method);
            }
            return new CertificateCorrelationResult(candidate.xref(),
                    matches.isEmpty() ? "NOT_FOUND" : "AMBIGUOUS",
                    null, null, null);
        }).toList();
    }

    private static boolean validXref(String value) {
        return value != null && value.matches("[A-Za-z0-9_-]{1,100}");
    }

    private static String normalizeSha1(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String normalized = value.replace(":", "").replace(" ", "")
                .toLowerCase(Locale.ROOT);
        return normalized.matches("[0-9a-f]{40}") ? normalized : null;
    }

    private static String normalizeSerial(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String normalized = value.replace(":", "").replace(" ", "")
                .toLowerCase(Locale.ROOT).replaceFirst("^0+(?!$)", "");
        return normalized.matches("[0-9a-f]{1,160}") ? normalized : null;
    }

    private static String normalizeIssuer(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return new X500Principal(value).getName(X500Principal.CANONICAL);
        } catch (IllegalArgumentException exception) {
            return null;
        }
    }

    private static String string(Object value) {
        return value == null ? null : value.toString();
    }

    private record Candidate(String xref, String sha1, String issuer, String serial) {
    }

    private record ProfileKey(String id, String type) {
        private static ProfileKey validated(String id, String type) {
            if (id == null || !id.matches("[A-Za-z0-9-]{1,100}")
                    || type == null || type.length() > 150) {
                throw new PermanentAgentException("PLATFORM_RESPONSE_INVALID",
                        "Intune returned an invalid SCEP profile identity");
            }
            return new ProfileKey(id, type);
        }
    }
}
