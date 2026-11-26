// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.globalsign;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.CheckpointRecorder;
import com.certping.agent.exception.IssuanceCheckpoint;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.model.enums.CertType;
import com.certping.agent.ssl.CertificateMetadata;
import com.certping.agent.ssl.CertificateMetadataExtractor;
import com.certping.agent.ssl.CsrKeyPairService;
import com.certping.agent.ssl.IssuanceResult;
import com.certping.agent.ssl.KeyCustody;
import com.certping.agent.ssl.KeyStagingHelper;
import com.certping.agent.ssl.dns.DnsProvider;
import com.certping.agent.ssl.dns.DnsTxtCleanupService;
import com.certping.agent.ssl.dns.DnsTxtWorkflowService;
import com.certping.agent.ssl.dns.DnsValidationDomainService;
import com.certping.agent.secrets.SecretStore;
import tools.jackson.databind.JsonNode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class GlobalSignIssuanceService {

    private final CsrKeyPairService csrKeyPairService;
    private final SecretStore secretStore;
    private final AgentProperties properties;
    private final GlobalSignAtlasClient atlasClient;
    private final DnsTxtCleanupService dnsTxtCleanupService;
    private final DnsValidationDomainService dnsValidationDomainService;
    private final DnsTxtWorkflowService dnsTxtWorkflowService;
    private final KeyStagingHelper keyStagingHelper;

    /**
     * Issue certificate via GlobalSign Atlas API.
     * GlobalSign Atlas is NOT ACME: domains must be claimed and verified (DV) before POST /certificates will succeed.
     */
    public IssuanceResult issue(String certificateXref,
                                String domain,
                                boolean wildcardPrimary,
                                List<String> sanDomains,
                                DnsProvider rootDnsProvider,
                                Map<String, DnsProvider> sanDnsProviders,
                                Integer validityDays) {
        return issue(certificateXref, domain, wildcardPrimary, sanDomains,
                rootDnsProvider, sanDnsProviders, validityDays, null, false, CheckpointRecorder.NONE);
    }

    /** Overload that accepts a resume checkpoint from a prior failed attempt. */
    public IssuanceResult issue(String certificateXref,
                                String domain,
                                boolean wildcardPrimary,
                                List<String> sanDomains,
                                DnsProvider rootDnsProvider,
                                Map<String, DnsProvider> sanDnsProviders,
                                Integer validityDays,
                                IssuanceCheckpoint resumeCheckpoint,
                                boolean finalPropagationWait,
                                CheckpointRecorder recorder) {
        log.info("GlobalSign issuance started: domain={}, xref={}, validityDays={}, resumeStep={}",
                domain, certificateXref, validityDays,
                resumeCheckpoint == null ? "none" : resumeCheckpoint.step());

        List<String> certificateDomains = dnsValidationDomainService
            .buildCertificateDomains(domain, wildcardPrimary, sanDomains);

        List<DnsTxtCleanupService.DnsTxtCleanupEntry> cleanupEntries = new ArrayList<>();
        try {
            ensureDomainsVerified(certificateDomains, domain, rootDnsProvider, sanDnsProviders, cleanupEntries,
                    finalPropagationWait);
        } catch (RuntimeException e) {
            dnsTxtCleanupService.cleanup(cleanupEntries);
            throw e;
        }

        JsonNode validationPolicy = null;
        try {
            validationPolicy = atlasClient.getValidationPolicy();
        } catch (Exception e) {
            log.warn("GlobalSign validationpolicy fetch failed before CSR generation, using defaults: {}", e.getMessage());
        }

        CsrPolicy csrPolicy = resolveCsrPolicy(validationPolicy);
        CsrKeyPairService.CsrKeyPairResult csrResult;
        String privateKeyKvPath;
        if (resumeCheckpoint == null || resumeCheckpoint.privateKeyKvPath() == null) {
            csrResult = csrKeyPairService.generateCsrAndKeyPair(
                certificateDomains.get(0),
                certificateDomains.size() > 1 ? certificateDomains.subList(1, certificateDomains.size()) : List.of(),
                csrPolicy.keyType(),
                csrPolicy.keySize());
            privateKeyKvPath = keyStagingHelper.stage(certificateXref,
                    csrResult.privateKeyPem(), csrResult.csrPem());
        } else {
            KeyStagingHelper.Staged staged = keyStagingHelper.read(resumeCheckpoint.privateKeyKvPath());
            csrResult = new CsrKeyPairService.CsrKeyPairResult(
                    null, staged.csrPem(), staged.privateKeyPem());
            privateKeyKvPath = resumeCheckpoint.privateKeyKvPath();
            log.info("GlobalSign resume: read staged key from {}", privateKeyKvPath);
        }

        return issueCore(certificateXref, domain, certificateDomains, cleanupEntries,
                csrResult.csrPem(), csrResult.privateKeyPem(), validationPolicy,
                validityDays, resumeCheckpoint, privateKeyKvPath, recorder);
    }

    /** Issues using a CSR supplied externally (e.g. Akamai CPS). Private key stays with the caller; only the chain is stored in KV. */
    public IssuanceResult issueWithExternalCsr(String certificateXref,
                                               String domain,
                                               boolean wildcardPrimary,
                                               List<String> sanDomains,
                                               DnsProvider rootDnsProvider,
                                               Map<String, DnsProvider> sanDnsProviders,
                                               String externalCsrPem,
                                               Integer validityDays,
                                               boolean finalPropagationWait) {
        return issueWithExternalCsr(certificateXref, domain, wildcardPrimary, sanDomains, rootDnsProvider,
                sanDnsProviders, externalCsrPem, validityDays, finalPropagationWait, null, CheckpointRecorder.NONE);
    }

    /** Issues from a CSR whose key the customer holds; with a recorder a retry resumes from the recorded order. */
    public IssuanceResult issueWithExternalCsr(String certificateXref,
                                               String domain,
                                               boolean wildcardPrimary,
                                               List<String> sanDomains,
                                               DnsProvider rootDnsProvider,
                                               Map<String, DnsProvider> sanDnsProviders,
                                               String externalCsrPem,
                                               Integer validityDays,
                                               boolean finalPropagationWait,
                                               IssuanceCheckpoint resumeCheckpoint,
                                               CheckpointRecorder recorder) {
        log.info("GlobalSign external-CSR issuance started: domain={}, xref={}, resumeStep={}", domain, certificateXref,
                resumeCheckpoint == null ? "none" : resumeCheckpoint.step());

        List<String> certificateDomains = dnsValidationDomainService
            .buildCertificateDomains(domain, wildcardPrimary, sanDomains);

        List<DnsTxtCleanupService.DnsTxtCleanupEntry> cleanupEntries = new ArrayList<>();
        try {
            ensureDomainsVerified(certificateDomains, domain, rootDnsProvider, sanDnsProviders, cleanupEntries,
                    finalPropagationWait);
        } catch (RuntimeException e) {
            dnsTxtCleanupService.cleanup(cleanupEntries);
            throw e;
        }

        JsonNode validationPolicy = null;
        try {
            validationPolicy = atlasClient.getValidationPolicy();
        } catch (Exception e) {
            log.warn("GlobalSign validationpolicy fetch failed, using defaults: {}", e.getMessage());
        }

        return issueCore(certificateXref, domain, certificateDomains, cleanupEntries,
                externalCsrPem, null, validationPolicy, validityDays, resumeCheckpoint, null, recorder);
    }

    /**
     * Core GlobalSign issuance: submit CSR, poll, store bundle, return IssuanceResult.
     *
     * @param privateKeyPem null when the private key is held externally; chain is stored without it.
     * @param validityDays  user-requested validity; null = Atlas account-policy default.
     */
    private IssuanceResult issueCore(String certificateXref,
                                     String domain,
                                     List<String> certificateDomains,
                                     List<DnsTxtCleanupService.DnsTxtCleanupEntry> cleanupEntries,
                                     String csrPem,
                                     String privateKeyPem,
                                     JsonNode validationPolicy,
                                     Integer validityDays,
                                     IssuanceCheckpoint resumeCheckpoint,
                                     String privateKeyKvPath,
                                     CheckpointRecorder recorder) {
        // Mutable local state — every Retryable thrown past ORDER_CREATED carries this
        // back so the next attempt skips the POST /certificates (the billable boundary).
        // Null on the external-CSR (Akamai) path.
        IssuanceCheckpoint state = privateKeyKvPath == null && recorder == CheckpointRecorder.NONE && resumeCheckpoint == null
                ? null
                : (resumeCheckpoint != null
                    ? resumeCheckpoint
                    : new IssuanceCheckpoint(
                            "GLOBALSIGN",
                            IssuanceCheckpoint.Step.CSR_GENERATED,
                            null, null, privateKeyKvPath));

        try {
            String issuanceSerial;

            if (resumeCheckpoint != null
                    && resumeCheckpoint.reached(IssuanceCheckpoint.Step.ORDER_CREATED)
                    && resumeCheckpoint.orderRef() != null) {
                // RESUME: skip POST /certificates (the billable boundary). Atlas pinned
                // our CSR's public key at order time; the staged key + existing serial
                // are sufficient to drive the free poll-loop to completion.
                issuanceSerial = resumeCheckpoint.orderRef();
                log.info("GlobalSign resume: reusing serial={} (skipping POST /certificates)", issuanceSerial);
            } else {
                GlobalSignAtlasClient.IssueResult issueResult =
                    atlasClient.issueCertificate(
                        certificateDomains.get(0),
                        certificateDomains.size() > 1 ? certificateDomains.subList(1, certificateDomains.size()) : List.of(),
                        csrPem,
                        validationPolicy,
                        validityDays);
                issuanceSerial = issueResult.serial();
                log.info("GlobalSign issuance request submitted: serial={}, xref={}, validityDays={}",
                        issuanceSerial, certificateXref, validityDays);
                if (state != null) {
                    state = state.withOrderRef(issuanceSerial, null);
                    recorder.recordAnswered(state);
                }
            }

            JsonNode cert = pollUntilIssued(issuanceSerial, domain);
            if (state != null) {
                state = state.withStep(IssuanceCheckpoint.Step.ORDER_FINALIZED);
            }
            String leafPem = extractLeafPem(cert);
            String chainPem = atlasClient.getTrustChainPem();

            String bundle = privateKeyPem != null
                    ? leafPem + "\n" + chainPem + "\n" + privateKeyPem
                    : leafPem + "\n" + chainPem;
            String certSecretHandle = secretStore.create(certificateXref, bundle);
            String certSecretHandleWithVersion = privateKeyPem == null ? certSecretHandle : null;

            dnsTxtCleanupService.cleanup(cleanupEntries);

            if (privateKeyKvPath != null) {
                keyStagingHelper.purge(privateKeyKvPath);
            }

            X509Certificate leaf = parseFirstCert(leafPem);
            String serial = leaf.getSerialNumber().toString(16).toUpperCase();
            String fingerprint = sha256Fingerprint(leaf);
            OffsetDateTime validFrom = leaf.getNotBefore().toInstant().atOffset(ZoneOffset.UTC);
            OffsetDateTime validTo = leaf.getNotAfter().toInstant().atOffset(ZoneOffset.UTC);
            String issuer = leaf.getIssuerX500Principal().getName();
            CertificateMetadata metadata = CertificateMetadataExtractor.fromLeaf(leaf);

            log.info("GlobalSign issuance complete: domain={}, serial={}, certSecretHandle={}", domain, serial, certSecretHandle);

            return new IssuanceResult(
                certSecretHandle, certSecretHandleWithVersion, null,
                serial, fingerprint, validFrom, validTo, issuer, issuanceSerial,
                metadata.signatureAlgorithm(), metadata.signatureAlgorithmOid(),
                metadata.subjectDn(), metadata.commonName(),
                metadata.publicKeyAlgorithm(), metadata.keySize(), metadata.publicKeyCurve(),
                metadata.keyUsage(), metadata.extendedKeyUsage(),
                metadata.subjectKeyIdentifier(), metadata.authorityKeyIdentifier(),
                CertType.DV).withKeyCustody(KeyCustody.ofStoredKey(privateKeyPem));
        } catch (PermanentAgentException e) {
            throw e;
        } catch (TransientAgentException | RetryableAgentException e) {
            throw attachCheckpoint(e, state);
        }
    }

    /** See {@code LetsEncryptAcmeService.attachCheckpoint} — only Retryable carries it. */
    private RuntimeException attachCheckpoint(RuntimeException e, IssuanceCheckpoint state) {
        if (state == null || !state.reached(IssuanceCheckpoint.Step.ORDER_CREATED)) {
            return e;
        }
        if (e instanceof RetryableAgentException re) {
            return re.withCheckpoint(state);
        }
        return e;
    }

    private void ensureDomainsVerified(List<String> certificateDomains,
                                      String rootDomain,
                                      DnsProvider rootDnsProvider,
                                      Map<String, DnsProvider> sanDnsProviders,
                                      List<DnsTxtCleanupService.DnsTxtCleanupEntry> cleanupEntries,
                                      boolean finalPropagationWait) {
        if (certificateDomains == null || certificateDomains.isEmpty()) {
            throw new PermanentAgentException("GLOBALSIGN_DOMAIN_INVALID", "No domains provided for GlobalSign issuance");
        }

        // Atlas claims are for base FQDNs (no "*." prefix). Multiple names in the certificate can still share a base.
        // Extract ALL unique domains to verify, including registrable domains (root domains).
        Set<String> toVerify = new HashSet<>();
        for (String d : certificateDomains) {
            if (d == null || d.isBlank()) continue;
            String normalized = stripWildcard(d.trim().toLowerCase(Locale.ROOT));
            toVerify.add(normalized);
            // Also add the registrable domain (e.g., "example.com" from "api.example.com" or "*.api.example.com")
            String registrableDomain = extractRegistrableDomain(normalized);
            if (registrableDomain != null && !registrableDomain.equals(normalized)) {
                toVerify.add(registrableDomain);
            }
        }

        List<DnsTxtWorkflowService.TxtRecordRequest> requests = new ArrayList<>();
        record DomainClaimWork(String domain, String claimId) {}
        List<DomainClaimWork> claims = new ArrayList<>();

        for (String verifyDomain : toVerify) {
            // If the domain is already VERIFIED on this Atlas account, skip re-claiming.
            // Re-claiming a VERIFIED domain creates a new pending claim and forces re-verification.
            String existingClaimId = atlasClient.findVerifiedClaimId(verifyDomain);
            if (existingClaimId != null) {
                log.info("GlobalSign DV: domain already VERIFIED, skipping re-claim: {}", verifyDomain);
                continue;
            }

            GlobalSignAtlasClient.DomainClaim claim = atlasClient.findPendingClaim(verifyDomain);
            if (claim != null) {
                log.info("GlobalSign DV: reusing pending claim {} for {}", claim.claimId(), verifyDomain);
            } else {
                claim = atlasClient.initiateDomainClaim(verifyDomain);
            }

            String recordName = verifyDomain;
            String recordValue = normalizeClaimTokenForDnsTxt(claim.token());

            requests.add(new DnsTxtWorkflowService.TxtRecordRequest(verifyDomain, recordName, recordValue));
            claims.add(new DomainClaimWork(verifyDomain, claim.claimId()));
        }

        // All domains already verified — nothing to claim or add DNS records for.
        if (requests.isEmpty()) {
            log.info("GlobalSign DV: all {} domain(s) already VERIFIED, skipping DNS TXT workflow", toVerify.size());
            return;
        }

        // Shared workflow: add TXT + wait for propagation.
        DnsTxtWorkflowService.TxtWorkflowResult txtWorkflow =
            dnsTxtWorkflowService.addTxtRecordsAndWaitForPropagation(requests, rootDomain, rootDnsProvider,
                    sanDnsProviders, finalPropagationWait);
        cleanupEntries.addAll(txtWorkflow.cleanupEntries());

        for (DomainClaimWork c : claims) {
            atlasClient.verifyDomainDns(c.claimId(), c.domain());
            waitUntilClaimVerified(c.claimId(), c.domain());
            log.info("GlobalSign DV: domain VERIFIED: {}", c.domain());
        }
    }

    private void waitUntilClaimVerified(String claimId, String domain) {
        int maxAttempts = Math.max(1, properties.getGlobalsign().getPollMaxAttempts());
        long pollMs = Math.max(1000, properties.getGlobalsign().getPollIntervalMs());

        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            JsonNode claim = atlasClient.getDomainClaim(claimId);
            String status = claim.path("status").asString("");
            String normalized = status.toUpperCase(Locale.ROOT);
            log.debug("GlobalSign claim {} status={} (attempt {}/{})", claimId, status, attempt, maxAttempts);

            if ("VERIFIED".equals(normalized)) {
                return;
            }
            if ("ERROR".equals(normalized) || "FAILED".equals(normalized) || "REJECTED".equals(normalized)) {
                throw new PermanentAgentException("GLOBALSIGN_DOMAIN_VERIFICATION_FAILED",
                    "GlobalSign domain claim " + claimId + " reached terminal status " + status + " for domain " + domain);
            }

            try {
                Thread.sleep(pollMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new TransientAgentException("GLOBALSIGN_INTERRUPTED",
                    "Interrupted while waiting for GlobalSign domain verification", e);
            }
        }

        throw new PermanentAgentException("GLOBALSIGN_DOMAIN_VERIFICATION_TIMEOUT",
            "GlobalSign domain claim " + claimId + " was not VERIFIED after " + maxAttempts + " polls for domain " + domain);
    }

    private String stripWildcard(String domain) {
        if (domain == null) {
            return "";
        }
        return domain.startsWith("*.") ? domain.substring(2) : domain;
    }

    /**
     * Extract the registrable domain (also called "base domain" or "root domain") from a fully qualified domain name.
     * For most cases, this is the last two labels (e.g., "example.com" from "api.example.com").
     * Returns null if the domain cannot be parsed.
     * 
     * Examples:
     * - "api.example.com" → "example.com"
     * - "test.api.example.com" → "example.com"
     * - "example.com" → "example.com"
     * - "other.co.uk" → "co.uk" (limitation: does not handle all public suffixes, but acceptable for most domains)
     * - "other.in" → "other.in"
     */
    private String extractRegistrableDomain(String domain) {
        if (domain == null || domain.isBlank()) {
            return null;
        }
        String[] labels = domain.split("\\.");
        if (labels.length <= 2) {
            // Already at root level
            return domain;
        }
        // Take last 2 labels for most TLDs (works for .com, .org, .net, .in, etc.)
        // Note: This is a simplification. For production, consider using a public suffix library.
        return labels[labels.length - 2] + "." + labels[labels.length - 1];
    }

    private String normalizeClaimTokenForDnsTxt(String token) {
        if (token == null || token.isBlank()) {
            throw new PermanentAgentException("GLOBALSIGN_RESPONSE_INVALID",
                "GlobalSign claim response missing token");
        }
        // DNS TXT record must be: globalsign-domain-verification=<token>
        if (token.startsWith("globalsign-domain-verification=")) {
            return token;
        }
        return "globalsign-domain-verification=" + token;
    }

    private CsrPolicy resolveCsrPolicy(JsonNode policy) {
        // Safe defaults compatible with most GlobalSign DV policies.
        String keyType = "RSA";
        int keySize = 2048;

        if (policy == null) {
            return new CsrPolicy(keyType, keySize);
        }

        JsonNode publicKey = policy.path("public_key");
        String keyFormat = publicKey.path("key_format").asString("PKCS10");
        if (!"PKCS10".equalsIgnoreCase(keyFormat)) {
            throw new PermanentAgentException("GLOBALSIGN_POLICY_UNSUPPORTED",
                    "GlobalSign policy key_format='" + keyFormat + "' is not supported by agent CSR flow (requires PKCS10)");
        }

        String policyKeyType = publicKey.path("key_type").asString("");
        if (!policyKeyType.isBlank()) {
            keyType = policyKeyType.toUpperCase(Locale.ROOT);
        }

        JsonNode allowedLengths = publicKey.path("allowed_lengths");
        if (allowedLengths.isArray() && allowedLengths.size() > 0) {
            List<Integer> lengths = new ArrayList<>();
            for (JsonNode n : allowedLengths) {
                if (n.canConvertToInt()) {
                    lengths.add(n.asInt());
                }
            }
            if (!lengths.isEmpty()) {
                keySize = pickBestKeySize(keyType, lengths);
            }
        }

        return new CsrPolicy(keyType, keySize);
    }

    private int pickBestKeySize(String keyType, List<Integer> lengths) {
        if ("ECDSA".equalsIgnoreCase(keyType)) {
            if (lengths.contains(256)) return 256;
            if (lengths.contains(384)) return 384;
            if (lengths.contains(521)) return 521;
            return lengths.get(0);
        }

        // Default RSA preference: 2048 for compatibility and speed.
        if (lengths.contains(2048)) return 2048;
        if (lengths.contains(3072)) return 3072;
        if (lengths.contains(4096)) return 4096;
        return lengths.get(0);
    }

    private record CsrPolicy(String keyType, int keySize) {}

    private JsonNode pollUntilIssued(String serial, String domain) {
        int maxAttempts = Math.max(1, properties.getGlobalsign().getPollMaxAttempts());
        long pollMs = Math.max(1000, properties.getGlobalsign().getPollIntervalMs());

        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            JsonNode cert = atlasClient.getCertificate(serial);
            String status = cert.path("status").asString("");
            String normalized = status.toUpperCase(Locale.ROOT);
            log.debug("GlobalSign certificate {} status={} (attempt {}/{})", serial, status, attempt, maxAttempts);

            if ("ISSUED".equals(normalized) || "ACTIVE".equals(normalized) || "VALID".equals(normalized)) {
                return cert;
            }
            if ("REVOKED".equals(normalized) || "REJECTED".equals(normalized) || "FAILED".equals(normalized)) {
                throw new PermanentAgentException("GLOBALSIGN_ISSUANCE_FAILED",
                        "GlobalSign returned terminal status " + status + " for domain " + domain);
            }

            try {
                Thread.sleep(pollMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new PermanentAgentException("GLOBALSIGN_INTERRUPTED",
                        "Interrupted while waiting for GlobalSign issuance", e);
            }
        }

        throw new PermanentAgentException("GLOBALSIGN_ISSUANCE_TIMEOUT",
                "GlobalSign certificate " + serial + " was not issued after " + maxAttempts + " polls");
    }

    private String extractLeafPem(JsonNode cert) {
        if (cert.has("certificate") && cert.get("certificate").isString()) {
            return cert.get("certificate").asString();
        }
        if (cert.has("pem") && cert.get("pem").isString()) {
            return cert.get("pem").asString();
        }
        if (cert.has("crt") && cert.get("crt").isString()) {
            return cert.get("crt").asString();
        }
        if (cert.has("data") && cert.get("data").has("certificate") && cert.get("data").get("certificate").isString()) {
            return cert.get("data").get("certificate").asString();
        }
        throw new PermanentAgentException("GLOBALSIGN_RESPONSE_INVALID",
                "GlobalSign GET /certificates/{serial} did not include certificate PEM");
    }

    private X509Certificate parseFirstCert(String pem) {
        try {
            int start = pem.indexOf("-----BEGIN CERTIFICATE-----");
            int end = pem.indexOf("-----END CERTIFICATE-----") + "-----END CERTIFICATE-----".length();
            String firstPem = pem.substring(start, end);
            String b64 = firstPem
                    .replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "")
                    .replaceAll("\\s", "");
            byte[] der = Base64.getDecoder().decode(b64);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
        } catch (Exception e) {
            throw new PermanentAgentException("CERT_PARSE_FAILED",
                    "Failed to parse GlobalSign certificate: " + e.getMessage(), e);
        }
    }

    private String sha256Fingerprint(X509Certificate cert) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(cert.getEncoded());
            return HexFormat.of().withUpperCase().withDelimiter(":").formatHex(digest);
        } catch (Exception e) {
            log.warn("Failed to compute fingerprint: {}", e.getMessage());
            return "unknown";
        }
    }
}