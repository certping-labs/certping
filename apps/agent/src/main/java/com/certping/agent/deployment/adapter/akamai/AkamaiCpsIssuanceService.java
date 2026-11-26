// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.akamai;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.credential.AkamaiCpsDeploymentCredential;
import com.certping.agent.model.credential.AkamaiCpsDeploymentCredential.AkamaiEnrollment;
import com.certping.agent.model.enums.CaProvider;
import com.certping.agent.model.message.CertIssuanceMessage;
import com.certping.agent.model.message.SanDomainEntry;
import com.certping.agent.service.CredentialAccessService;
import com.certping.agent.ssl.IssuanceResult;
import com.certping.agent.ssl.acme.LetsEncryptAcmeService;
import com.certping.agent.ssl.digicert.DigiCertIssuanceService;
import com.certping.agent.ssl.dns.DnsProvider;
import com.certping.agent.ssl.dns.DnsProviderFactory;
import com.certping.agent.ssl.globalsign.GlobalSignIssuanceService;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Handles certificate issuance for Akamai CPS third-party enrollment.
 *
 * <p>Flow:
 * 1. Load Akamai credential from KV (specialDeploymentCredHandle).
 * 2. Find the pending change for the domain's enrollment.
 * 3. Fetch the Akamai-generated CSR from the pending change.
 * 4. Submit the CSR to the CA (only DigiCert is supported; others throw unsupported).
 * 5. Return an IssuanceResult — the cert chain is stored in KV; no private key is included
 *    since Akamai holds it.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AkamaiCpsIssuanceService {

    private static final String CSR_MEDIA = "application/vnd.akamai.cps.csr.v2+json";
    private static final String ENROLLMENT_MEDIA = "application/vnd.akamai.cps.enrollment.v11+json";

    private final AkamaiCpsAuthService akamaiCpsAuthService;
    private final DigiCertIssuanceService digicertService;
    private final LetsEncryptAcmeService leService;
    private final GlobalSignIssuanceService globalSignService;
    private final CredentialAccessService credentialAccessService;
    private final DnsProviderFactory dnsProviderFactory;
    private final ObjectMapper objectMapper;

    public IssuanceResult issue(CertIssuanceMessage msg) {
        String credKvPath = msg.getSpecialDeploymentCredHandle();
        if (credKvPath == null || credKvPath.isBlank()) {
            throw new PermanentAgentException("AKAMAI_CRED_MISSING",
                    "specialDeploymentCredHandle is required for AKAMAI_CPS issuance, xref="
                            + msg.getCertificateXref());
        }

        AkamaiCpsDeploymentCredential cred = akamaiCpsAuthService.loadCredential(credKvPath);
        String domain = msg.getDomain();
        AkamaiEnrollment enrollment = resolveEnrollment(cred, domain);

        String csrPem;
        try (CloseableHttpClient http = akamaiCpsAuthService.buildClient(cred)) {
            String changeId = resolvePendingChangeId(http, cred, enrollment);
            csrPem = fetchCsr(http, cred, enrollment, changeId);
            log.info("Fetched Akamai CSR for domain={}, enrollmentId={}, changeId={}",
                    domain, enrollment.getEnrollmentId(), changeId);
        } catch (PermanentAgentException | com.certping.agent.exception.TransientAgentException e) {
            throw e;
        } catch (Exception e) {
            throw new PermanentAgentException("AKAMAI_CPS_ISSUANCE_FAILED",
                    "Akamai CPS CSR fetch failed for domain=" + domain + ": " + e.getMessage(), e);
        }

        List<String> sanDomains = flattenPatterns(msg.getSanDomainEntries());
        CaProvider ca = msg.getCaProvider();

        Integer validityDays = msg.getValidityDays();

        return switch (ca) {
            case DIGICERT -> {
                DnsProvider rootDns = buildRootDnsProvider(msg.getDnsProvider(), msg.getDnsCredentialHandle());
                Map<String, DnsProvider> sanDns = buildSanDnsProviders(msg.getSanDomainEntries());
                yield digicertService.issueWithExternalCsr(
                        msg.getCertificateXref(), domain, sanDomains, rootDns, sanDns,
                        msg.getCaCredentialHandle(), csrPem, validityDays,
                        msg.getCheckpoint(), msg.getCheckpointRecorder());
            }
            case LETS_ENCRYPT -> {
                DnsProvider rootDns = buildRootDnsProvider(msg.getDnsProvider(), msg.getDnsCredentialHandle());
                Map<String, DnsProvider> sanDns = buildSanDnsProviders(msg.getSanDomainEntries());
                yield leService.issueWithExternalCsr(
                        msg.getOrganizationId(), msg.getCertificateXref(), domain,
                        msg.isWildcard(), sanDomains, rootDns, sanDns,
                        msg.getAcmeAccountHandle(), csrPem, msg.isFinalPropagationWait(),
                        msg.getCheckpoint(), msg.getCheckpointRecorder());
            }
            case GLOBALSIGN -> {
                DnsProvider rootDns = buildRootDnsProvider(msg.getDnsProvider(), msg.getDnsCredentialHandle());
                Map<String, DnsProvider> sanDns = buildSanDnsProviders(msg.getSanDomainEntries());
                yield globalSignService.issueWithExternalCsr(
                        msg.getCertificateXref(), domain, msg.isWildcard(), sanDomains,
                        rootDns, sanDns, csrPem, validityDays, msg.isFinalPropagationWait(),
                        msg.getCheckpoint(), msg.getCheckpointRecorder());
            }
            default -> throw new PermanentAgentException("AKAMAI_UNSUPPORTED_CA",
                    "Akamai CPS special issuance has no implementation for CA: " + ca);
        };
    }

    private AkamaiEnrollment resolveEnrollment(AkamaiCpsDeploymentCredential cred, String domain) {
        List<AkamaiEnrollment> enrollments = cred.getEnrollments();
        if (enrollments.size() == 1) {
            return enrollments.get(0);
        }
        String match = domain.toLowerCase(Locale.ROOT);
        for (AkamaiEnrollment enrollment : enrollments) {
            if (enrollment.getCommonName() != null
                    && match.equalsIgnoreCase(enrollment.getCommonName().trim())) {
                return enrollment;
            }
            if (enrollment.getDomains() != null) {
                for (String candidate : enrollment.getDomains()) {
                    if (candidate != null && match.equalsIgnoreCase(candidate.trim())) {
                        return enrollment;
                    }
                }
            }
        }
        throw new PermanentAgentException("AKAMAI_ENROLLMENT_NOT_FOUND",
                "No Akamai enrollment matched domain: " + domain);
    }

    private String resolvePendingChangeId(CloseableHttpClient http,
                                          AkamaiCpsDeploymentCredential cred,
                                          AkamaiEnrollment enrollment) throws Exception {
        String enrollmentId = enrollment.getEnrollmentId();
        String url = akamaiCpsAuthService.baseUrl(cred) + "/cps/v2/enrollments/" + enrollmentId;

        HttpGet get = new HttpGet(url);
        get.setHeader("Accept", ENROLLMENT_MEDIA);

        String body = executeGet(http, get, "AKAMAI_ENROLLMENT_FETCH");
        JsonNode root = objectMapper.readTree(body);
        JsonNode pending = root.get("pendingChanges");
        if (pending == null || !pending.isArray() || pending.isEmpty()) {
            throw new PermanentAgentException("AKAMAI_NO_PENDING_CHANGE",
                    "No pending CPS change found for enrollmentId=" + enrollmentId
                            + ". A third-party enrollment change must be initiated in Akamai CPS "
                            + "before issuance can proceed.");
        }
        String changeUrl = pending.get(0).asString();
        String changeId = changeUrl.substring(changeUrl.lastIndexOf('/') + 1);
        if (changeId.isBlank()) {
            throw new PermanentAgentException("AKAMAI_NO_PENDING_CHANGE",
                    "Pending changeId missing for enrollmentId=" + enrollmentId);
        }
        return changeId;
    }

    private String fetchCsr(CloseableHttpClient http,
                            AkamaiCpsDeploymentCredential cred,
                            AkamaiEnrollment enrollment,
                            String changeId) throws Exception {
        String enrollmentId = enrollment.getEnrollmentId();
        String url = akamaiCpsAuthService.baseUrl(cred)
                + "/cps/v2/enrollments/" + enrollmentId
                + "/changes/" + changeId
                + "/input/info/third-party-csr";

        HttpGet get = new HttpGet(url);
        get.setHeader("Accept", CSR_MEDIA);

        String body = executeGet(http, get, "AKAMAI_CSR_FETCH");
        JsonNode root = objectMapper.readTree(body);

        // Response: {"csrs": [{"csr": "-----BEGIN CERTIFICATE REQUEST-----...", "keyAlgorithm": "RSA"}]}
        JsonNode csrs = root.get("csrs");
        if (csrs == null || !csrs.isArray() || csrs.isEmpty()) {
            throw new PermanentAgentException("AKAMAI_CSR_MISSING",
                    "Akamai CPS returned no CSRs for enrollmentId=" + enrollmentId
                            + " changeId=" + changeId);
        }

        // Prefer RSA CSR; fall back to first available
        for (JsonNode entry : csrs) {
            String algo = entry.path("keyAlgorithm").asString("");
            if ("RSA".equalsIgnoreCase(algo)) {
                return entry.path("csr").asString();
            }
        }
        return csrs.get(0).path("csr").asString();
    }

    private String executeGet(CloseableHttpClient http, HttpGet request, String errorCode) throws Exception {
        try (CloseableHttpResponse response = http.execute(request)) {
            int status = response.getCode();
            String body = response.getEntity() == null ? ""
                    : EntityUtils.toString(response.getEntity());
            if (status >= 200 && status < 300) {
                return body;
            }
            if (status >= 500) {
                throw new com.certping.agent.exception.TransientAgentException(errorCode,
                        "Akamai CPS HTTP " + status + ": " + truncate(body));
            }
            throw new PermanentAgentException(errorCode,
                    "Akamai CPS HTTP " + status + ": " + truncate(body));
        }
    }

    private DnsProvider buildRootDnsProvider(String dnsProvider, String dnsCredentialHandle) {
        String rawCred = credentialAccessService.readSecret(dnsCredentialHandle);
        return dnsProviderFactory.create(dnsProvider, rawCred);
    }

    private Map<String, DnsProvider> buildSanDnsProviders(List<SanDomainEntry> entries) {
        if (entries == null || entries.isEmpty()) {
            return Collections.emptyMap();
        }
        Map<String, DnsProvider> map = new HashMap<>();
        for (SanDomainEntry entry : entries) {
            String raw = credentialAccessService.readSecret(entry.getDnsCredentialHandle());
            DnsProvider provider = dnsProviderFactory.create(entry.getDnsProvider(), raw);
            if (entry.getPatterns() != null) {
                for (String pattern : entry.getPatterns()) {
                    if (pattern != null && !pattern.isBlank()) {
                        map.put(pattern, provider);
                    }
                }
            }
        }
        return map;
    }

    private List<String> flattenPatterns(List<SanDomainEntry> entries) {
        if (entries == null || entries.isEmpty()) {
            return Collections.emptyList();
        }
        return entries.stream()
                .filter(e -> e.getPatterns() != null)
                .flatMap(e -> e.getPatterns().stream())
                .distinct()
                .toList();
    }

    private String truncate(String body) {
        if (body == null) return "";
        String trimmed = body.trim();
        return trimmed.length() > 400 ? trimmed.substring(0, 400) + "..." : trimmed;
    }
}
