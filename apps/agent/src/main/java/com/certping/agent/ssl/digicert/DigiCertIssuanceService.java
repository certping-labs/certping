// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.digicert;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.CaOrderPendingException;
import com.certping.agent.exception.CheckpointRecorder;
import com.certping.agent.exception.IssuanceCheckpoint;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RateLimitClassifier;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.ssl.CaOrderPolling;
import com.certping.agent.ssl.CertificateMetadata;
import com.certping.agent.ssl.CertificateMetadataExtractor;
import com.certping.agent.ssl.CsrKeyPairService;
import com.certping.agent.ssl.IssuanceResult;
import com.certping.agent.ssl.KeyCustody;
import com.certping.agent.ssl.dns.DnsProvider;
import com.certping.agent.ssl.dns.DnsProviderSelector;
import com.certping.agent.ssl.dns.DnsTxtCleanupService;
import com.certping.agent.ssl.dns.DnsValidationDomainService;
import com.certping.agent.secrets.SecretStore;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class DigiCertIssuanceService {

    private final CsrKeyPairService csrKeyPairService;
    private final SecretStore secretStore;
    private final AgentProperties properties;
    private final ObjectMapper objectMapper;
    private final DnsProviderSelector dnsProviderSelector;
    private final DnsTxtCleanupService dnsTxtCleanupService;
    private final DnsValidationDomainService dnsValidationDomainService;
    private final com.certping.agent.ssl.KeyStagingHelper keyStagingHelper;

    /** Default when caller doesn't supply validityDays. 90d aligns with LE + CA/B Forum
     *  short-validity baseline. DigiCert auto-truncates anything >199d post 2026-02-24. */
    private static final int DEFAULT_VALIDITY_DAYS = 90;

    public IssuanceResult issue(
            String certificateXref,
            String domain,
            List<String> sanDomains,
            DnsProvider rootDnsProvider,
            Map<String, DnsProvider> sanDnsProviders,
            String caCredentialHandle,
            Integer validityDays) {
        return issue(certificateXref, domain, sanDomains, rootDnsProvider, sanDnsProviders,
                caCredentialHandle, validityDays, null, CheckpointRecorder.NONE);
    }

    /** Overload that accepts a resume checkpoint from a prior failed attempt. */
    public IssuanceResult issue(
            String certificateXref,
            String domain,
            List<String> sanDomains,
            DnsProvider rootDnsProvider,
            Map<String, DnsProvider> sanDnsProviders,
            String caCredentialHandle,
            Integer validityDays,
            com.certping.agent.exception.IssuanceCheckpoint resumeCheckpoint,
            CheckpointRecorder recorder) {

        log.info("DigiCert issuance started: domain={}, xref={}, validityDays={}, resumeStep={}",
                domain, certificateXref, validityDays,
                resumeCheckpoint == null ? "none" : resumeCheckpoint.step());
        String apiKey = DigiCertApiKey.from(secretStore.read(caCredentialHandle));

        // Stage key on first attempt; read it back on resume so finalize sees the SAME
        // public key DigiCert pinned to the order. (DigiCert pins the CSR's public key
        // at POST /order time; a regenerated key would force a new POST = double-bill.)
        CsrKeyPairService.CsrKeyPairResult csrResult;
        String privateKeyKvPath;
        if (resumeCheckpoint == null || resumeCheckpoint.privateKeyKvPath() == null) {
            csrResult = csrKeyPairService.generateCsrAndKeyPair(domain, sanDomains);
            privateKeyKvPath = keyStagingHelper.stage(certificateXref,
                    csrResult.privateKeyPem(), csrResult.csrPem());
        } else {
            com.certping.agent.ssl.KeyStagingHelper.Staged staged =
                    keyStagingHelper.read(resumeCheckpoint.privateKeyKvPath());
            csrResult = new CsrKeyPairService.CsrKeyPairResult(
                    null, staged.csrPem(), staged.privateKeyPem());
            privateKeyKvPath = resumeCheckpoint.privateKeyKvPath();
            log.info("DigiCert resume: read staged key from {}", privateKeyKvPath);
        }

        return issueCore(certificateXref, domain, sanDomains, rootDnsProvider, sanDnsProviders,
                apiKey, csrResult.csrPem(), csrResult.privateKeyPem(),
                validityDays, resumeCheckpoint, privateKeyKvPath, recorder);
    }

    /** Issues using a CSR supplied externally (e.g. Akamai CPS). Private key stays with the caller; only the chain is stored in KV. */
    public IssuanceResult issueWithExternalCsr(
            String certificateXref,
            String domain,
            List<String> sanDomains,
            DnsProvider rootDnsProvider,
            Map<String, DnsProvider> sanDnsProviders,
            String caCredentialHandle,
            String externalCsrPem,
            Integer validityDays) {
        return issueWithExternalCsr(certificateXref, domain, sanDomains, rootDnsProvider, sanDnsProviders,
                caCredentialHandle, externalCsrPem, validityDays, null, CheckpointRecorder.NONE);
    }

    /** Issues from a CSR whose key the customer holds; with a recorder the order is collected on later deliveries. */
    public IssuanceResult issueWithExternalCsr(
            String certificateXref,
            String domain,
            List<String> sanDomains,
            DnsProvider rootDnsProvider,
            Map<String, DnsProvider> sanDnsProviders,
            String caCredentialHandle,
            String externalCsrPem,
            Integer validityDays,
            IssuanceCheckpoint resumeCheckpoint,
            CheckpointRecorder recorder) {

        log.info("DigiCert external-CSR issuance started: domain={}, xref={}, validityDays={}, resumeStep={}",
                domain, certificateXref, validityDays, resumeCheckpoint == null ? "none" : resumeCheckpoint.step());
        String apiKey = DigiCertApiKey.from(secretStore.read(caCredentialHandle));
        return issueCore(certificateXref, domain, sanDomains, rootDnsProvider, sanDnsProviders,
                apiKey, externalCsrPem, null, validityDays, resumeCheckpoint, null, recorder);
    }

    /**
     * Places the order, submits validation and collects the certificate. With a checkpoint to record (a message
     * flow) the order is collected on later deliveries, {@link CaOrderPendingException} between them; an external
     * CSR (Akamai CPS) has none and is polled in process.
     *
     * @param privateKeyPem null when the private key is held externally; the chain is stored without it.
     */
    private IssuanceResult issueCore(
            String certificateXref,
            String domain,
            List<String> sanDomains,
            DnsProvider rootDnsProvider,
            Map<String, DnsProvider> sanDnsProviders,
            String apiKey,
            String csrPem,
            String privateKeyPem,
            Integer validityDays,
            IssuanceCheckpoint resumeCheckpoint,
            String privateKeyKvPath,
            CheckpointRecorder recorder) {

        IssuanceCheckpoint state = privateKeyKvPath == null && recorder == CheckpointRecorder.NONE && resumeCheckpoint == null
                ? null
                : (resumeCheckpoint != null
                    ? resumeCheckpoint
                    : new IssuanceCheckpoint("DIGICERT", IssuanceCheckpoint.Step.CSR_GENERATED, null, null,
                            privateKeyKvPath));

        RestTemplate rest = new RestTemplate();
        String base = properties.getDigicert().getApiBaseUrl();
        int effectiveValidityDays = validityDays != null ? validityDays : DEFAULT_VALIDITY_DAYS;

        try {
            if (state == null) {
                PlacedOrder order = placeOrder(rest, base, apiKey, domain, sanDomains, csrPem, effectiveValidityDays);
                validateDomains(rest, base, apiKey, order.id(), order.token(), domain, sanDomains, rootDnsProvider,
                        sanDnsProviders);
                String certId = pollUntilIssued(rest, base, apiKey, order.id(), domain);
                return storeIssued(rest, base, apiKey, certId, order.ref(), certificateXref, domain, privateKeyPem,
                        null);
            }

            boolean placedNow = !state.reached(IssuanceCheckpoint.Step.ORDER_CREATED);
            if (placedNow) {
                PlacedOrder order = placeOrder(rest, base, apiKey, domain, sanDomains, csrPem, effectiveValidityDays);
                state = state.withOrderRef(order.ref(), null).withDcv(order.token().serialize(), Instant.now());
                recorder.recordAnswered(state);
            }
            int orderId = Integer.parseInt(state.orderRef());
            if (!state.reached(IssuanceCheckpoint.Step.ORDER_FINALIZED)) {
                if (!placedNow) {
                    JsonNode order = orderStatus(rest, base, apiKey, orderId);
                    if ("issued".equalsIgnoreCase(order.path("status").asString())) {
                        return storeIssued(rest, base, apiKey, order.path("certificate").path("id").asString(),
                                state.orderRef(), certificateXref, domain, privateKeyPem, privateKeyKvPath);
                    }
                }
                DcvToken token = DcvToken.parse(state.dcv());
                if (token == null) {
                    log.warn("DigiCert order {} has no recorded DCV token; collecting it without validating again", orderId);
                } else {
                    validateDomains(rest, base, apiKey, orderId, token, domain, sanDomains, rootDnsProvider,
                            sanDnsProviders);
                    log.info("DigiCert validation submitted: orderId={}", orderId);
                }
                state = state.withStep(IssuanceCheckpoint.Step.ORDER_FINALIZED);
                recorder.recordAnswered(state);
            }

            JsonNode order = orderStatus(rest, base, apiKey, orderId);
            String status = order.path("status").asString("unknown");
            if ("issued".equalsIgnoreCase(status)) {
                return storeIssued(rest, base, apiKey, order.path("certificate").path("id").asString(), state.orderRef(),
                        certificateXref, domain, privateKeyPem, privateKeyKvPath);
            }
            if ("rejected".equalsIgnoreCase(status) || "cancelled".equalsIgnoreCase(status)) {
                throw new PermanentAgentException("CA_ORDER_REJECTED", "DigiCert order " + orderId + " was " + status);
            }
            Instant now = Instant.now();
            CaOrderPolling polling = polling();
            long ageSec = state.orderPlacedAt() == null ? 0 : Duration.between(state.orderPlacedAt(), now).toSeconds();
            if (polling.pastDeadline(state.orderPlacedAt(), now)) {
                throw new PermanentAgentException("CA_ORDER_TIMEOUT", "DigiCert order " + orderId + " is still "
                        + status + " " + ageSec + " s after it was placed (deadline " + polling.deadline().toSeconds()
                        + " s) for domain " + domain);
            }
            Duration next = polling.nextDelay(state.orderPlacedAt(), now);
            log.info("DigiCert order pending: orderId={} status={} ageSec={} nextCheckSec={}", orderId, status, ageSec,
                    next.toSeconds());
            throw new CaOrderPendingException("DIGICERT", state.orderRef(), next, state);

        } catch (HttpClientErrorException e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "CA_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw attachCheckpoint(rl.get().toRetryable("digicert issuance", domain, e), state);
            }
            if (e.getStatusCode().value() == 401 || e.getStatusCode().value() == 403) {
                throw new PermanentAgentException("CA_AUTH_FAILED",
                        "DigiCert API auth failed: " + e.getMessage(), e);
            }
            throw attachCheckpoint(new TransientAgentException("CA_API_ERROR",
                    "DigiCert API error: " + e.getMessage(), e), state);
        } catch (PermanentAgentException e) {
            throw e;
        } catch (TransientAgentException | RetryableAgentException e) {
            throw attachCheckpoint(e, state);
        } catch (Exception e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "CA_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw attachCheckpoint(rl.get().toRetryable("digicert issuance", domain, e), state);
            }
            throw new PermanentAgentException("DIGICERT_ISSUANCE_FAILED",
                    "DigiCert issuance error: " + e.getMessage(), e);
        }
    }

    /** See {@code LetsEncryptAcmeService.attachCheckpoint} — only Retryable carries it. */
    private RuntimeException attachCheckpoint(RuntimeException e,
            com.certping.agent.exception.IssuanceCheckpoint state) {
        if (state == null || !state.reached(
                com.certping.agent.exception.IssuanceCheckpoint.Step.ORDER_CREATED)) {
            return e;
        }
        if (e instanceof RetryableAgentException re) {
            return re.withCheckpoint(state);
        }
        return e;
    }

    private record PlacedOrder(int id, String ref, DcvToken token) {
    }

    private PlacedOrder placeOrder(RestTemplate rest, String base, String apiKey, String domain,
                                   List<String> sanDomains, String csrPem, int validityDays) {
        // DigiCert truncates validity_days to its own ceiling (199 days since 2026-02-24); no clamp here.
        Map<String, Object> orderBody = Map.of(
                "certificate", Map.of(
                        "common_name", domain,
                        "dns_names", sanDomains != null ? sanDomains : List.of(),
                        "csr", csrPem,
                        "signature_hash", "sha256"),
                "organization", Map.of("id", 0),
                "cert_validity", Map.of("validity_days", validityDays),
                "product", Map.of("name_id", "ssl_dv_sha2"),
                "dcv_method", "dns_txt_token");

        ResponseEntity<JsonNode> orderResp = rest.exchange(base + "/order/certificate/ssl_dv_sha2",
                HttpMethod.POST, new HttpEntity<>(orderBody, dcHeaders(apiKey)), JsonNode.class);
        validateDcResponse(orderResp, "submit order");
        JsonNode orderJson = orderResp.getBody();
        JsonNode idNode = orderJson.path("id");
        if (idNode.isMissingNode() || idNode.isNull()) {
            throw new PermanentAgentException("DIGICERT_ORDER_INVALID", "DigiCert order response missing id");
        }
        log.info("DigiCert order submitted: orderId={}", idNode.asInt());
        JsonNode dcvInfo = orderJson.path("dcv_token");
        return new PlacedOrder(idNode.asInt(), idNode.asString(),
                new DcvToken(dcvInfo.path("name").asString(), dcvInfo.path("value").asString()));
    }

    private IssuanceResult storeIssued(RestTemplate rest, String base, String apiKey, String certId, String orderRef,
                                       String certificateXref, String domain, String privateKeyPem,
                                       String privateKeyKvPath) {
        ResponseEntity<String> downloadResp = rest.exchange(
                base + "/certificate/" + certId + "/download/format/pem_all",
                HttpMethod.GET, new HttpEntity<>(dcHeaders(apiKey)), String.class);

        String chainPem = downloadResp.getBody();
        String bundle = privateKeyPem != null ? chainPem + "\n" + privateKeyPem : chainPem;
        String certSecretHandle = secretStore.create(certificateXref, bundle);
        String certSecretHandleWithVersion = privateKeyPem == null ? certSecretHandle : null;
        log.info("DigiCert cert stored at {}", certSecretHandle);
        if (privateKeyKvPath != null) {
            keyStagingHelper.purge(privateKeyKvPath);
        }

        X509Certificate leaf = parseFirstCert(chainPem);
        String serial = leaf.getSerialNumber().toString(16).toUpperCase();
        String fingerprint = sha256Fingerprint(leaf);
        OffsetDateTime validFrom = leaf.getNotBefore().toInstant().atOffset(ZoneOffset.UTC);
        OffsetDateTime validTo = leaf.getNotAfter().toInstant().atOffset(ZoneOffset.UTC);
        String issuer = leaf.getIssuerX500Principal().getName();
        CertificateMetadata metadata = CertificateMetadataExtractor.fromLeaf(leaf);

        log.info("DigiCert issuance complete: domain={}, serial={}, validTo={}, orderId={}, keyCustody={}",
                domain, serial, validTo, orderRef, KeyCustody.ofStoredKey(privateKeyPem));
        return new IssuanceResult(certSecretHandle, certSecretHandleWithVersion, null, serial, fingerprint,
                validFrom, validTo, issuer, orderRef,
                metadata.signatureAlgorithm(),
                metadata.signatureAlgorithmOid(),
                metadata.subjectDn(),
                metadata.commonName(),
                metadata.publicKeyAlgorithm(),
                metadata.keySize(),
                metadata.publicKeyCurve(),
                metadata.keyUsage(),
                metadata.extendedKeyUsage(),
                metadata.subjectKeyIdentifier(),
                metadata.authorityKeyIdentifier(),
                null).withKeyCustody(KeyCustody.ofStoredKey(privateKeyPem));
    }

    private CaOrderPolling polling() {
        return new CaOrderPolling(properties.getDigicert().getOrderPollIntervals(),
                properties.getDigicert().getOrderDeadline());
    }

    /** Publishes the DCV TXT record on every validated domain, asks DigiCert to check it, then removes it. */
    private void validateDomains(RestTemplate rest, String base, String apiKey, int orderId, DcvToken token,
                                 String domain, List<String> sanDomains, DnsProvider rootDnsProvider,
                                 Map<String, DnsProvider> sanDnsProviders) {
        List<DnsTxtCleanupService.DnsTxtCleanupEntry> cleanupEntries = new java.util.ArrayList<>();
        for (String d : dnsValidationDomainService.buildValidationDomains(domain, sanDomains)) {
            String recordName = buildDcvRecordName(token.name(), dnsValidationDomainService.toRecordDomain(d));
            DnsProvider provider = dnsProviderSelector.selectProvider(d, domain, rootDnsProvider, sanDnsProviders);
            String recordId = provider.addTxtRecord(recordName, token.value());
            cleanupEntries.add(new DnsTxtCleanupService.DnsTxtCleanupEntry(provider, recordName, recordId));
            log.info("DigiCert DCV TXT published: domain={}, recordName={}", d, recordName);
        }
        try {
            rest.exchange(base + "/order/certificate/" + orderId + "/check-dcv",
                    HttpMethod.PUT, new HttpEntity<>(dcHeaders(apiKey)), JsonNode.class);
        } finally {
            // DigiCert keeps the proof once check-dcv has been called, so the record can go before polling.
            dnsTxtCleanupService.cleanup(cleanupEntries);
        }
    }

    private JsonNode orderStatus(RestTemplate rest, String base, String apiKey, int orderId) {
        ResponseEntity<JsonNode> resp = rest.exchange(base + "/order/certificate/" + orderId,
                HttpMethod.GET, new HttpEntity<>(dcHeaders(apiKey)), JsonNode.class);
        return resp.getBody() == null ? tools.jackson.databind.node.MissingNode.getInstance() : resp.getBody();
    }

    /** The DNS TXT record DigiCert asked for, carried in the checkpoint so a resume can publish it again. */
    public record DcvToken(String name, String value) {
        public String serialize() {
            return name + "\n" + value;
        }

        public static DcvToken parse(String recorded) {
            if (recorded == null) {
                return null;
            }
            int nl = recorded.indexOf('\n');
            return nl < 0 ? null : new DcvToken(recorded.substring(0, nl), recorded.substring(nl + 1));
        }
    }

    private String pollUntilIssued(RestTemplate rest, String base, String apiKey,
                                   int orderId, String domain) throws InterruptedException {
        int maxAttempts = properties.getDigicert().getOrderPollMaxAttempts();
        long pollMs = properties.getDigicert().getOrderPollIntervalMs();

        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            ResponseEntity<JsonNode> resp = rest.exchange(
                    base + "/order/certificate/" + orderId,
                    HttpMethod.GET,
                    new HttpEntity<>(dcHeaders(apiKey)),
                    JsonNode.class);

            JsonNode order = resp.getBody();
            String status = order != null ? order.path("status").asString() : "unknown";
            log.debug("DigiCert order {} status={} (attempt {}/{})", orderId, status, attempt, maxAttempts);

            if ("issued".equalsIgnoreCase(status)) {
                return order.path("certificate").path("id").asString();
            }
            if ("rejected".equalsIgnoreCase(status) || "cancelled".equalsIgnoreCase(status)) {
                throw new PermanentAgentException("CA_ORDER_REJECTED",
                        "DigiCert order " + orderId + " was " + status);
            }
            Thread.sleep(pollMs);
        }
        throw new PermanentAgentException("CA_ORDER_TIMEOUT",
                "DigiCert order " + orderId + " did not reach 'issued' after "
                        + maxAttempts + " attempts for domain " + domain);
    }

    private HttpHeaders dcHeaders(String apiKey) {
        HttpHeaders h = new HttpHeaders();
        h.set("X-DC-DEVKEY", apiKey);
        h.setContentType(MediaType.APPLICATION_JSON);
        return h;
    }

    private String buildDcvRecordName(String apiRecordName, String domain) {
        if (apiRecordName != null && !apiRecordName.isBlank()) {
            if (apiRecordName.startsWith("_digicert.")) {
                return "_digicert." + domain;
            }
            return apiRecordName;
        }
        return "_digicert." + domain;
    }

    private void validateDcResponse(ResponseEntity<JsonNode> resp, String operation) {
        if (!resp.getStatusCode().is2xxSuccessful() || resp.getBody() == null) {
            throw new PermanentAgentException("CA_API_ERROR",
                    "DigiCert " + operation + " returned non-2xx: " + resp.getStatusCode());
        }
    }

    private X509Certificate parseFirstCert(String chainPem) {
        try {
            int start = chainPem.indexOf("-----BEGIN CERTIFICATE-----");
            int end   = chainPem.indexOf("-----END CERTIFICATE-----") + "-----END CERTIFICATE-----".length();
            String firstPem = chainPem.substring(start, end);
            String b64 = firstPem
                    .replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "")
                    .replaceAll("\\s", "");
            byte[] der = Base64.getDecoder().decode(b64);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new java.io.ByteArrayInputStream(der));
        } catch (Exception e) {
            throw new PermanentAgentException("CERT_PARSE_FAILED",
                    "Failed to parse DigiCert cert chain: " + e.getMessage(), e);
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
