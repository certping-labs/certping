// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.akamai;

import com.certping.agent.deployment.CertificateBundle;
import com.certping.agent.deployment.DeploymentResult;
import com.certping.agent.deployment.adapter.DeploymentAdapter;
import com.certping.agent.deployment.adapter.DeploymentAdapterFor;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RateLimitClassifier;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.model.enums.TargetType;
import com.certping.agent.model.message.CertDeploymentMessage;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Akamai CPS deployment adapter.
 *
 * <p>One credential = one Akamai enrollment. Enrollment ID, network, host,
 * and polling tunables all live in the credential scope. Targets are empty.
 *
 * <p>Three-step flow: resolve pending change → upload cert + trust chain → acknowledge warnings → poll.
 *
 * <p>Result includes a structured {@code lastChange} record (changeId, changeUrl, status,
 * uploadedAt). The server's merger appends to {@code history[]} for audit trail.
 */
@Slf4j
@Component
@DeploymentAdapterFor(TargetType.AKAMAI_CPS)
@RequiredArgsConstructor
public class AkamaiCpsDeploymentAdapter implements DeploymentAdapter {

    private static final String CTX = "Akamai CPS";

    private static final String ENROLLMENT_MEDIA = "application/vnd.akamai.cps.enrollment.v11+json";
    private static final String CHANGE_MEDIA = "application/vnd.akamai.cps.change.v2+json";
    private static final String CHANGE_ID_MEDIA = "application/vnd.akamai.cps.change-id.v1+json";
    private static final String CERT_UPLOAD_MEDIA = "application/vnd.akamai.cps.certificate-and-trust-chain.v2+json";
    private static final String WARNINGS_MEDIA = "application/vnd.akamai.cps.warnings.v1+json";
    private static final String WARNINGS_ACK_MEDIA = "application/vnd.akamai.cps.acknowledgement-with-hash.v1+json";

    private static final int DEFAULT_POLL_INTERVAL_SECONDS = 300;
    private static final int DEFAULT_POLL_TIMEOUT_MINUTES = 480;

    private static final Pattern CERT_BLOCK_PATTERN = Pattern.compile(
            "-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----",
            Pattern.DOTALL);

    private final AkamaiCpsAuthService akamaiCpsAuthService;
    private final ObjectMapper objectMapper;

    @Override
    public DeploymentResult deploy(CertificateBundle bundle, CertDeploymentMessage message) {
        AkamaiScope scope = parseScope(message.getCredentialScopeJson());
        validateScope(scope);

        String enrollmentId = scope.enrollmentId().trim();
        String host = scope.host().trim();

        AkamaiKvSecret kv = akamaiCpsAuthService.parseKvSecret(message.getDeploymentCredHandle());
        int intervalSeconds = scope.pollIntervalSeconds() != null
                ? scope.pollIntervalSeconds() : DEFAULT_POLL_INTERVAL_SECONDS;
        int timeoutMinutes = scope.pollTimeoutMinutes() != null
                ? scope.pollTimeoutMinutes() : DEFAULT_POLL_TIMEOUT_MINUTES;
        String desiredStatus = scope.waitForStatus() == null || scope.waitForStatus().isBlank()
                ? "complete" : scope.waitForStatus().trim().toLowerCase(Locale.ROOT);

        log.info("{} deploy: host={}, enrollmentId={}, xref={}",
                CTX, host, enrollmentId, message.getCertificateXref());

        try (CloseableHttpClient http = akamaiCpsAuthService.buildClient(kv, host)) {
            String baseUrl = akamaiCpsAuthService.baseUrl(host);
            String changeId = resolvePendingChangeId(http, baseUrl, enrollmentId);
            uploadCertAndTrustChain(http, baseUrl, enrollmentId, changeId, bundle);
            acknowledgeWarnings(http, baseUrl, enrollmentId, changeId);
            pollUntilStatus(http, baseUrl, enrollmentId, changeId, intervalSeconds, timeoutMinutes, desiredStatus);

            String changeUrl = "/cps/v2/enrollments/" + enrollmentId + "/changes/" + changeId;
            return DeploymentResult.of(changeUrl,
                    toResultJson(changeId, changeUrl, "complete", OffsetDateTime.now(ZoneOffset.UTC).toString()));

        } catch (PermanentAgentException | TransientAgentException | RetryableAgentException e) {
            throw e;
        } catch (Exception e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "DEPLOY_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("akamai CPS deploy", enrollmentId, e);
            }
            throw new PermanentAgentException("DEPLOY_AKAMAI_FAILED",
                    CTX + " deployment failed: " + e.getMessage(), e);
        }
    }

    // ---------- validation ----------

    void validateScope(AkamaiScope scope) {
        requireField(scope.host(), "scope.host");
        requireField(scope.enrollmentId(), "scope.enrollmentId");
    }

    // ---------- parsing helpers ----------

    private AkamaiScope parseScope(String json) {
        if (json == null || json.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " requires credentialScopeJson");
        }
        try {
            return objectMapper.readValue(json, AkamaiScope.class);
        } catch (Exception e) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    "Failed to parse " + CTX + " credentialScopeJson: " + e.getMessage(), e);
        }
    }

    private String requireField(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " missing required field: " + name);
        }
        return value.trim();
    }

    // ---------- CPS API calls ----------

    private String resolvePendingChangeId(CloseableHttpClient http, String baseUrl, String enrollmentId) throws Exception {
        HttpGet get = new HttpGet(baseUrl + "/cps/v2/enrollments/" + enrollmentId);
        get.setHeader("Accept", ENROLLMENT_MEDIA);
        String body = executeJson(http, get, "DEPLOY_AKAMAI_ENROLLMENT");
        JsonNode root = objectMapper.readTree(body);
        JsonNode pending = root.get("pendingChanges");
        if (pending == null || !pending.isArray() || pending.isEmpty()) {
            throw new PermanentAgentException("DEPLOY_AKAMAI_NO_CHANGE",
                    "No pending CPS change found for enrollmentId=" + enrollmentId);
        }
        String changeUrl = pending.get(0).asString();
        String changeId = changeUrl.substring(changeUrl.lastIndexOf('/') + 1);
        if (changeId.isBlank()) {
            throw new PermanentAgentException("DEPLOY_AKAMAI_NO_CHANGE",
                    "Pending changeId missing for enrollmentId=" + enrollmentId);
        }
        return changeId;
    }

    private void uploadCertAndTrustChain(CloseableHttpClient http, String baseUrl,
                                         String enrollmentId, String changeId,
                                         CertificateBundle bundle) throws Exception {
        String leafCert = requirePem("leaf certificate", bundle.leafCertificate());
        String trustChain = buildTrustChain(bundle.certChain());

        Map<String, Object> certEntry = new LinkedHashMap<>();
        certEntry.put("certificate", leafCert);
        certEntry.put("trustChain", trustChain);
        certEntry.put("keyAlgorithm", "RSA");
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("certificatesAndTrustChains", List.of(certEntry));

        HttpPost post = new HttpPost(baseUrl + "/cps/v2/enrollments/" + enrollmentId
                + "/changes/" + changeId + "/input/update/third-party-cert-and-trust-chain");
        post.setHeader("Accept", CHANGE_ID_MEDIA);
        post.setHeader("Content-Type", CERT_UPLOAD_MEDIA);
        post.setEntity(new StringEntity(objectMapper.writeValueAsString(payload), StandardCharsets.UTF_8));
        executeJson(http, post, "DEPLOY_AKAMAI_UPLOAD");
        log.info("Akamai CPS cert uploaded: enrollmentId={}, changeId={}", enrollmentId, changeId);
    }

    private void acknowledgeWarnings(CloseableHttpClient http, String baseUrl,
                                     String enrollmentId, String changeId) throws Exception {
        HttpGet get = new HttpGet(baseUrl + "/cps/v2/enrollments/" + enrollmentId
                + "/changes/" + changeId + "/input/info/post-verification-warnings");
        get.setHeader("Accept", WARNINGS_MEDIA);
        String body = executeJson(http, get, "DEPLOY_AKAMAI_WARNINGS");
        JsonNode root = objectMapper.readTree(body);
        JsonNode warnings = root.get("warnings");
        if (warnings == null || !warnings.isArray() || warnings.isEmpty()) return;

        List<String> codes = new ArrayList<>();
        for (JsonNode warn : warnings) {
            JsonNode code = warn.get("messageCode");
            if (code != null && !code.asString().isBlank()) codes.add(code.asString());
        }
        if (codes.isEmpty()) return;

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("acknowledgement", "acknowledge");
        payload.put("acknowledgedWarnings", codes);

        HttpPost post = new HttpPost(baseUrl + "/cps/v2/enrollments/" + enrollmentId
                + "/changes/" + changeId + "/input/update/post-verification-warnings-ack");
        post.setHeader("Accept", CHANGE_ID_MEDIA);
        post.setHeader("Content-Type", WARNINGS_ACK_MEDIA);
        post.setEntity(new StringEntity(objectMapper.writeValueAsString(payload), StandardCharsets.UTF_8));
        executeJson(http, post, "DEPLOY_AKAMAI_WARN_ACK");
        log.info("Akamai CPS warnings acknowledged: enrollmentId={}, changeId={}, warnings={}",
                enrollmentId, changeId, codes.size());
    }

    private void pollUntilStatus(CloseableHttpClient http, String baseUrl, String enrollmentId,
                                 String changeId, int intervalSeconds, int timeoutMinutes,
                                 String desiredStatus) throws Exception {
        long deadline = System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(timeoutMinutes);
        while (System.currentTimeMillis() < deadline) {
            HttpGet get = new HttpGet(baseUrl + "/cps/v2/enrollments/" + enrollmentId
                    + "/changes/" + changeId);
            get.setHeader("Accept", CHANGE_MEDIA);
            String body = executeJson(http, get, "DEPLOY_AKAMAI_CHANGE");
            JsonNode root = objectMapper.readTree(body);
            String status = root.path("statusInfo").path("status").asString("");
            log.info("Akamai CPS change status: enrollmentId={}, changeId={}, status={}",
                    enrollmentId, changeId, status);
            if (status.equalsIgnoreCase(desiredStatus)) return;
            if ("error".equalsIgnoreCase(status)) {
                throw new PermanentAgentException("DEPLOY_AKAMAI_ERROR",
                        "Akamai CPS deployment error for enrollmentId=" + enrollmentId
                                + " changeId=" + changeId);
            }
            Thread.sleep(intervalSeconds * 1000L);
        }
        throw new TransientAgentException("DEPLOY_AKAMAI_TIMEOUT",
                "Timed out waiting for CPS change status '" + desiredStatus + "' for enrollmentId="
                        + enrollmentId + " changeId=" + changeId);
    }

    // ---------- bundle / HTTP helpers ----------

    private String buildTrustChain(String certChain) throws Exception {
        if (certChain == null || certChain.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CERT_INVALID",
                    "Certificate bundle missing trust chain for Akamai deployment");
        }
        List<String> blocks = extractCertBlocks(certChain);
        List<String> intermediates = new ArrayList<>();
        for (String block : blocks) {
            if (!isSelfSigned(block)) intermediates.add(block.trim());
        }
        if (intermediates.isEmpty()) {
            throw new PermanentAgentException("DEPLOY_CERT_INVALID",
                    "Trust chain only contains a root certificate; intermediates are required");
        }
        return String.join("\n", intermediates);
    }

    private List<String> extractCertBlocks(String pem) {
        List<String> blocks = new ArrayList<>();
        Matcher matcher = CERT_BLOCK_PATTERN.matcher(pem);
        while (matcher.find()) blocks.add(matcher.group());
        return blocks;
    }

    private boolean isSelfSigned(String certPem) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        try (ByteArrayInputStream in = new ByteArrayInputStream(certPem.getBytes(StandardCharsets.UTF_8))) {
            X509Certificate cert = (X509Certificate) factory.generateCertificate(in);
            return cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal());
        }
    }

    private String requirePem(String name, String pem) {
        if (pem == null || pem.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CERT_INVALID",
                    "Certificate bundle missing " + name + " for Akamai deployment");
        }
        return pem.trim();
    }

    private String executeJson(CloseableHttpClient http, HttpGet request, String errorCode) throws Exception {
        try (CloseableHttpResponse response = http.execute(request)) {
            return handleResponse(response, errorCode);
        }
    }

    private String executeJson(CloseableHttpClient http, HttpPost request, String errorCode) throws Exception {
        try (CloseableHttpResponse response = http.execute(request)) {
            return handleResponse(response, errorCode);
        }
    }

    private String handleResponse(CloseableHttpResponse response, String errorCode) throws Exception {
        int status = response.getCode();
        HttpEntity entity = response.getEntity();
        String body = entity == null ? "" : EntityUtils.toString(entity);
        if (status >= 200 && status < 300) return body;
        if (status == 429 || status == 503) {
            // Akamai CPS: 35/min + 20/2s burst; honour Retry-After.
            Header retryAfterHeader = response.getFirstHeader("Retry-After");
            Duration retryAfter = retryAfterHeader == null ? null
                    : RateLimitClassifier.parseRetryAfterValueOpt(retryAfterHeader.getValue()).orElse(null);
            throw new RetryableAgentException("DEPLOY_PROVIDER_THROTTLED",
                    "akamai CPS deploy was rate-limited (HTTP " + status + "): " + truncate(body),
                    retryAfter);
        }
        if (status >= 500) {
            throw new TransientAgentException(errorCode, "Akamai CPS HTTP " + status + ": " + truncate(body));
        }
        throw new PermanentAgentException(errorCode, "Akamai CPS HTTP " + status + ": " + truncate(body));
    }

    private String truncate(String body) {
        if (body == null) return "";
        String trimmed = body.trim();
        return trimmed.length() > 400 ? trimmed.substring(0, 400) + "..." : trimmed;
    }

    private String toResultJson(String changeId, String changeUrl, String status, String uploadedAt) {
        try {
            Map<String, Object> lastChange = new LinkedHashMap<>();
            lastChange.put("changeId", changeId);
            lastChange.put("changeUrl", changeUrl);
            lastChange.put("status", status);
            lastChange.put("uploadedAt", uploadedAt);
            Map<String, Object> root = new LinkedHashMap<>();
            root.put("lastChange", lastChange);
            return objectMapper.writeValueAsString(root);
        } catch (Exception e) {
            return "{\"lastChange\":{\"changeId\":\"" + changeId + "\"}}";
        }
    }
}
