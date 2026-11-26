// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.cloudflare;

import com.certping.agent.deployment.CertificateBundle;
import com.certping.agent.deployment.DeploymentResult;
import com.certping.agent.deployment.adapter.DeploymentAdapter;
import com.certping.agent.deployment.adapter.DeploymentAdapterFor;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RateLimitClassifier;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.model.credential.CloudflareEdgeDeploymentCredential;
import com.certping.agent.model.enums.TargetType;
import com.certping.agent.model.message.CertDeploymentMessage;
import com.certping.agent.secrets.SecretStore;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Cloudflare Edge custom-cert deployment.
 *
 * <p>One credential = one Cloudflare zone. Zone ID, bundle method, cert type all live
 * in the credential scope. Targets are empty. Result stores a flat {@code certId}.
 *
 * <p>Two-step flow: upload cert (POST first deploy / PATCH rotation) → poll until active.
 */
@Slf4j
@Component
@DeploymentAdapterFor(TargetType.CLOUDFLARE_EDGE)
@RequiredArgsConstructor
public class CloudflareEdgeDeploymentAdapter implements DeploymentAdapter {

    private static final String CTX = "Cloudflare Edge";
    private static final String API_BASE = "https://api.cloudflare.com/client/v4";
    private static final int POLL_ATTEMPTS = 30;
    private static final long POLL_INTERVAL_MS = 5_000L;
    private static final String DEFAULT_BUNDLE_METHOD = "ubiquitous";
    private static final String DEFAULT_CERT_TYPE = "sni_custom";

    private final SecretStore secretStore;
    private final ObjectMapper objectMapper;
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(20))
            .build();

    @Override
    public DeploymentResult deploy(CertificateBundle bundle, CertDeploymentMessage message) {
        String credRaw = secretStore.read(message.getDeploymentCredHandle());
        CloudflareEdgeDeploymentCredential kv = CloudflareDeploymentAuthHelper.parseKvSecret(objectMapper, credRaw);
        String authHeader = CloudflareDeploymentAuthHelper.bearerToken(kv.getApiToken());

        CloudflareScope scope = parseScope(message.getCredentialScopeJson());
        validateScope(scope);

        String zoneId = scope.zoneId().trim();
        String bundleMethod = pickBundleMethod(scope);
        String certType = pickCertType(scope);

        CloudflareResult prior = parsePriorResult(message.getConfigJson());

        String keyPem = requirePrivateKey(bundle.privateKey());
        String certPem = selectCertificatePem(bundle, bundleMethod);

        log.info("Cloudflare Edge deploy: zoneId={}, xref={}", zoneId, message.getCertificateXref());

        try {
            String newCertId;
            String existingCertId = prior.certId();
            if (existingCertId != null && !existingCertId.isBlank()) {
                log.info("Cloudflare PATCH (rotation): zoneId={}, oldCertId={}", zoneId, existingCertId);
                newCertId = patchCert(authHeader, zoneId, existingCertId, certPem, keyPem, bundleMethod, certType);
            } else {
                log.info("Cloudflare POST (first deploy): zoneId={}", zoneId);
                newCertId = postCert(authHeader, zoneId, certPem, keyPem, bundleMethod, certType);
            }
            waitForActive(authHeader, zoneId, newCertId);

            String resultJson = serializeResult(newCertId);
            return DeploymentResult.of(newCertId, resultJson);

        } catch (PermanentAgentException | TransientAgentException | RetryableAgentException e) {
            throw e;
        } catch (Exception e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "DEPLOY_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("cloudflare edge upsert", zoneId, e);
            }
            throw new PermanentAgentException("DEPLOY_CLOUDFLARE_FAILED",
                    "Cloudflare Edge deployment failed: " + e.getMessage(), e);
        }
    }

    // ---------- validation ----------

    void validateScope(CloudflareScope scope) {
        requireField(scope.zoneId(), "scope.zoneId");
    }

    // ---------- parsing helpers ----------

    private CloudflareScope parseScope(String json) {
        if (json == null || json.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " requires credentialScopeJson");
        }
        try {
            return objectMapper.readValue(json, CloudflareScope.class);
        } catch (Exception e) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    "Failed to parse " + CTX + " credentialScopeJson: " + e.getMessage(), e);
        }
    }

    private CloudflareResult parsePriorResult(String json) {
        if (json == null || json.isBlank()) {
            return CloudflareResult.empty();
        }
        try {
            CloudflareResult parsed = objectMapper.readValue(json, CloudflareResult.class);
            return parsed != null ? parsed : CloudflareResult.empty();
        } catch (Exception e) {
            log.warn("Cloudflare prior configJson unparseable — treating as first-deploy: {}",
                    e.getMessage());
            return CloudflareResult.empty();
        }
    }

    private String pickBundleMethod(CloudflareScope scope) {
        if (scope.bundleMethod() != null && !scope.bundleMethod().isBlank()) {
            return scope.bundleMethod().trim().toLowerCase();
        }
        return DEFAULT_BUNDLE_METHOD;
    }

    private String pickCertType(CloudflareScope scope) {
        if (scope.certType() != null && !scope.certType().isBlank()) {
            return scope.certType().trim().toLowerCase();
        }
        return DEFAULT_CERT_TYPE;
    }

    private String requirePrivateKey(String keyPem) {
        if (keyPem == null || keyPem.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CERT_INVALID",
                    "Certificate bundle missing private key for Cloudflare deployment");
        }
        return keyPem.trim();
    }

    private String requireField(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " missing required field: " + name);
        }
        return value.trim();
    }

    private String selectCertificatePem(CertificateBundle bundle, String bundleMethod) {
        String leaf = bundle.leafCertificate();
        String fullChain = bundle.fullChain();

        boolean leafOnly = "ubiquitous".equalsIgnoreCase(bundleMethod)
                || "optimal".equalsIgnoreCase(bundleMethod);

        if (leafOnly && leaf != null && !leaf.isBlank()) {
            return leaf.trim();
        }
        if (fullChain != null && !fullChain.isBlank()) {
            return fullChain.trim();
        }
        if (leaf != null && !leaf.isBlank()) {
            return leaf.trim();
        }
        throw new PermanentAgentException("DEPLOY_CERT_INVALID",
                "Certificate bundle missing leaf or chain for Cloudflare deployment");
    }

    private String serializeResult(String certId) {
        try {
            Map<String, Object> root = new LinkedHashMap<>();
            root.put("certId", certId);
            return objectMapper.writeValueAsString(root);
        } catch (Exception e) {
            return "{\"certId\":\"" + certId + "\"}";
        }
    }

    // ---------- HTTP helpers ----------

    private String postCert(String authHeader, String zoneId, String certPem, String keyPem,
                            String bundleMethod, String certType) throws Exception {
        Map<String, Object> body = buildCertBody(certPem, keyPem, bundleMethod, certType);
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(API_BASE + "/zones/" + zoneId + "/custom_certificates"))
                .header("Authorization", authHeader)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(body)))
                .build();
        return executeAndExtractCertId(req, "DEPLOY_CLOUDFLARE_UPLOAD_FAILED", zoneId);
    }

    private String patchCert(String authHeader, String zoneId, String existingCertId,
                             String certPem, String keyPem, String bundleMethod, String certType) throws Exception {
        Map<String, Object> body = buildCertBody(certPem, keyPem, bundleMethod, certType);
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(API_BASE + "/zones/" + zoneId + "/custom_certificates/" + existingCertId))
                .header("Authorization", authHeader)
                .header("Content-Type", "application/json")
                .method("PATCH", HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(body)))
                .build();
        return executeAndExtractCertId(req, "DEPLOY_CLOUDFLARE_PATCH_FAILED", zoneId);
    }

    private Map<String, Object> buildCertBody(String certPem, String keyPem,
                                              String bundleMethod, String certType) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("certificate", certPem);
        body.put("private_key", keyPem);
        body.put("bundle_method", bundleMethod);
        body.put("type", certType);
        return body;
    }

    private String executeAndExtractCertId(HttpRequest req, String errorCode, String zoneId) throws Exception {
        HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        int status = resp.statusCode();
        if (status != 200) {
            throw wrapCloudflareError(errorCode, resp);
        }
        JsonNode root = objectMapper.readTree(resp.body());
        if (!root.path("success").asBoolean(false)) {
            throw new PermanentAgentException(errorCode,
                    "Cloudflare API rejected request: " + extractErrors(root));
        }
        String certId = root.path("result").path("id").asString("");
        if (certId.isBlank()) {
            throw new PermanentAgentException(errorCode,
                    "Cloudflare response for zone " + zoneId + " missing certificate id");
        }
        log.info("Cloudflare cert id received: zoneId={}, certId={}", zoneId, certId);
        return certId;
    }

    private void waitForActive(String authHeader, String zoneId, String certId) throws Exception {
        for (int i = 0; i < POLL_ATTEMPTS; i++) {
            Thread.sleep(POLL_INTERVAL_MS);

            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(API_BASE + "/zones/" + zoneId + "/custom_certificates/" + certId))
                    .header("Authorization", authHeader)
                    .GET()
                    .build();

            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                throw wrapCloudflareError("DEPLOY_CLOUDFLARE_POLL_FAILED", resp);
            }
            JsonNode root = objectMapper.readTree(resp.body());
            if (!root.path("success").asBoolean(false)) {
                throw new PermanentAgentException("DEPLOY_CLOUDFLARE_POLL_FAILED",
                        "Cloudflare status lookup failed: " + extractErrors(root));
            }
            String certStatus = root.path("result").path("status").asString("");
            log.debug("Cloudflare cert status: zoneId={}, certId={}, status={}", zoneId, certId, certStatus);

            if ("active".equalsIgnoreCase(certStatus)) {
                return;
            }
            if ("pending_deployment".equalsIgnoreCase(certStatus)) {
                continue;
            }
            throw new PermanentAgentException("DEPLOY_CLOUDFLARE_POLL_FAILED",
                    "Unexpected Cloudflare cert status: " + certStatus);
        }
        throw new TransientAgentException("DEPLOY_CLOUDFLARE_TIMEOUT",
                "Timed out waiting for Cloudflare cert to become active: " + certId);
    }

    private RuntimeException wrapCloudflareError(String code, HttpResponse<String> resp) {
        int status = resp.statusCode();
        String body = resp.body() == null ? "" : resp.body();
        String message = "Cloudflare API error (HTTP " + status + "): " + body;
        if (status == 429 || status == 503) {
            // Cloudflare custom-cert endpoints are rate-limited; honour Retry-After.
            Duration retryAfter = resp.headers().firstValue("Retry-After")
                    .flatMap(RateLimitClassifier::parseRetryAfterValueOpt)
                    .orElse(null);
            return new RetryableAgentException("DEPLOY_PROVIDER_THROTTLED",
                    "cloudflare edge call was rate-limited (HTTP " + status + "): " + body,
                    retryAfter);
        }
        if (status >= 500) {
            return new TransientAgentException(code, message);
        }
        return new PermanentAgentException(code, message);
    }

    private String extractErrors(JsonNode root) {
        if (root == null || !root.has("errors")) return "Unknown error";
        StringBuilder sb = new StringBuilder();
        for (JsonNode err : root.path("errors")) {
            String code = err.path("code").asString("");
            String msg = err.path("message").asString("");
            if (sb.length() > 0) sb.append("; ");
            if (!code.isBlank()) sb.append(code).append(": ");
            sb.append(msg);
        }
        return sb.length() == 0 ? "Unknown error" : sb.toString();
    }
}
